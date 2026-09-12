# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project-memory store tests
"""Verify retained generation chains through public history and CLI boundaries."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from project_memory_store_support import manifest, parents, record, repository

from rigor_foundry.project_memory_models import ProjectMemoryManifest
from rigor_foundry.project_memory_primitives import (
    ProjectMemoryActor,
)
from rigor_foundry.project_memory_store import (
    PROJECT_MEMORY_MAX_HISTORY_ENTRIES,
    ProjectMemoryStoreInvalid,
    commit_project_memory_generation,
    load_project_memory_generation,
    verify_project_memory_history,
    write_project_memory_record,
)


def test_history_verifier_rejects_missing_and_nonregular_entries(tmp_path: Path) -> None:
    """On-demand chain verification rejects broken history and directory injection."""
    root = repository(tmp_path)
    content = b"# Identity\n"
    item = record("identity-0001", content)
    write_project_memory_record(root, item, content)
    candidate = manifest("2026-09-04T12:01:00.000000Z", (item,))
    history = commit_project_memory_generation(root, candidate)
    history.unlink()
    with pytest.raises(ProjectMemoryStoreInvalid, match="history manifest is unavailable"):
        verify_project_memory_history(root)

    history.write_bytes(candidate.to_bytes())
    history.chmod(0o600)
    injected = history.parent / "unexpected"
    injected.mkdir(mode=0o700)
    with pytest.raises(ProjectMemoryStoreInvalid, match="non-regular entry"):
        verify_project_memory_history(root)
    injected.rmdir()
    invalid_name = history.parent / "invalid.json"
    invalid_name.write_text("{}", encoding="utf-8")
    invalid_name.chmod(0o600)
    with pytest.raises(ProjectMemoryStoreInvalid, match="filename is invalid"):
        verify_project_memory_history(root)
    invalid_name.unlink()
    mismatched_name = history.parent / f"{candidate.generation_id}_{'0' * 64}.json"
    mismatched_name.write_bytes(candidate.to_bytes())
    mismatched_name.chmod(0o600)
    with pytest.raises(ProjectMemoryStoreInvalid, match="filename does not match"):
        verify_project_memory_history(root)


def test_history_verifier_requires_every_predecessor_object(tmp_path: Path) -> None:
    """The current object alone cannot conceal a missing predecessor generation."""
    root = repository(tmp_path)
    first_content = b"# Identity one\n"
    first = record("identity-0001", first_content)
    write_project_memory_record(root, first, first_content)
    first_manifest = manifest("2026-09-04T12:01:00.000000Z", (first,))
    first_history = commit_project_memory_generation(root, first_manifest)
    second_content = b"# Identity two\n"
    second = record("identity-0002", second_content, supersedes=(first.record_id,))
    write_project_memory_record(root, second, second_content)
    second_manifest = manifest(
        "2026-09-04T12:02:00.000000Z",
        (second,),
        first_manifest.manifest_sha256,
    )
    commit_project_memory_generation(root, second_manifest)
    first_history.unlink()

    with pytest.raises(ProjectMemoryStoreInvalid, match="predecessor is missing"):
        verify_project_memory_history(root)


@pytest.mark.parametrize(
    ("corruption", "message"),
    [
        ("omission", "cannot disappear"),
        ("metadata", "metadata cannot change"),
        ("unknown-supersession", "unknown current record"),
        ("initial-supersession", "unseen supersession"),
        ("forked-supersession", "multiple direct successors"),
    ],
)
def test_history_verifier_replays_generation_rules(
    tmp_path: Path, corruption: str, message: str
) -> None:
    """Rehashed history must not legitimise a transition the writer would refuse."""
    root = repository(tmp_path)
    payload = b"# Permanent project identity\n"
    original = record("identity-original", payload)
    write_project_memory_record(root, original, payload)
    anchor = record("identity-anchor", payload)
    write_project_memory_record(root, anchor, payload)
    first = manifest("2026-09-04T12:01:00.000000Z", (anchor, original))
    commit_project_memory_generation(root, first)
    successor = record("identity-successor", payload, supersedes=("never-current",))
    write_project_memory_record(root, successor, payload)
    forks = tuple(
        record(identifier, payload, supersedes=(original.record_id,))
        for identifier in ("identity-fork-one", "identity-fork-two")
    )
    for fork in forks:
        write_project_memory_record(root, fork, payload)
    variants = {
        "omission": (anchor,),
        "metadata": (replace(original, actor=ProjectMemoryActor("PROJECT/other", "other")),),
        "unknown-supersession": (successor,),
        "initial-supersession": (successor,),
        "forked-supersession": (anchor, *forks),
    }
    predecessor = None if corruption == "initial-supersession" else first.manifest_sha256
    invalid = manifest("2026-09-04T12:02:00.000000Z", variants[corruption], predecessor)
    with pytest.raises(ProjectMemoryStoreInvalid):
        commit_project_memory_generation(root, invalid)

    tip = manifest("2026-09-04T12:03:00.000000Z", invalid.records, invalid.manifest_sha256)
    private = root / "agentic_project_memory"
    for generation in (invalid, tip):
        history = (
            private
            / "history/manifests"
            / (f"{generation.generation_id}_{generation.manifest_sha256}.json")
        )
        history.write_bytes(generation.to_bytes())
        history.chmod(0o600)
    (private / "memory_manifest.json").write_bytes(tip.to_bytes())
    (private / "memory_index.md").write_text(tip.index_text(), encoding="utf-8")
    assert load_project_memory_generation(root) == tip
    before = {path: path.read_bytes() for path in private.rglob("*") if path.is_file()}

    with pytest.raises(ProjectMemoryStoreInvalid, match=message):
        verify_project_memory_history(root)

    result = subprocess.run(
        [sys.executable, "-m", "tools.check_project_memory_integrity", str(root), "--history"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 1
    assert result.stdout == b"project-memory-integrity: FAIL\n"
    assert result.stderr == b""
    assert {path: path.read_bytes() for path in before} == before


@pytest.mark.parametrize("invalid_predecessor", ["identity", "order"])
def test_history_rejects_rehashed_project_or_time_discontinuity(
    tmp_path: Path, invalid_predecessor: str
) -> None:
    """Valid object hashes do not permit project changes or backwards history."""
    root = repository(tmp_path)
    payload = b"# Identity\n"
    item = record("identity-history", payload)
    write_project_memory_record(root, item, payload)
    predecessor = ProjectMemoryManifest.build(
        project_id="OTHER" if invalid_predecessor == "identity" else "PROJECT",
        generated_at="2026-09-04T12:03:00.000000Z",
        previous_manifest_sha256=None,
        parents=parents(),
        records=(item,),
    )
    tip = manifest("2026-09-04T12:02:00.000000Z", (item,), predecessor.manifest_sha256)
    private = root / "agentic_project_memory"
    history = private / "history/manifests"
    history.mkdir(parents=True, mode=0o700)
    history.parent.chmod(0o700)
    for generation in (predecessor, tip):
        path = history / f"{generation.generation_id}_{generation.manifest_sha256}.json"
        path.write_bytes(generation.to_bytes())
        path.chmod(0o600)
    for name, data in [
        ("memory_manifest.json", tip.to_bytes()),
        ("memory_index.md", tip.index_text().encode()),
    ]:
        path = private / name
        path.write_bytes(data)
        path.chmod(0o600)
    assert load_project_memory_generation(root) == tip
    with pytest.raises(ProjectMemoryStoreInvalid, match="predecessor order or identity"):
        verify_project_memory_history(root)


def test_history_entry_quota_counts_real_retained_generations(tmp_path: Path) -> None:
    """The public verifier refuses a real history directory beyond its quota."""
    root = repository(tmp_path)
    payload = b"# Identity\n"
    item = record("identity-quota", payload)
    write_project_memory_record(root, item, payload)
    first = manifest("2026-09-04T12:01:00.000000Z", (item,))
    history = commit_project_memory_generation(root, first).parent
    start = datetime(2026, 9, 4, 12, 2, tzinfo=UTC)
    for offset in range(PROJECT_MEMORY_MAX_HISTORY_ENTRIES):
        timestamp = (start + timedelta(seconds=offset)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
        generation = manifest(timestamp, (item,))
        path = history / f"{generation.generation_id}_{generation.manifest_sha256}.json"
        path.write_bytes(generation.to_bytes())
        path.chmod(0o600)
    with pytest.raises(ProjectMemoryStoreInvalid, match="entry count is out of bounds"):
        verify_project_memory_history(root)
    assert load_project_memory_generation(root) == first
