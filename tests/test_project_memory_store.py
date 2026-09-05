# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project-memory store tests
"""Exercise immutable content and generation commits in real Git worktrees."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from test_project_memory_models import profiled_manifest

from rigor_foundry.project_memory_models import ProjectMemoryManifest, ProjectMemoryRecord
from rigor_foundry.project_memory_primitives import (
    PROJECT_MEMORY_PARENT_KINDS,
    ProjectMemoryActor,
    ProjectMemoryFreshness,
    ProjectMemoryParent,
    ProjectMemorySource,
)
from rigor_foundry.project_memory_store import (
    PROJECT_MEMORY_MAX_HISTORY_ENTRIES,
    ProjectMemoryStoreInvalid,
    commit_project_memory_generation,
    load_project_memory_generation,
    verify_project_memory_history,
    write_project_memory_record,
)


def git(repository: Path, *arguments: str) -> None:
    """Run Git against one real temporary worktree."""
    subprocess.run(
        ["git", "-c", f"safe.directory={repository}", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )


def repository(tmp_path: Path) -> Path:
    """Create a real worktree with portable private-root protection."""
    root = tmp_path / "repository"
    root.mkdir(parents=True)
    git(root, "init", "--quiet")
    (root / ".gitignore").write_text("/agentic_project_memory/\n", encoding="utf-8")
    git(root, "add", ".gitignore")
    (root / "agentic_project_memory").mkdir(mode=0o700)
    return root


def parents() -> tuple[ProjectMemoryParent, ...]:
    """Return every selective parent layer in canonical order."""
    return tuple(
        ProjectMemoryParent(
            kind,
            {
                "ecosystem-boot": "../../../AGENTS.md",
                "ecosystem-rules": "../../../agentic-shared/SHARED_CONTEXT.md",
                "ecosystem-memory": "../../../agentic-shared/memory/INDEX.md",
                "group-memory": "../../agentic_group_memory/memory_index.md",
                "project-sessions": "../../../.coordination/sessions/PROJECT/",
                "project-handovers": "../../../.coordination/handovers/PROJECT/",
                "vendor-memory": "../../../agentic-shared/memory/vendors/",
            }[kind],
        )
        for kind in PROJECT_MEMORY_PARENT_KINDS
    )


def record(
    record_id: str,
    content: bytes,
    *,
    supersedes: tuple[str, ...] = (),
    freshness: ProjectMemoryFreshness | None = None,
) -> ProjectMemoryRecord:
    """Build one immutable identity-record fixture."""
    return ProjectMemoryRecord.for_content(
        record_id=record_id,
        category="identity",
        created_at="2026-09-04T12:00:00.000000Z",
        observed_at="2026-09-04T11:59:00.000000Z",
        freshness=freshness or ProjectMemoryFreshness("immutable", None),
        assertion_class="observation",
        sources=(ProjectMemorySource("source", "coordination/session.md", "a" * 64),),
        actor=ProjectMemoryActor("RIGOR-FOUNDRY/validator-1", "memory-write"),
        supersedes=supersedes,
        content=content,
    )


def manifest(
    generated_at: str,
    records: tuple[ProjectMemoryRecord, ...],
    previous: str | None = None,
) -> ProjectMemoryManifest:
    """Build one exact current-view fixture."""
    return ProjectMemoryManifest.build(
        project_id="PROJECT",
        generated_at=generated_at,
        previous_manifest_sha256=previous,
        parents=parents(),
        records=tuple(sorted(records, key=lambda item: item.record_id)),
    )


@pytest.mark.parametrize("transition", ["same-profile", "upgrade", "downgrade", "changed-profile"])
def test_profiled_history_preserves_identity_and_prior_bytes(
    tmp_path: Path, transition: str
) -> None:
    root = repository(tmp_path)
    content = b"# Profile-bound project identity\n"
    identity = record("identity-0001", content)
    record_path = write_project_memory_record(root, identity, content)
    legacy = manifest("2026-09-04T12:01:00.000000Z", (identity,))
    first = legacy if transition == "upgrade" else profiled_manifest(legacy)
    old_history = commit_project_memory_generation(root, first)
    sentinel = root / "owner-untracked.md"
    sentinel.write_bytes(b"keep-owner-work")
    next_base = manifest("2026-09-04T12:02:00.000000Z", (identity,), first.manifest_sha256)
    second = (
        next_base
        if transition == "downgrade"
        else profiled_manifest(
            next_base,
            root="06_WEBMASTER" if transition == "changed-profile" else "portfolios/SCIENCE",
        )
    )
    if transition == "same-profile":
        commit_project_memory_generation(root, second)
        assert load_project_memory_generation(root) == second
        assert set(verify_project_memory_history(root)) == {
            first.manifest_sha256,
            second.manifest_sha256,
        }
        result = subprocess.run(
            [sys.executable, "-m", "tools.check_project_memory_integrity", str(root), "--history"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout == "project-memory-integrity: PASS\n"
    else:
        before = {
            path: path.read_bytes()
            for path in (root / "agentic_project_memory").rglob("*")
            if path.is_file()
        }
        with pytest.raises(ProjectMemoryStoreInvalid, match="explicit migration"):
            commit_project_memory_generation(root, second)
        assert load_project_memory_generation(root) == first
        assert before == {
            path: path.read_bytes()
            for path in (root / "agentic_project_memory").rglob("*")
            if path.is_file()
        }
    assert old_history.read_bytes() == first.to_bytes()
    assert record_path.read_bytes() == content
    assert sentinel.read_bytes() == b"keep-owner-work"


def test_initial_generation_closes_content_index_manifest_and_history(tmp_path: Path) -> None:
    """A real initial commit retains one immutable object and exact current views."""
    root = repository(tmp_path)
    content = b"# Project identity\n"
    identity = record("identity-0001", content)
    content_path = write_project_memory_record(root, identity, content)
    candidate = manifest("2026-09-04T12:01:00.000000Z", (identity,))

    history_path = commit_project_memory_generation(root, candidate)

    assert load_project_memory_generation(root) == candidate
    assert history_path.read_bytes() == candidate.to_bytes()
    assert content_path.read_bytes() == content
    private_files = [
        content_path,
        history_path,
        root / "agentic_project_memory/memory_manifest.json",
        root / "agentic_project_memory/memory_index.md",
        root / "agentic_project_memory/.generation.lock",
    ]
    assert all(os.stat(path).st_mode & 0o777 == 0o600 for path in private_files)
    private_directories = [
        root / "agentic_project_memory",
        root / "agentic_project_memory/records",
        root / "agentic_project_memory/records/identity",
        root / "agentic_project_memory/history",
        root / "agentic_project_memory/history/manifests",
    ]
    assert all(os.stat(path).st_mode & 0o777 == 0o700 for path in private_directories)


@pytest.mark.parametrize("profiled", [False, True])
def test_supersession_preserves_old_content_and_chains_history(
    tmp_path: Path, profiled: bool
) -> None:
    """A successor removes the prior view without mutating content or history."""
    root = repository(tmp_path)
    first_content = b"# Identity one\n"
    first = record("identity-0001", first_content)
    write_project_memory_record(root, first, first_content)
    first_manifest = manifest("2026-09-04T12:01:00.000000Z", (first,))
    if profiled:
        first_manifest = profiled_manifest(first_manifest)
    first_history = commit_project_memory_generation(root, first_manifest)

    second_content = b"# Identity two\n"
    second = record("identity-0002", second_content, supersedes=(first.record_id,))
    write_project_memory_record(root, second, second_content)
    second_manifest = manifest(
        "2026-09-04T12:02:00.000000Z",
        (second,),
        first_manifest.manifest_sha256,
    )
    if profiled:
        second_manifest = profiled_manifest(second_manifest)
    second_history = commit_project_memory_generation(root, second_manifest)

    assert load_project_memory_generation(root) == second_manifest
    assert first_history.read_bytes() == first_manifest.to_bytes()
    assert second_history.read_bytes() == second_manifest.to_bytes()
    assert (root / "agentic_project_memory" / first.content_path).read_bytes() == first_content
    assert first.record_id not in second_manifest.index_text()
    assert verify_project_memory_history(root) == (
        second_manifest.manifest_sha256,
        first_manifest.manifest_sha256,
    )


def test_expiry_allows_omission_but_unexpired_disappearance_is_rejected(tmp_path: Path) -> None:
    """Only expiry or explicit supersession can remove a prior current record."""
    root = repository(tmp_path)
    stable_content = b"# Stable\n"
    expiring_content = b"# Temporary\n"
    stable = record("identity-stable", stable_content)
    expiring = record(
        "identity-temporary",
        expiring_content,
        freshness=ProjectMemoryFreshness("expires", "2026-09-04T12:01:30.000000Z"),
    )
    for item, content in ((stable, stable_content), (expiring, expiring_content)):
        write_project_memory_record(root, item, content)
    first = manifest("2026-09-04T12:01:00.000000Z", (stable, expiring))
    commit_project_memory_generation(root, first)

    invalid = manifest(
        "2026-09-04T12:01:20.000000Z",
        (stable,),
        first.manifest_sha256,
    )
    with pytest.raises(ProjectMemoryStoreInvalid, match="cannot disappear"):
        commit_project_memory_generation(root, invalid)

    expired = manifest(
        "2026-09-04T12:02:00.000000Z",
        (stable,),
        first.manifest_sha256,
    )
    commit_project_memory_generation(root, expired)
    assert load_project_memory_generation(root) == expired
    assert verify_project_memory_history(root) == (
        expired.manifest_sha256,
        first.manifest_sha256,
    )
    assert (root / "agentic_project_memory" / expiring.content_path).is_file()


def test_record_create_is_immutable_and_validates_markdown_bytes(tmp_path: Path) -> None:
    """Overwrite, changed digest, missing newline and binary content all fail closed."""
    root = repository(tmp_path)
    content = b"# Identity\n"
    item = record("identity-0001", content)
    write_project_memory_record(root, item, content)
    with pytest.raises(ProjectMemoryStoreInvalid, match="immutable content create failed"):
        write_project_memory_record(root, item, content)
    with pytest.raises(ProjectMemoryStoreInvalid, match="digest"):
        write_project_memory_record(root, item, b"# Changed!\n")
    without_newline = record("identity-0002", b"# No newline")
    with pytest.raises(ProjectMemoryStoreInvalid, match="ending in a newline"):
        write_project_memory_record(root, without_newline, b"# No newline")
    binary = record("identity-0003", b"\xff\n")
    with pytest.raises(ProjectMemoryStoreInvalid, match="must be UTF-8"):
        write_project_memory_record(root, binary, b"\xff\n")


def test_current_generation_rejects_tampered_index_content_and_history(tmp_path: Path) -> None:
    """Every accepted read rechecks all current and immutable closure surfaces."""
    root = repository(tmp_path)
    content = b"# Identity\n"
    item = record("identity-0001", content)
    write_project_memory_record(root, item, content)
    candidate = manifest("2026-09-04T12:01:00.000000Z", (item,))
    history = commit_project_memory_generation(root, candidate)
    index = root / "agentic_project_memory/memory_index.md"
    index.write_text("changed\n", encoding="utf-8")
    with pytest.raises(ProjectMemoryStoreInvalid, match="index does not match"):
        load_project_memory_generation(root)

    index.write_text(candidate.index_text(), encoding="utf-8")
    content_path = root / "agentic_project_memory" / item.content_path
    content_path.write_text("changed\n", encoding="utf-8")
    with pytest.raises(ProjectMemoryStoreInvalid, match=r"byte count|digest"):
        load_project_memory_generation(root)

    content_path.write_bytes(content)
    history.write_text("{}", encoding="utf-8")
    with pytest.raises(ProjectMemoryStoreInvalid, match="absent from history"):
        load_project_memory_generation(root)


def test_bootstrap_symlink_and_permissions_never_promote_silently(tmp_path: Path) -> None:
    """Non-v1 state and unsafe private roots remain explicit activation blockers."""
    root = repository(tmp_path)
    current = root / "agentic_project_memory/memory_manifest.json"
    current.write_text('{"schema_version":"project-memory.bootstrap.v1"}', encoding="utf-8")
    current.chmod(0o600)
    with pytest.raises(
        ProjectMemoryStoreInvalid, match="current project-memory manifest is invalid"
    ):
        load_project_memory_generation(root)

    current.unlink()
    memory = root / "agentic_project_memory"
    memory.chmod(0o755)
    with pytest.raises(ProjectMemoryStoreInvalid, match="owner-only real directory"):
        load_project_memory_generation(root)

    memory.chmod(0o700)
    memory.rmdir()
    memory.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ProjectMemoryStoreInvalid, match="not safely Git-ignored"):
        load_project_memory_generation(root)


def test_history_object_is_idempotent_only_for_identical_bytes(tmp_path: Path) -> None:
    """A pre-retained exact history object supports retry but collision fails."""
    root = repository(tmp_path)
    content = b"# Identity\n"
    item = record("identity-0001", content)
    write_project_memory_record(root, item, content)
    candidate = manifest("2026-09-04T12:01:00.000000Z", (item,))
    manifests = root / "agentic_project_memory/history/manifests"
    manifests.mkdir(parents=True, mode=0o700)
    (manifests.parent).chmod(0o700)
    history = manifests / f"{candidate.generation_id}_{candidate.manifest_sha256}.json"
    history.write_bytes(candidate.to_bytes())
    history.chmod(0o600)

    assert commit_project_memory_generation(root, candidate) == history

    other = repository(tmp_path / "other")
    write_project_memory_record(other, item, content)
    other_manifests = other / "agentic_project_memory/history/manifests"
    other_manifests.mkdir(parents=True, mode=0o700)
    other_manifests.parent.chmod(0o700)
    collision = other_manifests / history.name
    collision.write_text("{}", encoding="utf-8")
    collision.chmod(0o600)
    with pytest.raises(ProjectMemoryStoreInvalid, match="collides"):
        commit_project_memory_generation(other, candidate)


def test_transition_rejects_wrong_identity_predecessor_time_and_metadata(tmp_path: Path) -> None:
    """A current view cannot fork, rewind, rename its project or mutate a record."""
    root = repository(tmp_path)
    content = b"# Identity\n"
    item = record("identity-0001", content)
    write_project_memory_record(root, item, content)
    first = manifest("2026-09-04T12:01:00.000000Z", (item,))
    commit_project_memory_generation(root, first)

    wrong_identity = ProjectMemoryManifest.build(
        project_id="OTHER",
        generated_at="2026-09-04T12:02:00.000000Z",
        previous_manifest_sha256=first.manifest_sha256,
        parents=parents(),
        records=(item,),
    )
    with pytest.raises(ProjectMemoryStoreInvalid, match="project identity"):
        commit_project_memory_generation(root, wrong_identity)

    wrong_predecessor = manifest("2026-09-04T12:02:00.000000Z", (item,), "0" * 64)
    with pytest.raises(ProjectMemoryStoreInvalid, match="exact current predecessor"):
        commit_project_memory_generation(root, wrong_predecessor)

    rewind = manifest("2026-09-04T12:00:30.000000Z", (item,), first.manifest_sha256)
    with pytest.raises(ProjectMemoryStoreInvalid, match="increase monotonically"):
        commit_project_memory_generation(root, rewind)

    changed = record("identity-0001", b"# Changed!\n")
    changed_manifest = manifest(
        "2026-09-04T12:02:00.000000Z",
        (changed,),
        first.manifest_sha256,
    )
    with pytest.raises(ProjectMemoryStoreInvalid, match="metadata cannot change"):
        commit_project_memory_generation(root, changed_manifest)


def test_transition_rejects_unknown_or_unseen_supersession(tmp_path: Path) -> None:
    """Initial and successor views may supersede only the exact prior current set."""
    root = repository(tmp_path)
    content = b"# Identity\n"
    initial = record("identity-0001", content, supersedes=("unseen-record",))
    write_project_memory_record(root, initial, content)
    initial_manifest = manifest("2026-09-04T12:01:00.000000Z", (initial,))
    with pytest.raises(ProjectMemoryStoreInvalid, match="unseen supersession"):
        commit_project_memory_generation(root, initial_manifest)

    other = repository(tmp_path / "other")
    first = record("identity-0001", content)
    write_project_memory_record(other, first, content)
    first_manifest = manifest("2026-09-04T12:01:00.000000Z", (first,))
    commit_project_memory_generation(other, first_manifest)
    successor_content = b"# Successor\n"
    successor = record(
        "identity-0002",
        successor_content,
        supersedes=("never-current",),
    )
    write_project_memory_record(other, successor, successor_content)
    successor_manifest = manifest(
        "2026-09-04T12:02:00.000000Z",
        (successor,),
        first_manifest.manifest_sha256,
    )
    with pytest.raises(ProjectMemoryStoreInvalid, match="unknown current record"):
        commit_project_memory_generation(other, successor_manifest)


def test_private_file_absence_modes_links_and_root_ignore_fail_closed(tmp_path: Path) -> None:
    """Missing, permissive, hard-linked and unignored store objects are refused."""
    missing = repository(tmp_path / "missing")
    with pytest.raises(ProjectMemoryStoreInvalid, match="manifest is unavailable"):
        load_project_memory_generation(missing)

    unignored = tmp_path / "unignored"
    unignored.mkdir()
    git(unignored, "init", "--quiet")
    (unignored / "agentic_project_memory").mkdir(mode=0o700)
    with pytest.raises(ProjectMemoryStoreInvalid, match="not safely Git-ignored"):
        load_project_memory_generation(unignored)

    root = repository(tmp_path / "modes")
    content = b"# Identity\n"
    item = record("identity-0001", content)
    content_path = write_project_memory_record(root, item, content)
    candidate = manifest("2026-09-04T12:01:00.000000Z", (item,))
    commit_project_memory_generation(root, candidate)
    content_path.chmod(0o644)
    with pytest.raises(ProjectMemoryStoreInvalid, match="bounded owner-only"):
        load_project_memory_generation(root)

    content_path.chmod(0o600)
    linked = content_path.parent / "second-link.md"
    os.link(content_path, linked)
    with pytest.raises(ProjectMemoryStoreInvalid, match="bounded owner-only"):
        load_project_memory_generation(root)


def test_content_admission_revalidates_metadata_and_text_shape(tmp_path: Path) -> None:
    """Directly constructed invalid metadata, empty, BOM and NUL payloads are refused."""
    root = repository(tmp_path)
    content = b"# Identity\n"
    valid = record("identity-0001", content)
    invalid = ProjectMemoryRecord(
        **{**valid.__dict__, "category": "unknown"},
    )
    with pytest.raises(ProjectMemoryStoreInvalid, match="metadata is invalid"):
        write_project_memory_record(root, invalid, content)
    candidate = manifest("2026-09-04T12:01:00.000000Z", (valid,))
    invalid_manifest = ProjectMemoryManifest(
        **{**candidate.__dict__, "manifest_sha256": "0" * 64},
    )
    with pytest.raises(ProjectMemoryStoreInvalid, match=r"candidate.*manifest is invalid"):
        commit_project_memory_generation(root, invalid_manifest)
    with pytest.raises(ProjectMemoryStoreInvalid, match="byte count is out of bounds"):
        write_project_memory_record(root, valid, b"")
    for payload in (b"\xef\xbb\xbf# Identity\n", b"# Identity\x00\n"):
        matching = record("identity-shaped", payload)
        with pytest.raises(ProjectMemoryStoreInvalid, match="BOM-free, NUL-free"):
            write_project_memory_record(root, matching, payload)


def test_changed_predecessor_history_blocks_the_next_commit(tmp_path: Path) -> None:
    """A current manifest without its exact immutable history cannot be extended."""
    root = repository(tmp_path)
    content = b"# Identity\n"
    item = record("identity-0001", content)
    write_project_memory_record(root, item, content)
    first = manifest("2026-09-04T12:01:00.000000Z", (item,))
    history = commit_project_memory_generation(root, first)
    history.write_text("{}", encoding="utf-8")
    successor = manifest(
        "2026-09-04T12:02:00.000000Z",
        (item,),
        first.manifest_sha256,
    )
    with pytest.raises(ProjectMemoryStoreInvalid, match="predecessor is absent"):
        commit_project_memory_generation(root, successor)


def test_transition_rejects_two_direct_successors_for_one_record(tmp_path: Path) -> None:
    """One prior assertion cannot fork into two simultaneous direct successors."""
    root = repository(tmp_path)
    first_content = b"# Identity\n"
    first = record("identity-0001", first_content)
    write_project_memory_record(root, first, first_content)
    first_manifest = manifest("2026-09-04T12:01:00.000000Z", (first,))
    commit_project_memory_generation(root, first_manifest)
    successors = (
        record("identity-0002", b"# Successor two\n", supersedes=(first.record_id,)),
        record("identity-0003", b"# Successor three\n", supersedes=(first.record_id,)),
    )
    for item, payload in zip(
        successors, (b"# Successor two\n", b"# Successor three\n"), strict=True
    ):
        write_project_memory_record(root, item, payload)
    fork = manifest(
        "2026-09-04T12:02:00.000000Z",
        successors,
        first_manifest.manifest_sha256,
    )
    with pytest.raises(ProjectMemoryStoreInvalid, match="multiple direct successors"):
        commit_project_memory_generation(root, fork)


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


@pytest.mark.parametrize("surface", ["manifest", "index", "content", "history"])
@pytest.mark.parametrize("entrypoint", ["api", "cli"])
def test_fifo_replacement_refuses_without_waiting_for_a_writer(
    tmp_path: Path, surface: str, entrypoint: str
) -> None:
    """A substituted FIFO must not stall the public reader or integrity command."""
    root = repository(tmp_path)
    payload = b"# Project identity\n"
    item = record("identity-fifo-check", payload)
    content = write_project_memory_record(root, item, payload)
    candidate = manifest("2026-09-04T12:01:00.000000Z", (item,))
    history = commit_project_memory_generation(root, candidate)
    memory = root / "agentic_project_memory"
    target = {
        "manifest": memory / "memory_manifest.json",
        "index": memory / "memory_index.md",
        "content": content,
        "history": history,
    }[surface]
    preserved = {
        path: path.read_bytes() for path in memory.rglob("*") if path.is_file() and path != target
    }
    target.unlink()
    os.mkfifo(target, mode=0o600)
    before = target.lstat()
    if entrypoint == "api":
        arguments = [
            "-c",
            "from pathlib import Path; import sys\n"
            "from rigor_foundry.project_memory_store import "
            "ProjectMemoryStoreInvalid, load_project_memory_generation\n"
            "try:\n"
            "    load_project_memory_generation(Path(sys.argv[1]))\n"
            "except ProjectMemoryStoreInvalid:\n"
            "    print('refused'); sys.exit(1)\n"
            "raise SystemExit('unexpected acceptance')\n",
            str(root),
        ]
        expected = b"refused\n"
    else:
        arguments = ["-m", "tools.check_project_memory_integrity", str(root), "--history"]
        expected = b"project-memory-integrity: FAIL\n"
    result = subprocess.run(
        [sys.executable, *arguments],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 1
    assert result.stdout == expected
    assert result.stderr == b""
    after = target.lstat()
    assert stat.S_ISFIFO(after.st_mode)
    assert (after.st_dev, after.st_ino, after.st_mode, after.st_mtime_ns) == (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_mtime_ns,
    )
    assert {path: path.read_bytes() for path in preserved} == preserved


@pytest.mark.parametrize(
    "change", ["growth", "unlink", "replace", "permissions", "hardlink", "late-permissions"]
)
def test_current_read_rejects_file_change_after_descriptor_snapshot(
    tmp_path: Path, change: str
) -> None:
    """Change a real manifest after fstat returns, without faking syscall results.

    A child-local profiling hook schedules a deterministic filesystem mutation
    at the public OS boundary. The full public loader still runs normally.
    This proves the observed interleaving, not exclusion of arbitrary writers.
    """
    root = repository(tmp_path)
    payload = b"# Project identity\n"
    item = record("identity-stable-read", payload)
    write_project_memory_record(root, item, payload)
    candidate = manifest("2026-09-04T12:01:00.000000Z", (item,))
    commit_project_memory_generation(root, candidate)
    script = """
import os
import sys
from pathlib import Path
from rigor_foundry.project_memory_store import (
    ProjectMemoryStoreInvalid, load_project_memory_generation,
)
root, change = Path(sys.argv[1]), sys.argv[2]
target = root / "agentic_project_memory/memory_manifest.json"
original = target.read_bytes()
changed = False
snapshots = 0
def interfere(frame, event, function):
    global changed, snapshots
    if changed or event != "c_return" or function is not os.fstat:
        return
    for name in os.listdir("/proc/self/fd"):
        try:
            linked = os.readlink("/proc/self/fd/" + name)
        except FileNotFoundError:
            continue
        if linked == str(target):
            break
    else:
        return
    snapshots += 1
    if change == "late-permissions" and snapshots < 2:
        return
    changed = True
    if change == "growth":
        with target.open("ab") as output:
            output.write(b" " * 65537)
    elif change == "unlink":
        target.unlink()
    elif change == "replace":
        replacement = target.with_name("replacement.json")
        replacement.write_bytes(original)
        replacement.chmod(0o600)
        replacement.replace(target)
    elif change in ("permissions", "late-permissions"):
        target.chmod(0o644)
    else:
        os.link(target, target.with_name("retained-link.json"))
sys.setprofile(interfere)
try:
    load_project_memory_generation(root)
except ProjectMemoryStoreInvalid as error:
    sys.setprofile(None)
    assert changed
    print(str(error))
    raise SystemExit(1)
sys.setprofile(None)
raise SystemExit("unexpected acceptance")
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(root), change],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 1 and result.stderr == ""
    assert {
        "growth": "exceeds its byte bound",
        "unlink": "changed while being read",
        "replace": "changed while being read",
        "permissions": "changed while being read",
        "hardlink": "changed while being read",
        "late-permissions": "changed while being read",
    }[change] in result.stdout
    assert (root / "agentic_project_memory" / item.content_path).read_bytes() == payload


def test_missing_private_root_and_unsafe_record_destination_refuse(tmp_path: Path) -> None:
    """Neither absent roots nor redirected immutable destinations are admitted."""
    root = repository(tmp_path)
    private = root / "agentic_project_memory"
    private.rmdir()
    (root / ".gitignore").write_text("/agentic_project_memory\n", encoding="utf-8")
    with pytest.raises(ProjectMemoryStoreInvalid, match="root is missing"):
        load_project_memory_generation(root)
    private.mkdir(mode=0o700)
    payload = b"# Identity\n"
    item = record("identity-path", payload)
    destination = private / item.content_path
    destination.parent.mkdir(parents=True, mode=0o700)
    destination.parent.parent.chmod(0o700)
    retained = tmp_path / "retained.md"
    retained.write_bytes(payload)
    destination.symlink_to(retained)
    with pytest.raises(ProjectMemoryStoreInvalid, match="content path is unsafe"):
        write_project_memory_record(root, item, payload)
    assert retained.read_bytes() == payload


def test_initial_predecessor_refusal_preserves_uncommitted_content(tmp_path: Path) -> None:
    """An initial write cannot invent an absent predecessor generation."""
    root = repository(tmp_path)
    payload = b"# Identity\n"
    item = record("identity-first", payload)
    path = write_project_memory_record(root, item, payload)
    candidate = manifest("2026-09-04T12:01:00.000000Z", (item,), "a" * 64)
    with pytest.raises(ProjectMemoryStoreInvalid, match="initial generation cannot name"):
        commit_project_memory_generation(root, candidate)
    assert path.read_bytes() == payload
    assert not (root / "agentic_project_memory/memory_manifest.json").exists()


@pytest.mark.parametrize("blocked_view", ["memory_index.md", "memory_manifest.json"])
def test_interrupted_generation_retains_history_and_retries_exactly(
    tmp_path: Path, blocked_view: str
) -> None:
    """An obstructed replacement preserves evidence and permits exact retry."""
    root = repository(tmp_path)
    payload = b"# Identity\n"
    item = record("identity-retry", payload)
    write_project_memory_record(root, item, payload)
    first = manifest("2026-09-04T12:01:00.000000Z", (item,))
    first_history = commit_project_memory_generation(root, first)
    candidate = manifest("2026-09-04T12:02:00.000000Z", (item,), first.manifest_sha256)
    private = root / "agentic_project_memory"
    candidate_file = tmp_path / "candidate.json"
    candidate_file.write_bytes(candidate.to_bytes())
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os, sys
from pathlib import Path
from rigor_foundry.project_memory_models import ProjectMemoryManifest
from rigor_foundry.project_memory_store import (
    ProjectMemoryStoreInvalid, commit_project_memory_generation,
)
root, candidate_file, view = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
candidate = ProjectMemoryManifest.from_bytes(candidate_file.read_bytes())
target = root / 'agentic_project_memory' / view
changed = False
def obstruct(event, arguments):
    global changed
    if event == 'os.rename' and str(arguments[1]) == str(target) and not changed:
        changed = True
        target.rename(target.with_name(view + '.retained'))
        target.mkdir(mode=0o700)
sys.addaudithook(obstruct)
try:
    commit_project_memory_generation(root, candidate)
except ProjectMemoryStoreInvalid as error:
    assert changed
    print(error)
    raise SystemExit(1)
raise SystemExit('unexpected acceptance')
""",
            str(root),
            str(candidate_file),
            blocked_view,
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 1 and result.stderr == ""
    assert "cannot replace the derived current generation" in result.stdout
    history = (
        private
        / "history/manifests"
        / (f"{candidate.generation_id}_{candidate.manifest_sha256}.json")
    )
    assert history.read_bytes() == candidate.to_bytes()
    assert first_history.read_bytes() == first.to_bytes()
    with pytest.raises(ProjectMemoryStoreInvalid):
        load_project_memory_generation(root)
    target = private / blocked_view
    target.rmdir()
    target.with_name(blocked_view + ".retained").rename(target)
    assert commit_project_memory_generation(root, candidate) == history
    assert load_project_memory_generation(root) == candidate
    assert verify_project_memory_history(root) == (
        candidate.manifest_sha256,
        first.manifest_sha256,
    )
    assert not list(private.glob(".*.tmp"))


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


@pytest.mark.parametrize("change", ["enumeration", "missing-current", "duplicate-digest"])
def test_history_directory_changes_are_refused(tmp_path: Path, change: str) -> None:
    """Real directory changes after current-view validation cannot certify history."""
    root = repository(tmp_path)
    payload = b"# Identity\n"
    item = record("identity-enumeration", payload)
    write_project_memory_record(root, item, payload)
    candidate = manifest("2026-09-04T12:01:00.000000Z", (item,))
    history_file = commit_project_memory_generation(root, candidate)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import sys
from pathlib import Path
from rigor_foundry.project_memory_store import ProjectMemoryStoreInvalid, verify_project_memory_history
root, history_file, change = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
directory = history_file.parent
changed = False
def interfere(event, arguments):
    global changed
    if event != 'os.scandir' or str(arguments[0]) != str(directory) or changed:
        return
    changed = True
    if change == 'enumeration':
        directory.rename(directory.with_name('retained-manifests'))
    elif change == 'missing-current':
        history_file.rename(directory.parent / 'retained-current.json')
    else:
        duplicate = directory / ('20260904T120200000000Z_' + history_file.name.split('_', 1)[1])
        duplicate.write_bytes(history_file.read_bytes())
        duplicate.chmod(0o600)
sys.addaudithook(interfere)
try:
    verify_project_memory_history(root)
except ProjectMemoryStoreInvalid as error:
    assert changed
    print(error)
    raise SystemExit(1)
raise SystemExit('unexpected acceptance')
""",
            str(root),
            str(history_file),
            change,
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 1 and result.stderr == ""
    expected = {
        "enumeration": "history cannot be enumerated",
        "missing-current": "predecessor is missing from history",
        "duplicate-digest": "history digest is ambiguous",
    }
    if change == "duplicate-digest":
        # Filesystem enumeration order determines which equivalent refusal comes first.
        assert any(
            message in result.stdout
            for message in (
                "history digest is ambiguous",
                "history filename does not match its manifest",
            )
        )
    else:
        assert expected[change] in result.stdout
    assert (root / "agentic_project_memory" / item.content_path).read_bytes() == payload


def test_repository_alias_change_cannot_redirect_record_write(tmp_path: Path) -> None:
    """Changing a caller's repository alias cannot move an admitted record write."""
    root = repository(tmp_path)
    other = repository(tmp_path / "other")
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    payload = b"# Identity\n"
    item = record("identity-alias", payload)
    metadata = tmp_path / "record.json"
    metadata.write_text(json.dumps(item.to_dict()), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import json, sys
from pathlib import Path
from rigor_foundry.project_memory_models import ProjectMemoryRecord
from rigor_foundry.project_memory_store import ProjectMemoryStoreInvalid, write_project_memory_record
root, other, alias, metadata = map(Path, sys.argv[1:])
item = ProjectMemoryRecord.from_dict(json.loads(metadata.read_text()), 'record')
target = root / 'agentic_project_memory/records/identity'
changed = False
def interfere(event, arguments):
    global changed
    if event == 'os.mkdir' and str(arguments[0]) == str(target) and not changed:
        changed = True
        alias.unlink()
        alias.symlink_to(other, target_is_directory=True)
sys.addaudithook(interfere)
try:
    write_project_memory_record(alias, item, b'# Identity\\n')
except ProjectMemoryStoreInvalid as error:
    assert changed
    print(error)
    raise SystemExit(1)
raise SystemExit('unexpected acceptance')
""",
            str(root),
            str(other),
            str(alias),
            str(metadata),
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 1 and result.stderr == ""
    assert "content path changed during resolution" in result.stdout
    assert not (root / "agentic_project_memory" / item.content_path).exists()
    assert not (other / "agentic_project_memory" / item.content_path).exists()


@pytest.mark.parametrize("change", ["history-create", "round-trip"])
def test_commit_detects_concurrent_history_or_current_writer(tmp_path: Path, change: str) -> None:
    """An out-of-protocol writer cannot silently replace the committed result."""
    root = repository(tmp_path)
    payload = b"# Identity\n"
    item = record("identity-concurrent", payload)
    write_project_memory_record(root, item, payload)
    candidate = manifest("2026-09-04T12:01:00.000000Z", (item,))
    other = manifest("2026-09-04T12:02:00.000000Z", (item,), candidate.manifest_sha256)
    candidate_file, other_file = tmp_path / "candidate.json", tmp_path / "other.json"
    candidate_file.write_bytes(candidate.to_bytes())
    other_file.write_bytes(other.to_bytes())
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os, sys
from pathlib import Path
from rigor_foundry.project_memory_models import ProjectMemoryManifest
from rigor_foundry.project_memory_store import ProjectMemoryStoreInvalid, commit_project_memory_generation
root, candidate_file, other_file = map(Path, sys.argv[1:4])
change = sys.argv[4]
candidate = ProjectMemoryManifest.from_bytes(candidate_file.read_bytes())
other = ProjectMemoryManifest.from_bytes(other_file.read_bytes())
private = root / 'agentic_project_memory'
history = private / 'history/manifests'
target = history / (candidate.generation_id + '_' + candidate.manifest_sha256 + '.json')
changed = False
replacements = 0
def interfere(event, arguments):
    global changed
    if change != 'history-create' or changed or event != 'open':
        return
    if str(arguments[0]) == str(target) and arguments[2] & os.O_EXCL:
        changed = True
        target.write_bytes(candidate.to_bytes())
        target.chmod(0o600)
def after_replace(frame, event, function):
    global replacements, changed
    if change != 'round-trip' or changed or event != 'c_return' or function is not os.replace:
        return
    replacements += 1
    if replacements != 2:
        return
    changed = True
    other_history = history / (other.generation_id + '_' + other.manifest_sha256 + '.json')
    other_history.write_bytes(other.to_bytes())
    other_history.chmod(0o600)
    (private / 'memory_manifest.json').write_bytes(other.to_bytes())
    (private / 'memory_index.md').write_text(other.index_text())
sys.addaudithook(interfere)
sys.setprofile(after_replace)
try:
    commit_project_memory_generation(root, candidate)
except ProjectMemoryStoreInvalid as error:
    sys.setprofile(None)
    assert changed
    print(error)
    raise SystemExit(1)
sys.setprofile(None)
raise SystemExit('unexpected acceptance')
""",
            str(root),
            str(candidate_file),
            str(other_file),
            change,
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 1 and result.stderr == ""
    assert {
        "history-create": "cannot retain immutable history manifest",
        "round-trip": "committed generation did not round-trip exactly",
    }[change] in result.stdout
    if change == "history-create":
        retained = commit_project_memory_generation(root, candidate)
        assert retained.read_bytes() == candidate.to_bytes()
    else:
        assert load_project_memory_generation(root) == other
        assert verify_project_memory_history(root) == (
            other.manifest_sha256,
            candidate.manifest_sha256,
        )


def test_writer_schema_refuses_simultaneously_current_supersession(tmp_path: Path) -> None:
    """Even a directly constructed candidate must pass the public schema boundary."""
    root = repository(tmp_path)
    payload = b"# Identity\n"
    initial = record("identity-initial", payload)
    successor = record("identity-successor", payload, supersedes=(initial.record_id,))
    for item in (initial, successor):
        write_project_memory_record(root, item, payload)
    first = manifest("2026-09-04T12:01:00.000000Z", (initial,))
    commit_project_memory_generation(root, first)
    valid_successor = manifest(
        "2026-09-04T12:02:00.000000Z",
        (successor,),
        first.manifest_sha256,
    )
    invalid = replace(valid_successor, records=(initial, successor))
    with pytest.raises(ProjectMemoryStoreInvalid, match=r"candidate.*manifest is invalid"):
        commit_project_memory_generation(root, invalid)
    assert load_project_memory_generation(root) == first
    assert verify_project_memory_history(root) == (first.manifest_sha256,)
