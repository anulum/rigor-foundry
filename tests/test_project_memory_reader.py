# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project-memory store tests
"""Verify pinned record selection and read-only memory access."""

from __future__ import annotations

from pathlib import Path

import pytest
from project_memory_store_support import manifest, record, repository
from test_project_memory_models import profiled_manifest

from rigor_foundry.project_memory_primitives import (
    ProjectMemoryFreshness,
)
from rigor_foundry.project_memory_store import (
    ProjectMemoryStoreInvalid,
    commit_project_memory_generation,
    read_project_memory_record,
    write_project_memory_record,
)


@pytest.mark.parametrize("profiled", [False, True])
def test_pinned_record_read_returns_bytes_without_mutation(tmp_path: Path, profiled: bool) -> None:
    """Return exact pinned content without changing owner files or filesystem metadata."""
    root = repository(tmp_path)
    content = b"# Private project identity\n"
    identity = record("identity-0001", content)
    write_project_memory_record(root, identity, content)
    generation = manifest("2026-09-04T12:01:00.000000Z", (identity,))
    if profiled:
        generation = profiled_manifest(generation)
    commit_project_memory_generation(root, generation)
    sentinel = root / "owner-untracked.md"
    sentinel.write_bytes(b"preserve owner work")
    before = {
        path: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
        for path in root.rglob("*")
        if path.is_file()
    }
    assert (
        read_project_memory_record(
            root,
            expected_project_id="PROJECT",
            expected_manifest_sha256=generation.manifest_sha256,
            record_id=identity.record_id,
            checked_at=generation.generated_at,
        )
        == content
    )
    assert before == {
        path: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
        for path in root.rglob("*")
        if path.is_file()
    }


@pytest.mark.parametrize(
    "failure",
    [
        "project",
        "pin",
        "missing-record",
        "path-record",
        "future",
        "timestamp",
        "expired",
        "history",
    ],
)
def test_pinned_record_read_refuses_invalid_selection(tmp_path: Path, failure: str) -> None:
    """Refuse wrong identity, stale pins, invalid time and incomplete history."""
    root = repository(tmp_path)
    content = b"# Time-bounded project identity\n"
    identity = record(
        "identity-0001",
        content,
        freshness=ProjectMemoryFreshness("expires", "2026-09-04T12:03:00.000000Z"),
    )
    write_project_memory_record(root, identity, content)
    first = manifest("2026-09-04T12:01:00.000000Z", (identity,))
    old_history = commit_project_memory_generation(root, first)
    current = manifest("2026-09-04T12:02:00.000000Z", (identity,), first.manifest_sha256)
    commit_project_memory_generation(root, current)
    if failure == "history":
        old_history.unlink()
    checked_at = {
        "future": "2026-09-04T12:01:59.999999Z",
        "timestamp": "2026-09-04",
        "expired": "2026-09-04T12:03:00.000000Z",
    }.get(failure, "2026-09-04T12:02:59.999999Z")
    with pytest.raises(ValueError):
        read_project_memory_record(
            root,
            expected_project_id="OTHER" if failure == "project" else "PROJECT",
            expected_manifest_sha256=first.manifest_sha256
            if failure == "pin"
            else current.manifest_sha256,
            record_id={"missing-record": "missing", "path-record": "../../owner.md"}.get(
                failure, identity.record_id
            ),
            checked_at=checked_at,
        )


def test_pinned_record_read_excludes_superseded_content(tmp_path: Path) -> None:
    """Keep superseded bytes intact while excluding them from the pinned current view."""
    root = repository(tmp_path)
    old_content, new_content = b"# Original identity\n", b"# Revised identity\n"
    old = record("identity-0001", old_content)
    old_path = write_project_memory_record(root, old, old_content)
    first = manifest("2026-09-04T12:01:00.000000Z", (old,))
    commit_project_memory_generation(root, first)
    new = record("identity-0002", new_content, supersedes=(old.record_id,))
    write_project_memory_record(root, new, new_content)
    second = manifest("2026-09-04T12:02:00.000000Z", (new,), first.manifest_sha256)
    commit_project_memory_generation(root, second)
    with pytest.raises(ProjectMemoryStoreInvalid, match="absent or expired"):
        read_project_memory_record(
            root,
            expected_project_id="PROJECT",
            expected_manifest_sha256=second.manifest_sha256,
            record_id=old.record_id,
            checked_at=second.generated_at,
        )
    assert (
        read_project_memory_record(
            root,
            expected_project_id="PROJECT",
            expected_manifest_sha256=second.manifest_sha256,
            record_id=new.record_id,
            checked_at=second.generated_at,
        )
        == new_content
    )
    assert old_path.read_bytes() == old_content
