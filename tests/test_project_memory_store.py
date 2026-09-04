# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project-memory store tests
"""Exercise immutable content and generation commits in real Git worktrees."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from rigor_foundry.project_memory_models import ProjectMemoryManifest, ProjectMemoryRecord
from rigor_foundry.project_memory_primitives import (
    PROJECT_MEMORY_PARENT_KINDS,
    ProjectMemoryActor,
    ProjectMemoryFreshness,
    ProjectMemoryParent,
    ProjectMemorySource,
)
from rigor_foundry.project_memory_store import (
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


def test_supersession_preserves_old_content_and_chains_history(tmp_path: Path) -> None:
    """A successor removes the prior view without mutating content or history."""
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
