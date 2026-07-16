# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real Git inventory tests
"""Verify exact tracked-content inventory against real Git worktrees."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.git_inventory import (
    MAX_TEXT_BYTES,
    StableReadError,
    is_git_ignored,
    load_git_inventory,
    open_directory_no_follow,
    read_stable_regular_file_at,
)
from rigor_foundry.git_provenance import GitExecutableProvenance, GitTrustPolicy
from rigor_foundry.scanner import scan_repository


def test_inventory_classifies_real_tracked_content_and_dirty_state(tmp_path: Path) -> None:
    """Text, binary, non-UTF8, symlink, oversize, and missing paths fail closed."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/text.py", "VALUE = 1\n")
    repository.write_bytes("src/pkg/binary.bin", b"a\0b")
    repository.write_bytes("src/pkg/non_utf8.py", b"\xff\xfe")
    repository.symlink("src/pkg/link.py", "text.py")
    large = repository.root / "src/pkg/large.py"
    large.parent.mkdir(parents=True, exist_ok=True)
    with large.open("wb") as handle:
        handle.seek(MAX_TEXT_BYTES)
        handle.write(b"x")
    head = repository.commit()
    (repository.root / "src/pkg/text.py").unlink()

    inventory = load_git_inventory(repository.root / "src")
    by_path = {item.path: item for item in inventory.files}
    assert inventory.head == head
    assert inventory.branch == "main"
    assert len(inventory.head_tree) == 40
    assert len(inventory.tracked_content_digest) == 64
    assert inventory.dirty_paths == ("src/pkg/text.py",)
    assert by_path["src/pkg/text.py"].content_kind == "missing"
    assert by_path["src/pkg/binary.bin"].content_kind == "binary"
    assert by_path["src/pkg/non_utf8.py"].content_kind == "non-utf8"
    assert by_path["src/pkg/link.py"].content_kind == "symlink"
    assert by_path["src/pkg/link.py"].git_mode == "120000"
    assert by_path["src/pkg/large.py"].content_kind == "oversize"
    assert all(len(item.content_digest) == 64 for item in inventory.files)
    assert all(len(item.object_id) in {40, 64} for item in inventory.files)
    assert not any(item.path == "src/pkg/text.py" for item in inventory.text_files())


def test_stable_reader_validates_buffer_limit_and_keeps_tracked_hardlink_compatibility(
    tmp_path: Path,
) -> None:
    """The shared reader rejects invalid limits without changing tracked link policy."""
    root = tmp_path / "root"
    root.mkdir()
    target = root / "target.bin"
    target.write_bytes(b"content")
    os.link(target, root / "second-link.bin")
    descriptor = open_directory_no_follow(root)
    try:
        with pytest.raises(ValueError, match="buffer_limit"):
            read_stable_regular_file_at(descriptor, target.name, target.name, buffer_limit=-1)
        result = read_stable_regular_file_at(
            descriptor,
            target.name,
            target.name,
            require_single_link=False,
        )
        assert result.payload == b"content"
        with pytest.raises(RuntimeError, match="multiple hard links"):
            read_stable_regular_file_at(
                descriptor,
                target.name,
                target.name,
                require_single_link=True,
            )
    finally:
        os.close(descriptor)


def test_directory_open_rejects_relative_paths_before_traversal(tmp_path: Path) -> None:
    """No-follow directory binding never silently changes a relative caller path."""
    relative = Path(os.path.relpath(tmp_path, Path.cwd()))
    assert not relative.is_absolute()
    with pytest.raises(ValueError, match="must be absolute"):
        open_directory_no_follow(relative)


def test_stable_reader_reports_platform_unavailability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing descriptor-relative open surface returns its finite reason code."""
    root = tmp_path / "root"
    root.mkdir()
    (root / "state.bin").write_bytes(b"content")
    descriptor = open_directory_no_follow(root)
    monkeypatch.setattr(
        os,
        "supports_dir_fd",
        frozenset(function for function in os.supports_dir_fd if function is not os.open),
    )
    try:
        with pytest.raises(StableReadError, match="platform lacks stable no-follow") as error:
            read_stable_regular_file_at(descriptor, "state.bin", "state.bin")
        assert error.value.reason == "platform-unavailable"
    finally:
        os.close(descriptor)


def test_inventory_rejects_symlinked_tracked_parent_component(tmp_path: Path) -> None:
    """Tracked regular-file reads never follow a replaced parent directory component."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.commit()
    real = repository.root / "real-src"
    (repository.root / "src").rename(real)
    repository.symlink("src", "real-src")
    with pytest.raises(RuntimeError, match="tracked parent"):
        load_git_inventory(repository.root)


def test_failed_tracked_parent_walk_does_not_leak_descriptors(tmp_path: Path) -> None:
    """Repeated public inventory failures close the last successfully opened parent."""
    descriptor_directory = Path("/proc/self/fd")
    if not descriptor_directory.is_dir():
        pytest.skip("descriptor inventory is unavailable on this platform")
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/deep/module.py", "VALUE = 1\n")
    repository.commit()
    real = repository.root / "real-deep"
    (repository.root / "src/pkg/deep").rename(real)
    repository.symlink("src/pkg/deep", "../../real-deep")
    before = len(tuple(descriptor_directory.iterdir()))
    for _ in range(20):
        with pytest.raises(RuntimeError, match="tracked parent"):
            load_git_inventory(repository.root)
    after = len(tuple(descriptor_directory.iterdir()))
    assert after == before


def test_inventory_digest_tracks_worktree_bytes_and_rename_records(tmp_path: Path) -> None:
    """Tracked-content identity changes before commit and rename paths are both retained."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/a.py", "VALUE = 1\n")
    repository.commit()
    original = load_git_inventory(repository.root)
    repository.write_text("src/pkg/a.py", "VALUE = 2\n")
    changed = load_git_inventory(repository.root)
    assert changed.head == original.head
    assert changed.tracked_content_digest != original.tracked_content_digest
    repository.git_command("mv", "src/pkg/a.py", "src/pkg/b.py")
    renamed = load_git_inventory(repository.root)
    assert renamed.dirty_paths == ("src/pkg/a.py", "src/pkg/b.py")


def test_inventory_and_scan_reject_concurrent_oversize_mutation(tmp_path: Path) -> None:
    """Public inventory and scan never combine identities from different bytes."""
    repository = GitRepository.create(tmp_path / "repository")
    large = repository.write_bytes(
        "native/large.rs",
        b"a" * (MAX_TEXT_BYTES * 4),
    )
    repository.write_policy()
    repository.commit()
    writer = tmp_path / "mutate.py"
    writer.write_text(
        """
import ctypes
import os
import sys
from pathlib import Path

target = Path(sys.argv[1])
ready = Path(sys.argv[2])
mutated = Path(sys.argv[3])
stop = Path(sys.argv[4])
libc = ctypes.CDLL(None, use_errno=True)
notify_fd = libc.inotify_init1(os.O_CLOEXEC)
if notify_fd < 0:
    raise OSError(ctypes.get_errno(), "inotify_init1 failed")
target_fd = os.open(target, os.O_RDWR | os.O_CLOEXEC)
try:
    watch = libc.inotify_add_watch(notify_fd, os.fsencode(target), 0x00000020)
    if watch < 0:
        raise OSError(ctypes.get_errno(), "inotify_add_watch failed")
    original_size = os.fstat(target_fd).st_size
    ready_temporary = ready.with_suffix(".tmp")
    ready_temporary.write_text("watching", encoding="utf-8")
    os.replace(ready_temporary, ready)
    os.read(notify_fd, 4096)
    os.ftruncate(target_fd, original_size - 1)
    os.pwrite(target_fd, b"b", 0)
    mutated_temporary = mutated.with_suffix(".tmp")
    mutated_temporary.write_text("changed", encoding="utf-8")
    os.replace(mutated_temporary, mutated)
    index = 1
    while not stop.exists():
        os.ftruncate(target_fd, original_size - (index % 2))
        os.pwrite(target_fd, b"b" if index % 2 else b"c", 0)
        index += 1
finally:
    os.close(target_fd)
    os.close(notify_fd)
""".strip()
        + "\n",
        encoding="utf-8",
    )

    def assert_mutation_rejected(scan: bool, attempt: int) -> None:
        large.write_bytes(b"a" * (MAX_TEXT_BYTES * 4))
        ready = tmp_path / f"ready-{scan}-{attempt}"
        mutated = tmp_path / f"mutated-{scan}-{attempt}"
        stop = tmp_path / f"stop-{scan}-{attempt}"
        process = subprocess.Popen(  # nosec B603
            [sys.executable, str(writer), str(large), str(ready), str(mutated), str(stop)],
            shell=False,
        )
        try:
            deadline = time.monotonic() + 5.0
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            assert ready.read_text(encoding="utf-8") == "watching"
            with pytest.raises(RuntimeError, match="changed while being read"):
                if scan:
                    scan_repository(repository.root)
                else:
                    load_git_inventory(repository.root)
            assert mutated.read_text(encoding="utf-8") == "changed"
        finally:
            stop.write_text("stop", encoding="utf-8")
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=5)
                raise
            assert process.returncode == 0

    for attempt in range(3):
        assert_mutation_rejected(scan=False, attempt=attempt)
        assert_mutation_rejected(scan=True, attempt=attempt)


def test_git_ignore_check_uses_real_repository_rules(tmp_path: Path) -> None:
    """Internal storage is accepted only when real Git ignore rules cover it."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.commit()
    assert is_git_ignored(repository.root, Path(".coordination/audits/run.json"))
    assert is_git_ignored(repository.root, Path("docs/internal/work/INDEX.md"))
    assert not is_git_ignored(repository.root, Path("public-report.json"))
    with pytest.raises(ValueError, match="repository-relative"):
        is_git_ignored(repository.root, Path("../outside"))
    with pytest.raises(ValueError, match="repository-relative"):
        is_git_ignored(repository.root, tmp_path / "absolute")

    observed = load_git_inventory(repository.root).git_provenance
    different = GitExecutableProvenance.build(
        resolved_path=observed.resolved_path,
        trusted_root=observed.trusted_root,
        version=observed.version,
        executable_digest="0" * 64,
        trust_policy=observed.trust_policy,
    )
    with pytest.raises(RuntimeError, match="does not match expected identity"):
        is_git_ignored(
            repository.root,
            Path("docs/internal/work/INDEX.md"),
            expected_git_provenance=different,
        )


def test_inventory_rejects_non_repository(tmp_path: Path) -> None:
    """Repository discovery fails closed outside a real Git worktree."""
    path = tmp_path / "not-a-repository"
    path.mkdir()
    with pytest.raises(RuntimeError, match=r"git .* failed"):
        load_git_inventory(path)


def test_inventory_binds_uninitialised_gitlink_mode_and_object(tmp_path: Path) -> None:
    """A stage-160000 entry remains an explicit gitlink without a worktree directory."""
    child = GitRepository.create(tmp_path / "child")
    child.write_text("README.md", "child\n")
    child_head = child.commit()
    repository = GitRepository.create(tmp_path / "repository")
    repository.git_command("update-index", "--add", "--cacheinfo", "160000", child_head, "vendor")
    repository.git_command("commit", "-m", "test: add uninitialised gitlink")

    inventory = load_git_inventory(repository.root)
    gitlink = next(item for item in inventory.files if item.path == "vendor")

    assert gitlink.content_kind == "gitlink"
    assert gitlink.git_mode == "160000"
    assert gitlink.object_id == child_head
    assert not gitlink.absolute_path.exists()


def test_inventory_rejects_real_non_utf8_tracked_path(tmp_path: Path) -> None:
    """A Git-valid path that cannot enter the UTF-8 report schema fails closed."""
    repository = GitRepository.create(tmp_path / "repository")
    raw_root = os.fsencode(repository.root)
    raw_directory = raw_root + b"/src/pkg"
    os.makedirs(raw_directory)
    raw_path = raw_directory + b"/invalid-\xff.py"
    descriptor = os.open(raw_path, os.O_CREAT | os.O_WRONLY, 0o644)
    try:
        os.write(descriptor, b"VALUE = 1\n")
    finally:
        os.close(descriptor)
    repository.commit()

    with pytest.raises(RuntimeError, match="non-UTF-8 field"):
        load_git_inventory(repository.root)


def test_inventory_rejects_real_unmerged_index_stages(tmp_path: Path) -> None:
    """A real merge conflict cannot be mistaken for a stage-zero tracked tree."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/value.py", "VALUE = 'base'\n")
    base = repository.commit()
    repository.write_text("src/pkg/value.py", "VALUE = 'ours'\n")
    ours = repository.commit()
    repository.write_text("src/pkg/value.py", "VALUE = 'theirs'\n")
    theirs = repository.commit()
    repository.git_command("read-tree", "--empty")
    repository.git_command("read-tree", "-i", "-m", base, ours, theirs)

    with pytest.raises(RuntimeError, match="unresolved stage"):
        load_git_inventory(repository.root)


def test_inventory_rejects_tracked_symlink_replaced_by_regular_file(tmp_path: Path) -> None:
    """Worktree type drift cannot substitute regular content for a tracked symlink."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/target.py", "VALUE = 1\n")
    link = repository.symlink("src/pkg/link.py", "target.py")
    repository.commit()
    link.unlink()
    link.write_text("VALUE = 2\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="tracked symlink is unavailable"):
        load_git_inventory(repository.root)


def test_inventory_rejects_tracked_regular_file_replaced_by_symlink(tmp_path: Path) -> None:
    """A tracked regular file cannot redirect inventory through a worktree symlink."""
    repository = GitRepository.create(tmp_path / "repository")
    owner = repository.write_text("src/pkg/owner.py", "VALUE = 1\n")
    target = repository.write_text("outside.py", "VALUE = 2\n")
    repository.commit()
    owner.unlink()
    os.symlink(os.path.relpath(target, owner.parent), owner)

    with pytest.raises(RuntimeError, match="tracked regular file is a symlink"):
        load_git_inventory(repository.root)


def test_inventory_and_scan_reject_dangling_symlink_for_regular_file(tmp_path: Path) -> None:
    """A dangling symlink cannot be laundered into missing regular content."""
    repository = GitRepository.create(tmp_path / "repository")
    owner = repository.write_text("src/pkg/owner.py", "VALUE = 1\n")
    repository.write_policy()
    repository.commit()
    owner.unlink()
    os.symlink("absent.py", owner)

    for operation in (
        lambda: load_git_inventory(repository.root),
        lambda: scan_repository(repository.root),
    ):
        with pytest.raises(RuntimeError, match="tracked regular file is a symlink"):
            operation()


def test_inventory_classifies_tracked_file_replaced_by_directory(tmp_path: Path) -> None:
    """A tracked regular-file path replaced by a directory remains explicit missing content."""
    repository = GitRepository.create(tmp_path / "repository")
    owner = repository.write_text("src/pkg/owner.py", "VALUE = 1\n")
    repository.commit()
    owner.unlink()
    owner.mkdir()

    inventory = load_git_inventory(repository.root)
    tracked = next(item for item in inventory.files if item.path == "src/pkg/owner.py")
    assert tracked.content_kind == "missing"
    assert tracked.byte_size == 0


def test_inventory_fails_when_git_is_unavailable(
    tmp_path: Path,
) -> None:
    """Repository inventory refuses to proceed without a resolved Git executable."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.commit()
    policy = GitTrustPolicy(trusted_roots=(str(tmp_path / "missing-tools"),))
    with pytest.raises(RuntimeError, match="unavailable below configured trusted roots"):
        load_git_inventory(repository.root, git_trust_policy=policy)
