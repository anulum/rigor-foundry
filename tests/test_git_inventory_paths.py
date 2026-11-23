# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — public Git inventory path and caller contracts
"""Verify ordinary static path refusals and recovery through public Git inventory APIs."""

from __future__ import annotations

import errno
import hashlib
import os
import subprocess
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry import stable_reads
from rigor_foundry.git_inventory import is_git_ignored, load_git_inventory
from rigor_foundry.git_provenance import GitRunner
from rigor_foundry.stable_reads import (
    StableReadError,
    open_directory_no_follow,
    read_stable_regular_file_at,
)


def test_stable_reader_validates_caller_paths_before_reading(
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
        for name in ("", ".", "..", "child/target.bin"):
            with pytest.raises(ValueError, match="one path component"):
                read_stable_regular_file_at(descriptor, name, name)
        with pytest.raises(ValueError, match="unsupported Git object format"):
            read_stable_regular_file_at(
                descriptor, target.name, target.name, object_format="unsupported"
            )
        with pytest.raises(ValueError, match="buffer_limit"):
            read_stable_regular_file_at(descriptor, target.name, target.name, buffer_limit=-1)
        with pytest.raises(ValueError, match="maximum_bytes"):
            read_stable_regular_file_at(
                descriptor,
                target.name,
                target.name,
                maximum_bytes=-1,
            )
        with pytest.raises(RuntimeError, match="exceeds the read limit"):
            read_stable_regular_file_at(
                descriptor,
                target.name,
                target.name,
                maximum_bytes=6,
            )
        result = read_stable_regular_file_at(
            descriptor,
            target.name,
            target.name,
            maximum_bytes=7,
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


def test_stable_reader_refuses_real_missing_and_nonregular_paths_and_recovers(
    tmp_path: Path,
) -> None:
    """Retain real refusal causes and read the same original bytes after every failure."""
    target = tmp_path / "record.bin"
    payload = b"record\x00bytes\n"
    target.write_bytes(payload)
    before = target.stat()
    directory = tmp_path / "directory"
    directory.mkdir()
    fifo = tmp_path / "record.fifo"
    os.mkfifo(fifo)
    alias = tmp_path / "alias.bin"
    alias.symlink_to(target.name)
    descriptor = open_directory_no_follow(tmp_path)
    try:
        with pytest.raises(StableReadError) as missing:
            read_stable_regular_file_at(descriptor, "missing.bin", "missing.bin")
        assert missing.value.reason == "inaccessible"
        assert isinstance(missing.value.__cause__, FileNotFoundError)
        for entry in (directory, fifo):
            with pytest.raises(StableReadError) as wrong_kind:
                read_stable_regular_file_at(descriptor, entry.name, entry.name)
            assert wrong_kind.value.reason == "not-regular-file"
        with pytest.raises(StableReadError) as linked:
            read_stable_regular_file_at(descriptor, alias.name, alias.name)
        assert linked.value.reason == "inaccessible"
        assert isinstance(linked.value.__cause__, OSError)
        assert linked.value.__cause__.errno == errno.ELOOP
        result = read_stable_regular_file_at(
            descriptor, target.name, target.name, object_format="sha1"
        )
        assert result.payload == payload
        assert result.byte_size == len(payload)
        assert result.content_digest == hashlib.sha256(payload).hexdigest()
        assert (
            result.git_blob_id
            == hashlib.sha1(
                f"blob {len(payload)}\0".encode() + payload, usedforsecurity=False
            ).hexdigest()
        )
    finally:
        os.close(descriptor)
    assert target.read_bytes() == payload
    assert target.stat().st_mtime_ns == before.st_mtime_ns


def test_directory_open_refuses_traversal_and_missing_components_then_recovers(
    tmp_path: Path,
) -> None:
    """Reject lexical traversal and genuine component errors without changing caller files."""
    target = tmp_path / "record.txt"
    target.write_bytes(b"preserved")
    before = target.stat()
    with pytest.raises(ValueError, match="parent traversal"):
        open_directory_no_follow(tmp_path / "..")
    with pytest.raises(FileNotFoundError):
        open_directory_no_follow(tmp_path / "missing" / "directory")
    with pytest.raises(NotADirectoryError):
        open_directory_no_follow(target / "directory")
    descriptor = open_directory_no_follow(tmp_path)
    try:
        opened = os.fstat(descriptor)
        expected = tmp_path.stat()
        assert (opened.st_dev, opened.st_ino) == (expected.st_dev, expected.st_ino)
    finally:
        os.close(descriptor)
    assert target.read_bytes() == b"preserved"
    assert target.stat().st_mtime_ns == before.st_mtime_ns


def test_inventory_and_ignore_reject_competing_trust_inputs(tmp_path: Path) -> None:
    """Require one caller trust source and preserve real inventory and ignore-rule results."""
    repository = GitRepository.create(tmp_path / "repository")
    head = repository.commit()
    runner = GitRunner()
    with pytest.raises(ValueError, match="either a Git trust policy or an existing runner"):
        load_git_inventory(repository.root, git_trust_policy=runner.policy, git_runner=runner)
    with pytest.raises(ValueError, match="either a Git trust policy or an existing runner"):
        is_git_ignored(
            repository.root,
            Path("docs/internal/record.json"),
            git_trust_policy=runner.policy,
            git_runner=runner,
        )
    assert load_git_inventory(repository.root, git_runner=runner).head == head
    assert is_git_ignored(repository.root, Path("docs/internal/record.json"), git_runner=runner)
    assert not is_git_ignored(repository.root, Path("public.json"), git_runner=runner)


def test_inventory_refuses_non_utf8_repository_root_without_mutation(tmp_path: Path) -> None:
    """Refuse a real Git root outside the UTF-8 report contract while retaining exact state."""
    repository = GitRepository.create(tmp_path / "repository")
    target = repository.write_bytes("src/value.bin", b"original")
    head = repository.commit()
    before = target.stat()
    index = (repository.root / ".git/index").read_bytes()
    renamed = Path(os.fsdecode(os.fsencode(tmp_path) + b"/repository-\xff"))
    repository.root.rename(renamed)
    try:
        with pytest.raises(RuntimeError, match="non-UTF-8 repository root") as failure:
            load_git_inventory(renamed)
        assert isinstance(failure.value.__cause__, UnicodeDecodeError)
        moved = GitRepository(root=renamed, git=repository.git)
        assert moved.git_command("rev-parse", "HEAD").stdout.strip() == head
        assert (renamed / ".git/index").read_bytes() == index
        assert (renamed / "src/value.bin").read_bytes() == b"original"
        assert (renamed / "src/value.bin").stat().st_mtime_ns == before.st_mtime_ns
    finally:
        renamed.rename(repository.root)


def test_ignore_check_refuses_a_real_symlink_parent_without_changing_the_target(
    tmp_path: Path,
) -> None:
    """Keep Git's fatal pathspec status distinct from a negative ignore-rule result."""
    repository = GitRepository.create(tmp_path / "repository")
    target = repository.write_bytes("real/record.txt", b"preserved")
    head = repository.commit()
    before = target.stat()
    alias = repository.symlink("alias", "real")
    runner = GitRunner()
    with pytest.raises(RuntimeError, match="git check-ignore returned 128"):
        is_git_ignored(repository.root, Path("alias/record.txt"), git_runner=runner)
    assert target.read_bytes() == b"preserved"
    assert target.stat().st_mtime_ns == before.st_mtime_ns
    assert os.readlink(alias) == "real"
    assert is_git_ignored(repository.root, Path("docs/internal/state.json"), git_runner=runner)
    assert not is_git_ignored(repository.root, Path("public.json"), git_runner=runner)
    assert load_git_inventory(repository.root, git_runner=runner).head == head


def test_ignore_check_preserves_actual_argument_limit_error_and_reuses_runner(
    tmp_path: Path,
) -> None:
    """Retain the kernel's caller-argument refusal before a child can execute."""
    repository = GitRepository.create(tmp_path / "repository")
    head = repository.commit()
    index = (repository.root / ".git/index").read_bytes()
    runner = GitRunner()
    argument_limit = os.sysconf("SC_ARG_MAX")
    assert argument_limit > 0
    path = Path("x" * (argument_limit + 1))
    with pytest.raises(RuntimeError, match="git check-ignore failed") as failure:
        is_git_ignored(repository.root, path, git_runner=runner)
    transport_error = failure.value.__cause__
    assert isinstance(transport_error, RuntimeError)
    cause = transport_error.__cause__
    assert isinstance(cause, OSError)
    assert cause.errno == errno.E2BIG
    assert (repository.root / ".git/index").read_bytes() == index
    assert is_git_ignored(repository.root, Path("docs/internal/state.json"), git_runner=runner)
    assert load_git_inventory(repository.root, git_runner=runner).head == head


def test_inventory_refuses_non_utf8_rename_source_then_reads_committed_rename(
    tmp_path: Path,
) -> None:
    """Reject an unrepresentable historical rename source and retain the real Git index."""
    repository = GitRepository.create(tmp_path / "repository")
    old_name = os.fsdecode(b"src/original-\xff.py")
    original = repository.write_bytes(old_name, b"VALUE = 1\n")
    head = repository.commit()
    before = original.stat()
    repository.git_command("mv", old_name, "src/renamed.py")
    index = (repository.root / ".git/index").read_bytes()
    status = subprocess.run(
        [repository.git, "status", "--porcelain=v1", "-z", "--untracked-files=no"],
        cwd=repository.root,
        check=True,
        capture_output=True,
    )
    assert status.stdout == b"R  src/renamed.py\0src/original-\xff.py\0"
    with pytest.raises(RuntimeError, match="non-UTF-8 rename path") as failure:
        load_git_inventory(repository.root)
    assert isinstance(failure.value.__cause__, UnicodeDecodeError)
    assert (repository.root / ".git/index").read_bytes() == index
    assert repository.git_command("rev-parse", "HEAD").stdout.strip() == head
    target = repository.root / "src/renamed.py"
    assert target.read_bytes() == b"VALUE = 1\n"
    assert target.stat().st_mtime_ns == before.st_mtime_ns
    renamed_head = repository.commit()
    inventory = load_git_inventory(repository.root)
    assert inventory.head == renamed_head
    assert inventory.dirty_paths == ()
    by_path = {entry.path: entry for entry in inventory.files}
    assert by_path["src/renamed.py"].text == "VALUE = 1\n"


def test_inventory_refuses_non_utf8_status_path_then_reads_the_committed_removal(
    tmp_path: Path,
) -> None:
    """Reject an unrepresentable staged removal and read the index once it is committed."""
    repository = GitRepository.create(tmp_path / "repository")
    removed = os.fsdecode(b"src/removed-\xff.py")
    repository.write_bytes(removed, b"VALUE = 1\n")
    repository.write_bytes("src/kept.py", b"KEPT = 1\n")
    repository.commit()
    repository.git_command("rm", "--cached", "--quiet", "--", removed)
    index = (repository.root / ".git/index").read_bytes()
    status = subprocess.run(
        [repository.git, "status", "--porcelain=v1", "-z", "--untracked-files=no"],
        cwd=repository.root,
        check=True,
        capture_output=True,
    )
    assert status.stdout == b"D  src/removed-\xff.py\0"
    with pytest.raises(RuntimeError, match="contains a non-UTF-8 path") as failure:
        load_git_inventory(repository.root)
    assert isinstance(failure.value.__cause__, UnicodeDecodeError)
    assert (repository.root / ".git/index").read_bytes() == index
    (repository.root / removed).unlink()
    head = repository.commit()
    inventory = load_git_inventory(repository.root)
    assert inventory.head == head
    assert inventory.dirty_paths == ()
    paths = {entry.path for entry in inventory.files}
    assert "src/kept.py" in paths
    assert not any(path.startswith("src/removed-") for path in paths)


def test_stable_reader_refuses_a_file_removed_while_it_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A name removed after the descriptor opened makes the final path check inaccessible.

    Parameters
    ----------
    tmp_path : Path
        Owned directory holding one record.
    monkeypatch : pytest.MonkeyPatch
        Wraps the genuine snapshot so the real name is removed right after the first one.
    """
    target = tmp_path / "record.bin"
    target.write_bytes(b"record\n")
    snapshot = stable_reads._file_snapshot
    calls = 0

    def remove_after_first_snapshot(
        metadata: os.stat_result,
    ) -> tuple[int, int, int, int, int, int, int]:
        """Take the genuine snapshot, then unlink the real name once."""
        nonlocal calls
        calls += 1
        result = snapshot(metadata)
        if calls == 1:
            target.unlink()
        return result

    monkeypatch.setattr(stable_reads, "_file_snapshot", remove_after_first_snapshot)
    descriptor = open_directory_no_follow(tmp_path)
    try:
        with pytest.raises(StableReadError) as failure:
            read_stable_regular_file_at(descriptor, target.name, target.name)
    finally:
        os.close(descriptor)
    assert failure.value.reason == "inaccessible"
    assert isinstance(failure.value.__cause__, FileNotFoundError)
    assert calls == 1
    assert not target.exists()


def test_inventory_refuses_a_tracked_symlink_removed_after_its_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A tracked symlink removed between its type check and its target read is refused.

    Parameters
    ----------
    tmp_path : Path
        Owned repository allocation.
    monkeypatch : pytest.MonkeyPatch
        Wraps the genuine type check so the real link is removed right after it answers.
    """
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/target.py", "VALUE = 1\n")
    link = repository.root / "src/alias.py"
    link.symlink_to("target.py")
    repository.commit()
    is_symlink = Path.is_symlink

    def remove_after_type_check(path: Path) -> bool:
        """Answer from the real check, then remove the tracked link once."""
        answer = is_symlink(path)
        if path == link and answer:
            link.unlink()
        return answer

    monkeypatch.setattr(Path, "is_symlink", remove_after_type_check)
    with pytest.raises(
        RuntimeError, match=r"cannot read tracked symlink: src/alias\.py"
    ) as failure:
        load_git_inventory(repository.root)
    assert isinstance(failure.value.__cause__, FileNotFoundError)
    assert not link.exists() and not link.is_symlink()
