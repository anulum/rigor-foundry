# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — internal storage integration tests
"""Verify internal storage against a real Git worktree and filesystem."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from rigor_foundry.internal_storage import (
    atomic_replace_text,
    exclusive_lock,
    open_verified_text_for_append,
    regular_file_identity,
    resolve_ignored_path,
    write_new_text,
)


def git(repository: Path, *arguments: str) -> None:
    """Run Git against a real temporary repository."""
    subprocess.run(
        ["git", "-c", f"safe.directory={repository}", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )


def repository(tmp_path: Path) -> Path:
    """Create a real repository with one ignored internal namespace."""
    root = tmp_path / "repository"
    root.mkdir()
    git(root, "init", "--quiet")
    (root / ".gitignore").write_text(".rigor-internal/\n", encoding="utf-8")
    git(root, "add", ".gitignore")
    return root


def test_resolve_ignored_path_accepts_only_untracked_safe_paths(tmp_path: Path) -> None:
    """Ignored untracked paths resolve while tracked, escaping, and linked paths fail."""
    root = repository(tmp_path)
    expected = root / ".rigor-internal" / "records" / "one.json"
    assert (
        resolve_ignored_path(
            root,
            Path(".rigor-internal/records/one.json"),
            label="record",
        )
        == expected
    )

    tracked = root / ".rigor-internal" / "tracked.json"
    tracked.parent.mkdir()
    tracked.write_text("{}", encoding="utf-8")
    git(root, "add", "-f", ".rigor-internal/tracked.json")
    with pytest.raises(ValueError, match="must not be tracked"):
        resolve_ignored_path(root, Path(".rigor-internal/tracked.json"), label="record")
    with pytest.raises(ValueError, match="repository-relative"):
        resolve_ignored_path(root, Path("../escape"), label="record")
    with pytest.raises(ValueError, match="ignore rules"):
        resolve_ignored_path(root, Path("visible.json"), label="record")

    linked = root / ".rigor-internal" / "linked"
    linked.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic links"):
        resolve_ignored_path(root, Path(".rigor-internal/linked/file"), label="record")


def test_immutable_and_atomic_writes_use_real_files(tmp_path: Path) -> None:
    """Immutable writes refuse overwrite and derived views replace atomically."""
    directory = tmp_path / "records"
    directory.mkdir()
    immutable = directory / "event.json"
    write_new_text(immutable, "first\n")
    assert immutable.read_text(encoding="utf-8") == "first\n"
    assert os.stat(immutable).st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match="already exists"):
        write_new_text(immutable, "second\n")

    derived = directory / "registry.json"
    atomic_replace_text(derived, "one\n")
    atomic_replace_text(derived, "two\n")
    assert derived.read_text(encoding="utf-8") == "two\n"
    linked = directory / "linked.json"
    linked.symlink_to(derived)
    with pytest.raises(ValueError, match="symbolic link"):
        atomic_replace_text(linked, "unsafe\n")


def test_exclusive_lock_serializes_real_file_descriptors(tmp_path: Path) -> None:
    """A second descriptor cannot enter until the first advisory lock exits."""
    path = tmp_path / "records.lock"
    with (
        exclusive_lock(path),
        pytest.raises(RuntimeError, match="another process"),
        exclusive_lock(path),
    ):
        raise AssertionError("contended lock unexpectedly entered")
    with exclusive_lock(path):
        assert path.is_file()
    assert os.stat(path).st_mode & 0o777 == 0o600


def test_real_git_errors_and_nonregular_locks_fail_closed(tmp_path: Path) -> None:
    """A non-repository root and a real character device are rejected without coercion."""
    root = tmp_path / "not-a-repository"
    root.mkdir()
    with pytest.raises(RuntimeError, match="git tracked-path check returned"):
        resolve_ignored_path(root, Path(".internal/record"), label="record")
    with pytest.raises(ValueError, match="repository-relative"):
        resolve_ignored_path(repository(tmp_path), Path("/absolute/record"), label="record")
    with pytest.raises(ValueError, match="regular file"), exclusive_lock(Path("/dev/null")):
        raise AssertionError("character device unexpectedly accepted as a lock")


def test_verified_append_rejects_post_validation_regular_file_swap(tmp_path: Path) -> None:
    """An inode captured before a regular-file replacement cannot authorise the new file."""
    target = tmp_path / "TODO.md"
    target.write_text("original\n", encoding="utf-8")
    identity = regular_file_identity(target, label="TODO path")
    replacement = tmp_path / "replacement.md"
    replacement.write_text("attacker replacement\n", encoding="utf-8")
    os.replace(replacement, target)

    with (
        pytest.raises(ValueError, match="changed after path validation"),
        open_verified_text_for_append(target, identity, label="TODO path") as handle,
    ):
        handle.write("must not be written\n")

    assert target.read_text(encoding="utf-8") == "attacker replacement\n"


def test_verified_append_rejects_missing_linked_and_nonregular_paths(tmp_path: Path) -> None:
    """The append descriptor never follows links or accepts non-regular files."""
    missing = tmp_path / "missing.md"
    with (
        pytest.raises(ValueError, match="existing regular"),
        open_verified_text_for_append(
            missing,
            (0, 0),
            label="TODO path",
        ),
    ):
        raise AssertionError("missing path unexpectedly opened")

    victim = tmp_path / "victim.md"
    victim.write_text("unchanged\n", encoding="utf-8")
    linked = tmp_path / "linked.md"
    linked.symlink_to(victim)
    with (
        pytest.raises(ValueError, match="existing regular"),
        open_verified_text_for_append(
            linked,
            regular_file_identity(victim, label="TODO path"),
            label="TODO path",
        ),
    ):
        raise AssertionError("linked path unexpectedly opened")

    device_metadata = os.stat("/dev/null")
    with (
        pytest.raises(ValueError, match="existing regular"),
        open_verified_text_for_append(
            Path("/dev/null"),
            (device_metadata.st_dev, device_metadata.st_ino),
            label="TODO path",
        ),
    ):
        raise AssertionError("non-regular path unexpectedly opened")


def test_verified_append_detects_replacement_while_descriptor_is_open(
    tmp_path: Path,
) -> None:
    """An opened inode receives no authority to mutate a replacement path."""
    target = tmp_path / "TODO.md"
    target.write_text("original\n", encoding="utf-8")
    identity = regular_file_identity(target, label="TODO path")
    replacement = tmp_path / "replacement.md"
    replacement.write_text("attacker replacement\n", encoding="utf-8")

    with (
        pytest.raises(ValueError, match="changed while it was open"),
        open_verified_text_for_append(target, identity, label="TODO path") as handle,
    ):
        os.replace(replacement, target)
        handle.write("write reaches only the validated inode\n")

    assert target.read_text(encoding="utf-8") == "attacker replacement\n"


def test_verified_append_serializes_on_the_validated_target_inode(tmp_path: Path) -> None:
    """A second append descriptor cannot enter while the exact target inode is held."""
    target = tmp_path / "TODO.md"
    target.write_text("original\n", encoding="utf-8")
    identity = regular_file_identity(target, label="TODO path")

    with (
        open_verified_text_for_append(target, identity, label="TODO path"),
        pytest.raises(RuntimeError, match="another process"),
        open_verified_text_for_append(target, identity, label="TODO path"),
    ):
        raise AssertionError("second target descriptor unexpectedly entered")


def test_exclusive_lock_never_unlinks_replacement_on_exit(tmp_path: Path) -> None:
    """Releasing an opened lock descriptor leaves a replacement path untouched."""
    lock = tmp_path / "records.lock"
    lock.write_text("original lock\n", encoding="utf-8")
    victim = tmp_path / "victim.txt"
    victim.write_text("unchanged\n", encoding="utf-8")

    with (
        pytest.raises(ValueError, match="changed while held"),
        exclusive_lock(lock),
    ):
        lock.unlink()
        lock.symlink_to(victim)

    assert lock.is_symlink()
    assert victim.read_text(encoding="utf-8") == "unchanged\n"


def test_exclusive_lock_replacement_cannot_split_serialization(tmp_path: Path) -> None:
    """A second contender cannot lock a recreated pathname in the held directory."""
    lock = tmp_path / "records.lock"
    with (
        pytest.raises(ValueError, match="changed while held"),
        exclusive_lock(lock),
    ):
        lock.unlink()
        lock.write_text("replacement\n", encoding="utf-8")
        with pytest.raises(RuntimeError, match="another process"), exclusive_lock(lock):
            raise AssertionError("replacement inode unexpectedly split serialization")

    assert lock.read_text(encoding="utf-8") == "replacement\n"


def test_exclusive_lock_rejects_hard_link_without_mutating_victim(tmp_path: Path) -> None:
    """A multi-link lock cannot change an aliased file's mode or content."""
    victim = tmp_path / "victim.txt"
    victim.write_text("unchanged\n", encoding="utf-8")
    victim.chmod(0o644)
    lock = tmp_path / "records.lock"
    os.link(victim, lock)

    with pytest.raises(ValueError, match="exactly one link"), exclusive_lock(lock):
        raise AssertionError("hard-linked lock unexpectedly entered")

    assert victim.read_text(encoding="utf-8") == "unchanged\n"
    assert os.stat(victim).st_mode & 0o777 == 0o644
