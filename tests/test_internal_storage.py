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
