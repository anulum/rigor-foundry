# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — internal storage race tests
"""Force real filesystem changes between internal storage's paired observations.

Each test wraps the module function that makes one observation so that it first
changes the real file, directory or descriptor and then calls the genuine function.
No product seam is added and no observation result is fabricated.
"""

from __future__ import annotations

import errno
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from rigor_foundry import internal_storage
from rigor_foundry.git_inventory import is_git_ignored
from rigor_foundry.git_provenance import (
    _COMMAND_OUTPUT_LIMIT,
    _COMMAND_TIMEOUT_SECONDS,
    GitRunner,
    GitTrustPolicy,
)
from rigor_foundry.internal_storage import (
    exclusive_lock,
    open_verified_text_for_append,
    regular_file_identity,
    resolve_ignored_path,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX storage races")


def _git(repository: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-c", f"safe.directory={repository}", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "--quiet")
    (root / ".gitignore").write_text(".rigor-internal/\n", encoding="utf-8")
    _git(root, "add", ".gitignore")
    return root


def _record(path: Path, text: str = "first\n") -> tuple[int, int]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return regular_file_identity(path, label="record")


def _replace(path: Path) -> None:
    replacement = path.with_name(path.name + ".replacement")
    replacement.write_text("replacement\n", encoding="utf-8")
    os.replace(replacement, path)


def test_tracked_check_reports_a_trusted_git_that_vanishes_before_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A trusted Git removed before the tracked-path check fails closed with context.

    Parameters
    ----------
    tmp_path : Path
        Owned repository and trusted tool directory.
    monkeypatch : pytest.MonkeyPatch
        Wraps the genuine runner so the executable disappears before the real call.
    """
    root = _repository(tmp_path)
    tools = tmp_path / "tools"
    tools.mkdir()
    real_git = shutil.which("git")
    assert real_git is not None
    executable = tools / "git"
    executable.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then\n'
        "  printf '%s\\n' 'git version 2.43.0'\n"
        "  exit 0\n"
        "fi\n"
        f"exec '{Path(real_git).resolve(strict=True)}' \"$@\"\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    run = GitRunner.run

    def remove_before_tracked_check(
        owner: GitRunner,
        cwd: Path,
        *arguments: str,
        check: bool = True,
        timeout_seconds: int = _COMMAND_TIMEOUT_SECONDS,
        output_limit: int = _COMMAND_OUTPUT_LIMIT,
    ) -> subprocess.CompletedProcess[bytes]:
        """Remove the real trusted executable only before the tracked-path query."""
        if "ls-files" in arguments:
            executable.unlink()
        return run(
            owner,
            cwd,
            *arguments,
            check=check,
            timeout_seconds=timeout_seconds,
            output_limit=output_limit,
        )

    monkeypatch.setattr(GitRunner, "run", remove_before_tracked_check)
    with pytest.raises(RuntimeError, match="git tracked-path check failed") as failure:
        resolve_ignored_path(
            root,
            Path(".rigor-internal/record.json"),
            label="record",
            git_trust_policy=GitTrustPolicy(trusted_roots=(str(tools),)),
        )
    assert isinstance(failure.value.__cause__, (OSError, RuntimeError))
    assert not executable.exists()


def test_component_linked_out_after_the_ignore_check_cannot_escape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A directory swapped for an outside link after the checks is refused on resolution.

    Parameters
    ----------
    tmp_path : Path
        Owned repository and outside target.
    monkeypatch : pytest.MonkeyPatch
        Wraps the genuine ignore check so the link appears right after it answers.
    """
    root = _repository(tmp_path)
    records = root / ".rigor-internal/records"
    records.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    is_ignored = is_git_ignored

    def link_out_after_check(
        repository: Path, relative: Path, *, git_runner: GitRunner | None = None
    ) -> bool:
        """Answer from the real check, then replace the directory with an outside link."""
        answer = is_ignored(repository, relative, git_runner=git_runner)
        records.rmdir()
        records.symlink_to(outside, target_is_directory=True)
        return answer

    monkeypatch.setattr(internal_storage, "is_git_ignored", link_out_after_check)
    with pytest.raises(ValueError, match="path escapes the repository") as failure:
        resolve_ignored_path(root, Path(".rigor-internal/records/one.json"), label="record")
    assert isinstance(failure.value.__cause__, ValueError)
    assert records.is_symlink()
    assert list(outside.iterdir()) == []


def test_append_refuses_a_file_replaced_after_its_descriptor_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The path identity checked after opening must still be the opened inode.

    Parameters
    ----------
    tmp_path : Path
        Owned record allocation.
    monkeypatch : pytest.MonkeyPatch
        Wraps the genuine identity read so the file is replaced just before it.
    """
    path = tmp_path / "record.log"
    expected = _record(path)
    identity = internal_storage.regular_file_identity

    def replace_before_read(candidate: Path, *, label: str) -> tuple[int, int]:
        """Replace the real file at the path, then read its identity."""
        _replace(candidate)
        return identity(candidate, label=label)

    monkeypatch.setattr(internal_storage, "regular_file_identity", replace_before_read)
    with (
        pytest.raises(ValueError, match="changed while it was opened"),
        open_verified_text_for_append(path, expected, label="record"),
    ):
        pass
    assert path.read_text(encoding="utf-8") == "replacement\n"


def test_append_refuses_a_link_added_before_locking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second hard link created before the lock is taken is detected after locking.

    Parameters
    ----------
    tmp_path : Path
        Owned record allocation.
    monkeypatch : pytest.MonkeyPatch
        Wraps the genuine lock so a real second link exists before it is acquired.
    """
    path = tmp_path / "record.log"
    expected = _record(path)
    second = tmp_path / "second-link.log"
    acquire = internal_storage._acquire_flock

    def link_before_lock(descriptor: int, locked: Path) -> None:
        """Create a real second link to the record, then take the genuine lock."""
        os.link(locked, second)
        acquire(descriptor, locked)

    monkeypatch.setattr(internal_storage, "_acquire_flock", link_before_lock)
    with (
        pytest.raises(ValueError, match="gained another link before append locking"),
        open_verified_text_for_append(path, expected, label="record"),
    ):
        pass
    assert os.stat(path).st_nlink == 2
    assert second.read_text(encoding="utf-8") == "first\n"


def test_append_refuses_a_file_replaced_while_it_was_being_locked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The identity read after locking must still name the locked inode.

    Parameters
    ----------
    tmp_path : Path
        Owned record allocation.
    monkeypatch : pytest.MonkeyPatch
        Wraps the genuine identity read so only the post-lock read sees a replacement.
    """
    path = tmp_path / "record.log"
    expected = _record(path)
    identity = internal_storage.regular_file_identity
    calls = 0

    def replace_before_second_read(candidate: Path, *, label: str) -> tuple[int, int]:
        """Read the real identity, replacing the file before the post-lock read."""
        nonlocal calls
        calls += 1
        if calls == 2:
            _replace(candidate)
        return identity(candidate, label=label)

    monkeypatch.setattr(internal_storage, "regular_file_identity", replace_before_second_read)
    with (
        pytest.raises(ValueError, match="changed while append locking"),
        open_verified_text_for_append(path, expected, label="record"),
    ):
        pass
    assert calls == 2


def test_lock_refuses_a_lock_file_replaced_before_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lock file replaced before its lock is taken is refused before the body runs.

    Parameters
    ----------
    tmp_path : Path
        Owned lock allocation.
    monkeypatch : pytest.MonkeyPatch
        Wraps the genuine lock so the lock file is replaced right before it is locked.
    """
    path = tmp_path / "record.lock"
    acquire = internal_storage._acquire_flock

    def replace_lock_before_locking(descriptor: int, locked: Path) -> None:
        """Replace the real lock file, then take the genuine lock on the opened inode."""
        if locked == path:
            _replace(path)
        acquire(descriptor, locked)

    monkeypatch.setattr(internal_storage, "_acquire_flock", replace_lock_before_locking)
    with (
        pytest.raises(ValueError, match="lock path changed before entry"),
        exclusive_lock(path),
    ):
        raise AssertionError("the lock body ran after the lock file was replaced")
    assert path.read_text(encoding="utf-8") == "replacement\n"


def test_lock_propagates_a_real_unexpected_lock_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lock failure other than contention is re-raised unchanged.

    Parameters
    ----------
    tmp_path : Path
        Owned lock allocation.
    monkeypatch : pytest.MonkeyPatch
        Wraps the genuine lock call so its descriptor really refers to a path-only open.
    """
    path = tmp_path / "record.lock"
    lock = internal_storage._flock

    def lock_a_path_only_descriptor(descriptor: int, *, unlock: bool = False) -> None:
        """Make the descriptor a real path-only open, then call the genuine lock."""
        if not unlock:
            path_only = os.open(tmp_path, os.O_PATH)
            try:
                os.dup2(path_only, descriptor)
            finally:
                os.close(path_only)
        lock(descriptor, unlock=unlock)

    monkeypatch.setattr(internal_storage, "_flock", lock_a_path_only_descriptor)
    with pytest.raises(OSError) as failure, exclusive_lock(path):
        raise AssertionError("the lock body ran without a lock")
    assert failure.value.errno == errno.EBADF
