# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — ignored internal-record storage primitives
"""Provide symlink-safe, crash-resistant storage below ignored repository paths."""

from __future__ import annotations

import errno
import fcntl
import os
import shutil
import stat
import subprocess  # nosec B404
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .git_inventory import is_git_ignored


def _git_executable() -> str:
    """Return an absolute Git executable for tracked-path checks."""
    executable = shutil.which("git")
    if executable is None:
        raise RuntimeError("git is required for internal record storage")
    return str(Path(executable).resolve(strict=True))


def _is_git_tracked(repository: Path, relative: Path) -> bool:
    """Return whether ``relative`` is present in the real Git index."""
    try:
        completed = subprocess.run(  # nosec B603
            [
                _git_executable(),
                "-c",
                f"safe.directory={repository}",
                "ls-files",
                "--error-unmatch",
                "--",
                relative.as_posix(),
            ],
            cwd=repository,
            check=False,
            capture_output=True,
            shell=False,
        )
    except OSError as exc:
        raise RuntimeError(f"git tracked-path check failed for {relative}") from exc
    if completed.returncode == 0:
        return True
    if completed.returncode == 1:
        return False
    raise RuntimeError(f"git tracked-path check returned {completed.returncode} for {relative}")


def resolve_ignored_path(
    repository_root: Path,
    relative: Path,
    *,
    label: str,
) -> Path:
    """Resolve one repository-relative, Git-ignored, symlink-free path.

    Parameters
    ----------
    repository_root:
        Existing Git worktree root.
    relative:
        Repository-relative internal path.
    label:
        Human-readable record type used in validation errors.

    Returns
    -------
    pathlib.Path
        Absolute path that remains below ``repository_root``.

    Raises
    ------
    ValueError
        If the path is absolute, escapes the repository, is not ignored, or
        traverses an existing symbolic link.

    """
    repository = repository_root.resolve(strict=True)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError(f"{label} path must be repository-relative")
    cursor = repository
    for part in relative.parts:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError(f"{label} path must not contain symbolic links")
    if _is_git_tracked(repository, relative):
        raise ValueError(f"{label} path must not be tracked by Git")
    if not is_git_ignored(repository, relative):
        raise ValueError(f"{label} path must be covered by repository Git ignore rules")
    resolved = (repository / relative).resolve(strict=False)
    try:
        resolved.relative_to(repository)
    except ValueError as exc:
        raise ValueError(f"{label} path escapes the repository") from exc
    return resolved


def fsync_directory(directory: Path) -> None:
    """Synchronise directory metadata after an atomic record operation."""
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_new_text(path: Path, text: str) -> None:
    """Create and synchronise one immutable UTF-8 record without overwrite."""
    descriptor: int | None = None
    try:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            descriptor = None
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        fsync_directory(path.parent)
    except FileExistsError as exc:
        raise ValueError(f"immutable internal record already exists: {path}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def atomic_replace_text(path: Path, text: str) -> None:
    """Replace one derived UTF-8 view atomically after synchronising its bytes."""
    if path.is_symlink():
        raise ValueError(f"derived internal record must not be a symbolic link: {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            descriptor = -1
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


@contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    """Hold a non-blocking advisory lock on one persistent regular file."""
    descriptor: int | None = None
    locked = False
    try:
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"internal record lock must be a regular file: {path}")
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise RuntimeError(
                    f"another process holds the internal record lock: {path}"
                ) from exc
            raise
        locked = True
        yield
    finally:
        if descriptor is not None:
            if locked:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
