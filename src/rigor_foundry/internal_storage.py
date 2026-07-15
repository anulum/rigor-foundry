# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
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
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TextIO

from .git_inventory import is_git_ignored
from .git_provenance import GitRunner, GitTrustPolicy


def _is_git_tracked(repository: Path, relative: Path, runner: GitRunner) -> bool:
    """Return whether ``relative`` is present in the real Git index."""
    try:
        completed = runner.run(
            repository,
            "-c",
            f"safe.directory={repository}",
            "ls-files",
            "--error-unmatch",
            "--",
            relative.as_posix(),
            check=False,
        )
    except (OSError, RuntimeError) as exc:
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
    git_trust_policy: GitTrustPolicy | None = None,
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
    git_trust_policy:
        Optional runtime trust contract shared by tracked and ignored checks.

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
    runner = GitRunner(git_trust_policy)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError(f"{label} path must be repository-relative")
    cursor = repository
    for part in relative.parts:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError(f"{label} path must not contain symbolic links")
    if _is_git_tracked(repository, relative, runner):
        raise ValueError(f"{label} path must not be tracked by Git")
    if not is_git_ignored(repository, relative, git_runner=runner):
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


def regular_file_identity(path: Path, *, label: str) -> tuple[int, int]:
    """Return the device and inode of one existing single-link regular file."""
    try:
        metadata = path.stat(follow_symlinks=False)
    except FileNotFoundError as exc:
        raise ValueError(
            f"{label} must be an existing regular non-symlink file with exactly one link"
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(
            f"{label} must be an existing regular non-symlink file with exactly one link"
        )
    return metadata.st_dev, metadata.st_ino


def _acquire_flock(descriptor: int, path: Path) -> None:
    """Acquire one non-blocking exclusive advisory lock or fail closed."""
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EAGAIN}:
            raise RuntimeError(f"another process holds the internal record lock: {path}") from exc
        raise


@contextmanager
def open_verified_text_for_append(
    path: Path,
    expected_identity: tuple[int, int],
    *,
    label: str,
) -> Iterator[TextIO]:
    """Open an inode-bound UTF-8 append stream and synchronise successful writes."""
    descriptor: int | None = None
    try:
        flags = os.O_RDWR | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            if exc.errno in {errno.ENOENT, errno.ELOOP}:
                raise ValueError(f"{label} must be an existing regular non-symlink file") from exc
            raise
        metadata = os.fstat(descriptor)
        descriptor_identity = (metadata.st_dev, metadata.st_ino)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError(
                f"{label} must be an existing regular non-symlink file with exactly one link"
            )
        if descriptor_identity != expected_identity:
            raise ValueError(f"{label} changed after path validation")
        if regular_file_identity(path, label=label) != descriptor_identity:
            raise ValueError(f"{label} changed while it was opened")
        _acquire_flock(descriptor, path)
        metadata = os.fstat(descriptor)
        if metadata.st_nlink != 1:
            raise ValueError(f"{label} gained another link before append locking")
        if regular_file_identity(path, label=label) != descriptor_identity:
            raise ValueError(f"{label} changed while append locking")
        with os.fdopen(descriptor, "r+", encoding="utf-8", newline="") as handle:
            descriptor = None
            yield handle
            handle.flush()
            os.fsync(handle.fileno())
            if regular_file_identity(path, label=label) != descriptor_identity:
                raise ValueError(f"{label} changed while it was open")
    finally:
        if descriptor is not None:
            os.close(descriptor)


@contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    """Hold a path-stable lock without mutating pre-existing file metadata."""
    parent_descriptor: int | None = None
    parent_locked = False
    descriptor: int | None = None
    locked = False
    try:
        parent_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        parent_flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            parent_descriptor = os.open(path.parent, parent_flags)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise ValueError(
                    f"internal record lock parent must not be a symbolic link: {path.parent}"
                ) from exc
            raise
        parent_metadata = os.fstat(parent_descriptor)
        if not stat.S_ISDIR(parent_metadata.st_mode):
            raise ValueError(f"internal record lock parent must be a directory: {path.parent}")
        _acquire_flock(parent_descriptor, path.parent)
        parent_locked = True

        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise ValueError(
                    f"internal record lock must not be a symbolic link: {path}"
                ) from exc
            raise
        metadata = os.fstat(descriptor)
        lock_identity = (metadata.st_dev, metadata.st_ino)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError(
                f"internal record lock must be a regular file, not a symlink, "
                f"with exactly one link: {path}"
            )
        _acquire_flock(descriptor, path)
        locked = True
        if regular_file_identity(path, label="internal record lock") != lock_identity:
            raise ValueError(f"internal record lock path changed before entry: {path}")
        yield
        try:
            current_identity = regular_file_identity(path, label="internal record lock")
        except ValueError as exc:
            raise ValueError(f"internal record lock path changed while held: {path}") from exc
        if current_identity != lock_identity:
            raise ValueError(f"internal record lock path changed while held: {path}")
    finally:
        if descriptor is not None:
            if locked:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        if parent_descriptor is not None:
            if parent_locked:
                fcntl.flock(parent_descriptor, fcntl.LOCK_UN)
            os.close(parent_descriptor)
