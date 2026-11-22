# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — descriptor-anchored stable file reads
"""Read regular files and open directories through stable no-follow descriptors."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, overload

StableReadFailure = Literal[
    "changed-while-read",
    "inaccessible",
    "limit-exceeded",
    "multiple-links",
    "not-regular-file",
    "platform-unavailable",
]
MAX_TEXT_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class StableRegularRead:
    """Content identities derived from one stable regular-file descriptor."""

    byte_size: int
    payload: bytes | None
    content_digest: str
    git_blob_id: str | None


@dataclass(frozen=True)
class StableGitRead(StableRegularRead):
    """Content identities including a Git blob computed from the same read."""

    git_blob_id: str


class StableReadError(RuntimeError):
    """One finite stable-file read failure suitable for bounded evidence."""

    def __init__(self, reason: StableReadFailure, relative: str) -> None:
        messages = {
            "changed-while-read": "regular path changed while being read",
            "inaccessible": "cannot access regular path",
            "limit-exceeded": "regular path exceeds the read limit",
            "multiple-links": "regular path has multiple hard links",
            "not-regular-file": "path is not one regular file",
            "platform-unavailable": "platform lacks stable no-follow file reads",
        }
        super().__init__(f"{messages[reason]}: {relative}")
        self.reason = reason


def _file_snapshot(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    """Return descriptor fields that must remain stable during one read."""
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


@overload
def read_stable_regular_file_at(
    parent_descriptor: int,
    name: str,
    relative: str,
    *,
    object_format: str,
    buffer_limit: int = MAX_TEXT_BYTES,
    maximum_bytes: int | None = None,
    require_single_link: bool = False,
) -> StableGitRead: ...


@overload
def read_stable_regular_file_at(
    parent_descriptor: int,
    name: str,
    relative: str,
    *,
    object_format: str | None = None,
    buffer_limit: int = MAX_TEXT_BYTES,
    maximum_bytes: int | None = None,
    require_single_link: bool = False,
) -> StableRegularRead: ...


def read_stable_regular_file_at(
    parent_descriptor: int,
    name: str,
    relative: str,
    *,
    object_format: str | None = None,
    buffer_limit: int = MAX_TEXT_BYTES,
    maximum_bytes: int | None = None,
    require_single_link: bool = False,
) -> StableRegularRead:
    """Read one no-follow regular file once through a trusted parent descriptor.

    Returns
    -------
    StableRegularRead
        Exact byte count, optional bounded payload, SHA-256, and optional Git
        blob identity, all derived from the same descriptor pass.

    Raises
    ------
    ValueError
        If a name, object format, or buffer limit is invalid.
    StableReadError
        If the path is inaccessible, is not one regular file, violates the
        requested link policy, or changes during the complete read.
    """
    if "/" in name or name in {"", ".", ".."}:
        raise ValueError("stable-read name must be one path component")
    if object_format is not None and object_format not in {"sha1", "sha256"}:
        raise ValueError("unsupported Git object format")
    if isinstance(buffer_limit, bool) or not isinstance(buffer_limit, int) or buffer_limit < 0:
        raise ValueError("buffer_limit must be an integer >= 0")
    if maximum_bytes is not None and (
        isinstance(maximum_bytes, bool) or not isinstance(maximum_bytes, int) or maximum_bytes < 0
    ):
        raise ValueError("maximum_bytes must be an integer >= 0 or None")
    if (
        not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_NONBLOCK")
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        raise StableReadError("platform-unavailable", relative)
    # A FIFO must not block before the descriptor's regular-file check.
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    except OSError as exc:
        raise StableReadError("inaccessible", relative) from exc
    try:
        before = os.fstat(descriptor)
        path_before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or _file_snapshot(path_before)[:2] != (
            before.st_dev,
            before.st_ino,
        ):
            raise StableReadError("not-regular-file", relative)
        if require_single_link and before.st_nlink != 1:
            raise StableReadError("multiple-links", relative)
        if maximum_bytes is not None and before.st_size > maximum_bytes:
            raise StableReadError("limit-exceeded", relative)
        content_digest = hashlib.sha256()
        blob_digest = hashlib.new(object_format) if object_format is not None else None
        if blob_digest is not None:
            blob_digest.update(f"blob {before.st_size}\0".encode())
        buffered = bytearray() if before.st_size <= buffer_limit else None
        byte_count = 0
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            while True:
                read_size = 1024 * 1024
                if maximum_bytes is not None:
                    read_size = min(read_size, maximum_bytes - byte_count + 1)
                chunk = handle.read(read_size)
                if not chunk:
                    break
                byte_count += len(chunk)
                if maximum_bytes is not None and byte_count > maximum_bytes:
                    raise StableReadError("limit-exceeded", relative)
                content_digest.update(chunk)
                if blob_digest is not None:
                    blob_digest.update(chunk)
                if buffered is not None:
                    buffered.extend(chunk)
        after = os.fstat(descriptor)
        path_after = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as exc:
        raise StableReadError("inaccessible", relative) from exc
    finally:
        os.close(descriptor)
    if (
        byte_count != before.st_size
        or _file_snapshot(after) != _file_snapshot(before)
        or _file_snapshot(path_before) != _file_snapshot(before)
        or _file_snapshot(path_after) != _file_snapshot(before)
    ):
        raise StableReadError("changed-while-read", relative)
    payload = None if buffered is None else bytes(buffered)
    digest = content_digest.hexdigest()
    if blob_digest is None:
        return StableRegularRead(byte_count, payload, digest, None)
    return StableGitRead(byte_count, payload, digest, blob_digest.hexdigest())


def open_directory_no_follow(path: Path) -> int:
    """Open an absolute directory only through no-follow path components."""
    if not path.is_absolute():
        raise ValueError("directory path must be absolute")
    if ".." in path.parts:
        raise ValueError("directory path must not contain parent traversal")
    if (
        not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        raise RuntimeError("platform lacks no-follow descriptor traversal")
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
    except OSError:
        os.close(descriptor)
        raise
    return descriptor
