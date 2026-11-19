# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native Windows stable reads and exclusive output
"""Read and create exact NTFS bytes through retained no-reparse resources."""

from __future__ import annotations

import hashlib
import os
from contextlib import nullcontext
from pathlib import Path
from typing import overload

from .git_inventory import StableGitRead, StableReadError, StableRegularRead
from .windows_handles import WindowsDirectory, WindowsFileIdentity


def _require_single_link(count: int, failure: Exception) -> None:
    """Enforce the same link-count requirement at every native file boundary."""
    if count != 1:
        raise failure


# A docstring documents each overload without adding an executable stub body.
# Ruff D418 is waived only on these two declarations.
@overload
def read_regular_file(  # noqa: D418
    path: Path,
    *,
    object_format: str,
    buffer_limit: int = 8 * 1024 * 1024,
    maximum_bytes: int | None = None,
    require_single_link: bool = True,
    retained_parent: WindowsDirectory | None = None,
    expected_identity: WindowsFileIdentity | None = None,
) -> StableGitRead:
    """Declare a stable read with a Git blob identity derived from the captured bytes."""


@overload
def read_regular_file(  # noqa: D418
    path: Path,
    *,
    object_format: str | None = None,
    buffer_limit: int = 8 * 1024 * 1024,
    maximum_bytes: int | None = None,
    require_single_link: bool = True,
    retained_parent: WindowsDirectory | None = None,
    expected_identity: WindowsFileIdentity | None = None,
) -> StableRegularRead:
    """Declare a stable read whose Git blob identity depends on the requested format."""


def read_regular_file(
    path: Path,
    *,
    object_format: str | None = None,
    buffer_limit: int = 8 * 1024 * 1024,
    maximum_bytes: int | None = None,
    require_single_link: bool = True,
    retained_parent: WindowsDirectory | None = None,
    expected_identity: WindowsFileIdentity | None = None,
) -> StableRegularRead:
    """Hash one exact bounded regular file while retaining all Windows path components.

    Parameters
    ----------
    path : Path
        Explicit absolute path on a local fixed NTFS volume.
    object_format : str or None
        Git blob hash algorithm, or no Git identity when omitted.
    buffer_limit : int
        Maximum size for retaining the content payload in memory.
    maximum_bytes : int or None
        Optional hard read ceiling, checked before and during reads.
    require_single_link : bool
        Refuse hard links for records and executables; tracked source may permit them.
    retained_parent : WindowsDirectory or None
        Borrow the caller's live parent chain when reading an already resolved entry.
    expected_identity : WindowsFileIdentity or None
        Require the opened object to match a prior handle-relative observation.

    Returns
    -------
    StableRegularRead
        Exact byte count, optional payload and identities from the same descriptor.

    Raises
    ------
    StableReadError
        If file type, links, identity, accessibility or finite read bounds fail.
    ValueError
        If the explicit limits or hash algorithm are invalid.
    """
    if type(buffer_limit) is not int or buffer_limit < 0:
        raise ValueError("buffer_limit must be an integer >= 0")
    if maximum_bytes is not None and (type(maximum_bytes) is not int or maximum_bytes < 0):
        raise ValueError("maximum_bytes must be an integer >= 0 or None")
    blob = hashlib.new(object_format) if object_format is not None else None
    content = hashlib.sha256()
    if retained_parent is not None and retained_parent.path != path.parent:
        raise StableReadError("changed-while-read", str(path))
    try:
        parent_context = (
            WindowsDirectory(path.parent)
            if retained_parent is None
            else nullcontext(retained_parent)
        )
        with parent_context as parent, parent.open_file(path.name) as file:
            _ = parent.identity
            before = file.identity()
            if expected_identity is not None and before != expected_identity:
                raise StableReadError("changed-while-read", str(path))
            if require_single_link:
                _require_single_link(before.links, StableReadError("multiple-links", str(path)))
            if maximum_bytes is not None and before.size > maximum_bytes:
                raise StableReadError("limit-exceeded", str(path))
            if blob is not None:
                blob.update(f"blob {before.size}\0".encode())
            payload = bytearray() if before.size <= buffer_limit else None
            count = 0
            while True:
                size = min(1024 * 1024, before.size - count + 1)
                if maximum_bytes is not None:
                    size = min(size, maximum_bytes - count + 1)
                chunk = os.read(file.descriptor, size)
                if not chunk:
                    break
                count += len(chunk)
                if maximum_bytes is not None and count > maximum_bytes:
                    raise StableReadError("limit-exceeded", str(path))
                if count > before.size:
                    raise StableReadError("changed-while-read", str(path))
                content.update(chunk)
                if blob is not None:
                    blob.update(chunk)
                if payload is not None:
                    payload.extend(chunk)
            if count != before.size or file.identity() != before:
                raise StableReadError("changed-while-read", str(path))
            _ = parent.identity
    except OSError as exc:
        raise StableReadError("inaccessible", str(path)) from exc
    except ValueError as exc:
        raise StableReadError("not-regular-file", str(path)) from exc
    retained = None if payload is None else bytes(payload)
    digest = content.hexdigest()
    if blob is None:
        return StableRegularRead(count, retained, digest, None)
    return StableGitRead(count, retained, digest, blob.hexdigest())


def write_new_file(path: Path, text: str) -> None:
    """Create exact UTF-8 output exclusively with NTFS data and metadata write-through.

    Parameters
    ----------
    path : Path
        Explicit absolute new filename below an existing local fixed NTFS directory.
    text : str
        Complete UTF-8 payload, without newline conversion.

    Raises
    ------
    ValueError
        If the target exists or the path/object contract cannot be met.
    OSError
        If writing or flushing fails; cleanup affects only this owned created handle.
    """
    with WindowsDirectory(path.parent) as parent:
        write_new_file_at(parent, path.name, text)


def write_new_file_at(
    parent: WindowsDirectory, name: str, text: str, *, private: bool = True
) -> tuple[int, int]:
    """Create UTF-8 bytes relative to an already retained directory.

    Parameters
    ----------
    parent : WindowsDirectory
        Caller-owned directory retained throughout creation and flushing.
    name : str
        One new regular filename, without path traversal or aliases.
    text : str
        Exact complete UTF-8 payload, without newline conversion.
    private : bool
        Apply a protected current-user-only DACL at creation, rather than inheritance.

    Returns
    -------
    tuple[int, int]
        Native volume and file identity of the newly flushed object.

    Raises
    ------
    ValueError, OSError
        On an existing target, changed identity or incomplete write/flush.
        A failed write discards only the object created by this invocation.
    """
    payload = text.encode("utf-8")
    _ = parent.identity
    try:
        file = parent.open_file(name, create=True, private=private)
    except FileExistsError as exc:
        raise ValueError(f"output path already exists: {parent.path / name}") from exc
    with file:
        try:
            created = file.identity()
            _require_single_link(
                created.links, ValueError("new output is not a single-link regular file")
            )
            written = 0
            while written < len(payload):
                count = os.write(file.descriptor, payload[written:])
                if count <= 0:
                    raise OSError("output write made no progress")
                written += count
            file.flush()
            after = file.identity()
            _require_single_link(
                after.links, ValueError("new Windows output identity changed during creation")
            )
            _ = parent.identity
            return after.volume, after.file_id
        except BaseException:
            file.discard()
            raise
