# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — retained original policy bytes
"""Keep host-selected original bytes and descriptor identities through use and close."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Iterable
from pathlib import Path
from types import TracebackType
from typing import cast
from uuid import uuid4

from .audit_primitives import canonical_digest, require_integer
from .model_primitives import require_digest
from .policy_read_budget import PolicyReadBudget1
from .stable_reads import open_directory_no_follow, read_stable_regular_file_at


def entry_list_digest(entries: Iterable[tuple[bytes, int]]) -> str:
    """Return the SHA-256 of directory entries, sorted by name whatever order they come in.

    Parameters
    ----------
    entries : Iterable[tuple[bytes, int]]
        Each entry's name bytes and inode number, in any order.

    Returns
    -------
    str
        The hexadecimal SHA-256 of every length-prefixed name and its inode number, in name
        order.
    """
    digest = hashlib.sha256()
    for name, inode in sorted(entries):
        digest.update(len(name).to_bytes(8, "big") + name + inode.to_bytes(8, "big"))
    return digest.hexdigest()


def directory_entry_digest(descriptor: int) -> str:
    """Return the SHA-256 of one open directory's complete entry list.

    Directory timestamps come from a coarse kernel clock on many hosts, so an entry added,
    removed or replaced within one clock tick can leave every ``stat`` field of the directory
    unchanged. The sorted entry names and inode numbers bind the entries themselves.

    Parameters
    ----------
    descriptor : int
        An open directory descriptor. CPython's ``os.scandir`` lists it through a duplicate
        descriptor, which shares the directory offset, and rewinds that offset when the
        iterator closes. The ``with`` block always closes the iterator, so consecutive
        listings through one descriptor see the whole directory.

    Returns
    -------
    str
        The :func:`entry_list_digest` of every entry's name bytes and inode number.

    Raises
    ------
    OSError
        If the directory cannot be listed through the descriptor.
    """
    with os.scandir(descriptor) as entries:
        listed = [(os.fsencode(entry.name), entry.inode()) for entry in entries]
    return entry_list_digest(listed)


def parent_directory_identity(descriptor: int) -> tuple[int | str, ...]:
    """Return a retained parent directory's stability identity and complete entry list.

    Parameters
    ----------
    descriptor : int
        An open descriptor of the retained source's parent directory.

    Returns
    -------
    tuple[int | str, ...]
        The directory's ``stat`` stability fields followed by its entry digest, so a changed
        entry is seen even when a coarse clock leaves the directory timestamps unchanged.

    Raises
    ------
    OSError
        If the directory cannot be examined through the descriptor.
    """
    return (*_identity(os.fstat(descriptor)), directory_entry_digest(descriptor))


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Bind the complete retained file or directory stability identity."""
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


class RetainedPolicySource:
    """Hold one original raw source chosen by a host that already owns access.

    Parameters
    ----------
    path : Path
        Explicit original file selection, independent of any opaque locator.
    byte_digest : str
        Expected exact original byte SHA-256, not its metadata record digest.
    byte_count : int
        Expected complete byte count, including zero for an empty source.
    budget : PolicyReadBudget1
        Explicit read ceiling for this individual source.

    Raises
    ------
    ValueError
        If limits, exact bytes, file type or retained identities disagree.
    OSError
        If the original selection cannot be opened without following links.
    StableReadError
        If the original bytes exceed the read ceiling or change during reading.

    Notes
    -----
    This class never fetches sources, copies an inventory or grants access. Its
    caller owns lifetime and must close it after the final guarded operation.
    """

    def __init__(
        self, path: Path, *, byte_digest: str, byte_count: int, budget: PolicyReadBudget1
    ) -> None:
        """Retain original descriptors only after validating explicit host limits."""
        if type(budget) is not PolicyReadBudget1:
            raise ValueError("policy read budget is required")
        self._budget = PolicyReadBudget1.from_dict(budget.to_dict())
        self._byte_digest = require_digest(byte_digest, "original policy byte digest")
        self._byte_count = require_integer(byte_count, "original policy byte count")
        if self._byte_count > self._budget.max_source_bytes:
            raise ValueError("policy source exceeds its byte budget")
        self._path = path.absolute()
        self._parent = self._file = -1
        self._closed = False
        try:
            self._parent = open_directory_no_follow(self._path.parent)
            self._file = os.open(
                self._path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._parent
            )
            metadata = os.fstat(self._file)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError("policy source must be a single-link regular file")
            self._file_identity = _identity(metadata)
            self._parent_identity = parent_directory_identity(self._parent)
            self._snapshot_id = canonical_digest(
                {
                    "selection_id": uuid4().hex,
                    "path": str(self._path),
                    "byte_digest": self._byte_digest,
                    "byte_count": self._byte_count,
                    "file_identity": list(self._file_identity),
                    "parent_identity": list(self._parent_identity),
                }
            )
            self.read()
        except BaseException:
            self._release()
            raise

    @property
    def snapshot_id(self) -> str:
        """Return this actual retained selection identity after checking its lifetime."""
        self._check_identity()
        return self._snapshot_id

    @property
    def path(self) -> Path:
        """Expose the checked host selection for original native/discovery joins."""
        self._check_identity()
        return self._path

    def _check_identity(self) -> None:
        """Refuse a closed handle, parent replacement, alias or edited source."""
        if self._closed:
            raise ValueError("policy source lease is closed")
        parent = open_directory_no_follow(self._path.parent)
        try:
            if (
                parent_directory_identity(parent) != self._parent_identity
                or parent_directory_identity(self._parent) != self._parent_identity
            ):
                raise ValueError("policy source directory identity changed")
            if (
                _identity(os.fstat(self._file)) != self._file_identity
                or _identity(os.stat(self._path.name, dir_fd=parent, follow_symlinks=False))
                != self._file_identity
            ):
                raise ValueError("policy source file identity changed")
        finally:
            os.close(parent)

    def read(self) -> bytes:
        """Read all original bytes within the held identity and explicit byte ceiling.

        Returns
        -------
        bytes
            Complete raw payload, without text decoding or newline conversion.

        Raises
        ------
        ValueError
            If lifetime, source identity, complete byte count or digest differs.
        OSError
            If a no-follow stable read cannot complete.
        StableReadError
            If an original file is unstable or exceeds the actual byte ceiling.
        """
        self._check_identity()
        read = read_stable_regular_file_at(
            self._parent,
            self._path.name,
            str(self._path),
            buffer_limit=self._budget.max_source_bytes,
            maximum_bytes=self._budget.max_source_bytes,
            require_single_link=True,
        )
        payload = cast(bytes, read.payload)
        self._check_identity()
        if (
            len(payload) != self._byte_count
            or hashlib.sha256(payload).hexdigest() != self._byte_digest
        ):
            raise ValueError("policy source differs from its selected original bytes")
        return payload

    def _release(self) -> None:
        """Release both owned descriptors exactly once even after construction fails."""
        for name in ("_file", "_parent"):
            descriptor = getattr(self, name)
            if descriptor != -1:
                os.close(descriptor)
                setattr(self, name, -1)
        self._closed = True

    def close(self) -> None:
        """Re-read at the closing boundary and always release both descriptors."""
        if self._closed:
            return
        try:
            self.read()
        finally:
            self._release()

    def __enter__(self) -> RetainedPolicySource:
        """Check the original identity before entering its retained lifetime."""
        self._check_identity()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Validate final original bytes and release the actual owned handles."""
        self.close()
