# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — immutable protected recovery evidence
"""Store exact digest-named recovery objects in one selected owner-only directory."""

from __future__ import annotations

import ctypes
import fcntl
import os
import re
import secrets
import stat
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from ._permit_ledger_storage_io_v2 import _identity, _owner_only, _read_exact, _write_all
from .git_inventory import open_directory_no_follow
from .model_primitives import require_digest
from .recovery_evidence_schema_v2 import validate_recovery_evidence_bytes_v2

_NAME = re.compile(r"[0-9a-f]{64}\.json\Z")
_JOURNAL_DOMAIN = "rigor.effect-journal-tail-recovery.v2.1"
_RENAME_NOREPLACE = 1


def _rename_noreplace(parent: int, temporary: str, name: str) -> None:
    """Publish one staged object with the reviewed Linux no-replace primitive."""
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError as exc:
        raise OSError("renameat2 is unavailable for journal evidence") from exc
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if (
        renameat2(
            parent,
            temporary.encode("ascii"),
            parent,
            name.encode("ascii"),
            _RENAME_NOREPLACE,
        )
        != 0
    ):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), name)


@dataclass(frozen=True)
class RecoveryEvidenceStoreV2:
    """Bounded immutable evidence custody selected by a qualified host profile.

    Callers retain the anchor, ledger and journal locks while consulting this
    store; this class enforces exact object bytes and file custody, not their
    semantic relationship to the selected chains.

    Attributes
    ----------
    directory : Path
        Existing absolute no-follow evidence directory, owned by the effective UID, mode 0700.
    max_objects : int
        Positive entry-count budget, including inert staging remnants.
    max_total_bytes : int
        Positive aggregate canonical-object byte budget.

    """

    directory: Path
    max_objects: int
    max_total_bytes: int

    @contextmanager
    def _opened(self, *, exclusive: bool) -> Iterator[int]:
        """Pin one no-follow 0700 directory and serialize its budget checks."""
        if not isinstance(self.directory, Path) or not self.directory.is_absolute():
            raise ValueError("recovery evidence needs an absolute directory")
        if (
            type(self.max_objects) is not int
            or self.max_objects < 1
            or type(self.max_total_bytes) is not int
            or self.max_total_bytes < 1
        ):
            raise ValueError("recovery evidence budgets are invalid")
        parent = open_directory_no_follow(self.directory)
        try:
            entry = os.fstat(parent)
            if not _owner_only(entry, directory=True) or stat.S_IMODE(entry.st_mode) != 0o700:
                raise PermissionError("recovery evidence directory is not owner-only")
            fcntl.flock(parent, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            yield parent
            reopened = open_directory_no_follow(self.directory)
            try:
                path_identity = _identity(os.fstat(reopened))
            finally:
                os.close(reopened)
            if (
                _identity(entry) != _identity(os.fstat(parent))
                or _identity(entry) != path_identity
            ):
                raise PermissionError("recovery evidence directory identity changed")
        finally:
            os.close(parent)

    def _read(self, parent: int, name: str) -> bytes:
        """Open, rehash and parse one published object without following links."""
        if _NAME.fullmatch(name) is None:
            raise ValueError("recovery evidence file name differs")
        descriptor = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent
        )
        try:
            before = os.fstat(descriptor)
            path_before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (
                not _owner_only(before, directory=False)
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
                or _identity(before) != _identity(path_before)
                or not 1 <= before.st_size <= self.max_total_bytes
            ):
                raise PermissionError("recovery evidence file custody differs")
            data = _read_exact(descriptor, before.st_size)
            after = os.fstat(descriptor)
            path_after = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (
                _identity(before) != _identity(after)
                or _identity(before) != _identity(path_after)
                or after.st_size != before.st_size
                or sha256(data).hexdigest() + ".json" != name
            ):
                raise PermissionError("recovery evidence content or identity changed")
            validate_recovery_evidence_bytes_v2(data)
            return data
        finally:
            os.close(descriptor)

    def _scan(self, parent: int) -> dict[str, bytes]:
        """Read every published object under finite count and byte budgets."""
        names = self._names(parent)
        objects: dict[str, bytes] = {}
        total = 0
        for name in names:
            if name.startswith(".staging-"):
                continue
            if _NAME.fullmatch(name) is None:
                raise PermissionError("recovery evidence directory has an unknown entry")
            data = self._read(parent, name)
            total += len(data)
            if total > self.max_total_bytes:
                raise PermissionError("recovery evidence byte budget exceeded")
            objects[name[:-5]] = data
        if names != self._names(parent):
            raise PermissionError("recovery evidence directory changed during scan")
        return objects

    def _names(self, parent: int) -> list[str]:
        """Enumerate at most the selected count plus one directory entry."""
        names: list[str] = []
        with os.scandir(parent) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > self.max_objects:
                    raise PermissionError("recovery evidence entry budget exceeded")
        return sorted(names)

    def scan(self) -> dict[str, bytes]:
        """Return exact published objects; staging remnants confer no authority.

        Returns
        -------
        dict[str, bytes]
            All exact published objects indexed by digest; staging entries carry no authority.

        Raises
        ------
        PermissionError
            Selected chain, commitment, pending-intent or file custody checks refuse.
        OSError
            The actual filesystem operation fails; no success is synthesized.

        """
        with self._opened(exclusive=False) as parent:
            return self._scan(parent)

    def read(self, object_digest: str) -> bytes:
        """Resolve one exact digest while refusing any other damaged evidence.

        Parameters
        ----------
        object_digest : str
            Lowercase SHA-256 of the complete canonical object bytes.

        Returns
        -------
        bytes
            Exact verified object bytes after scanning the entire bounded store.

        Raises
        ------
        PermissionError
            Selected chain, commitment, pending-intent or file custody checks refuse.
        OSError
            The actual filesystem operation fails; no success is synthesized.
        FileNotFoundError
            The requested digest is absent from an otherwise valid store.

        """
        name = require_digest(object_digest, "recovery.object_digest") + ".json"
        with self._opened(exclusive=False) as parent:
            objects = self._scan(parent)
            try:
                return objects[object_digest]
            except KeyError as exc:
                raise FileNotFoundError(name) from exc

    def publish(self, data: bytes) -> str:
        """Fsync a canonical object under its digest name without replacement.

        Parameters
        ----------
        data : bytes
            Exact canonical UTF-8 evidence bytes; whitespace and duplicate-key aliases refuse.

        Returns
        -------
        str
            SHA-256 name of the durable object; duplicate exact bytes are idempotent.

        Raises
        ------
        ValueError
            The object is not bytes, exceeds the store's byte budget, or
            violates the canonical recovery-evidence schema.
        PermissionError
            Selected chain, commitment, pending-intent or file custody checks refuse.
        OSError
            The actual filesystem operation fails; no success is synthesized.

        """
        if not isinstance(data, bytes) or len(data) > self.max_total_bytes:
            raise ValueError("recovery evidence object exceeds its byte budget")
        domain = validate_recovery_evidence_bytes_v2(data)
        object_digest = sha256(data).hexdigest()
        name = object_digest + ".json"
        with self._opened(exclusive=True) as parent:
            objects = self._scan(parent)
            if object_digest in objects:
                if objects[object_digest] != data:
                    raise PermissionError("recovery evidence digest collision")
                return object_digest
            if (
                len(self._names(parent)) >= self.max_objects
                or sum(map(len, objects.values())) + len(data) > self.max_total_bytes
            ):
                raise PermissionError("recovery evidence budget would be exceeded")
            staged = domain == _JOURNAL_DOMAIN
            temporary = ".staging-" + secrets.token_hex(16) if staged else name
            descriptor: int | None = None
            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=parent,
                )
                _write_all(descriptor, data)
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = None
                if staged:
                    _rename_noreplace(parent, temporary, name)
                os.fsync(parent)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                if staged:
                    with suppress(FileNotFoundError):
                        os.unlink(temporary, dir_fd=parent)
            if self._read(parent, name) != data:
                raise PermissionError("published recovery evidence changed")
        return object_digest
