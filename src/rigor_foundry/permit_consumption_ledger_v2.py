# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — v2 single-use permit ledger
"""Durably consume exact permit IDs in a protected, hash-chained local log."""

from __future__ import annotations

import fcntl
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import NoReturn, SupportsIndex

from ._permit_ledger_records_v2 import (
    _CONSUMED,
    _EMPTY_DIGEST,
    _EMPTY_ID,
    _INITIAL_HEAD,
    _MAGIC,
    _RECORD,
    _RECORD_BYTES,
    _RECOVERY,
    _append,
    _micros,
    _nonce,
    _scan,
)
from ._permit_ledger_records_v2 import LedgerFileIdentityV2 as LedgerFileIdentityV2
from ._permit_ledger_records_v2 import LedgerRecordV2 as LedgerRecordV2
from ._permit_ledger_records_v2 import LedgerSnapshotV2 as LedgerSnapshotV2
from ._permit_ledger_storage_io_v2 import _identity, _owner_only, _read_exact, _write_all
from .git_inventory import open_directory_no_follow
from .model_primitives import require_digest
from .models import canonical_digest


@dataclass
class LedgerAdmissionLeaseV2:
    """One issued ledger lease retained through exactly one append attempt.

    Attributes
    ----------
    descriptor : int
        Actual locked descriptor, usable only during its original issuing context.
    snapshot : LedgerSnapshotV2
        Full verified history, rechecked against current bytes before consumption.
    expected_size : int
        Exact expected file length, advanced only after the fsynced append.
    used : bool
        Whether an append attempt has already begun.

    Notes
    -----
    Direct construction does not issue a live lease. Context closure and a fork
    refuse later use, including ordinary reuse of the closed descriptor number.
    This storage lease authenticates neither permit signatures nor effect authority.
    """

    descriptor: int
    snapshot: LedgerSnapshotV2
    expected_size: int
    used: bool = False
    _active: bool = field(default=False, init=False, repr=False)
    _creator_pid: int = field(default_factory=os.getpid, init=False, repr=False)
    _parent_descriptor: int = field(default=-1, init=False, repr=False)
    _path_name: str = field(default="", init=False, repr=False)
    _file_identity: tuple[int, int, int, int, int] | None = field(
        default=None, init=False, repr=False
    )

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        """Refuse copying or serialising a lease outside its issuing context.

        Parameters
        ----------
        protocol : SupportsIndex
            Requested Python reduction protocol; every version refuses.

        Raises
        ------
        PermissionError
            A live descriptor lease cannot be duplicated or serialised.
        """
        raise PermissionError("permit ledger admission lease cannot be copied or serialised")

    def _require_current(self) -> None:
        """Recheck the issued live lease, current custody and every retained record."""
        if not self._active or self._creator_pid != os.getpid():
            raise PermissionError("permit ledger admission lease is closed or inherited")
        before = os.fstat(self.descriptor)
        parent = os.fstat(self._parent_descriptor)
        current = os.stat(self._path_name, dir_fd=self._parent_descriptor, follow_symlinks=False)
        if (
            not _owner_only(parent, directory=True)
            or stat.S_IMODE(parent.st_mode) != 0o700
            or _identity(before) != self._file_identity
            or _identity(current) != self._file_identity
            or before.st_size != self.expected_size
        ):
            raise PermissionError("permit ledger custody or identity changed before admission")
        remaining = self.expected_size - len(_MAGIC)
        count, tail = divmod(remaining, _RECORD_BYTES)
        if tail or count != self.snapshot.record_count:
            raise PermissionError("permit ledger admission snapshot count differs")
        head, _, _, records = _scan(self.descriptor, count, nonce=None)
        identity = LedgerFileIdentityV2(
            path_digest=self.snapshot.identity.path_digest,
            device=before.st_dev,
            inode=before.st_ino,
        )
        if LedgerSnapshotV2(count, head.hex(), identity, records) != self.snapshot:
            raise PermissionError("permit ledger admission history differs")

    def consume(
        self,
        *,
        permit_id: str,
        permit_digest: str,
        expires_at: str,
        single_use_id: str | None = None,
    ) -> LedgerRecordV2:
        """Revalidate and fsync one dual-ID consumption within this issued lease.

        Parameters
        ----------
        permit_id, single_use_id : str or None
            Nonreserved canonical UUIDs, distinct from each other and every prior ID.
            The permit ID is required; the additional single-use ID is optional.
        permit_digest : str
            Nonzero SHA-256 digest supplied by the independently verifying caller.
        expires_at : str
            Explicit UTC metadata representable as positive epoch microseconds.

        Returns
        -------
        LedgerRecordV2
            Complete fsynced record and resulting head.

        Raises
        ------
        ValueError
            If either ID, digest or timestamp violates the fixed wire contract.
        PermissionError, OSError
            If the lease is closed, inherited, spent, stale or its actual custody,
            contents or write fails. No permission or signature is inferred.
        """
        self._require_current()
        if self.used:
            raise PermissionError("ledger admission lease was already consumed")
        nonce = _nonce(permit_id)
        single = _nonce(single_use_id) if single_use_id is not None else _EMPTY_ID
        if nonce == single:
            raise ValueError("permit and single-use UUID must differ")
        digest = bytes.fromhex(require_digest(permit_digest, "permit_ledger.permit_digest"))
        if digest == _EMPTY_DIGEST:
            raise ValueError("permit ledger digest cannot be the reserved zero sentinel")
        expires = _micros(expires_at, "permit_ledger.expires_at")
        used_ids = {
            used_id
            for record in self.snapshot.records
            for used_id in (record.permit_id, record.single_use_id)
            if used_id is not None
        }
        if permit_id in used_ids or (single_use_id is not None and single_use_id in used_ids):
            raise PermissionError("v2 permit or single-use ID was already consumed")
        if os.fstat(self.descriptor).st_size != self.expected_size:
            raise PermissionError("permit ledger changed before admission append")
        self._require_current()
        previous = bytes.fromhex(self.snapshot.head_digest)
        raw = _RECORD.pack(_CONSUMED, nonce, single, digest, expires, 0, previous)
        self.used = True
        new_head = _append(
            self.descriptor,
            head=previous,
            kind=_CONSUMED,
            nonce=nonce,
            single_use_nonce=single,
            digest=digest,
            stamp=expires,
            metadata=0,
        )
        record = LedgerRecordV2(
            kind=_CONSUMED,
            permit_id=permit_id,
            single_use_id=single_use_id,
            permit_digest=permit_digest,
            head_digest=new_head.hex(),
            record_digest=sha256(raw).hexdigest(),
        )
        self.expected_size += _RECORD_BYTES
        self.snapshot = LedgerSnapshotV2(
            record_count=self.snapshot.record_count + 1,
            head_digest=new_head.hex(),
            identity=self.snapshot.identity,
            records=(*self.snapshot.records, record),
        )
        return record


@dataclass(frozen=True)
class ConsumedPermitLedgerV2:
    """Durable owner-only consumption log for an independently selected service.

    Parameters
    ----------
    path : Path
        Absolute preselected log path below a service-owned mode-0700 parent.
        Existing files must be service-owned mode-0600 regular single-link files.

    Notes
    -----
    Current-UID fixtures prove storage mechanics only. The actual host separately
    authenticates permit signatures, expiry, authority, selection and anchoring.
    This API never invokes an effect, enrols a signer or selects a protected anchor.
    """

    path: Path

    def _parent(self) -> int:
        """Open the parent without following any path component."""
        if not isinstance(self.path, Path) or not self.path.is_absolute():
            raise ValueError("permit ledger needs an absolute path")
        parent = open_directory_no_follow(self.path.parent)
        parent_stat = os.fstat(parent)
        if (
            not _owner_only(parent_stat, directory=True)
            or stat.S_IMODE(parent_stat.st_mode) != 0o700
        ):
            os.close(parent)
            raise PermissionError("permit ledger directory is not owner-only")
        return parent

    @contextmanager
    def _locked(self) -> Iterator[tuple[int, int, os.stat_result]]:
        """Hold the selected owner-only regular file under an exclusive lock."""
        parent = self._parent()
        descriptor: int | None = None
        try:
            flags = os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            descriptor = os.open(self.path.name, flags, dir_fd=parent)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            before = os.fstat(descriptor)
            path_before = os.stat(self.path.name, dir_fd=parent, follow_symlinks=False)
            if (
                not _owner_only(before, directory=False)
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
                or _identity(before) != _identity(path_before)
                or before.st_size < len(_MAGIC)
            ):
                raise PermissionError("permit ledger file identity or length differs")
            yield parent, descriptor, before
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)

    def _post_check(self, parent: int, descriptor: int, before: os.stat_result, size: int) -> None:
        """Refuse a swapped path or unexpected size after a locked operation."""
        parent_after = os.fstat(parent)
        if (
            not _owner_only(parent_after, directory=True)
            or stat.S_IMODE(parent_after.st_mode) != 0o700
        ):
            raise PermissionError("permit ledger directory changed during locked operation")
        after = os.fstat(descriptor)
        path_after = os.stat(self.path.name, dir_fd=parent, follow_symlinks=False)
        if (
            _identity(before) != _identity(after)
            or _identity(before) != _identity(path_after)
            or after.st_size != size
        ):
            raise PermissionError("permit ledger changed during locked operation")

    def initialize(self) -> str:
        """Create and fsync a new log without replacing an existing file.

        Returns
        -------
        str
            Initial SHA-256 chain head for the fixed versioned header.

        Raises
        ------
        ValueError, PermissionError, OSError
            If the path or parent custody refuses, a file already exists or I/O fails.
        """
        parent = self._parent()
        descriptor: int | None = None
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
            descriptor = os.open(self.path.name, flags, 0o600, dir_fd=parent)
            _write_all(descriptor, _MAGIC)
            os.fsync(descriptor)
            os.fsync(parent)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)
        return _INITIAL_HEAD.hex()

    def verify_anchor(self, *, record_count: int, head_digest: str) -> tuple[int, str]:
        """Verify a supplied prefix against every complete current record.

        Parameters
        ----------
        record_count : int
            Nonnegative selected prefix length, obtained from the independent host.
        head_digest : str
            SHA-256 expected at that exact prefix.

        Returns
        -------
        tuple[int, str]
            Complete current count and head, possibly extending the selected prefix.

        Raises
        ------
        ValueError, PermissionError, OSError
            If selection, complete wire, prefix, custody or I/O refuses.

        Notes
        -----
        Verification chooses no protected anchor and grants no effect authority.
        """
        count, head, _ = self.verify_anchor_with_identity(
            record_count=record_count, head_digest=head_digest
        )
        return count, head

    def verify_anchor_with_identity(
        self, *, record_count: int, head_digest: str
    ) -> tuple[int, str, LedgerFileIdentityV2]:
        """Verify a selected prefix and observe its file identity in the same lock.

        Parameters
        ----------
        record_count : int
            Nonnegative independently selected prefix length.
        head_digest : str
            Exact expected SHA-256 chain head at that prefix.

        Returns
        -------
        tuple[int, str, LedgerFileIdentityV2]
            Current complete count, head and actual retained descriptor identity.

        Raises
        ------
        ValueError, PermissionError, OSError
            If the supplied prefix, actual file or complete history refuses.
        """
        if type(record_count) is not int or record_count < 0:
            raise ValueError("permit ledger anchor record count must be non-negative")
        expected = bytes.fromhex(require_digest(head_digest, "permit_ledger.anchor_head"))
        with self._locked() as (parent, descriptor, before):
            remaining = before.st_size - len(_MAGIC)
            if remaining % _RECORD_BYTES:
                raise PermissionError("permit ledger has an incomplete tail")
            count = remaining // _RECORD_BYTES
            if record_count > count:
                raise PermissionError("permit ledger is shorter than its protected anchor")
            head, _, anchor, _ = _scan(descriptor, count, nonce=None, anchor_count=record_count)
            if anchor != expected or os.fstat(descriptor).st_size != before.st_size:
                raise PermissionError("permit ledger differs from its protected anchor")
            self._post_check(parent, descriptor, before, before.st_size)
            identity = LedgerFileIdentityV2(
                path_digest=canonical_digest(str(self.path)),
                device=before.st_dev,
                inode=before.st_ino,
            )
            return count, head.hex(), identity

    @contextmanager
    def locked_snapshot(
        self, *, selected_count: int, selected_head_digest: str
    ) -> Iterator[LedgerSnapshotV2]:
        """Retain a verified complete snapshot and recheck file custody on exit.

        Parameters
        ----------
        selected_count : int
            Nonnegative independently selected prefix length.
        selected_head_digest : str
            Exact SHA-256 head expected at that selected prefix.

        Yields
        ------
        LedgerSnapshotV2
            Full current history under the same locked descriptor.

        Raises
        ------
        ValueError, PermissionError, OSError
            If the prefix, actual custody, full history or closing check refuses.

        Notes
        -----
        A returned snapshot retained after closure is data, not an admission lease.
        """
        if type(selected_count) is not int or selected_count < 0:
            raise ValueError("permit ledger selected count is invalid")
        selected_head = bytes.fromhex(
            require_digest(selected_head_digest, "permit_ledger.selected_head")
        )
        with self._locked() as (parent, descriptor, before):
            remaining = before.st_size - len(_MAGIC)
            if remaining % _RECORD_BYTES:
                raise PermissionError("permit ledger has an incomplete tail")
            count = remaining // _RECORD_BYTES
            if selected_count > count:
                raise PermissionError("permit ledger is shorter than its protected anchor")
            head, _, anchor, records = _scan(
                descriptor, count, nonce=None, anchor_count=selected_count
            )
            if anchor != selected_head or os.fstat(descriptor).st_size != before.st_size:
                raise PermissionError("permit ledger differs from its protected anchor")
            identity = LedgerFileIdentityV2(
                path_digest=canonical_digest(str(self.path)),
                device=before.st_dev,
                inode=before.st_ino,
            )
            try:
                yield LedgerSnapshotV2(count, head.hex(), identity, records)
            finally:
                self._post_check(parent, descriptor, before, before.st_size)

    @contextmanager
    def locked_admission(
        self, *, selected_count: int, selected_head_digest: str
    ) -> Iterator[LedgerAdmissionLeaseV2]:
        """Issue one live append lease only at the exact selected current tail.

        Parameters
        ----------
        selected_count : int
            Complete selected current count; an unanchored suffix refuses.
        selected_head_digest : str
            Exact independently selected SHA-256 head at that complete tail.

        Yields
        ------
        LedgerAdmissionLeaseV2
            Original-process lease, closed before the context's final custody check.

        Raises
        ------
        ValueError, PermissionError, OSError
            If selection, custody, history or the closing check refuses.

        Notes
        -----
        The protected caller must separately retain its selection and anchor locks
        through journal and anchor fsync. This method issues no effect permit.
        """
        if type(selected_count) is not int or selected_count < 0:
            raise ValueError("permit ledger selected count is invalid")
        selected_head = bytes.fromhex(
            require_digest(selected_head_digest, "permit_ledger.selected_head")
        )
        with self._locked() as (parent, descriptor, before):
            remaining = before.st_size - len(_MAGIC)
            if remaining % _RECORD_BYTES:
                raise PermissionError("permit ledger has an incomplete tail")
            count = remaining // _RECORD_BYTES
            if count != selected_count:
                raise PermissionError("permit ledger has an unanchored suffix")
            head, _, anchor, records = _scan(
                descriptor, count, nonce=None, anchor_count=selected_count
            )
            if anchor != selected_head or os.fstat(descriptor).st_size != before.st_size:
                raise PermissionError("permit ledger differs from its protected anchor")
            identity = LedgerFileIdentityV2(
                path_digest=canonical_digest(str(self.path)),
                device=before.st_dev,
                inode=before.st_ino,
            )
            lease = LedgerAdmissionLeaseV2(
                descriptor,
                LedgerSnapshotV2(count, head.hex(), identity, records),
                before.st_size,
            )
            lease._parent_descriptor = parent
            lease._path_name = self.path.name
            lease._file_identity = _identity(before)
            lease._active = True
            try:
                yield lease
            finally:
                lease._active = False
                self._post_check(parent, descriptor, before, lease.expected_size)

    def consume(
        self,
        *,
        permit_id: str,
        permit_digest: str,
        expires_at: str,
        single_use_id: str | None = None,
    ) -> str:
        """Fsync both supplied IDs and refuse their later replay in either field.

        Parameters
        ----------
        permit_id, single_use_id : str or None
            Nonreserved canonical UUIDs; the optional additional ID must be distinct.
        permit_digest : str
            Nonzero SHA-256 digest supplied by the independently verifying caller.
        expires_at : str
            Explicit UTC metadata encoded as positive epoch microseconds.

        Returns
        -------
        str
            New chain head after the actual complete append and fsync.

        Raises
        ------
        ValueError, PermissionError, OSError
            If input, prior consumption, full history, custody or I/O refuses.

        Notes
        -----
        A later handler failure does not undo consumption. Signature and actual expiry
        verification belong to the caller; this method dispatches no handler.
        """
        nonce = _nonce(permit_id)
        single_use_nonce = _nonce(single_use_id) if single_use_id is not None else _EMPTY_ID
        if single_use_nonce == nonce:
            raise ValueError("permit and single-use UUID must differ")
        digest = bytes.fromhex(require_digest(permit_digest, "permit_ledger.permit_digest"))
        if digest == _EMPTY_DIGEST:
            raise ValueError("permit ledger digest cannot be the reserved zero sentinel")
        expires = _micros(expires_at, "permit_ledger.expires_at")
        with self._locked() as (parent, descriptor, before):
            remaining = before.st_size - len(_MAGIC)
            if remaining % _RECORD_BYTES:
                raise PermissionError("permit ledger has an incomplete tail")
            head, found, _, _ = _scan(
                descriptor,
                remaining // _RECORD_BYTES,
                nonce=nonce,
                single_use_nonce=single_use_nonce if single_use_id is not None else None,
            )
            if found:
                raise PermissionError("v2 permit or single-use ID was already consumed")
            if os.fstat(descriptor).st_size != before.st_size:
                raise PermissionError("permit ledger changed outside its lock")
            self._post_check(parent, descriptor, before, before.st_size)
            new_head = _append(
                descriptor,
                head=head,
                kind=_CONSUMED,
                nonce=nonce,
                single_use_nonce=single_use_nonce,
                digest=digest,
                stamp=expires,
                metadata=0,
            )
            self._post_check(parent, descriptor, before, before.st_size + _RECORD_BYTES)
            return new_head.hex()

    def recover_torn_tail(self, *, recovered_at: str) -> str:
        """Remove only an incomplete tail and fsync a record of its exact removed bytes.

        Parameters
        ----------
        recovered_at : str
            Explicit owner-authorised UTC recovery time in the ledger's wire range.

        Returns
        -------
        str
            Chain head after complete prior history and the audited recovery record.

        Raises
        ------
        ValueError, PermissionError, OSError
            If no incomplete tail exists, prior complete history or custody refuses,
            or truncation/fsync fails.

        Notes
        -----
        The owner or protected host must authorise recovery independently. It never
        runs automatically from consumption and cannot repair corrupted complete rows.
        """
        recovered = _micros(recovered_at, "permit_ledger.recovered_at")
        with self._locked() as (parent, descriptor, before):
            remaining = before.st_size - len(_MAGIC)
            count, tail_size = divmod(remaining, _RECORD_BYTES)
            if not tail_size:
                raise ValueError("permit ledger has no incomplete tail")
            head, _, _, _ = _scan(descriptor, count, nonce=None)
            tail = _read_exact(descriptor, tail_size)
            if os.fstat(descriptor).st_size != before.st_size:
                raise PermissionError("permit ledger changed outside its lock")
            self._post_check(parent, descriptor, before, before.st_size)
            os.ftruncate(descriptor, before.st_size - tail_size)
            os.fsync(descriptor)
            new_head = _append(
                descriptor,
                head=head,
                kind=_RECOVERY,
                nonce=_EMPTY_ID,
                single_use_nonce=_EMPTY_ID,
                digest=sha256(tail).digest(),
                stamp=recovered,
                metadata=tail_size,
            )
            self._post_check(
                parent, descriptor, before, before.st_size - tail_size + _RECORD_BYTES
            )
            return new_head.hex()
