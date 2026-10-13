# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — protected v2 effect-journal file
"""Verify and append exact effect-journal frames under one selected file lock."""

from __future__ import annotations

import fcntl
import os
import stat
import struct
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Final

from ._effect_journal_storage_io_v2 import _identity, _owner_only, _read_exact, _write_all
from .effect_intent_token_v2 import (
    EffectIntentBindingV2,
    EffectIntentTokenV2,
    _close_effect_intent_tokens_v2,
    _export_effect_intent_record_v2,
    _issue_effect_intent_token_v2,
    _prepare_effect_failure_v2,
)
from .effect_journal_records_v2 import (
    JOURNAL_GENESIS_V2,
    JOURNAL_MAGIC_V2,
    EffectJournalRecordV2,
    build_effect_journal_frame_v2,
    parse_effect_journal_frame_v2,
)
from .git_inventory import open_directory_no_follow
from .handler_effect_intent_receipt_v1 import HandlerEffectIntentReceiptV1
from .model_primitives import require_digest
from .models import canonical_digest

if TYPE_CHECKING:
    from .effect_journal_tail_v2 import JournalTailScanV21

_LENGTH: Final = struct.Struct(">I")
_MAX_PAYLOAD: Final = 65536
_FRAME_OVERHEAD: Final = 36


@dataclass(frozen=True)
class EffectJournalFileIdentityV2:
    """Selected journal path identity and opened regular-file device/inode.

    Attributes
    ----------
    path_digest : str
        Canonical digest of the selected absolute path string.
    device, inode : int
        Kernel identities sampled from the opened descriptor.

    Notes
    -----
    This data record does not authenticate current path or descriptor custody.
    """

    path_digest: str
    device: int
    inode: int


@dataclass(frozen=True)
class EffectJournalSnapshotV2:
    """Journal chain with proof that the selected head is a prefix.

    Attributes
    ----------
    identity : EffectJournalFileIdentityV2
        Path and kernel identity sampled by the selected store lease.
    records : tuple[EffectJournalRecordV2, ...]
        Complete verified records, including records beyond the selected prefix.
    head_digest, selected_head_digest : str
        Complete current head and independently selected prefix head.
    selected_record_count : int
        Exact number of complete records in the selected prefix; zero at genesis.

    Notes
    -----
    A directly constructed snapshot is not verified custody. Replay rechecks
    every supplied frame, while the actual store lease authenticates file mechanics.
    """

    identity: EffectJournalFileIdentityV2
    records: tuple[EffectJournalRecordV2, ...]
    head_digest: str
    selected_head_digest: str
    selected_record_count: int


def _scan(
    descriptor: int, *, size: int, selected_head: bytes, identity: EffectJournalFileIdentityV2
) -> EffectJournalSnapshotV2:
    """Read the entire bounded file and prove the selected head is in its chain."""
    os.lseek(descriptor, 0, os.SEEK_SET)
    if _read_exact(descriptor, len(JOURNAL_MAGIC_V2)) != JOURNAL_MAGIC_V2:
        raise PermissionError("effect journal header differs")
    offset = len(JOURNAL_MAGIC_V2)
    head = JOURNAL_GENESIS_V2
    selected_positions = [0] if selected_head == head else []
    records: list[EffectJournalRecordV2] = []
    while offset < size:
        remaining = size - offset
        if remaining < _LENGTH.size:
            raise PermissionError("effect journal has an incomplete tail")
        length_bytes = _read_exact(descriptor, _LENGTH.size)
        length = _LENGTH.unpack(length_bytes)[0]
        if not 1 <= length <= _MAX_PAYLOAD:
            raise PermissionError("effect journal frame length differs")
        frame_size = length + _FRAME_OVERHEAD
        if remaining < frame_size:
            raise PermissionError("effect journal has an incomplete tail")
        frame = length_bytes + _read_exact(descriptor, length + 32)
        record = parse_effect_journal_frame_v2(
            frame, previous_head=head, expected_seq=len(records) + 1
        )
        records.append(record)
        head = bytes.fromhex(record.record_head)
        if head == selected_head:
            selected_positions.append(len(records))
        offset += frame_size
    if len(selected_positions) != 1:
        raise PermissionError("effect journal selected head is not a unique verified prefix")
    return EffectJournalSnapshotV2(
        identity=identity,
        records=tuple(records),
        head_digest=head.hex(),
        selected_head_digest=selected_head.hex(),
        selected_record_count=selected_positions[0],
    )


@dataclass
class EffectJournalLeaseV2:
    """Checked journal descriptor retained by one exclusive store context.

    Attributes
    ----------
    descriptor : int
        Live descriptor; the enclosing store context owns its lock and lifetime.
    snapshot : EffectJournalSnapshotV2
        Current complete chain, updated only after a successful append and fsync.
    expected_size, max_bytes : int
        Current checked length and selected maximum byte budget.

    Notes
    -----
    Constructing this class does not acquire a lock or authenticate protected
    custody. Use the actual ``EffectJournalStoreV2.locked`` context.
    """

    descriptor: int
    snapshot: EffectJournalSnapshotV2
    expected_size: int
    max_bytes: int

    def verified_snapshot(self) -> EffectJournalSnapshotV2:
        """Rescan the retained descriptor and compare every current frame.

        Returns
        -------
        EffectJournalSnapshotV2
            Complete current chain, including records beyond the selected prefix.

        Raises
        ------
        PermissionError, OSError
            If descriptor ownership, identity, budget, bytes or retained state differ.

        Notes
        -----
        The installing owner must retain the actual store lease. Constructing a
        lease directly authenticates neither its lock nor protected custody.
        Decoded record-body dictionaries are mutable caches. Comparison retains
        every immutable field and original frame byte; the returned snapshot
        reparses the actual file and does not consume an altered cache body.
        """
        opened = os.fstat(self.descriptor)
        identity = self.snapshot.identity
        if (
            not _owner_only(opened, directory=False)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (identity.device, identity.inode)
            or opened.st_size != self.expected_size
            or not len(JOURNAL_MAGIC_V2) <= opened.st_size <= self.max_bytes
        ):
            raise PermissionError("effect journal retained descriptor differs")
        current = _scan(
            self.descriptor,
            size=opened.st_size,
            selected_head=bytes.fromhex(self.snapshot.selected_head_digest),
            identity=identity,
        )
        observed = replace(
            current, records=tuple(replace(record, body={}) for record in current.records)
        )
        retained = replace(
            self.snapshot,
            records=tuple(replace(record, body={}) for record in self.snapshot.records),
        )
        if observed != retained:
            raise PermissionError("effect journal retained bytes or state differ")
        return current

    def append_from_host(
        self, *, kind: str, body: dict[str, object], host_time: str
    ) -> EffectJournalRecordV2:
        """Fsync one host-derived event without releasing the journal lock.

        Parameters
        ----------
        kind, body
            Event kind and exact host-derived fields accepted by the frame grammar.
        host_time
            Canonical UTC timestamp supplied by the installed transaction owner.

        Returns
        -------
        EffectJournalRecordV2
            Actual appended frame after successful descriptor fsync.

        Raises
        ------
        ValueError
            Event fields or time violate the canonical frame grammar.
        PermissionError, OSError
            Byte budget, current custody, complete retained chain, write or fsync refuses.

        Notes
        -----
        Every append rechecks current owner mode, link count and complete retained
        bytes before invalidating matching local tokens or writing. A failed write
        leaves its real tail for explicit recovery and does not restore a token.
        """
        frame = build_effect_journal_frame_v2(
            kind=kind,
            body=body,
            host_time=host_time,
            previous_head=bytes.fromhex(self.snapshot.head_digest),
            seq=len(self.snapshot.records) + 1,
        )
        if self.expected_size + len(frame.frame) > self.max_bytes:
            raise PermissionError("effect journal exceeds selected byte budget")
        if os.fstat(self.descriptor).st_size != self.expected_size:
            raise PermissionError("effect journal changed before append")
        self.verified_snapshot()
        _close_effect_intent_tokens_v2(
            frame, (self.snapshot.identity.device, self.snapshot.identity.inode)
        )
        os.lseek(self.descriptor, 0, os.SEEK_END)
        _write_all(self.descriptor, frame.frame)
        os.fsync(self.descriptor)
        self.expected_size += len(frame.frame)
        self.snapshot = EffectJournalSnapshotV2(
            identity=self.snapshot.identity,
            records=(*self.snapshot.records, frame),
            head_digest=frame.record_head,
            selected_head_digest=self.snapshot.selected_head_digest,
            selected_record_count=self.snapshot.selected_record_count,
        )
        return frame

    def append_effect_intent_from_host(
        self, *, body: dict[str, object], host_time: str
    ) -> EffectIntentTokenV2:
        """Issue a process-local mutation token after the intent append and fsync.

        Parameters
        ----------
        body, host_time
            Host-derived effect-intent fields and canonical UTC timestamp.

        Returns
        -------
        EffectIntentTokenV2
            Registered identity bound to the actual successfully fsynced record.

        Raises
        ------
        ValueError, PermissionError, OSError
            Intent grammar, budget, retained file, write or fsync refuses.

        Notes
        -----
        Failed write or fsync returns no token. Issuance is process-local and
        authenticates neither protected selection nor a child handler.
        """
        frame = self.append_from_host(kind="effect-intent", body=body, host_time=host_time)
        return _issue_effect_intent_token_v2(
            frame, (self.snapshot.identity.device, self.snapshot.identity.inode)
        )

    def prepare_effect_failure(
        self, token: EffectIntentTokenV2, *, current: EffectIntentBindingV2
    ) -> None:
        """Restrict the same journal's token to unlink before writing its failure.

        Parameters
        ----------
        token, current
            Actual issued identity and the operation owner's exact current part binding.

        Returns
        -------
        None
            Local phase becomes failure-prepared; no journal bytes are written.

        Raises
        ------
        PermissionError
            Issuance, part, journal identity or current token phase differs.
        """
        _prepare_effect_failure_v2(
            token, current, (self.snapshot.identity.device, self.snapshot.identity.inode)
        )

    def export_effect_intent_receipt_for_handler(
        self,
        token: EffectIntentTokenV2,
        *,
        current: EffectIntentBindingV2,
        handler_operation_digest: str,
        effect_context_digest: str,
        ready_nonce: bytes,
    ) -> HandlerEffectIntentReceiptV1:
        """Export this journal's actual registered intent with operation/nonce bindings.

        Parameters
        ----------
        token, current
            Actual registered identity and exact current handler part binding.
        handler_operation_digest, effect_context_digest
            Operation owner's exact header and retained effect context digests.
        ready_nonce
            Original 32-byte nonce bound to the current handler exchange.

        Returns
        -------
        HandlerEffectIntentReceiptV1
            Canonical receipt containing the actual registered post-fsync frame.

        Raises
        ------
        ValueError, PermissionError, OSError
            Binding, journal identity, current descriptor, nonce or frame refuses.

        Notes
        -----
        Export rechecks current owner mode, link count and complete retained bytes.
        Receipt bytes do not issue a token in another process. The protected owner
        separately enforces private endpoint custody and phase order.
        """
        identity = (self.snapshot.identity.device, self.snapshot.identity.inode)
        record = _export_effect_intent_record_v2(token, current, identity)
        opened = os.fstat(self.descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (*identity, self.expected_size):
            raise PermissionError("effect intent receipt journal descriptor changed")
        self.verified_snapshot()
        return HandlerEffectIntentReceiptV1.from_record(
            record,
            journal_identity=identity,
            handler_operation_digest=handler_operation_digest,
            effect_context_digest=effect_context_digest,
            ready_nonce=ready_nonce,
        )


@dataclass
class EffectJournalRecoveryLeaseV2:
    """Held file descriptor and classified terminal damage for operator recovery.

    Attributes
    ----------
    descriptor : int
        Live descriptor owned by the actual store recovery context.
    scan : JournalTailScanV21
        Verified prefix and exact optional damaged final fragment.
    expected_size, max_bytes : int
        Sampled file length and selected byte budget.

    Notes
    -----
    Classification grants neither permission to truncate nor operator authority.
    """

    descriptor: int
    scan: JournalTailScanV21
    expected_size: int
    max_bytes: int

    def check(self, path: Path) -> None:
        """Refuse an unlocked path swap or size change before any mutation.

        Parameters
        ----------
        path
            Actual selected journal path checked without following a symlink.

        Returns
        -------
        None
            Opened descriptor and path still match the selected file identity and size.

        Raises
        ------
        PermissionError, OSError
            Identity, mode, link count, size or actual descriptor/path lookup differs.
        """
        opened = os.fstat(self.descriptor)
        current = os.stat(path, follow_symlinks=False)
        selected = self.scan.snapshot.identity
        if (
            not _owner_only(opened, directory=False)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or opened.st_dev != selected.device
            or opened.st_ino != selected.inode
            or _identity(opened) != _identity(current)
            or opened.st_size != self.expected_size
        ):
            raise PermissionError("effect journal changed during locked recovery")


@dataclass(frozen=True)
class EffectJournalStoreV2:
    """Owner-only journal file for the future protected `tier0-signer` host.

    Attributes
    ----------
    path : Path
        Absolute journal path below an owner-only no-follow parent directory.

    Notes
    -----
    Ordinary owner fixtures prove file mechanics only. Protected admission also
    needs installed source custody, retained anchor/accounting locks, sealed
    adapter comparison and authenticated ingress. Construction acquires no lock.
    """

    path: Path

    def _parent(self) -> int:
        """Open an absolute owner-only parent without following components."""
        if not isinstance(self.path, Path) or not self.path.is_absolute():
            raise ValueError("effect journal needs an absolute path")
        parent = open_directory_no_follow(self.path.parent)
        parent_stat = os.fstat(parent)
        if (
            not _owner_only(parent_stat, directory=True)
            or stat.S_IMODE(parent_stat.st_mode) != 0o700
        ):
            os.close(parent)
            raise PermissionError("effect journal directory is not owner-only")
        return parent

    def initialize(self) -> str:
        """Create a new empty journal exclusively and fsync its directory.

        Returns
        -------
        str
            Exact genesis head digest after file and directory fsync succeed.

        Raises
        ------
        ValueError, PermissionError, OSError
            Path, parent custody, exclusive creation, write or fsync refuses.

        Notes
        -----
        Existing bytes are never replaced or repaired by initialization.
        """
        parent = self._parent()
        descriptor: int | None = None
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
            descriptor = os.open(self.path.name, flags, 0o600, dir_fd=parent)
            _write_all(descriptor, JOURNAL_MAGIC_V2)
            os.fsync(descriptor)
            os.fsync(parent)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)
        return JOURNAL_GENESIS_V2.hex()

    @contextmanager
    def locked(
        self, *, selected_head_digest: str, max_bytes: int
    ) -> Iterator[EffectJournalLeaseV2]:
        """Hold the selected file from full verification through the consumer.

        Parameters
        ----------
        selected_head_digest
            Independently selected head that must occur exactly once in the complete chain.
        max_bytes
            Selected positive file budget, at least the header length.

        Yields
        ------
        EffectJournalLeaseV2
            Actual descriptor and exclusive lock retained through closing identity checks.

        Raises
        ------
        ValueError, PermissionError, OSError
            Budget, parent/file custody, complete frame chain or closing identity refuses.

        Notes
        -----
        The installing owner authenticates selection and protects parent namespace
        custody. Cooperative locking alone is not a protected transaction.
        """
        selected_head = bytes.fromhex(
            require_digest(selected_head_digest, "effect_journal.selected_head")
        )
        if type(max_bytes) is not int or max_bytes < len(JOURNAL_MAGIC_V2):
            raise ValueError("effect journal byte budget is invalid")
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
                or not len(JOURNAL_MAGIC_V2) <= before.st_size <= max_bytes
            ):
                raise PermissionError("effect journal file identity or length differs")
            identity = EffectJournalFileIdentityV2(
                path_digest=canonical_digest(str(self.path)),
                device=before.st_dev,
                inode=before.st_ino,
            )
            snapshot = _scan(
                descriptor, size=before.st_size, selected_head=selected_head, identity=identity
            )
            lease = EffectJournalLeaseV2(
                descriptor=descriptor,
                snapshot=snapshot,
                expected_size=before.st_size,
                max_bytes=max_bytes,
            )
            yield lease
            after = os.fstat(descriptor)
            path_after = os.stat(self.path.name, dir_fd=parent, follow_symlinks=False)
            if (
                _identity(before) != _identity(after)
                or _identity(before) != _identity(path_after)
                or after.st_size != lease.expected_size
            ):
                raise PermissionError("effect journal changed during locked operation")
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)

    @contextmanager
    def locked_recovery(
        self, *, selected_head_digest: str, max_bytes: int
    ) -> Iterator[EffectJournalRecoveryLeaseV2]:
        """Keep an exact damaged file locked while an operator proves its tail.

        Parameters
        ----------
        selected_head_digest, max_bytes
            Independently selected complete-prefix head and bounded actual file budget.

        Yields
        ------
        EffectJournalRecoveryLeaseV2
            Actual retained descriptor, verified prefix and classified final damage.

        Raises
        ------
        ValueError, PermissionError, OSError
            Budget, custody, selected prefix, ambiguous damage or closing checks refuse.

        Notes
        -----
        This context repairs no bytes and grants no operator action. Explicit
        authorized recovery must preserve the retained identity and size contract.
        """
        from .effect_journal_tail_v2 import scan_journal_tail_v21

        selected_head = bytes.fromhex(
            require_digest(selected_head_digest, "effect_journal.selected_head")
        )
        if type(max_bytes) is not int or max_bytes < len(JOURNAL_MAGIC_V2):
            raise ValueError("effect journal byte budget is invalid")
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
                or not len(JOURNAL_MAGIC_V2) <= before.st_size <= max_bytes
            ):
                raise PermissionError("effect journal file identity or length differs")
            identity = EffectJournalFileIdentityV2(
                path_digest=canonical_digest(str(self.path)),
                device=before.st_dev,
                inode=before.st_ino,
            )
            scan = scan_journal_tail_v21(
                descriptor, size=before.st_size, selected_head=selected_head, identity=identity
            )
            lease = EffectJournalRecoveryLeaseV2(
                descriptor=descriptor,
                scan=scan,
                expected_size=before.st_size,
                max_bytes=max_bytes,
            )
            yield lease
            after = os.fstat(descriptor)
            path_after = os.stat(self.path.name, dir_fd=parent, follow_symlinks=False)
            if (
                _identity(before) != _identity(after)
                or _identity(before) != _identity(path_after)
                or after.st_size != lease.expected_size
            ):
                raise PermissionError("effect journal changed during locked recovery")
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)

    def snapshot(self, *, selected_head_digest: str, max_bytes: int) -> EffectJournalSnapshotV2:
        """Return a complete verified chain and selected-prefix proof.

        Parameters
        ----------
        selected_head_digest, max_bytes
            Independently selected prefix head and bounded actual file budget.

        Returns
        -------
        EffectJournalSnapshotV2
            Actual verified snapshot after closing store checks and descriptor release.

        Raises
        ------
        ValueError, PermissionError, OSError
            Selected head, budget, custody, frames or closing checks refuse.

        Notes
        -----
        Retain a real lease instead when a consumer needs current descriptor custody.
        """
        with self.locked(selected_head_digest=selected_head_digest, max_bytes=max_bytes) as lease:
            return lease.snapshot
