# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — protected V2.4 permit-anchor file
"""Verify an owner-only V2.4 anchor against locked ledger and journal files."""

from __future__ import annotations

import fcntl
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from ._permit_ledger_records_v2 import _INITIAL_HEAD
from ._permit_ledger_storage_io_v2 import _identity, _owner_only, _read_exact, _write_all
from .effect_journal_records_v2 import JOURNAL_GENESIS_V2
from .effect_journal_v2 import (
    EffectJournalFileIdentityV2,
    EffectJournalStoreV2,
)
from .git_inventory import open_directory_no_follow
from .permit_anchor_journal_binding_v2 import (
    AnchorJournalBindingV24,
    verify_anchor_journal_binding_v24,
)
from .permit_anchor_prefix_v2 import verify_anchor_prefix_v24
from .permit_anchor_records_v2 import (
    ANCHOR_GENESIS_V24,
    ANCHOR_MAGIC_V24,
    ANCHOR_RECORD_V24,
    AnchorSelectionV24,
)
from .permit_anchor_tail_v2 import scan_anchor_tail_v24
from .permit_consumption_ledger_v2 import ConsumedPermitLedgerV2
from .recovery_evidence_store_v2 import RecoveryEvidenceStoreV2


@dataclass(frozen=True)
class PermitLedgerAnchorV2:
    """Verified selected anchor and journal state from one held file chain.

    Attributes
    ----------
    selection : AnchorSelectionV24
        Verified intrinsic ledger and journal selection.
    binding : AnchorJournalBindingV24
        Verified ledger/journal relationship and honoured closure replay.
    journal_identity : EffectJournalFileIdentityV2
        Verified journal path digest, device and inode.
    """

    selection: AnchorSelectionV24
    binding: AnchorJournalBindingV24
    journal_identity: EffectJournalFileIdentityV2

    @property
    def ledger_record_count(self) -> int:
        """Return the selected complete ledger prefix length.

        Returns
        -------
        int
            Complete selected ledger prefix length.
        """
        return self.selection.ledger_record_count

    @property
    def ledger_head_digest(self) -> str:
        """Return the selected ledger head, inherited across kind-1 recovery.

        Returns
        -------
        str
            Lowercase selected ledger SHA-256 inherited across kind-1 recovery.
        """
        return self.selection.ledger_head.hex()

    @property
    def journal_head_digest(self) -> str:
        """Return the selected journal content head.

        Returns
        -------
        str
            Lowercase selected journal content head.
        """
        return self.selection.journal_head.hex()

    @property
    def anchor_log_head_digest(self) -> str:
        """Return the complete V2.4 anchor chain head.

        Returns
        -------
        str
            Lowercase complete anchor chain head.
        """
        return self.selection.anchor_head.hex()


@dataclass(frozen=True)
class PermitLedgerAnchorStoreV2:
    """Owner-only V2.4 anchor reader and exclusive empty-file initializer.

    A uid-1000 fixture proves file mechanics only. Its journal identity and
    byte budget must come from the qualified host selection before real use.

    Attributes
    ----------
    path : Path
        Absolute selected owner-only anchor path; parent must be mode 0700.
    """

    path: Path

    def _parent(self) -> int:
        """Open an absolute mode-0700 parent without following components."""
        if not isinstance(self.path, Path) or not self.path.is_absolute():
            raise ValueError("permit anchor needs an absolute path")
        parent = open_directory_no_follow(self.path.parent)
        parent_stat = os.fstat(parent)
        if (
            not _owner_only(parent_stat, directory=True)
            or stat.S_IMODE(parent_stat.st_mode) != 0o700
        ):
            os.close(parent)
            raise PermissionError("permit anchor directory is not owner-only")
        return parent

    @contextmanager
    def _locked(self) -> Iterator[tuple[int, int, os.stat_result]]:
        """Hold the exact existing mode-0600 anchor through verification."""
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
                or before.st_size < len(ANCHOR_MAGIC_V24)
            ):
                raise PermissionError("permit anchor file identity or length differs")
            yield parent, descriptor, before
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)

    def _post_check(
        self, parent: int, descriptor: int, before: os.stat_result, expected_size: int
    ) -> None:
        """Recheck the selected parent, exact file custody and captured byte size."""
        reopened = open_directory_no_follow(self.path.parent)
        try:
            parent_stat = os.fstat(parent)
            if (
                not _owner_only(parent_stat, directory=True)
                or stat.S_IMODE(parent_stat.st_mode) != 0o700
                or _identity(parent_stat) != _identity(os.fstat(reopened))
            ):
                raise PermissionError("permit anchor directory identity changed")
        finally:
            os.close(reopened)
        after = os.fstat(descriptor)
        path_after = os.stat(self.path.name, dir_fd=parent, follow_symlinks=False)
        if (
            not _owner_only(after, directory=False)
            or stat.S_IMODE(after.st_mode) != 0o600
            or after.st_nlink != 1
            or _identity(before) != _identity(after)
            or _identity(before) != _identity(path_after)
            or after.st_size != expected_size
        ):
            raise PermissionError("permit anchor changed during locked operation")

    def initialize(
        self,
        *,
        ledger: ConsumedPermitLedgerV2,
        journal: EffectJournalStoreV2,
        max_journal_bytes: int,
    ) -> PermitLedgerAnchorV2:
        """Create the genesis anchor after checking both new empty selected files.

        Parameters
        ----------
        ledger : ConsumedPermitLedgerV2
            Held and fully verified ledger snapshot, or its file store for storage operations.
        journal : EffectJournalStoreV2
            Held verified journal snapshot, or its file store for storage operations.
        max_journal_bytes : int
            Positive finite journal byte budget supplied by the caller.

        Returns
        -------
        PermitLedgerAnchorV2
            Genesis selection after exclusive anchor creation and file/directory fsync.

        Raises
        ------
        PermissionError
            Selected chain, commitment, pending-intent or file custody checks refuse.
        OSError
            The actual filesystem operation fails; no success is synthesized.
        FileExistsError
            The anchor path already exists; its bytes are never replaced.
        """
        with ledger.locked_snapshot(
            selected_count=0, selected_head_digest=_INITIAL_HEAD.hex()
        ) as ledger_snapshot:
            if ledger_snapshot.record_count != 0:
                raise PermissionError("permit anchor initialization needs an empty ledger")
            with journal.locked(
                selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=max_journal_bytes
            ) as journal_lease:
                if journal_lease.snapshot.records:
                    raise PermissionError("permit anchor initialization needs an empty journal")
                identity = ledger_snapshot.identity
                raw = ANCHOR_RECORD_V24.pack(
                    0,
                    0,
                    _INITIAL_HEAD,
                    bytes.fromhex(identity.path_digest),
                    identity.device,
                    identity.inode,
                    0,
                    0,
                    JOURNAL_GENESIS_V2,
                    bytes(32),
                    ANCHOR_GENESIS_V24,
                )
                parent = self._parent()
                descriptor: int | None = None
                try:
                    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
                    descriptor = os.open(self.path.name, flags, 0o600, dir_fd=parent)
                    created = os.fstat(descriptor)
                    _write_all(descriptor, ANCHOR_MAGIC_V24 + raw)
                    os.fsync(descriptor)
                    os.fsync(parent)
                    self._post_check(parent, descriptor, created, len(ANCHOR_MAGIC_V24) + len(raw))
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    if (
                        _read_exact(descriptor, len(ANCHOR_MAGIC_V24) + len(raw))
                        != ANCHOR_MAGIC_V24 + raw
                    ):
                        raise PermissionError("permit anchor initial content changed")
                    self._post_check(parent, descriptor, created, len(ANCHOR_MAGIC_V24) + len(raw))
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
                    os.close(parent)
                binding = verify_anchor_journal_binding_v24(
                    (raw,), journal=journal_lease.snapshot, admissions=()
                )
                return PermitLedgerAnchorV2(
                    binding.selection, binding, journal_lease.snapshot.identity
                )

    def current(
        self,
        *,
        ledger: ConsumedPermitLedgerV2,
        journal: EffectJournalStoreV2,
        evidence: RecoveryEvidenceStoreV2,
        selected_journal_identity: EffectJournalFileIdentityV2,
        max_journal_bytes: int,
    ) -> PermitLedgerAnchorV2:
        """Verify every V2.4 record and its ledger/journal prefix under lock order.

        Parameters
        ----------
        ledger : ConsumedPermitLedgerV2
            Held and fully verified ledger snapshot, or its file store for storage operations.
        journal : EffectJournalStoreV2
            Held verified journal snapshot, or its file store for storage operations.
        evidence : RecoveryEvidenceStoreV2
            Bounded immutable evidence store consulted while the file locks remain held.
        selected_journal_identity : EffectJournalFileIdentityV2
            Expected path digest, device and inode supplied by the caller.
        max_journal_bytes : int
            Positive finite journal byte budget supplied by the caller.

        Returns
        -------
        PermitLedgerAnchorV2
            Verified selected chains; pending intents and damaged tails refuse.

        Raises
        ------
        PermissionError
            Selected chain, commitment, pending-intent or file custody checks refuse.
        OSError
            The actual filesystem operation fails; no success is synthesized.
        """
        with self._locked() as (parent, descriptor, before):
            scan = scan_anchor_tail_v24(descriptor, before.st_size)
            retained = (
                scan_anchor_tail_v24(descriptor, before.st_size - ANCHOR_RECORD_V24.size)
                if scan.tail is None and len(scan.records) > 1
                else scan
            )
            selected = retained.selection
            with ledger.locked_snapshot(
                selected_count=selected.ledger_record_count,
                selected_head_digest=selected.ledger_head.hex(),
            ) as ledger_snapshot:
                if ledger_snapshot.identity != selected.ledger_identity:
                    raise PermissionError("permit anchor ledger identity differs")
                with journal.locked_recovery(
                    selected_head_digest=JOURNAL_GENESIS_V2.hex(),
                    max_bytes=max_journal_bytes,
                ) as journal_lease:
                    journal_snapshot = journal_lease.scan.snapshot
                    if journal_snapshot.identity != selected_journal_identity:
                        raise PermissionError("permit anchor journal identity differs")
                    objects = evidence.scan()
                    verified = verify_anchor_prefix_v24(
                        retained.records,
                        objects=objects,
                        anchor_path=self.path,
                        anchor_stat=before,
                        ledger_path=ledger.path,
                        ledger=ledger_snapshot,
                        journal_path=journal.path,
                        journal=journal_snapshot,
                    )
                    if retained is not scan:
                        try:
                            full = verify_anchor_prefix_v24(
                                scan.records,
                                objects=objects,
                                anchor_path=self.path,
                                anchor_stat=before,
                                ledger_path=ledger.path,
                                ledger=ledger_snapshot,
                                journal_path=journal.path,
                                journal=journal_snapshot,
                            )
                        except (PermissionError, ValueError) as exc:
                            self._post_check(parent, descriptor, before, before.st_size)
                            raise PermissionError(
                                "permit anchor recovery-needed: final tail damage"
                            ) from exc
                        verified = full
                        selected = scan.selection
                    if verified.pending_anchor_intents:
                        raise PermissionError("permit anchor recovery-needed: pending intent")
                    if verified.pending_journal_intents:
                        raise PermissionError("effect journal recovery-needed: pending intent")
                    if journal_lease.scan.tail is not None:
                        raise PermissionError("effect journal recovery-needed: final tail damage")
                    self._post_check(parent, descriptor, before, before.st_size)
                    if scan.tail is not None:
                        raise PermissionError("permit anchor recovery-needed: final tail damage")
                    if ledger_snapshot.record_count != selected.ledger_record_count:
                        raise PermissionError(
                            "permit anchor needs complete ledger suffix adoption"
                        )
                    return PermitLedgerAnchorV2(
                        selected, verified.binding, journal_snapshot.identity
                    )
