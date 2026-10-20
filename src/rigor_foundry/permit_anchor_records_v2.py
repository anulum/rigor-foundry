# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — protected permit-anchor V2.4 record wire
"""Decode the exact V2.4 anchor bytes and their intrinsic state transitions."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from hashlib import sha256
from typing import Final

from ._permit_ledger_records_v2 import _INITIAL_HEAD
from .effect_journal_records_v2 import JOURNAL_GENESIS_V2
from .permit_consumption_ledger_v2 import LedgerFileIdentityV2

ANCHOR_SCHEMA_VERSION: Final = "2.4"

ANCHOR_MAGIC_V24: Final = b"RIGOR-PERMIT-ANCHOR-V2.4\n"
ANCHOR_GENESIS_V24: Final = sha256(ANCHOR_MAGIC_V24).digest()
ANCHOR_RECORD_V24: Final = struct.Struct(">B3xQ32s32sQQQI32s32s32s")
_ZERO: Final = bytes(32)
_INITIAL: Final = 0
_RECOVERY: Final = 1
_ADOPTION: Final = 2
_CLOSURE: Final = 3


@dataclass(frozen=True)
class AnchorRecordV24:
    """One exact parsed record and its cryptographic anchor-chain head.

    Attributes
    ----------
    kind : int
        Wire discriminator: initial/admission 0, final-tail recovery 1, adoption 2, closure 3.
    ledger_record_count : int
        Complete selected ledger prefix length.
    digest : bytes
        Ledger head for ordinary/adoption/closure records; removed-byte digest for recovery.
    ledger_identity : LedgerFileIdentityV2
        Selected ledger path digest, device and inode.
    stamp_us : int
        Recovery/adoption host timestamp in microseconds; zero for ordinary records.
    metadata : int
        Recovery byte count or adopted record count; zero for ordinary records.
    journal_head : bytes
        Selected journal prefix head as exactly 32 bytes.
    event_digest : bytes
        Committed evidence or closure digest; zero for an ordinary record.
    previous_head : bytes
        Preceding anchor chain head.
    head : bytes
        Resulting anchor chain head.
    raw : bytes
        Exact captured record or final-tail bytes.

    """

    kind: int
    ledger_record_count: int
    digest: bytes
    ledger_identity: LedgerFileIdentityV2
    stamp_us: int
    metadata: int
    journal_head: bytes
    event_digest: bytes
    previous_head: bytes
    head: bytes
    raw: bytes


@dataclass(frozen=True)
class AnchorSelectionV24:
    """The ledger and journal selection inherited through audited recovery.

    Attributes
    ----------
    ledger_record_count : int
        Complete selected ledger prefix length.
    ledger_head : bytes
        Selected ledger prefix head, inherited across recovery.
    ledger_identity : LedgerFileIdentityV2
        Selected ledger path digest, device and inode.
    journal_head : bytes
        Selected journal prefix head as exactly 32 bytes.
    anchor_head : bytes
        Selected anchor chain head.

    """

    ledger_record_count: int
    ledger_head: bytes
    ledger_identity: LedgerFileIdentityV2
    journal_head: bytes
    anchor_head: bytes


def parse_anchor_record_v24(raw: bytes, *, previous_head: bytes) -> AnchorRecordV24:
    """Reject malformed reserved, identity, chain and intrinsic field bytes.

    Parameters
    ----------
    raw : bytes
        Exact 200-byte binary anchor record, including its previous-head field.
    previous_head : bytes
        Verified 32-byte preceding chain head; genesis for the first record.

    Returns
    -------
    AnchorRecordV24
        Parsed fields, exact original bytes and the resulting chain head.

    Raises
    ------
    PermissionError
        Selected chain, commitment, pending-intent or file custody checks refuse.

    """
    if len(raw) != ANCHOR_RECORD_V24.size or len(previous_head) != 32:
        raise PermissionError("permit anchor record length differs")
    if raw[1:4] != b"\x00\x00\x00":
        raise PermissionError("permit anchor reserved bytes differ")
    (
        kind,
        count,
        digest,
        path_digest,
        device,
        inode,
        stamp,
        metadata,
        journal_head,
        event_digest,
        linked_head,
    ) = ANCHOR_RECORD_V24.unpack(raw)
    if linked_head != previous_head:
        raise PermissionError("permit anchor chain differs")
    if kind not in (_INITIAL, _RECOVERY, _ADOPTION, _CLOSURE):
        raise PermissionError("permit anchor kind differs")
    if path_digest == _ZERO or inode == 0 or journal_head == _ZERO:
        raise PermissionError("permit anchor identity or journal head differs")
    if kind in (_INITIAL, _CLOSURE):
        if stamp != 0 or metadata != 0 or digest == _ZERO:
            raise PermissionError("permit anchor ordinary fields differ")
        if kind == _INITIAL and event_digest != _ZERO:
            raise PermissionError("permit anchor ordinary event digest differs")
        if kind == _CLOSURE and event_digest == _ZERO:
            raise PermissionError("permit anchor closure digest is absent")
    elif kind == _RECOVERY:
        if not (stamp > 0 and 1 <= metadata <= 200 and digest != _ZERO and event_digest != _ZERO):
            raise PermissionError("permit anchor recovery fields differ")
    elif not (stamp > 0 and metadata > 0 and digest != _ZERO and event_digest != _ZERO):
        raise PermissionError("permit anchor adoption fields differ")
    identity = LedgerFileIdentityV2(path_digest.hex(), device, inode)
    return AnchorRecordV24(
        kind=kind,
        ledger_record_count=count,
        digest=digest,
        ledger_identity=identity,
        stamp_us=stamp,
        metadata=metadata,
        journal_head=journal_head,
        event_digest=event_digest,
        previous_head=linked_head,
        head=sha256(previous_head + raw[:168]).digest(),
        raw=raw,
    )


def advance_anchor_selection_v24(
    previous: AnchorSelectionV24 | None, record: AnchorRecordV24
) -> AnchorSelectionV24:
    """Check count, ledger-head and journal-head transitions without trusting recovery digest.

    Parameters
    ----------
    previous : AnchorSelectionV24 | None
        Verified selection preceding this record; None only at genesis.
    record : AnchorRecordV24
        Parsed successor record whose selected boundaries must match the held files.

    Returns
    -------
    AnchorSelectionV24
        Successor selection; kind-1 recovery preserves the preceding ledger head.

    Raises
    ------
    PermissionError
        Selected chain, commitment, pending-intent or file custody checks refuse.

    """
    if previous is None:
        if (
            record.kind != _INITIAL
            or record.previous_head != ANCHOR_GENESIS_V24
            or record.ledger_record_count != 0
            or record.digest != _INITIAL_HEAD
            or record.journal_head != JOURNAL_GENESIS_V2
        ):
            raise PermissionError("permit anchor initial selection differs")
        return AnchorSelectionV24(
            0, record.digest, record.ledger_identity, record.journal_head, record.head
        )
    if (
        record.previous_head != previous.anchor_head
        or record.ledger_identity != previous.ledger_identity
    ):
        raise PermissionError("permit anchor selected identity or chain differs")
    if record.kind == _INITIAL:
        if record.ledger_record_count == previous.ledger_record_count:
            if (
                record.digest != previous.ledger_head
                or record.journal_head == previous.journal_head
            ):
                raise PermissionError("permit anchor journal-only advance differs")
        elif (
            record.ledger_record_count != previous.ledger_record_count + 1
            or record.journal_head == previous.journal_head
        ):
            raise PermissionError("permit anchor admission advance differs")
        ledger_head = record.digest
    elif record.kind == _RECOVERY:
        if (
            record.ledger_record_count != previous.ledger_record_count
            or record.journal_head != previous.journal_head
        ):
            raise PermissionError("permit anchor recovery changed selection")
        ledger_head = previous.ledger_head
    elif record.kind == _ADOPTION:
        if record.ledger_record_count != previous.ledger_record_count + record.metadata:
            raise PermissionError("permit anchor adopted ledger count differs")
        ledger_head = record.digest
    else:
        if (
            record.ledger_record_count != previous.ledger_record_count
            or record.digest != previous.ledger_head
            or record.journal_head == previous.journal_head
        ):
            raise PermissionError("permit anchor closure changed ledger or omitted journal")
        ledger_head = previous.ledger_head
    return AnchorSelectionV24(
        record.ledger_record_count,
        ledger_head,
        record.ledger_identity,
        record.journal_head,
        record.head,
    )
