# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — V2.1 terminal journal frame classification
"""Classify only a damaged final journal frame after a verified selected prefix."""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from ._effect_journal_storage_io_v2 import _read_exact
from .effect_journal_records_v2 import (
    JOURNAL_GENESIS_V2,
    JOURNAL_MAGIC_V2,
    EffectJournalRecordV2,
    parse_effect_journal_frame_v2,
)
from .effect_journal_v2 import EffectJournalFileIdentityV2, EffectJournalSnapshotV2

_LENGTH = struct.Struct(">I")
_MAX_PAYLOAD = 65536
_FRAME_OVERHEAD = 36


@dataclass(frozen=True)
class JournalTailCandidateV21:
    """Exact damaged final bytes without permission to remove them.

    Attributes
    ----------
    offset : int
        Byte offset after the fully verified complete prefix.
    raw : bytes
        Exact retained terminal fragment, never repaired by classification.
    failure_class : str
        Partial frame, bad head or noncanonical terminal frame classification.
    declared_payload_length : int | None
        Decoded length when a complete length field exists.
    """

    offset: int
    raw: bytes
    failure_class: str
    declared_payload_length: int | None


@dataclass(frozen=True)
class JournalTailScanV21:
    """Verified complete prefix and an optional damaged terminal fragment.

    Attributes
    ----------
    snapshot : EffectJournalSnapshotV2
        Complete verified records and proof that the selected head is in the prefix.
    tail : JournalTailCandidateV21 | None
        Exact final damage candidate, or none for a complete chain.
    """

    snapshot: EffectJournalSnapshotV2
    tail: JournalTailCandidateV21 | None


def scan_journal_tail_v21(
    descriptor: int,
    *,
    size: int,
    selected_head: bytes,
    identity: EffectJournalFileIdentityV2,
) -> JournalTailScanV21:
    """Read an exact file and preserve damage only after its selected head.

    Parameters
    ----------
    descriptor
        Actual descriptor retained by the caller's selected recovery lease.
    size
        Sampled bounded file length; concurrent truncation refuses.
    selected_head
        Exact 32-byte head that must occur in the verified complete prefix.
    identity
        Path/device/inode identity sampled by the actual store owner.

    Returns
    -------
    JournalTailScanV21
        Complete prefix and only an unambiguous damaged final fragment.

    Raises
    ------
    PermissionError
        Header, selected prefix, first/interior frame or final length is invalid.
    OSError
        Actual descriptor seek or read fails.

    Notes
    -----
    This function changes no bytes and grants no operator repair authority.
    The caller authenticates descriptor custody and enforces the byte budget.
    """
    os.lseek(descriptor, 0, os.SEEK_SET)
    if _read_exact(descriptor, len(JOURNAL_MAGIC_V2)) != JOURNAL_MAGIC_V2:
        raise PermissionError("effect journal header differs")
    offset = len(JOURNAL_MAGIC_V2)
    head = JOURNAL_GENESIS_V2
    selected_count: int | None = 0 if selected_head == head else None
    records: list[EffectJournalRecordV2] = []

    def result(tail: JournalTailCandidateV21 | None) -> JournalTailScanV21:
        """Return only after the selected head was proved in this prefix.

        Parameters
        ----------
        tail
            Retained final damage candidate, or none for a complete chain.

        Returns
        -------
        JournalTailScanV21
            Snapshot of the verified prefix and its optional terminal fragment.

        Raises
        ------
        PermissionError
            No complete record boundary proves the selected head.
        """
        if selected_count is None:
            raise PermissionError("effect journal selected head is not a verified prefix")
        snapshot = EffectJournalSnapshotV2(
            identity=identity,
            records=tuple(records),
            head_digest=head.hex(),
            selected_head_digest=selected_head.hex(),
            selected_record_count=selected_count,
        )
        return JournalTailScanV21(snapshot, tail)

    while offset < size:
        remaining = size - offset
        if remaining < _LENGTH.size:
            if selected_count is None:
                raise PermissionError("effect journal anchored frame is incomplete")
            return result(
                JournalTailCandidateV21(
                    offset, _read_exact(descriptor, remaining), "partial", None
                )
            )
        length_bytes = _read_exact(descriptor, _LENGTH.size)
        length = _LENGTH.unpack(length_bytes)[0]
        if not 1 <= length <= _MAX_PAYLOAD:
            raise PermissionError("effect journal final frame length is ambiguous")
        frame_size = length + _FRAME_OVERHEAD
        if remaining < frame_size:
            if selected_count is None:
                raise PermissionError("effect journal anchored frame is incomplete")
            return result(
                JournalTailCandidateV21(
                    offset,
                    length_bytes + _read_exact(descriptor, remaining - _LENGTH.size),
                    "partial",
                    length,
                )
            )
        frame = length_bytes + _read_exact(descriptor, length + 32)
        try:
            record = parse_effect_journal_frame_v2(
                frame, previous_head=head, expected_seq=len(records) + 1
            )
        except (PermissionError, ValueError) as exc:
            if remaining != frame_size or selected_count is None:
                raise PermissionError(
                    "effect journal first, anchored or interior frame is invalid"
                ) from exc
            failure = "bad-head" if str(exc) == "journal record head differs" else "noncanonical"
            return result(JournalTailCandidateV21(offset, frame, failure, length))
        records.append(record)
        head = bytes.fromhex(record.record_head)
        if head == selected_head:
            selected_count = len(records)
        offset += frame_size
    return result(None)
