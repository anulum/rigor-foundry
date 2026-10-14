# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — V2.4 final anchor tail classification
"""Classify only a sole final damaged anchor record after a valid retained prefix."""

from __future__ import annotations

import os
from dataclasses import dataclass

from ._permit_ledger_storage_io_v2 import _read_exact
from .permit_anchor_records_v2 import (
    ANCHOR_GENESIS_V24,
    ANCHOR_MAGIC_V24,
    ANCHOR_RECORD_V24,
    AnchorSelectionV24,
    advance_anchor_selection_v24,
    parse_anchor_record_v24,
)


@dataclass(frozen=True)
class AnchorTailCandidateV24:
    """Exact removable final bytes, without authorising their removal.

    Attributes
    ----------
    offset : int
        Byte offset of the sole final damaged fragment.
    raw : bytes
        Exact captured record or final-tail bytes.
    failure_class : str
        Partial tail or complete invalid final record classification.
    """

    offset: int
    raw: bytes
    failure_class: str


@dataclass(frozen=True)
class AnchorTailScanV24:
    """Valid retained prefix and an optional sole final damaged tail.

    Attributes
    ----------
    records : tuple[bytes, ...]
        Complete valid anchor records in file order.
    selection : AnchorSelectionV24
        Verified intrinsic ledger and journal selection.
    tail : AnchorTailCandidateV24 | None
        Sole final damage candidate, or None; classification authorises no removal.
    """

    records: tuple[bytes, ...]
    selection: AnchorSelectionV24
    tail: AnchorTailCandidateV24 | None


def scan_anchor_tail_v24(descriptor: int, size: int) -> AnchorTailScanV24:
    """Refuse first/interior damage and classify only the last damaged bytes.

    Parameters
    ----------
    descriptor : int
        Open anchor descriptor retained by the caller throughout the scan.
    size : int
        Exact captured file size; the caller must reject concurrent custody changes.

    Returns
    -------
    AnchorTailScanV24
        Verified retained prefix and at most one sole final damaged fragment.

    Raises
    ------
    PermissionError
        Selected chain, commitment, pending-intent or file custody checks refuse.
    OSError
        The actual filesystem operation fails; no success is synthesized.
    """
    header_size = len(ANCHOR_MAGIC_V24)
    remaining = size - header_size
    if remaining < 0:
        raise PermissionError("permit anchor header is incomplete")
    os.lseek(descriptor, 0, os.SEEK_SET)
    if _read_exact(descriptor, header_size) != ANCHOR_MAGIC_V24:
        raise PermissionError("permit anchor header differs")
    complete_count, remainder = divmod(remaining, ANCHOR_RECORD_V24.size)
    if complete_count < 1:
        if remainder:
            raise PermissionError("permit anchor initial record is incomplete")
        raise PermissionError("permit anchor initial record is absent")
    selected: AnchorSelectionV24 | None = None
    records: list[bytes] = []
    for index in range(complete_count):
        raw = _read_exact(descriptor, ANCHOR_RECORD_V24.size)
        previous = ANCHOR_GENESIS_V24 if selected is None else selected.anchor_head
        try:
            record = parse_anchor_record_v24(raw, previous_head=previous)
            next_selection = advance_anchor_selection_v24(selected, record)
        except PermissionError as exc:
            if index != complete_count - 1 or remainder or selected is None:
                raise PermissionError("permit anchor first or interior record is invalid") from exc
            return AnchorTailScanV24(
                tuple(records),
                selected,
                AnchorTailCandidateV24(
                    header_size + index * ANCHOR_RECORD_V24.size, raw, "complete-invalid-final"
                ),
            )
        selected = next_selection
        records.append(raw)
    if selected is None:
        raise PermissionError("permit anchor initial record is absent")
    if remainder:
        raw = _read_exact(descriptor, remainder)
        return AnchorTailScanV24(
            tuple(records),
            selected,
            AnchorTailCandidateV24(
                header_size + complete_count * ANCHOR_RECORD_V24.size, raw, "partial-tail"
            ),
        )
    return AnchorTailScanV24(tuple(records), selected, None)
