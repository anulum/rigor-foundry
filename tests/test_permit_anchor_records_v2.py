# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — protected permit-anchor V2.4 record tests
"""Check exact anchor wire bytes and all four intrinsic successor transitions."""

from __future__ import annotations

from hashlib import sha256

import pytest

from rigor_foundry._permit_ledger_records_v2 import _INITIAL_HEAD
from rigor_foundry.effect_journal_records_v2 import JOURNAL_GENESIS_V2
from rigor_foundry.permit_anchor_records_v2 import (
    ANCHOR_GENESIS_V24,
    ANCHOR_MAGIC_V24,
    ANCHOR_RECORD_V24,
    AnchorSelectionV24,
    advance_anchor_selection_v24,
    parse_anchor_record_v24,
)

_PATH = bytes(range(32))
_HEAD = bytes.fromhex("b2" * 32)
_NEXT = bytes.fromhex("c3" * 32)
_EVENT = bytes.fromhex("d4" * 32)
_ZERO = bytes(32)


def _record(
    kind: int,
    previous: bytes,
    *,
    count: int = 0,
    digest: bytes = _INITIAL_HEAD,
    journal: bytes = JOURNAL_GENESIS_V2,
    stamp: int = 0,
    metadata: int = 0,
    event: bytes = _ZERO,
    path: bytes = _PATH,
) -> bytes:
    """Pack the independent exact layout for a parser test vector."""
    return ANCHOR_RECORD_V24.pack(
        kind, count, digest, path, 81, 92, stamp, metadata, journal, event, previous
    )


def _initial() -> AnchorSelectionV24:
    """Return an initial selection parsed from a real 200-byte record."""
    raw = _record(0, ANCHOR_GENESIS_V24)
    record = parse_anchor_record_v24(raw, previous_head=ANCHOR_GENESIS_V24)
    return advance_anchor_selection_v24(None, record)


def _next(
    prior: AnchorSelectionV24,
    kind: int,
    *,
    count: int,
    digest: bytes,
    journal: bytes,
    stamp: int = 0,
    metadata: int = 0,
    event: bytes = _ZERO,
) -> AnchorSelectionV24:
    """Advance one chain link through the public decoder and transition checker."""
    raw = _record(
        kind,
        prior.anchor_head,
        count=count,
        digest=digest,
        journal=journal,
        stamp=stamp,
        metadata=metadata,
        event=event,
    )
    return advance_anchor_selection_v24(
        prior, parse_anchor_record_v24(raw, previous_head=prior.anchor_head)
    )


def test_exact_genesis_layout_and_initial_selection() -> None:
    """The V2.4 magic, record width and hash-covered prefix are exact."""
    assert ANCHOR_MAGIC_V24 == b"RIGOR-PERMIT-ANCHOR-V2.4\n"
    assert ANCHOR_RECORD_V24.size == 200
    raw = _record(0, ANCHOR_GENESIS_V24)
    record = parse_anchor_record_v24(raw, previous_head=ANCHOR_GENESIS_V24)
    assert record.head == sha256(ANCHOR_GENESIS_V24 + raw[:168]).digest()
    assert record.raw == raw
    selected = advance_anchor_selection_v24(None, record)
    assert selected.ledger_record_count == 0
    assert selected.ledger_head == _INITIAL_HEAD
    assert selected.journal_head == JOURNAL_GENESIS_V2
    assert selected.ledger_identity.path_digest == _PATH.hex()
    assert selected.ledger_identity.device == 81
    assert selected.ledger_identity.inode == 92


def test_four_successor_transitions_preserve_selected_ledger_head() -> None:
    """Kind 1 carries removed-byte digest without replacing the ledger head."""
    initial = _initial()
    admitted = _next(initial, 0, count=1, digest=_HEAD, journal=_NEXT)
    journal_only = _next(admitted, 0, count=1, digest=_HEAD, journal=_EVENT)
    recovered = _next(
        journal_only,
        1,
        count=1,
        digest=_EVENT,
        journal=_EVENT,
        stamp=1,
        metadata=200,
        event=_HEAD,
    )
    assert recovered.ledger_head == _HEAD
    adopted = _next(
        recovered,
        2,
        count=3,
        digest=_NEXT,
        journal=_NEXT,
        stamp=2,
        metadata=2,
        event=_EVENT,
    )
    assert adopted.ledger_record_count == 3
    closed = _next(adopted, 3, count=3, digest=_NEXT, journal=_EVENT, event=_HEAD)
    assert closed.ledger_head == _NEXT
    assert closed.journal_head == _EVENT


@pytest.mark.parametrize(
    ("kind", "stamp", "metadata", "event"),
    [
        (0, 1, 0, _ZERO),
        (0, 0, 1, _ZERO),
        (0, 0, 0, _EVENT),
        (1, 0, 1, _EVENT),
        (1, 1, 0, _EVENT),
        (1, 1, 201, _EVENT),
        (1, 1, 1, _ZERO),
        (2, 0, 1, _EVENT),
        (2, 1, 0, _EVENT),
        (2, 1, 1, _ZERO),
        (3, 1, 0, _EVENT),
        (3, 0, 1, _EVENT),
        (3, 0, 0, _ZERO),
    ],
)
def test_invalid_kind_fields_refuse(kind: int, stamp: int, metadata: int, event: bytes) -> None:
    """Each kind's independent stamp, metadata and event constraints fail closed."""
    with pytest.raises(PermissionError):
        parse_anchor_record_v24(
            _record(kind, ANCHOR_GENESIS_V24, stamp=stamp, metadata=metadata, event=event),
            previous_head=ANCHOR_GENESIS_V24,
        )


def test_corrupt_record_bytes_and_identity_refuse() -> None:
    """Width, reserves, previous head, known kind and selected identity are checked."""
    raw = _record(0, ANCHOR_GENESIS_V24)
    variants = (
        raw[:-1],
        raw[:1] + b"\x01" + raw[2:],
        _record(4, ANCHOR_GENESIS_V24),
        _record(0, ANCHOR_GENESIS_V24, path=_ZERO),
        _record(0, ANCHOR_GENESIS_V24, journal=_ZERO),
    )
    for variant in variants:
        with pytest.raises(PermissionError):
            parse_anchor_record_v24(variant, previous_head=ANCHOR_GENESIS_V24)
    with pytest.raises(PermissionError, match="chain"):
        parse_anchor_record_v24(raw, previous_head=_HEAD)


def test_bad_initial_and_successor_selection_refuse() -> None:
    """No later kind can bootstrap, and counts, heads and identities must agree."""
    initial = _initial()
    with pytest.raises(PermissionError, match="initial"):
        advance_anchor_selection_v24(
            None,
            parse_anchor_record_v24(
                _record(0, ANCHOR_GENESIS_V24, count=1),
                previous_head=ANCHOR_GENESIS_V24,
            ),
        )
    bad = (
        _record(0, initial.anchor_head),
        _record(0, initial.anchor_head, count=2, digest=_HEAD, journal=_NEXT),
        _record(1, initial.anchor_head, count=1, digest=_HEAD, stamp=1, metadata=1, event=_EVENT),
        _record(2, initial.anchor_head, count=2, digest=_HEAD, stamp=1, metadata=1, event=_EVENT),
        _record(3, initial.anchor_head, event=_EVENT, journal=_NEXT, count=1),
        _record(0, initial.anchor_head, journal=_NEXT, path=_HEAD),
    )
    for raw in bad:
        with pytest.raises(PermissionError):
            advance_anchor_selection_v24(
                initial, parse_anchor_record_v24(raw, previous_head=initial.anchor_head)
            )
