# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — V2.4 terminal anchor damage tests
"""Exercise exact first, interior, final and extra-byte classifications."""

from __future__ import annotations

import os
from hashlib import sha256
from pathlib import Path

import pytest

from rigor_foundry._permit_ledger_records_v2 import _INITIAL_HEAD
from rigor_foundry.effect_journal_records_v2 import JOURNAL_GENESIS_V2
from rigor_foundry.models import canonical_digest
from rigor_foundry.permit_anchor_records_v2 import (
    ANCHOR_GENESIS_V24,
    ANCHOR_MAGIC_V24,
    ANCHOR_RECORD_V24,
)
from rigor_foundry.permit_anchor_tail_v2 import AnchorTailScanV24, scan_anchor_tail_v24


def _initial(ledger_path: Path) -> bytes:
    """Build one valid initial V2.4 anchor record."""
    return ANCHOR_RECORD_V24.pack(
        0,
        0,
        _INITIAL_HEAD,
        bytes.fromhex(canonical_digest(str(ledger_path))),
        1,
        2,
        0,
        0,
        JOURNAL_GENESIS_V2,
        bytes(32),
        ANCHOR_GENESIS_V24,
    )


def _scan(path: Path) -> AnchorTailScanV24:
    """Scan the actual file descriptor at its exact observed byte size."""
    descriptor = os.open(path, os.O_RDONLY)
    try:
        return scan_anchor_tail_v24(descriptor, os.fstat(descriptor).st_size)
    finally:
        os.close(descriptor)


def test_clean_and_partial_final_lengths(tmp_path: Path) -> None:
    """Every partial width from 1 through 199 retains the exact verified prefix."""
    anchor = tmp_path / "anchor.bin"
    initial = _initial(tmp_path / "ledger.bin")
    anchor.write_bytes(ANCHOR_MAGIC_V24 + initial)
    clean = _scan(anchor)
    assert clean.tail is None
    assert len(clean.records) == 1
    for length in range(1, ANCHOR_RECORD_V24.size):
        anchor.write_bytes(ANCHOR_MAGIC_V24 + initial + b"x" * length)
        selected = _scan(anchor)
        assert selected.tail is not None
        assert selected.tail.failure_class == "partial-tail"
        assert selected.tail.offset == len(ANCHOR_MAGIC_V24) + 200
        assert selected.tail.raw == b"x" * length
        assert selected.records == (initial,)
        assert selected.selection == clean.selection
        assert anchor.read_bytes() == ANCHOR_MAGIC_V24 + initial + b"x" * length


def test_sole_complete_invalid_final_record_is_classified(tmp_path: Path) -> None:
    """A final invalid 200-byte record keeps the preceding valid selection."""
    anchor = tmp_path / "anchor.bin"
    initial = _initial(tmp_path / "ledger.bin")
    anchor.write_bytes(ANCHOR_MAGIC_V24 + initial + bytes(200))
    selected = _scan(anchor)
    assert selected.tail is not None
    assert selected.tail.failure_class == "complete-invalid-final"
    assert selected.tail.raw == bytes(200)
    assert selected.selection.ledger_record_count == 0


def test_invalid_first_interior_and_extra_bytes_refuse(tmp_path: Path) -> None:
    """A full invalid record cannot be relabelled when more bytes follow it."""
    anchor = tmp_path / "anchor.bin"
    initial = _initial(tmp_path / "ledger.bin")
    for data in (
        ANCHOR_MAGIC_V24 + bytes(200),
        ANCHOR_MAGIC_V24 + initial + bytes(200) + bytes(200),
        ANCHOR_MAGIC_V24 + initial + bytes(200) + b"x",
    ):
        anchor.write_bytes(data)
        with pytest.raises(PermissionError, match="first or interior"):
            _scan(anchor)


def test_missing_first_record_and_wrong_header_refuse(tmp_path: Path) -> None:
    """A missing or partial initial anchor is never recoverable as a tail."""
    anchor = tmp_path / "anchor.bin"
    for data, message in (
        (ANCHOR_MAGIC_V24[:-1], "header is incomplete"),
        (ANCHOR_MAGIC_V24, "absent"),
        (ANCHOR_MAGIC_V24 + b"x", "incomplete"),
        (b"wrong" + ANCHOR_MAGIC_V24, "header"),
    ):
        anchor.write_bytes(data)
        with pytest.raises(PermissionError, match=message):
            _scan(anchor)


def test_valid_complete_final_record_is_not_damage(tmp_path: Path) -> None:
    """A journal-only successor with a real new head remains selected."""
    anchor = tmp_path / "anchor.bin"
    ledger_path = tmp_path / "ledger.bin"
    initial = _initial(ledger_path)
    head = sha256(ANCHOR_GENESIS_V24 + initial[:168]).digest()
    next_record = ANCHOR_RECORD_V24.pack(
        0,
        0,
        _INITIAL_HEAD,
        bytes.fromhex(canonical_digest(str(ledger_path))),
        1,
        2,
        0,
        0,
        b"j" * 32,
        bytes(32),
        head,
    )
    anchor.write_bytes(ANCHOR_MAGIC_V24 + initial + next_record)
    selected = _scan(anchor)
    assert selected.tail is None
    assert len(selected.records) == 2
    assert selected.selection.journal_head == b"j" * 32


@pytest.mark.parametrize("field", ["kind", "count", "ledger-head", "journal-head"])
def test_intrinsically_valid_wrong_initial_selection_refuses(tmp_path: Path, field: str) -> None:
    """A complete decodable row must still satisfy every genesis selection invariant."""
    anchor = tmp_path / "anchor.bin"
    fields = list(ANCHOR_RECORD_V24.unpack(_initial(tmp_path / "ledger.bin")))
    if field == "kind":
        fields[0], fields[6], fields[7], fields[9] = 1, 1, 1, b"e" * 32
    elif field == "count":
        fields[1] = 1
    elif field == "ledger-head":
        fields[2] = b"l" * 32
    else:
        fields[8] = b"j" * 32
    raw = ANCHOR_RECORD_V24.pack(*fields)
    anchor.write_bytes(ANCHOR_MAGIC_V24 + raw)
    before = anchor.read_bytes()
    with pytest.raises(PermissionError, match="first or interior record is invalid"):
        _scan(anchor)
    assert anchor.read_bytes() == before
