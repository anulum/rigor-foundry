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
    """Only an existing verified initial record makes 1 or 199 bytes eligible."""
    anchor = tmp_path / "anchor.bin"
    initial = _initial(tmp_path / "ledger.bin")
    anchor.write_bytes(ANCHOR_MAGIC_V24 + initial)
    clean = _scan(anchor)
    assert clean.tail is None
    assert len(clean.records) == 1
    for length in (1, 199):
        anchor.write_bytes(ANCHOR_MAGIC_V24 + initial + b"x" * length)
        selected = _scan(anchor)
        assert selected.tail is not None
        assert selected.tail.failure_class == "partial-tail"
        assert selected.tail.offset == len(ANCHOR_MAGIC_V24) + 200
        assert selected.tail.raw == b"x" * length


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
