# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — permit ledger binary record workflows
"""Validate emitted wire records and corrupted stored input through the public ledger."""

from hashlib import sha256
from pathlib import Path
from struct import Struct
from uuid import UUID

import pytest

from rigor_foundry.permit_consumption_ledger_v2 import ConsumedPermitLedgerV2

_HEADER = b"RIGOR-PERMIT-LEDGER-V2.2\n"
_RECORD = Struct(">B3x16s16s32sQI32s")
_PERMIT = "01a09a66-7b5c-7a2e-93f0-b726808737d4"
_SECOND = "01a09a66-7b5c-7a2e-93f0-b726808737d5"
_EXPIRY = "2026-09-23T03:00:00Z"


def test_complete_emitted_record_has_exact_fixed_wire_and_replayed_identity(
    tmp_path: Path,
) -> None:
    """The actual fsynced bytes and public snapshot share UUID, record and chain identities."""
    tmp_path.chmod(0o700)
    ledger = ConsumedPermitLedgerV2(tmp_path / "consumed.bin")
    initial = ledger.initialize()
    head = ledger.consume(permit_id=_PERMIT, permit_digest="a" * 64, expires_at=_EXPIRY)
    wire = ledger.path.read_bytes()
    assert wire[: len(_HEADER)] == _HEADER
    raw = wire[len(_HEADER) :]
    assert len(raw) == _RECORD.size
    kind, permit, additional, digest, stamp, metadata, previous = _RECORD.unpack(raw)
    assert (kind, permit, additional, digest, metadata) == (
        0,
        UUID(_PERMIT).bytes,
        b"\x00" * 16,
        bytes.fromhex("a" * 64),
        0,
    )
    assert stamp > 0
    assert previous.hex() == initial
    assert sha256(previous + raw[:-32]).hexdigest() == head
    with ledger.locked_snapshot(selected_count=1, selected_head_digest=head) as snapshot:
        assert snapshot.records[0].record_digest == sha256(raw).hexdigest()
        assert snapshot.records[0].head_digest == head
        assert snapshot.records[0].permit_id == _PERMIT


@pytest.mark.parametrize("corruption", ["kind", "padding", "digest", "stamp", "metadata"])
def test_invalid_stored_wire_refuses_without_appending(tmp_path: Path, corruption: str) -> None:
    """Real stored record mutation cannot pass replay before a later public consume."""
    tmp_path.chmod(0o700)
    ledger = ConsumedPermitLedgerV2(tmp_path / "consumed.bin")
    ledger.initialize()
    ledger.consume(permit_id=_PERMIT, permit_digest="a" * 64, expires_at=_EXPIRY)
    offsets = {
        "kind": (0, b"X"),
        "padding": (1, b"X"),
        "digest": (36, b"\x00" * 32),
        "stamp": (68, b"\x00" * 8),
        "metadata": (76, b"\x00\x00\x00\x01"),
    }
    offset, value = offsets[corruption]
    with ledger.path.open("r+b") as writer:
        writer.seek(len(_HEADER) + offset)
        writer.write(value)
    before = ledger.path.read_bytes()
    with pytest.raises(PermissionError):
        ledger.consume(permit_id=_SECOND, permit_digest="b" * 64, expires_at=_EXPIRY)
    assert ledger.path.read_bytes() == before
