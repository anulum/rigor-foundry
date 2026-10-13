# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — permit ledger descriptor I/O public workflows
"""Exercise descriptor custody and binary I/O through complete ledger operations."""

from pathlib import Path

import pytest

from rigor_foundry.permit_consumption_ledger_v2 import ConsumedPermitLedgerV2


def test_actual_ledger_io_initialise_consume_and_replay(tmp_path: Path) -> None:
    """Real public writes and reads retain the selected prefix and both consumed IDs."""
    tmp_path.chmod(0o700)
    ledger = ConsumedPermitLedgerV2(tmp_path / "consumed.bin")
    initial = ledger.initialize()
    consumed = ledger.consume(
        permit_id="01a09a66-7b5c-7a2e-93f0-b726808737d4",
        single_use_id="01a09a66-7b5c-7a2e-93f0-b726808737d5",
        permit_digest="a" * 64,
        expires_at="2026-09-23T03:00:00Z",
    )
    with ledger.locked_snapshot(selected_count=0, selected_head_digest=initial) as snapshot:
        assert snapshot.record_count == 1
        assert snapshot.head_digest == consumed
        assert snapshot.records[0].single_use_id == "01a09a66-7b5c-7a2e-93f0-b726808737d5"
    assert ledger.verify_anchor(record_count=1, head_digest=consumed) == (1, consumed)


def test_real_alias_and_parent_mode_refuse_before_io(tmp_path: Path) -> None:
    """Kernel link and mode observations reject an unsafe selected file without writing."""
    tmp_path.chmod(0o700)
    ledger = ConsumedPermitLedgerV2(tmp_path / "consumed.bin")
    initial = ledger.initialize()
    before = ledger.path.read_bytes()
    alias = tmp_path / "alias.bin"
    alias.hardlink_to(ledger.path)
    with pytest.raises(PermissionError, match="identity or length"):
        ledger.verify_anchor(record_count=0, head_digest=initial)
    assert alias.read_bytes() == before
    alias.unlink()
    tmp_path.chmod(0o755)
    with pytest.raises(PermissionError, match="directory is not owner-only"):
        ledger.verify_anchor(record_count=0, head_digest=initial)
    assert ledger.path.read_bytes() == before
