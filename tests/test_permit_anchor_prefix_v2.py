# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — V2.4 retained prefix tests
"""Exercise retained-prefix refusal with real opened file identities."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from rigor_foundry._permit_ledger_records_v2 import _INITIAL_HEAD
from rigor_foundry.effect_journal_records_v2 import JOURNAL_GENESIS_V2
from rigor_foundry.effect_journal_v2 import EffectJournalStoreV2
from rigor_foundry.permit_anchor_prefix_v2 import verify_anchor_prefix_v24
from rigor_foundry.permit_anchor_store_v2 import PermitLedgerAnchorStoreV2
from rigor_foundry.permit_anchor_tail_v2 import scan_anchor_tail_v24
from rigor_foundry.permit_consumption_ledger_v2 import ConsumedPermitLedgerV2


def test_retained_prefix_requires_initial_record_and_selected_inode(tmp_path: Path) -> None:
    """Neither an absent anchor nor a same-content replacement ledger selects."""
    parent = tmp_path / "custody"
    parent.mkdir(mode=0o700)
    ledger = ConsumedPermitLedgerV2(parent / "consumed.bin")
    substitute = ConsumedPermitLedgerV2(parent / "substitute.bin")
    journal = EffectJournalStoreV2(parent / "effect.journal")
    anchor = PermitLedgerAnchorStoreV2(parent / "anchor.bin")
    ledger.initialize()
    substitute.initialize()
    journal.initialize()
    anchor.initialize(ledger=ledger, journal=journal, max_journal_bytes=100000)
    with (
        anchor.path.open("rb") as anchor_reader,
        substitute.locked_snapshot(
            selected_count=0, selected_head_digest=_INITIAL_HEAD.hex()
        ) as substitute_snapshot,
        journal.locked(
            selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000
        ) as journal_lease,
    ):
        descriptor = anchor_reader.fileno()
        anchor_stat = os.fstat(descriptor)

        def verify(records: tuple[bytes, ...]) -> None:
            """Use the same held file descriptors for both prefix challenges."""
            verify_anchor_prefix_v24(
                records,
                objects={},
                anchor_path=anchor.path,
                anchor_stat=anchor_stat,
                ledger_path=substitute.path,
                ledger=substitute_snapshot,
                journal_path=journal.path,
                journal=journal_lease.snapshot,
            )

        with pytest.raises(PermissionError, match="initial record is absent"):
            verify(())
        with pytest.raises(PermissionError, match="selected ledger identity differs"):
            verify(scan_anchor_tail_v24(descriptor, anchor_stat.st_size).records)
