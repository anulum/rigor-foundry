# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real anchor path replacement under journal lock
"""Exercise public anchor selection against actual outside-writer inode replacement."""

from __future__ import annotations

import fcntl
from pathlib import Path
from types import FrameType

import pytest
from test_permit_anchor_store_v2 import _evidence, _stores
from test_recovery_evidence_store_races_v2 import _filesystem_change

from rigor_foundry.effect_journal_records_v2 import JOURNAL_GENESIS_V2


def test_anchor_path_swap_during_journal_lock_refuses(tmp_path: Path) -> None:
    """A real replacement after journal lock acquisition invalidates public anchor current."""
    ledger, journal, anchor = _stores(tmp_path)
    identity = journal.snapshot(
        selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000
    ).identity
    evidence = _evidence(anchor)
    old = anchor.path.parent / "old-anchor.bin"
    original = anchor.path.read_bytes()
    original_inode = anchor.path.stat().st_ino

    def replace() -> None:
        """Install equal bytes at a new anchor inode while the old inode stays locked."""
        anchor.path.rename(old)
        anchor.path.write_bytes(original)
        anchor.path.chmod(0o600)

    def after_journal_lock(frame: FrameType, event: str, arg: object) -> bool:
        """Observe the real flock return in the selected journal recovery context."""
        return (
            frame.f_code.co_name == "locked_recovery"
            and frame.f_locals.get("self") is journal
            and event == "c_return"
            and arg is fcntl.flock
        )

    with (
        _filesystem_change(replace, after_journal_lock),
        pytest.raises(PermissionError, match="changed during locked operation"),
    ):
        anchor.current(
            ledger=ledger,
            journal=journal,
            evidence=evidence,
            selected_journal_identity=identity,
            max_journal_bytes=100000,
        )
    assert old.stat().st_ino == original_inode
    assert anchor.path.stat().st_ino != original_inode
    assert old.read_bytes() == anchor.path.read_bytes() == original


@pytest.mark.parametrize("change", ["inode", "bytes", "mode", "link"])
def test_initializer_refuses_replaced_created_anchor(tmp_path: Path, change: str) -> None:
    """Exclusive creation cannot return a selection for a substituted inode."""
    from rigor_foundry import _permit_ledger_storage_io_v2 as io
    from rigor_foundry.effect_journal_v2 import EffectJournalStoreV2
    from rigor_foundry.permit_anchor_store_v2 import PermitLedgerAnchorStoreV2
    from rigor_foundry.permit_consumption_ledger_v2 import ConsumedPermitLedgerV2

    parent = tmp_path / "custody"
    parent.mkdir(mode=0o700)
    ledger = ConsumedPermitLedgerV2(parent / "ledger.bin")
    journal = EffectJournalStoreV2(parent / "journal.bin")
    anchor = PermitLedgerAnchorStoreV2(parent / "anchor.bin")
    ledger.initialize()
    journal.initialize()
    old = parent / "old-anchor.bin"

    def replace() -> None:
        """Replace the fully written file with equal bytes before initial fsync."""
        original = anchor.path.read_bytes()
        if change == "inode":
            anchor.path.rename(old)
            anchor.path.write_bytes(original)
            anchor.path.chmod(0o600)
        elif change == "mode":
            anchor.path.chmod(0o640)
        elif change == "link":
            import os

            os.link(anchor.path, old)
        else:
            with anchor.path.open("r+b") as writer:
                writer.write(b"!")
                writer.flush()
                import os

                os.fsync(writer.fileno())

    def after_write(frame: FrameType, event: str, arg: object) -> bool:
        """Observe actual anchor write completion without replacing any syscall."""
        return (
            frame.f_code is io._write_all.__code__
            and event == "return"
            and frame.f_back is not None
            and frame.f_back.f_code is PermitLedgerAnchorStoreV2.initialize.__code__
        )

    with (
        _filesystem_change(replace, after_write),
        pytest.raises(
            PermissionError, match=r"changed during locked operation|initial content changed"
        ),
    ):
        anchor.initialize(ledger=ledger, journal=journal, max_journal_bytes=100000)
    if change == "inode":
        assert old.read_bytes() == anchor.path.read_bytes()
        assert old.stat().st_ino != anchor.path.stat().st_ino
    elif change == "bytes":
        assert anchor.path.read_bytes().startswith(b"!")
    elif change == "mode":
        assert anchor.path.stat().st_mode & 0o777 == 0o640
    else:
        assert old.stat().st_ino == anchor.path.stat().st_ino
        assert anchor.path.stat().st_nlink == 2


@pytest.mark.parametrize("change", ["inode", "mode"])
def test_current_refuses_replaced_parent_path(tmp_path: Path, change: str) -> None:
    """A held old custody directory cannot select its substituted pathname."""
    from rigor_foundry.recovery_evidence_store_v2 import RecoveryEvidenceStoreV2

    ledger, journal, anchor = _stores(tmp_path)
    identity = journal.snapshot(
        selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000
    ).identity
    evidence = _evidence(anchor)
    old = tmp_path / "old-custody"
    original = anchor.path.read_bytes()

    def replace() -> None:
        """Keep all held original files intact under an old directory name."""
        if change == "inode":
            anchor.path.parent.rename(old)
            anchor.path.parent.mkdir(mode=0o700)
        else:
            anchor.path.parent.chmod(0o750)

    def after_scan(frame: FrameType, event: str, arg: object) -> bool:
        """Wait until the unmodified public evidence scan has closed its checks."""
        return (
            frame.f_code is RecoveryEvidenceStoreV2.scan.__code__
            and frame.f_locals.get("self") is evidence
            and event == "return"
        )

    with (
        _filesystem_change(replace, after_scan),
        pytest.raises(
            PermissionError,
            match=r"directory identity changed|permit ledger directory changed during locked operation",
        ),
    ):
        anchor.current(
            ledger=ledger,
            journal=journal,
            evidence=evidence,
            selected_journal_identity=identity,
            max_journal_bytes=100000,
        )
    if change == "inode":
        assert (old / "anchor.bin").read_bytes() == original
        assert list(anchor.path.parent.iterdir()) == []
    else:
        assert anchor.path.read_bytes() == original
        assert anchor.path.parent.stat().st_mode & 0o777 == 0o750
