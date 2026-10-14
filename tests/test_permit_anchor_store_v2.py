# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — protected V2.4 anchor file tests
"""Check V2.4 anchor selection through real ledger and journal files."""

from __future__ import annotations

import base64
import os
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from rigor_foundry._permit_ledger_records_v2 import _INITIAL_HEAD
from rigor_foundry.effect_journal_records_v2 import JOURNAL_GENESIS_V2, JOURNAL_MAGIC_V2
from rigor_foundry.effect_journal_v2 import (
    EffectJournalFileIdentityV2,
    EffectJournalStoreV2,
)
from rigor_foundry.models import canonical_digest
from rigor_foundry.permit_anchor_prefix_v2 import verify_anchor_prefix_v24
from rigor_foundry.permit_anchor_records_v2 import ANCHOR_MAGIC_V24, ANCHOR_RECORD_V24
from rigor_foundry.permit_anchor_store_v2 import (
    PermitLedgerAnchorStoreV2,
    PermitLedgerAnchorV2,
)
from rigor_foundry.permit_consumption_ledger_v2 import ConsumedPermitLedgerV2
from rigor_foundry.recovery_evidence_binding_v2 import consumed_uuids_digest_v24
from rigor_foundry.recovery_evidence_schema_v2 import (
    exact_recovery_stamp_us_v2,
    validate_anchor_adoption_evidence_v2,
    validate_anchor_final_intent_v2,
    validate_journal_tail_intent_v2,
)
from rigor_foundry.recovery_evidence_store_v2 import RecoveryEvidenceStoreV2

_ID = "123e4567-e89b-12d3-a456-426614174000"
_OTHER = "123e4567-e89b-12d3-a456-426614174001"
_DIGEST = "a" * 64
_TIME = "2026-09-23T03:00:00Z"
_TARGET = {"form": "path", "value": "/srv/rigor/result"}


def _stores(
    tmp_path: Path,
) -> tuple[ConsumedPermitLedgerV2, EffectJournalStoreV2, PermitLedgerAnchorStoreV2]:
    """Create an exact mode-0700 local custody directory and three real files."""
    parent = tmp_path / "custody"
    parent.mkdir(mode=0o700)
    (parent / "evidence").mkdir(mode=0o700)
    ledger = ConsumedPermitLedgerV2(parent / "consumed.bin")
    journal = EffectJournalStoreV2(parent / "effect.journal")
    anchor = PermitLedgerAnchorStoreV2(parent / "anchor.bin")
    ledger.initialize()
    journal.initialize()
    anchor.initialize(ledger=ledger, journal=journal, max_journal_bytes=100000)
    return ledger, journal, anchor


def _evidence(anchor: PermitLedgerAnchorStoreV2) -> RecoveryEvidenceStoreV2:
    """Select the fixture's owner-only bounded immutable evidence directory."""
    return RecoveryEvidenceStoreV2(anchor.path.parent / "evidence", 16, 100000)


def _file_identity(path: Path) -> dict[str, object]:
    """Encode the selected real-file identity from its opened fixture path."""
    entry = path.stat()
    return {
        "path": str(path),
        "path_digest": canonical_digest(str(path)),
        "device": str(entry.st_dev),
        "inode": str(entry.st_ino),
    }


def _current(
    ledger: ConsumedPermitLedgerV2,
    journal: EffectJournalStoreV2,
    anchor: PermitLedgerAnchorStoreV2,
) -> PermitLedgerAnchorV2:
    """Read one V2.4 selection with the fixture's selected journal identity."""
    identity = journal.snapshot(
        selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000
    ).identity
    return anchor.current(
        ledger=ledger,
        journal=journal,
        evidence=_evidence(anchor),
        selected_journal_identity=identity,
        max_journal_bytes=100000,
    )


def test_current_reports_terminal_journal_damage_as_recovery_needed(tmp_path: Path) -> None:
    """Ordinary selected reads refuse a damaged final journal byte without repair."""
    ledger, journal, anchor = _stores(tmp_path)
    entry = journal.path.stat()
    identity = EffectJournalFileIdentityV2(
        canonical_digest(str(journal.path)), entry.st_dev, entry.st_ino
    )
    with journal.path.open("ab") as writer:
        writer.write(b"x")
        writer.flush()
        os.fsync(writer.fileno())
    before = journal.path.read_bytes()
    with pytest.raises(PermissionError, match="effect journal recovery-needed: final tail damage"):
        anchor.current(
            ledger=ledger,
            journal=journal,
            evidence=_evidence(anchor),
            selected_journal_identity=identity,
            max_journal_bytes=100000,
        )
    assert journal.path.read_bytes() == before
    assert _evidence(anchor).scan() == {}


def _intent(head: str, *, permit_id: str = _ID) -> dict[str, object]:
    """Build the complete operation intent required by journal wire V2.1."""
    return {
        "permit_id": permit_id,
        "permit_digest": _DIGEST,
        "ledger_head": head,
        "effect_target_digest": _DIGEST,
        "decision_digest": _DIGEST,
        "grant_snapshot_digest": _DIGEST,
        "adapter_operations_digest": _DIGEST,
        "operation_key": "write-artifact",
        "cgroup_id": "42",
        "atomicity": "atomic",
        "parts": [
            {
                "index": 0,
                "effect_class": "local-file-write",
                "target_ref": _TARGET,
                "route_digest": _DIGEST,
                "operation_variant": "default",
            }
        ],
    }


def _append_anchor(
    anchor: PermitLedgerAnchorStoreV2,
    *,
    kind: int,
    count: int,
    digest: bytes,
    journal_head: bytes,
    event_digest: bytes = bytes(32),
    stamp: int = 0,
    metadata: int = 0,
) -> None:
    """Write one test-only record from checked initial on-disk identity and head."""
    data = anchor.path.read_bytes()
    preceding = data[-ANCHOR_RECORD_V24.size :]
    from hashlib import sha256

    head = sha256(preceding[-32:] + preceding[:168]).digest()
    fields = ANCHOR_RECORD_V24.unpack(preceding)
    raw = ANCHOR_RECORD_V24.pack(
        kind,
        count,
        digest,
        fields[3],
        fields[4],
        fields[5],
        stamp,
        metadata,
        journal_head,
        event_digest,
        head,
    )
    with anchor.path.open("ab") as writer:
        writer.write(raw)
        writer.flush()
        os.fsync(writer.fileno())


def test_genesis_anchor_is_exact_v24_and_uses_both_empty_files(tmp_path: Path) -> None:
    """The initializer pins empty ledger and journal under the 200-byte wire."""
    ledger, journal, anchor = _stores(tmp_path)
    data = anchor.path.read_bytes()
    assert data.startswith(ANCHOR_MAGIC_V24)
    assert len(data) == len(ANCHOR_MAGIC_V24) + 200
    selected = _current(ledger, journal, anchor)
    assert selected.ledger_record_count == 0
    assert selected.ledger_head_digest == _INITIAL_HEAD.hex()
    assert selected.journal_head_digest == JOURNAL_GENESIS_V2.hex()
    assert len(selected.anchor_log_head_digest) == 64
    assert selected.binding.journal_state.open_targets == frozenset()
    with pytest.raises(FileExistsError):
        anchor.initialize(ledger=ledger, journal=journal, max_journal_bytes=100000)


def test_complete_ledger_suffix_refuses_until_adoption(tmp_path: Path) -> None:
    """A crash-leftover consumption burns its ID but cannot pass ordinary selection."""
    ledger, journal, anchor = _stores(tmp_path)
    ledger.consume(permit_id=_ID, permit_digest=_DIGEST, expires_at=_TIME)
    before = anchor.path.read_bytes()
    with pytest.raises(PermissionError, match="suffix adoption"):
        _current(ledger, journal, anchor)
    assert anchor.path.read_bytes() == before


def test_adoption_anchor_requires_immutable_evidence_object(tmp_path: Path) -> None:
    """A complete suffix cannot become selected through an unbacked kind-2 record."""
    ledger, journal, anchor = _stores(tmp_path)
    ledger_head = ledger.consume(permit_id=_ID, permit_digest=_DIGEST, expires_at=_TIME)
    _append_anchor(
        anchor,
        kind=2,
        count=1,
        digest=bytes.fromhex(ledger_head),
        journal_head=JOURNAL_GENESIS_V2,
        event_digest=bytes.fromhex(_DIGEST),
        stamp=1,
        metadata=1,
    )
    before = anchor.path.read_bytes()
    with pytest.raises(PermissionError, match="recovery-needed") as refused:
        _current(ledger, journal, anchor)
    assert isinstance(refused.value.__cause__, PermissionError)
    assert "adoption evidence is missing" in str(refused.value.__cause__)
    assert anchor.path.read_bytes() == before


def test_kind0_intent_and_kind3_closure_bind_real_frames(tmp_path: Path) -> None:
    """A complete kind-0 admission stays open until exact kind-3 closure."""
    ledger, journal, anchor = _stores(tmp_path)
    ledger_head = ledger.consume(permit_id=_ID, permit_digest=_DIGEST, expires_at=_TIME)
    with journal.locked(selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000) as lease:
        intent = lease.append_from_host(
            kind="operation-intent", body=_intent(ledger_head), host_time=_TIME
        )
    _append_anchor(
        anchor,
        kind=0,
        count=1,
        digest=bytes.fromhex(ledger_head),
        journal_head=bytes.fromhex(intent.record_head),
    )
    selected = _current(ledger, journal, anchor)
    assert selected.ledger_record_count == 1
    assert selected.binding.journal_state.blocks(
        effect_class="local-file-write", target_ref=_TARGET
    )
    with journal.locked(selected_head_digest=intent.record_head, max_bytes=100000) as lease:
        closure = lease.append_from_host(
            kind="operation-reconciled",
            body={
                "permit_id": _ID,
                "reconciliation_evidence_digest": _DIGEST,
                "operator_identity": "operator-1",
                "state_digest": _DIGEST,
            },
            host_time=_TIME,
        )
    pending = _current(ledger, journal, anchor)
    assert pending.binding.journal_state.blocks(
        effect_class="local-file-write", target_ref=_TARGET
    )
    _append_anchor(
        anchor,
        kind=3,
        count=1,
        digest=bytes.fromhex(ledger_head),
        journal_head=bytes.fromhex(closure.record_head),
        event_digest=bytes.fromhex(closure.record_digest),
    )
    closed = _current(ledger, journal, anchor)
    assert not closed.binding.journal_state.blocks(
        effect_class="local-file-write", target_ref=_TARGET
    )
    assert closed.binding.honoured_closure_digests == frozenset({closure.record_digest})


def test_mismatched_intent_refuses_with_no_anchor_mutation(tmp_path: Path) -> None:
    """A caller-supplied intent cannot relabel a consumed ledger UUID."""
    ledger, journal, anchor = _stores(tmp_path)
    ledger_head = ledger.consume(permit_id=_ID, permit_digest=_DIGEST, expires_at=_TIME)
    with journal.locked(selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000) as lease:
        wrong = lease.append_from_host(
            kind="operation-intent", body=_intent(ledger_head, permit_id=_OTHER), host_time=_TIME
        )
    _append_anchor(
        anchor,
        kind=0,
        count=1,
        digest=bytes.fromhex(ledger_head),
        journal_head=bytes.fromhex(wrong.record_head),
    )
    before = anchor.path.read_bytes()
    with pytest.raises(PermissionError, match="recovery-needed") as refused:
        _current(ledger, journal, anchor)
    assert isinstance(refused.value.__cause__, PermissionError)
    assert "matching journal intent" in str(refused.value.__cause__)
    assert anchor.path.read_bytes() == before


def test_old_magic_torn_tail_and_missing_first_record_refuse(tmp_path: Path) -> None:
    """V2.2 bytes cannot be silently upgraded or selected as V2.4."""
    ledger, journal, anchor = _stores(tmp_path)
    initial = anchor.path.read_bytes()
    anchor.path.write_bytes(b"RIGOR-PERMIT-ANCHOR-V2.2\n" + initial[len(ANCHOR_MAGIC_V24) :])
    with pytest.raises(PermissionError, match="header"):
        _current(ledger, journal, anchor)
    anchor.path.write_bytes(initial + b"x")
    with pytest.raises(PermissionError, match="recovery-needed"):
        _current(ledger, journal, anchor)
    anchor.path.write_bytes(ANCHOR_MAGIC_V24)
    with pytest.raises(PermissionError, match="initial record is absent"):
        _current(ledger, journal, anchor)


def test_wrong_journal_identity_and_owner_modes_refuse(tmp_path: Path) -> None:
    """An actual prefix in another journal inode or a loose mode is insufficient."""
    ledger, journal, anchor = _stores(tmp_path)
    identity = journal.snapshot(
        selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000
    ).identity
    with pytest.raises(PermissionError, match="journal identity"):
        anchor.current(
            ledger=ledger,
            journal=journal,
            evidence=_evidence(anchor),
            selected_journal_identity=replace(identity, inode=identity.inode + 1),
            max_journal_bytes=100000,
        )
    anchor.path.chmod(0o700)
    with pytest.raises(PermissionError, match="identity or length"):
        _current(ledger, journal, anchor)
    anchor.path.chmod(0o600)
    anchor.path.parent.chmod(0o500)
    with pytest.raises(PermissionError, match="directory is not owner-only"):
        anchor.current(
            ledger=ledger,
            journal=journal,
            evidence=_evidence(anchor),
            selected_journal_identity=identity,
            max_journal_bytes=100000,
        )


def test_relative_missing_and_substituted_anchor_path_refuse(tmp_path: Path) -> None:
    """The scanner never creates an absent anchor or follows a replacement link."""
    ledger, journal, anchor = _stores(tmp_path)
    identity = journal.snapshot(
        selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000
    ).identity
    with pytest.raises(ValueError, match="absolute path"):
        PermitLedgerAnchorStoreV2(Path("anchor.bin")).current(
            ledger=ledger,
            journal=journal,
            evidence=_evidence(anchor),
            selected_journal_identity=identity,
            max_journal_bytes=100000,
        )
    anchor.path.unlink()
    with pytest.raises(FileNotFoundError):
        _current(ledger, journal, anchor)
    anchor.path.symlink_to(tmp_path / "elsewhere")
    with pytest.raises(OSError):
        _current(ledger, journal, anchor)


def test_genesis_initializer_refuses_nonempty_ledger_or_journal(tmp_path: Path) -> None:
    """An unselected existing byte in either file cannot be reset by a new anchor."""
    first = tmp_path / "first"
    first.mkdir(mode=0o700)
    ledger = ConsumedPermitLedgerV2(first / "consumed.bin")
    journal = EffectJournalStoreV2(first / "effect.journal")
    anchor = PermitLedgerAnchorStoreV2(first / "anchor.bin")
    ledger.initialize()
    journal.initialize()
    ledger.consume(permit_id=_ID, permit_digest=_DIGEST, expires_at=_TIME)
    with pytest.raises(PermissionError, match="empty ledger"):
        anchor.initialize(ledger=ledger, journal=journal, max_journal_bytes=100000)
    assert not anchor.path.exists()

    second = tmp_path / "second"
    second.mkdir(mode=0o700)
    ledger2 = ConsumedPermitLedgerV2(second / "consumed.bin")
    journal2 = EffectJournalStoreV2(second / "effect.journal")
    anchor2 = PermitLedgerAnchorStoreV2(second / "anchor.bin")
    ledger2.initialize()
    genesis = journal2.initialize()
    with journal2.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        lease.append_from_host(
            kind="effect-intent",
            body={"permit_id": _ID, "part_index": 0, "pre_state_digest": None},
            host_time=_TIME,
        )
    with pytest.raises(PermissionError, match="empty journal"):
        anchor2.initialize(ledger=ledger2, journal=journal2, max_journal_bytes=100000)
    assert not anchor2.path.exists()


def test_recovery_record_waits_for_evidence_and_other_ledger_inode_refuses(tmp_path: Path) -> None:
    """The V2.4 reader rejects unverified recovery and a relabelled ledger."""
    ledger, journal, anchor = _stores(tmp_path)
    identity = journal.snapshot(
        selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000
    ).identity
    alternative = ConsumedPermitLedgerV2(anchor.path.parent / "other-ledger.bin")
    alternative.initialize()
    with pytest.raises(PermissionError, match="ledger identity"):
        anchor.current(
            ledger=alternative,
            journal=journal,
            evidence=_evidence(anchor),
            selected_journal_identity=identity,
            max_journal_bytes=100000,
        )
    _append_anchor(
        anchor,
        kind=1,
        count=0,
        digest=bytes.fromhex(_DIGEST),
        journal_head=JOURNAL_GENESIS_V2,
        event_digest=bytes.fromhex(_DIGEST),
        stamp=1,
        metadata=1,
    )
    with pytest.raises(PermissionError, match="recovery-needed") as refused:
        anchor.current(
            ledger=ledger,
            journal=journal,
            evidence=_evidence(anchor),
            selected_journal_identity=identity,
            max_journal_bytes=100000,
        )
    assert isinstance(refused.value.__cause__, PermissionError)
    assert "intent is missing" in str(refused.value.__cause__)


def test_real_anchor_kind1_resolves_published_root_intent(tmp_path: Path) -> None:
    """A pending selected intent blocks until its exact kind-1 anchor is durable."""
    ledger, journal, anchor = _stores(tmp_path)
    selected = _current(ledger, journal, anchor)
    damaged = b"x"
    offset = len(ANCHOR_MAGIC_V24) + ANCHOR_RECORD_V24.size
    intent = validate_anchor_final_intent_v2(
        {
            "domain": "rigor.permit-anchor-final-recovery.v2.4",
            "anchor_file": _file_identity(anchor.path),
            "ledger_file": _file_identity(ledger.path),
            "journal_file": _file_identity(journal.path),
            "prior_anchor_head": selected.anchor_log_head_digest,
            "prior_anchor_record_count": 1,
            "prior_ledger_record_count": 0,
            "prior_ledger_head": _INITIAL_HEAD.hex(),
            "prior_journal_head": JOURNAL_GENESIS_V2.hex(),
            "tail_offset": offset,
            "tail_length": 1,
            "captured_file_size": offset + 1,
            "removed_bytes_b64": base64.b64encode(damaged).decode("ascii"),
            "removed_digest": sha256(damaged).hexdigest(),
            "failure_class": "partial-tail",
            "operator_identity": "operator-1",
            "credential_proof_ref": _DIGEST,
            "recovery_code_digest": _DIGEST,
            "host_time": _TIME,
            "parent_intent_digest": None,
        }
    )
    evidence_digest = _evidence(anchor).publish(intent)
    with pytest.raises(PermissionError, match="recovery-needed"):
        _current(ledger, journal, anchor)
    _append_anchor(
        anchor,
        kind=1,
        count=0,
        digest=sha256(damaged).digest(),
        journal_head=JOURNAL_GENESIS_V2,
        event_digest=bytes.fromhex(evidence_digest),
        stamp=exact_recovery_stamp_us_v2(_TIME),
        metadata=1,
    )
    resolved = _current(ledger, journal, anchor)
    assert resolved.ledger_record_count == 0
    assert resolved.journal_head_digest == JOURNAL_GENESIS_V2.hex()


def test_real_anchor_kind2_adopts_complete_recovery_ledger_suffix(tmp_path: Path) -> None:
    """One checked recovery ledger record is adopted without fabricating an intent."""
    ledger, journal, anchor = _stores(tmp_path)
    selected = _current(ledger, journal, anchor)
    with ledger.path.open("ab") as writer:
        writer.write(b"x")
    ledger.recover_torn_tail(recovered_at=_TIME)
    with ledger.locked_snapshot(
        selected_count=0, selected_head_digest=_INITIAL_HEAD.hex()
    ) as snapshot:
        evidence = validate_anchor_adoption_evidence_v2(
            {
                "domain": "rigor.permit-anchor-recovery.v2.4",
                "anchor_file": _file_identity(anchor.path),
                "ledger_file": _file_identity(ledger.path),
                "journal_file": _file_identity(journal.path),
                "old_anchor_head": selected.anchor_log_head_digest,
                "old_ledger_record_count": 0,
                "new_ledger_record_count": 1,
                "old_ledger_head": _INITIAL_HEAD.hex(),
                "new_ledger_head": snapshot.head_digest,
                "old_journal_head": JOURNAL_GENESIS_V2.hex(),
                "new_journal_head": JOURNAL_GENESIS_V2.hex(),
                "adopted_ledger_record_digests": [snapshot.records[0].record_digest],
                "included_journal_record_digests": [],
                "consumed_uuids_digest": consumed_uuids_digest_v24(snapshot, 0, 1),
                "recovery_code_digest": _DIGEST,
                "host_time": _TIME,
            }
        )
        new_head = snapshot.head_digest
    evidence_digest = _evidence(anchor).publish(evidence)
    _append_anchor(
        anchor,
        kind=2,
        count=1,
        digest=bytes.fromhex(new_head),
        journal_head=JOURNAL_GENESIS_V2,
        event_digest=bytes.fromhex(evidence_digest),
        stamp=exact_recovery_stamp_us_v2(_TIME),
        metadata=1,
    )
    adopted = _current(ledger, journal, anchor)
    assert adopted.ledger_record_count == 1
    assert adopted.ledger_head_digest == new_head


def test_real_journal_recovery_intent_needs_anchored_audit_frame(tmp_path: Path) -> None:
    """A published journal intent stays pending through an unanchored audit append."""
    ledger, journal, anchor = _stores(tmp_path)
    selected = _current(ledger, journal, anchor)
    damaged = b"x"
    evidence = validate_journal_tail_intent_v2(
        {
            "domain": "rigor.effect-journal-tail-recovery.v2.1",
            "anchor_file": _file_identity(anchor.path),
            "ledger_file": _file_identity(ledger.path),
            "journal_file": _file_identity(journal.path),
            "selected_anchor_head": selected.anchor_log_head_digest,
            "selected_journal_head": JOURNAL_GENESIS_V2.hex(),
            "last_complete_journal_head": JOURNAL_GENESIS_V2.hex(),
            "old_size": len(JOURNAL_MAGIC_V2) + 1,
            "frame_offset": len(JOURNAL_MAGIC_V2),
            "declared_payload_length": None,
            "removed_length": 1,
            "removed_bytes_b64": base64.b64encode(damaged).decode("ascii"),
            "removed_digest": sha256(damaged).hexdigest(),
            "failure_class": "partial",
            "operator_identity": "operator-1",
            "credential_proof_ref": _DIGEST,
            "recovery_code_digest": _DIGEST,
            "host_time": _TIME,
            "parent_intent_digest": None,
        }
    )
    evidence_digest = _evidence(anchor).publish(evidence)
    with pytest.raises(PermissionError, match="journal recovery-needed"):
        _current(ledger, journal, anchor)
    with journal.locked(selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000) as lease:
        audit = lease.append_from_host(
            kind="journal-tail-recovery",
            body={
                "recovery_intent_digest": evidence_digest,
                "removed_digest": sha256(damaged).hexdigest(),
                "removed_length": 1,
                "operator_identity": "operator-1",
            },
            host_time=_TIME,
        )
    with pytest.raises(PermissionError, match="journal recovery-needed"):
        _current(ledger, journal, anchor)
    _append_anchor(
        anchor,
        kind=0,
        count=0,
        digest=_INITIAL_HEAD,
        journal_head=bytes.fromhex(audit.record_head),
    )
    resolved = _current(ledger, journal, anchor)
    assert resolved.journal_head_digest == audit.record_head


def test_anchored_journal_recovery_audit_requires_immutable_intent(tmp_path: Path) -> None:
    """A signed-looking anchor cannot make an orphan recovery frame evidence."""
    ledger, journal, anchor = _stores(tmp_path)
    with journal.locked(selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000) as lease:
        orphan = lease.append_from_host(
            kind="journal-tail-recovery",
            body={
                "recovery_intent_digest": _DIGEST,
                "removed_digest": sha256(b"x").hexdigest(),
                "removed_length": 1,
                "operator_identity": "operator-1",
            },
            host_time=_TIME,
        )
    _append_anchor(
        anchor,
        kind=0,
        count=0,
        digest=_INITIAL_HEAD,
        journal_head=bytes.fromhex(orphan.record_head),
    )
    with pytest.raises(PermissionError, match="recovery-needed: final tail damage"):
        _current(ledger, journal, anchor)


def test_verified_ledger_recovery_record_is_not_an_admission(tmp_path: Path) -> None:
    """The ledger-derived binding list excludes audited partial-tail recovery."""
    ledger, journal, anchor = _stores(tmp_path)
    with ledger.path.open("ab") as writer:
        writer.write(b"x")
    ledger.recover_torn_tail(recovered_at=_TIME)
    with ledger.locked_snapshot(
        selected_count=0, selected_head_digest=_INITIAL_HEAD.hex()
    ) as snapshot:
        assert snapshot.records[0].kind == 1
        with (
            journal.locked(
                selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000
            ) as lease,
            anchor.path.open("rb") as reader,
        ):
            verified = verify_anchor_prefix_v24(
                (reader.read()[len(ANCHOR_MAGIC_V24) :],),
                objects={},
                anchor_path=anchor.path,
                anchor_stat=os.fstat(reader.fileno()),
                ledger_path=ledger.path,
                ledger=snapshot,
                journal_path=journal.path,
                journal=lease.snapshot,
            )
        assert verified.binding.selection.ledger_record_count == 0
        assert verified.binding.journal_state.open_targets == frozenset()


def test_ledger_admission_binding_rejects_missing_verified_fields(tmp_path: Path) -> None:
    """A corrupted in-memory consumption cannot become an anchor admission."""
    ledger, journal, anchor = _stores(tmp_path)
    ledger.consume(permit_id=_ID, permit_digest=_DIGEST, expires_at=_TIME)
    with ledger.locked_snapshot(
        selected_count=0, selected_head_digest=_INITIAL_HEAD.hex()
    ) as snapshot:
        altered = replace(snapshot.records[0], permit_id=None)
        with (
            journal.locked(
                selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000
            ) as lease,
            anchor.path.open("rb") as reader,
            pytest.raises(PermissionError, match="consumption fields are absent"),
        ):
            verify_anchor_prefix_v24(
                (reader.read()[len(ANCHOR_MAGIC_V24) :],),
                objects={},
                anchor_path=anchor.path,
                anchor_stat=os.fstat(reader.fileno()),
                ledger_path=ledger.path,
                ledger=replace(snapshot, records=(altered,)),
                journal_path=journal.path,
                journal=lease.snapshot,
            )
