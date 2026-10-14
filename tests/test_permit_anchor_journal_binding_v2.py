# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — V2.4 anchor and V2.1 journal binding tests
"""Prove anchor heads against real journal frames and scoped closure replay."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from rigor_foundry._permit_ledger_records_v2 import _INITIAL_HEAD
from rigor_foundry.effect_journal_records_v2 import JOURNAL_GENESIS_V2
from rigor_foundry.effect_journal_v2 import EffectJournalSnapshotV2, EffectJournalStoreV2
from rigor_foundry.permit_anchor_journal_binding_v2 import (
    LedgerAdmissionBindingV24,
    verify_anchor_journal_binding_v24,
)
from rigor_foundry.permit_anchor_records_v2 import (
    ANCHOR_GENESIS_V24,
    ANCHOR_RECORD_V24,
    parse_anchor_record_v24,
)

_ID = "123e4567-e89b-12d3-a456-426614174000"
_DIGEST = "a" * 64
_LEDGER_HEAD = bytes.fromhex("b2" * 32)
_PATH = bytes.fromhex("c3" * 32)
_TIME = "2026-09-23T03:00:00Z"
_TARGET = {"form": "path", "value": "/srv/rigor/result"}


def _store(tmp_path: Path) -> tuple[EffectJournalStoreV2, str]:
    """Create one real journal behind an exact owner-only custody directory."""
    parent = tmp_path / "custody"
    parent.mkdir(mode=0o700)
    store = EffectJournalStoreV2(parent / "effect.journal")
    return store, store.initialize()


def _intent() -> dict[str, object]:
    """Build one complete typed operation intent bound to a ledger head."""
    return {
        "permit_id": _ID,
        "permit_digest": _DIGEST,
        "ledger_head": _LEDGER_HEAD.hex(),
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


def _anchor(
    prior: bytes,
    kind: int,
    *,
    count: int = 0,
    digest: bytes = _INITIAL_HEAD,
    journal: bytes = JOURNAL_GENESIS_V2,
    stamp: int = 0,
    metadata: int = 0,
    event: bytes = bytes(32),
) -> tuple[bytes, bytes]:
    """Return exact wire bytes and their independently parsed successor head."""
    raw = ANCHOR_RECORD_V24.pack(
        kind, count, digest, _PATH, 81, 92, stamp, metadata, journal, event, prior
    )
    return raw, parse_anchor_record_v24(raw, previous_head=prior).head


def _scenario(
    tmp_path: Path,
) -> tuple[EffectJournalSnapshotV2, tuple[bytes, ...], tuple[LedgerAdmissionBindingV24, ...]]:
    """Build admission, inert pending closure, then newly honoured reconciliation."""
    store, genesis = _store(tmp_path)
    with store.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        intent = lease.append_from_host(kind="operation-intent", body=_intent(), host_time=_TIME)
        pending = lease.append_from_host(
            kind="operation-reconciled",
            body={
                "permit_id": _ID,
                "reconciliation_evidence_digest": _DIGEST,
                "operator_identity": "operator-1",
                "state_digest": _DIGEST,
            },
            host_time=_TIME,
        )
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
    initial, head0 = _anchor(ANCHOR_GENESIS_V24, 0)
    admitted, head1 = _anchor(
        head0, 0, count=1, digest=_LEDGER_HEAD, journal=bytes.fromhex(intent.record_head)
    )
    inert, head2 = _anchor(
        head1, 0, count=1, digest=_LEDGER_HEAD, journal=bytes.fromhex(pending.record_head)
    )
    honoured, _ = _anchor(
        head2,
        3,
        count=1,
        digest=_LEDGER_HEAD,
        journal=bytes.fromhex(closure.record_head),
        event=bytes.fromhex(closure.record_digest),
    )
    binding = LedgerAdmissionBindingV24(1, _ID, _DIGEST, _LEDGER_HEAD.hex())
    return (
        store.snapshot(selected_head_digest=genesis, max_bytes=100000),
        (initial, admitted, inert, honoured),
        (binding,),
    )


def test_real_journal_pending_closure_is_inert_until_new_kind3(tmp_path: Path) -> None:
    """Kind 0 may select a pending closure but only later kind 3 honours a new frame."""
    journal, anchors, admissions = _scenario(tmp_path)
    pending = verify_anchor_journal_binding_v24(
        anchors[:-1], journal=journal, admissions=admissions
    )
    assert pending.journal_state.blocks(effect_class="local-file-write", target_ref=_TARGET)
    assert pending.honoured_closure_digests == frozenset()
    result = verify_anchor_journal_binding_v24(anchors, journal=journal, admissions=admissions)
    assert result.selection.ledger_head == _LEDGER_HEAD
    assert not result.journal_state.blocks(effect_class="local-file-write", target_ref=_TARGET)
    assert result.honoured_closure_digests == frozenset({journal.records[-1].record_digest})


def test_missing_or_wrong_admission_binding_refuses(tmp_path: Path) -> None:
    """A count increase needs the exact ledger-derived UUID, digest and head."""
    journal, anchors, admissions = _scenario(tmp_path)
    for bindings in (
        (),
        (replace(admissions[0], permit_id="123e4567-e89b-12d3-a456-426614174001"),),
        (replace(admissions[0], permit_digest="f" * 64),),
        (replace(admissions[0], ledger_head="f" * 64),),
    ):
        with pytest.raises(PermissionError, match="matching journal intent"):
            verify_anchor_journal_binding_v24(anchors, journal=journal, admissions=bindings)


def test_journal_only_advance_cannot_admit_unselected_intent(tmp_path: Path) -> None:
    """A consumed ledger record is required before any new operation intent is selected."""
    journal, anchors, admissions = _scenario(tmp_path)
    initial_head = parse_anchor_record_v24(anchors[0], previous_head=ANCHOR_GENESIS_V24).head
    forged, _ = _anchor(initial_head, 0, journal=bytes.fromhex(journal.records[0].record_head))
    with pytest.raises(PermissionError, match="journal-only"):
        verify_anchor_journal_binding_v24(
            (anchors[0], forged), journal=journal, admissions=admissions
        )


def test_closure_digest_must_name_last_new_closure_frame(tmp_path: Path) -> None:
    """A prior pending closure cannot become effective through a later kind 3."""
    journal, anchors, admissions = _scenario(tmp_path)
    prior = parse_anchor_record_v24(
        anchors[2],
        previous_head=parse_anchor_record_v24(
            anchors[1],
            previous_head=parse_anchor_record_v24(
                anchors[0], previous_head=ANCHOR_GENESIS_V24
            ).head,
        ).head,
    ).head
    wrong, _ = _anchor(
        prior,
        3,
        count=1,
        digest=_LEDGER_HEAD,
        journal=bytes.fromhex(journal.records[-1].record_head),
        event=bytes.fromhex(journal.records[1].record_digest),
    )
    with pytest.raises(PermissionError, match="new open operation"):
        verify_anchor_journal_binding_v24(
            (*anchors[:-1], wrong), journal=journal, admissions=admissions
        )


def test_unverified_journal_head_and_changed_memory_refuse(tmp_path: Path) -> None:
    """Neither an arbitrary head nor a modified in-memory frame can select content."""
    journal, anchors, admissions = _scenario(tmp_path)
    initial_head = parse_anchor_record_v24(anchors[0], previous_head=ANCHOR_GENESIS_V24).head
    forged, _ = _anchor(
        initial_head, 0, count=1, digest=_LEDGER_HEAD, journal=bytes.fromhex("e5" * 32)
    )
    with pytest.raises(PermissionError, match="verified prefix"):
        verify_anchor_journal_binding_v24(
            (anchors[0], forged), journal=journal, admissions=admissions
        )
    altered = replace(journal.records[0], body={"permit_id": _ID})
    with pytest.raises(PermissionError, match="record differs"):
        verify_anchor_journal_binding_v24(
            anchors,
            journal=replace(journal, records=(altered, *journal.records[1:])),
            admissions=admissions,
        )


def test_snapshot_and_admission_metadata_must_be_consistent(tmp_path: Path) -> None:
    """The binder refuses a non-genesis lease, altered terminal head or ambiguous input."""
    journal, anchors, admissions = _scenario(tmp_path)
    with pytest.raises(PermissionError, match="genesis selection"):
        verify_anchor_journal_binding_v24(
            anchors,
            journal=replace(journal, selected_record_count=1),
            admissions=admissions,
        )
    with pytest.raises(PermissionError, match="journal head differs"):
        verify_anchor_journal_binding_v24(
            anchors,
            journal=replace(journal, head_digest="f" * 64),
            admissions=admissions,
        )
    with pytest.raises(PermissionError, match="binding count repeats"):
        verify_anchor_journal_binding_v24(
            anchors, journal=journal, admissions=(*admissions, *admissions)
        )
    with pytest.raises(PermissionError, match="initial record is absent"):
        verify_anchor_journal_binding_v24((), journal=journal, admissions=())


def test_closure_anchor_cannot_select_a_new_intent(tmp_path: Path) -> None:
    """A kind 3 closure cannot smuggle the operation intent into its own segment."""
    journal, anchors, _ = _scenario(tmp_path)
    initial_head = parse_anchor_record_v24(anchors[0], previous_head=ANCHOR_GENESIS_V24).head
    adopted, adopted_head = _anchor(
        initial_head,
        2,
        count=1,
        digest=_LEDGER_HEAD,
        stamp=1,
        metadata=1,
        event=bytes.fromhex(_DIGEST),
    )
    closure, _ = _anchor(
        adopted_head,
        3,
        count=1,
        digest=_LEDGER_HEAD,
        journal=bytes.fromhex(journal.records[-1].record_head),
        event=bytes.fromhex(journal.records[-1].record_digest),
    )
    with pytest.raises(PermissionError, match="cannot admit an operation intent"):
        verify_anchor_journal_binding_v24(
            (anchors[0], adopted, closure), journal=journal, admissions=()
        )


def test_adopted_segments_refuse_repeated_operation_intent(tmp_path: Path) -> None:
    """Separate suffix adoptions cannot introduce the same permit twice."""
    store, genesis = _store(tmp_path)
    with store.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        first = lease.append_from_host(kind="operation-intent", body=_intent(), host_time=_TIME)
        second = lease.append_from_host(kind="operation-intent", body=_intent(), host_time=_TIME)
    initial, head0 = _anchor(ANCHOR_GENESIS_V24, 0)
    first_adoption, head1 = _anchor(
        head0,
        2,
        count=1,
        digest=_LEDGER_HEAD,
        journal=bytes.fromhex(first.record_head),
        stamp=1,
        metadata=1,
        event=bytes.fromhex(_DIGEST),
    )
    second_adoption, _ = _anchor(
        head1,
        2,
        count=2,
        digest=bytes.fromhex(_DIGEST),
        journal=bytes.fromhex(second.record_head),
        stamp=2,
        metadata=1,
        event=bytes.fromhex(_DIGEST),
    )
    with pytest.raises(PermissionError, match="intent repeats"):
        verify_anchor_journal_binding_v24(
            (initial, first_adoption, second_adoption),
            journal=store.snapshot(selected_head_digest=genesis, max_bytes=100000),
            admissions=(
                LedgerAdmissionBindingV24(1, _ID, _DIGEST, _LEDGER_HEAD.hex()),
                LedgerAdmissionBindingV24(2, _ID, _DIGEST, _DIGEST),
            ),
        )


def test_adoption_new_intent_must_match_adopted_consumption(tmp_path: Path) -> None:
    """A crash-leftover intent can open only its newly adopted ledger record."""
    store, genesis = _store(tmp_path)
    with store.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        intent = lease.append_from_host(kind="operation-intent", body=_intent(), host_time=_TIME)
    initial, prior = _anchor(ANCHOR_GENESIS_V24, 0)
    adopted, _ = _anchor(
        prior,
        2,
        count=1,
        digest=_LEDGER_HEAD,
        journal=bytes.fromhex(intent.record_head),
        stamp=1,
        metadata=1,
        event=bytes.fromhex(_DIGEST),
    )
    snapshot = store.snapshot(selected_head_digest=genesis, max_bytes=100000)
    binding = LedgerAdmissionBindingV24(1, _ID, _DIGEST, _LEDGER_HEAD.hex())
    result = verify_anchor_journal_binding_v24(
        (initial, adopted), journal=snapshot, admissions=(binding,)
    )
    assert result.journal_state.blocks(effect_class="local-file-write", target_ref=_TARGET)
    for bindings in (
        (),
        (replace(binding, permit_id="123e4567-e89b-12d3-a456-426614174001"),),
        (replace(binding, permit_digest="f" * 64),),
        (replace(binding, ledger_head="f" * 64),),
    ):
        with pytest.raises(PermissionError, match="matching adopted ledger consumption"):
            verify_anchor_journal_binding_v24(
                (initial, adopted), journal=snapshot, admissions=bindings
            )


def test_ordinary_admission_intent_must_be_last_selected_frame(tmp_path: Path) -> None:
    """The anchor cannot select a later status as if it were the admission intent."""
    store, genesis = _store(tmp_path)
    with store.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        lease.append_from_host(kind="operation-intent", body=_intent(), host_time=_TIME)
        status = lease.append_from_host(
            kind="terminated",
            body={"permit_id": _ID, "cgroup_id": "42", "status_evidence_digest": _DIGEST},
            host_time=_TIME,
        )
    initial, head0 = _anchor(ANCHOR_GENESIS_V24, 0)
    wrong, _ = _anchor(
        head0,
        0,
        count=1,
        digest=_LEDGER_HEAD,
        journal=bytes.fromhex(status.record_head),
    )
    with pytest.raises(PermissionError, match="matching journal intent"):
        verify_anchor_journal_binding_v24(
            (initial, wrong),
            journal=store.snapshot(selected_head_digest=genesis, max_bytes=100000),
            admissions=(LedgerAdmissionBindingV24(1, _ID, _DIGEST, _LEDGER_HEAD.hex()),),
        )
