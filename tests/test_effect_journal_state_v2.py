# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — effect-journal state replay tests
"""Replay real journal files against anchored and pending operation closures."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from rigor_foundry.effect_journal_state_v2 import replay_effect_journal_v2
from rigor_foundry.effect_journal_v2 import EffectJournalStoreV2

_FIRST = "123e4567-e89b-12d3-a456-426614174000"
_SECOND = "123e4567-e89b-12d3-a456-426614174001"
_DIGEST = "a" * 64
_TIME = "2026-09-23T03:00:00Z"
_TARGET = {"form": "path", "value": "/srv/rigor/result"}
_OTHER = {"form": "path", "value": "/srv/rigor/other"}


@pytest.mark.parametrize("kind", ["operation-partial", "trust-policy-activated", "key-revoked"])
def test_canonical_unsupported_event_refuses_before_operation_field_lookup(
    tmp_path: Path, kind: str
) -> None:
    """A valid frame outside this replay contract cannot be ignored or cause a missing-field error."""
    store, genesis = _store(tmp_path)
    bodies: dict[str, dict[str, object]] = {
        "operation-partial": {
            "permit_id": _FIRST,
            "parts_applied": [],
            "blocked_targets": [_TARGET],
            "evidence_digest": _DIGEST,
        },
        "trust-policy-activated": {
            "policy_digest": _DIGEST,
            "previous_policy_digest": _DIGEST,
            "activation_evidence_digest": _DIGEST,
            "root_signature": "a" * 128,
        },
        "key-revoked": {
            "key_fingerprint": _DIGEST,
            "compromised_since_seq": 1,
            "evidence_digest": _DIGEST,
            "root_signature": "a" * 128,
        },
    }
    with store.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        lease.append_from_host(kind=kind, body=bodies[kind], host_time=_TIME)
    before = store.path.read_bytes()
    snapshot = store.snapshot(selected_head_digest=genesis, max_bytes=100000)
    assert snapshot.records[0].kind == kind
    with pytest.raises(PermissionError, match="record kind is not replayable"):
        replay_effect_journal_v2(snapshot, honoured_closure_digests=frozenset())
    assert store.path.read_bytes() == before


def test_open_intent_blocks_ancestor_descendant_across_effect_classes(tmp_path: Path) -> None:
    """A read or second write cannot enter an overlapping open file target."""
    store, genesis = _store(tmp_path)
    parent = {"form": "path", "value": "/srv/rigor"}
    child = {"form": "path", "value": "/srv/rigor/result/child"}
    with store.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        lease.append_from_host(
            kind="operation-intent", body=_intent(_FIRST, parent), host_time=_TIME
        )
    open_state = replay_effect_journal_v2(
        store.snapshot(selected_head_digest=genesis, max_bytes=100000),
        honoured_closure_digests=frozenset(),
    )
    assert open_state.blocks(effect_class="read", target_ref=child)
    assert open_state.blocks(effect_class="git-commit", target_ref=parent)
    assert not open_state.blocks(
        effect_class="read", target_ref={"form": "path", "value": "/srv/rigorous"}
    )
    with pytest.raises(ValueError, match="class is unknown"):
        open_state.blocks(effect_class="unknown", target_ref=child)
    second = _intent(_SECOND, child)
    parts = cast(list[dict[str, object]], second["parts"])
    parts[0]["effect_class"] = "read"
    with store.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        lease.append_from_host(kind="operation-intent", body=second, host_time=_TIME)
    with pytest.raises(PermissionError, match="targets overlap"):
        replay_effect_journal_v2(
            store.snapshot(selected_head_digest=genesis, max_bytes=100000),
            honoured_closure_digests=frozenset(),
        )


def _store(tmp_path: Path) -> tuple[EffectJournalStoreV2, str]:
    """Create one real owner-only journal for a replay scenario."""
    parent = tmp_path / "custody"
    parent.mkdir(mode=0o700)
    store = EffectJournalStoreV2(parent / "effect.journal")
    return store, store.initialize()


def _intent(
    permit_id: str, target_ref: dict[str, str], atomicity: str = "atomic"
) -> dict[str, object]:
    """Build the retained registry-derived operation fields for a real frame."""
    return {
        "permit_id": permit_id,
        "permit_digest": _DIGEST,
        "ledger_head": _DIGEST,
        "effect_target_digest": _DIGEST,
        "decision_digest": _DIGEST,
        "grant_snapshot_digest": _DIGEST,
        "adapter_operations_digest": _DIGEST,
        "operation_key": "write-artifact",
        "cgroup_id": "42" if permit_id == _FIRST else "43",
        "atomicity": atomicity,
        "parts": [
            {
                "index": 0,
                "effect_class": "local-file-write",
                "target_ref": target_ref,
                "route_digest": _DIGEST,
                "operation_variant": "default",
            }
        ],
    }


def test_pending_closure_blocks_only_its_target_until_kind3_is_verified(tmp_path: Path) -> None:
    """A complete journal closure remains inert without its exact anchor reference."""
    store, genesis = _store(tmp_path)
    with store.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        lease.append_from_host(
            kind="operation-intent", body=_intent(_FIRST, _TARGET), host_time=_TIME
        )
        lease.append_from_host(
            kind="effect-intent",
            body={"permit_id": _FIRST, "part_index": 0, "pre_state_digest": None},
            host_time=_TIME,
        )
        lease.append_from_host(
            kind="effect-complete",
            body={"permit_id": _FIRST, "part_index": 0, "post_state_digest": _DIGEST},
            host_time=_TIME,
        )
        closure = lease.append_from_host(
            kind="operation-complete",
            body={"permit_id": _FIRST, "parts_result_digest": _DIGEST},
            host_time=_TIME,
        )
        lease.append_from_host(
            kind="operation-intent", body=_intent(_SECOND, _OTHER), host_time=_TIME
        )
    snapshot = store.snapshot(selected_head_digest=genesis, max_bytes=100000)
    pending = replay_effect_journal_v2(snapshot, honoured_closure_digests=frozenset())
    assert pending.blocks(effect_class="local-file-write", target_ref=_TARGET)
    assert pending.blocks(effect_class="local-file-write", target_ref=_OTHER)
    assert pending.operations[0].pending_closure_digests == (closure.record_digest,)
    with pytest.raises(PermissionError, match="outside selected prefix"):
        replay_effect_journal_v2(
            snapshot, honoured_closure_digests=frozenset({closure.record_digest})
        )
    selected_closure = store.snapshot(selected_head_digest=closure.record_head, max_bytes=100000)
    anchored = replay_effect_journal_v2(
        selected_closure, honoured_closure_digests=frozenset({closure.record_digest})
    )
    assert not anchored.blocks(effect_class="local-file-write", target_ref=_TARGET)
    assert anchored.blocks(effect_class="local-file-write", target_ref=_OTHER)
    assert anchored.operations[0].honoured_closure_digest == closure.record_digest


def test_new_reconciliation_can_close_prior_pending_closure(tmp_path: Path) -> None:
    """A crash-leftover closure is never retroactively honoured by later bytes."""
    store, genesis = _store(tmp_path)
    with store.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        lease.append_from_host(
            kind="operation-intent", body=_intent(_FIRST, _TARGET), host_time=_TIME
        )
        first = lease.append_from_host(
            kind="operation-reconciled",
            body={
                "permit_id": _FIRST,
                "reconciliation_evidence_digest": _DIGEST,
                "operator_identity": "operator-1",
                "state_digest": _DIGEST,
            },
            host_time=_TIME,
        )
        second = lease.append_from_host(
            kind="operation-reconciled",
            body={
                "permit_id": _FIRST,
                "reconciliation_evidence_digest": _DIGEST,
                "operator_identity": "operator-1",
                "state_digest": _DIGEST,
            },
            host_time=_TIME,
        )
    state = replay_effect_journal_v2(
        store.snapshot(selected_head_digest=second.record_head, max_bytes=100000),
        honoured_closure_digests=frozenset({second.record_digest}),
    )
    assert state.operations[0].pending_closure_digests == (first.record_digest,)
    assert not state.blocks(effect_class="local-file-write", target_ref=_TARGET)


def test_duplicate_target_or_unknown_operation_refuses_replay(tmp_path: Path) -> None:
    """A second open intent cannot overlap one target or invent prior work."""
    store, genesis = _store(tmp_path)
    with store.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        lease.append_from_host(
            kind="operation-intent", body=_intent(_FIRST, _TARGET), host_time=_TIME
        )
        lease.append_from_host(
            kind="operation-intent", body=_intent(_SECOND, _TARGET), host_time=_TIME
        )
    with pytest.raises(PermissionError, match="targets overlap"):
        replay_effect_journal_v2(
            store.snapshot(selected_head_digest=genesis, max_bytes=100000),
            honoured_closure_digests=frozenset(),
        )
    other_root = tmp_path / "another"
    other_root.mkdir()
    second_store, second_genesis = _store(other_root)
    with second_store.locked(selected_head_digest=second_genesis, max_bytes=100000) as lease:
        lease.append_from_host(
            kind="effect-intent",
            body={"permit_id": _FIRST, "part_index": 0, "pre_state_digest": None},
            host_time=_TIME,
        )
    with pytest.raises(PermissionError, match="unknown operation"):
        replay_effect_journal_v2(
            second_store.snapshot(selected_head_digest=second_genesis, max_bytes=100000),
            honoured_closure_digests=frozenset(),
        )


def test_forged_memory_record_and_missing_anchor_closure_refuse(tmp_path: Path) -> None:
    """The replay refuses altered in-memory body fields and non-existent closure digests."""
    store, genesis = _store(tmp_path)
    with store.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        lease.append_from_host(
            kind="operation-intent", body=_intent(_FIRST, _TARGET), host_time=_TIME
        )
    snapshot = store.snapshot(selected_head_digest=genesis, max_bytes=100000)
    altered_record = replace(snapshot.records[0], body={"permit_id": _SECOND})
    with pytest.raises(PermissionError, match="record differs"):
        replay_effect_journal_v2(
            replace(snapshot, records=(altered_record,)),
            honoured_closure_digests=frozenset(),
        )
    with pytest.raises(PermissionError, match="missing closure"):
        replay_effect_journal_v2(snapshot, honoured_closure_digests=frozenset({"b" * 64}))


def test_duplicate_operation_id_and_intra_operation_target_refuse(tmp_path: Path) -> None:
    """Replay rejects both a repeated permit and duplicate targets inside one intent."""
    store, genesis = _store(tmp_path)
    with store.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        lease.append_from_host(
            kind="operation-intent", body=_intent(_FIRST, _TARGET), host_time=_TIME
        )
        lease.append_from_host(
            kind="operation-intent", body=_intent(_FIRST, _OTHER), host_time=_TIME
        )
    with pytest.raises(PermissionError, match="intent repeats"):
        replay_effect_journal_v2(
            store.snapshot(selected_head_digest=genesis, max_bytes=100000),
            honoured_closure_digests=frozenset(),
        )
    other_root = tmp_path / "other"
    other_root.mkdir()
    second, second_genesis = _store(other_root)
    repeated = _intent(_FIRST, _TARGET)
    parts = repeated["parts"]
    assert isinstance(parts, list)
    parts.append({**parts[0], "index": 1})
    with second.locked(selected_head_digest=second_genesis, max_bytes=100000) as lease:
        lease.append_from_host(kind="operation-intent", body=repeated, host_time=_TIME)
    with pytest.raises(PermissionError, match="targets overlap"):
        replay_effect_journal_v2(
            second.snapshot(selected_head_digest=second_genesis, max_bytes=100000),
            honoured_closure_digests=frozenset(),
        )


def test_status_and_leaf_records_do_not_close_operation(tmp_path: Path) -> None:
    """A supervisor status and orphan-leaf audit remain non-closure data."""
    store, genesis = _store(tmp_path)
    with store.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        lease.append_from_host(
            kind="operation-intent", body=_intent(_FIRST, _TARGET), host_time=_TIME
        )
        lease.append_from_host(
            kind="terminated",
            body={"permit_id": _FIRST, "cgroup_id": "42", "status_evidence_digest": _DIGEST},
            host_time=_TIME,
        )
        lease.append_from_host(
            kind="cleared-orphan-leaf",
            body={
                "cgroup_id": "77",
                "operator_identity": "operator-1",
                "status_evidence_digest": _DIGEST,
            },
            host_time=_TIME,
        )
        lease.append_from_host(
            kind="journal-tail-recovery",
            body={
                "recovery_intent_digest": _DIGEST,
                "removed_digest": _DIGEST,
                "removed_length": 2,
                "operator_identity": "operator-1",
            },
            host_time=_TIME,
        )
    state = replay_effect_journal_v2(
        store.snapshot(selected_head_digest=genesis, max_bytes=100000),
        honoured_closure_digests=frozenset(),
    )
    assert state.operations[0].open
    assert state.blocks(effect_class="local-file-write", target_ref=_TARGET)
    other_root = tmp_path / "wrong-status"
    other_root.mkdir()
    second, second_genesis = _store(other_root)
    with second.locked(selected_head_digest=second_genesis, max_bytes=100000) as lease:
        lease.append_from_host(
            kind="operation-intent", body=_intent(_FIRST, _TARGET), host_time=_TIME
        )
        lease.append_from_host(
            kind="terminated",
            body={"permit_id": _FIRST, "cgroup_id": "99", "status_evidence_digest": _DIGEST},
            host_time=_TIME,
        )
    with pytest.raises(PermissionError, match="cgroup differs"):
        replay_effect_journal_v2(
            second.snapshot(selected_head_digest=second_genesis, max_bytes=100000),
            honoured_closure_digests=frozenset(),
        )


@pytest.mark.parametrize(
    ("events", "expected"),
    [
        (
            [
                (
                    "effect-complete",
                    {"permit_id": _FIRST, "part_index": 0, "post_state_digest": None},
                )
            ],
            "part transition",
        ),
        (
            [("effect-intent", {"permit_id": _FIRST, "part_index": 1, "pre_state_digest": None})],
            "part index is absent",
        ),
        (
            [
                (
                    "effect-intent",
                    {"permit_id": _FIRST, "part_index": 0, "pre_state_digest": None},
                ),
                (
                    "effect-intent",
                    {"permit_id": _FIRST, "part_index": 0, "pre_state_digest": None},
                ),
            ],
            "part transition",
        ),
        (
            [("operation-complete", {"permit_id": _FIRST, "parts_result_digest": _DIGEST})],
            "completion lacks completed parts",
        ),
        (
            [
                (
                    "operation-rolled-back",
                    {"permit_id": _FIRST, "rollback_evidence_digest": _DIGEST},
                )
            ],
            "rollback atomicity differs",
        ),
    ],
)
def test_part_and_closure_order_refuses(
    tmp_path: Path, events: list[tuple[str, dict[str, object]]], expected: str
) -> None:
    """Malformed part order and unsupported closure cannot release a target."""
    store, genesis = _store(tmp_path)
    with store.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        lease.append_from_host(
            kind="operation-intent", body=_intent(_FIRST, _TARGET), host_time=_TIME
        )
        for kind, body in events:
            lease.append_from_host(kind=kind, body=body, host_time=_TIME)
    with pytest.raises(PermissionError, match=expected):
        replay_effect_journal_v2(
            store.snapshot(selected_head_digest=genesis, max_bytes=100000),
            honoured_closure_digests=frozenset(),
        )


def test_failed_part_then_anchored_rollback_closes_under_declared_atomicity(
    tmp_path: Path,
) -> None:
    """An all-or-nothing rollback can close a failed part only when selected by anchor."""
    store, genesis = _store(tmp_path)
    with store.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        lease.append_from_host(
            kind="operation-intent",
            body=_intent(_FIRST, _TARGET, "all-or-nothing-journalled"),
            host_time=_TIME,
        )
        lease.append_from_host(
            kind="effect-intent",
            body={"permit_id": _FIRST, "part_index": 0, "pre_state_digest": None},
            host_time=_TIME,
        )
        lease.append_from_host(
            kind="effect-failed",
            body={
                "permit_id": _FIRST,
                "part_index": 0,
                "post_state_digest": None,
                "failure_code": "adapter-error",
            },
            host_time=_TIME,
        )
        rollback = lease.append_from_host(
            kind="operation-rolled-back",
            body={"permit_id": _FIRST, "rollback_evidence_digest": _DIGEST},
            host_time=_TIME,
        )
    state = replay_effect_journal_v2(
        store.snapshot(selected_head_digest=rollback.record_head, max_bytes=100000),
        honoured_closure_digests=frozenset({rollback.record_digest}),
    )
    assert state.operations[0].part_states == ("failed",)
    assert not state.operations[0].open
    assert not state.blocks(effect_class="local-file-write", target_ref=_TARGET)


def test_pending_or_honoured_closure_rejects_later_part_events(tmp_path: Path) -> None:
    """A pending closure needs fresh reconciliation; a closed operation cannot restart parts."""
    store, genesis = _store(tmp_path)
    with store.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        lease.append_from_host(
            kind="operation-intent", body=_intent(_FIRST, _TARGET), host_time=_TIME
        )
        closure = lease.append_from_host(
            kind="operation-reconciled",
            body={
                "permit_id": _FIRST,
                "reconciliation_evidence_digest": _DIGEST,
                "operator_identity": "operator-1",
                "state_digest": _DIGEST,
            },
            host_time=_TIME,
        )
        lease.append_from_host(
            kind="effect-intent",
            body={"permit_id": _FIRST, "part_index": 0, "pre_state_digest": None},
            host_time=_TIME,
        )
    snapshot = store.snapshot(selected_head_digest=closure.record_head, max_bytes=100000)
    with pytest.raises(PermissionError, match="pending closure needs reconciliation"):
        replay_effect_journal_v2(snapshot, honoured_closure_digests=frozenset())
    with pytest.raises(PermissionError, match="closed operation changed"):
        replay_effect_journal_v2(
            snapshot, honoured_closure_digests=frozenset({closure.record_digest})
        )


def test_forged_snapshot_head_count_and_prefix_refuse(tmp_path: Path) -> None:
    """In-memory metadata cannot substitute for the exact verified frame chain."""
    store, genesis = _store(tmp_path)
    with store.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        lease.append_from_host(
            kind="operation-intent", body=_intent(_FIRST, _TARGET), host_time=_TIME
        )
    snapshot = store.snapshot(selected_head_digest=genesis, max_bytes=100000)
    for altered, expected in (
        (replace(snapshot, head_digest="b" * 64), "replay head differs"),
        (replace(snapshot, selected_record_count=2), "selected count differs"),
        (replace(snapshot, selected_record_count=-1), "selected count differs"),
        (replace(snapshot, selected_head_digest="b" * 64), "selected prefix differs"),
    ):
        with pytest.raises(PermissionError, match=expected):
            replay_effect_journal_v2(altered, honoured_closure_digests=frozenset())


def test_second_nonreconciliation_closure_cannot_supersede_pending_one(tmp_path: Path) -> None:
    """A crash-leftover closure permits only a new operator reconciliation candidate."""
    store, genesis = _store(tmp_path)
    with store.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        lease.append_from_host(
            kind="operation-intent", body=_intent(_FIRST, _TARGET), host_time=_TIME
        )
        lease.append_from_host(
            kind="effect-intent",
            body={"permit_id": _FIRST, "part_index": 0, "pre_state_digest": None},
            host_time=_TIME,
        )
        lease.append_from_host(
            kind="effect-complete",
            body={"permit_id": _FIRST, "part_index": 0, "post_state_digest": _DIGEST},
            host_time=_TIME,
        )
        closure_body: dict[str, object] = {
            "permit_id": _FIRST,
            "parts_result_digest": _DIGEST,
        }
        lease.append_from_host(kind="operation-complete", body=closure_body, host_time=_TIME)
        lease.append_from_host(kind="operation-complete", body=closure_body, host_time=_TIME)
    with pytest.raises(PermissionError, match="pending closure needs new reconciliation"):
        replay_effect_journal_v2(
            store.snapshot(selected_head_digest=genesis, max_bytes=100000),
            honoured_closure_digests=frozenset(),
        )
