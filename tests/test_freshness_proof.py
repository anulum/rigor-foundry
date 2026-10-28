# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — qualitative freshness subject and invalidation tests
"""Exercise complete original policy binding without presenting metadata as current authority."""

from __future__ import annotations

import json
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest
from test_context_owner_proof import proof as original_proof
from test_policy_model_inputs import budget
from test_source_component_reader import components
from test_typed_object_reference import reference

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.context_owner_observations import ContextProducerObservation1, OwnerObservation
from rigor_foundry.context_owner_proof import OwnerProof1
from rigor_foundry.freshness_proof import (
    FreshnessProof1,
    InvalidatorObservation1,
    InvalidatorState,
    freshness_reference_count,
)
from rigor_foundry.policy_source_reads import read_policy_document
from rigor_foundry.rule_chain_pack_v2 import FreshnessMode, FreshnessPolicyV2
from rigor_foundry.source_component_reader import PolicyComponent1


def declared_proof(subject: str, snapshot: str = "subject-snapshot") -> OwnerProof1:
    """Build an actual independent observation preimage; no installed owner is authenticated here."""
    original = original_proof()
    observation = ContextProducerObservation1(
        original.owner_id,
        original.owner_contract.ref_digest,
        original.source_object.ref_digest,
        snapshot,
        "declared-subject",
        subject,
        (OwnerObservation("source.current", "known", True, subject),),
    )
    result = OwnerProof1.build(
        owner_id=original.owner_id,
        owner_class=original.owner_class,
        owner_contract=original.owner_contract,
        source_object=original.source_object,
        subject_digest=subject,
        snapshot_id=snapshot,
        observation_digest=observation.digest(budget=budget()),
        budget=budget(),
    )
    observation.verify_proof_binding(result, budget=budget())
    return result


def freshness_policy(
    *, mode: FreshnessMode = "mutable-state", invalidators: tuple[str, ...] = ("source-change",)
) -> FreshnessPolicyV2:
    """Retain every original qualitative policy field using its actual unchanged parser."""
    data = components()[2].to_dict()
    data["mode"] = mode
    data["invalidator_ids"] = list(invalidators)
    data.pop("policy_digest")
    data["policy_digest"] = canonical_digest(data)
    return FreshnessPolicyV2.from_dict(data)


def freshness_proof(
    *,
    subject: str | None = None,
    mode: FreshnessMode = "mutable-state",
    state: InvalidatorState = "clear",
) -> FreshnessProof1:
    """Bind exact independently declared subject and invalidator snapshots without a freshness PASS."""
    subject = (
        sha256(b"Complete exact observed artifact.\n").hexdigest() if subject is None else subject
    )
    policy = freshness_policy(mode=mode)
    observation = InvalidatorObservation1.build(
        invalidator_id=policy.invalidator_ids[0],
        state=state,
        proof=declared_proof(
            sha256(b"Independent invalidator observation.\n").hexdigest(), "invalidator-snapshot"
        )
        if state == "clear"
        else None,
        budget=budget(),
    )
    return FreshnessProof1.build(
        policy=PolicyComponent1(policy, budget()).reference(),
        subject_digest=subject,
        mode=mode,
        subject_proof=declared_proof(subject),
        invalidators=(observation,),
        snapshot_id="subject-snapshot",
        budget=budget(),
    )


@pytest.mark.parametrize("mode", ["immutable-object", "mutable-state"])
@pytest.mark.parametrize("state", ["clear", "invalid", "unknown"])
def test_complete_policy_binding_preserves_every_state_and_separate_snapshot(
    mode: FreshnessMode, state: InvalidatorState
) -> None:
    """Structural policy binding preserves nonpassing states and does not invent a numeric TTL."""
    value = freshness_proof(mode=mode, state=state)
    data = value.to_dict(budget=budget())
    assert FreshnessProof1.from_dict(data, budget=budget()) == value
    value.verify_policy_binding(freshness_policy(mode=mode), budget=budget())
    assert data.pop("proof_digest") == canonical_digest(data)
    assert value.subject_proof.subject_digest == value.subject_digest
    assert value.subject_proof.snapshot_id == value.snapshot_id
    assert value.invalidators[0].state == state
    assert not {"freshness_seconds", "expires_at", "observed_at", "accepted", "pass"}.intersection(
        data
    )
    if state == "clear":
        assert value.invalidators[0].proof is not None
        assert value.invalidators[0].proof.snapshot_id != value.snapshot_id


def test_real_file_parser_and_complete_independent_proof_digests(tmp_path: Path) -> None:
    """Real bounded file parsing retains exact subject/proof preimages and duplicate-key refusal."""
    value = freshness_proof()
    path = tmp_path / "freshness.json"
    path.write_text(json.dumps(value.to_dict(budget=budget())), encoding="utf-8")
    assert (
        FreshnessProof1.from_dict(read_policy_document(path, budget=budget()), budget=budget())
        == value
    )
    path.write_text('{"mode":"mutable-state","mode":"immutable-object"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        read_policy_document(path, budget=budget())
    assert value.subject_digest != value.proof_digest
    assert value.subject_proof.proof_digest != value.proof_digest


@pytest.mark.parametrize("state", ["clear", "invalid", "unknown"])
def test_invalidator_round_trip_and_optional_proofs_remain_explicit(
    state: InvalidatorState,
) -> None:
    """Proof-bearing states retain original metadata; invalid/unknown null remains a distinct declaration."""
    proof = declared_proof(sha256(b"invalidator").hexdigest())
    value = InvalidatorObservation1.build(
        invalidator_id="source-change", state=state, proof=proof, budget=budget()
    )
    data = value.to_dict(budget=budget())
    assert InvalidatorObservation1.from_dict(data, budget=budget()) == value
    assert data.pop("observation_digest") == canonical_digest(data)
    if state != "clear":
        missing = InvalidatorObservation1.build(
            invalidator_id="source-change", state=state, proof=None, budget=budget()
        )
        assert missing.to_dict(budget=budget())["proof"] is None
    with pytest.raises(ValueError, match="clear invalidator"):
        InvalidatorObservation1.build(
            invalidator_id="source-change", state="clear", proof=None, budget=budget()
        )


@pytest.mark.parametrize(
    "field,bad",
    [
        ("schema_version", "2.0"),
        ("object_kind", "other"),
        ("invalidator_id", "bad identity"),
        ("state", "passing"),
        ("state", True),
        ("proof", {}),
        ("proof", None),
        ("observation_digest", "0" * 64),
    ],
)
def test_rehashed_malformed_invalidator_cannot_establish_clear(field: str, bad: object) -> None:
    """Neither an altered state nor rehashed original envelope can replace the required exact contract."""
    data = freshness_proof().invalidators[0].to_dict(budget=budget())
    data.pop("observation_digest")
    data[field] = bad
    digest = "0" * 64 if field == "observation_digest" else canonical_digest(data)
    with pytest.raises(ValueError):
        InvalidatorObservation1.from_dict({**data, "observation_digest": digest}, budget=budget())


@pytest.mark.parametrize(
    "field,bad",
    [
        ("schema_version", "2.0"),
        ("object_kind", "other"),
        ("policy", reference().to_dict()),
        ("subject_digest", "0" * 64),
        ("mode", "numeric"),
        ("snapshot_id", "other"),
        ("subject_proof", {}),
        ("invalidators", {}),
        ("invalidators", [42]),
        ("proof_digest", "0" * 64),
    ],
)
def test_rehashed_wrong_subject_snapshot_format_and_children_refuse(
    field: str, bad: object
) -> None:
    """Rehashing cannot retarget an independent original subject proof or change qualitative policy syntax."""
    data = freshness_proof().to_dict(budget=budget())
    data.pop("proof_digest")
    data[field] = bad
    digest = "0" * 64 if field == "proof_digest" else canonical_digest(data)
    with pytest.raises(ValueError):
        FreshnessProof1.from_dict({**data, "proof_digest": digest}, budget=budget())


def test_complete_selected_policy_mode_and_invalidator_membership_are_checked() -> None:
    """Missing/foreign policy invalidators and mode mismatch refuse without emitting a freshness verdict."""
    value = freshness_proof()
    with pytest.raises(ValueError, match="actual original freshness"):
        value.verify_policy_binding({}, budget=budget())
    with pytest.raises(ValueError, match="exact selected policy"):
        value.verify_policy_binding(freshness_policy(mode="immutable-object"), budget=budget())
    for mode, invalidators in [("immutable-object", value.invalidators), ("mutable-state", ())]:
        data = value.to_dict(budget=budget())
        data["mode"] = mode
        data["invalidators"] = [row.to_dict(budget=budget()) for row in invalidators]
        data.pop("proof_digest")
        data["proof_digest"] = canonical_digest(data)
        changed = FreshnessProof1.from_dict(data, budget=budget())
        with pytest.raises(ValueError, match="exact selected policy"):
            changed.verify_policy_binding(freshness_policy(), budget=budget())
    with pytest.raises(ValueError, match="exact selected policy"):
        value.verify_policy_binding(
            freshness_policy(invalidators=("source-change", "key-revocation")), budget=budget()
        )


def test_allocations_bound_nested_proofs_before_their_parsers_run() -> None:
    """The complete one-invalidator allocation is exactly6 and includes both original proof pairs."""
    value = freshness_proof()
    data = value.to_dict(budget=budget())
    assert freshness_reference_count(value, budget=budget(references=6)) == 6
    assert freshness_reference_count(data, budget=budget(references=6)) == 6
    assert FreshnessProof1.from_dict(data, budget=budget(references=6)) == value
    for maximum in [3, 5]:
        with pytest.raises(ValueError, match="reference budget"):
            value.to_dict(budget=budget(references=maximum))
        with pytest.raises(ValueError, match=r"bounded array|reference budget"):
            FreshnessProof1.from_dict(data, budget=budget(references=maximum))


def test_direct_mutations_sorted_sets_and_closed_envelopes_are_rechecked() -> None:
    """Direct dataclasses, foreign children, reordered sets and ignored fields cannot bypass owning checks."""
    value = freshness_proof()
    row = value.invalidators[0]
    foreign = InvalidatorObservation1.build(
        invalidator_id="another-change", state="unknown", proof=None, budget=budget()
    )
    malformed = [
        replace(value, proof_digest="0" * 64),
        replace(value, invalidators=cast(tuple[InvalidatorObservation1, ...], [])),
        replace(value, invalidators=cast(tuple[InvalidatorObservation1, ...], ({},))),
        replace(value, invalidators=(row, row)),
        replace(value, invalidators=(row, foreign)),
        replace(value, subject_proof=cast(OwnerProof1, {})),
    ]
    for changed in malformed:
        with pytest.raises(ValueError):
            changed.to_dict(budget=budget())
    with pytest.raises(ValueError, match="invalidator observation digest"):
        replace(row, observation_digest="0" * 64).to_dict(budget=budget())
    with pytest.raises(ValueError, match="actual original owner proof"):
        replace(row, proof=cast(OwnerProof1, {})).to_dict(budget=budget())
    for changed_wire in [
        {**value.to_dict(budget=budget()), "expires_at": "later"},
        {"schema_version": "1.0"},
    ]:
        with pytest.raises(ValueError):
            FreshnessProof1.from_dict(changed_wire, budget=budget())
    for changed_wire in [
        {**row.to_dict(budget=budget()), "verified": True},
        {"schema_version": "1.0"},
    ]:
        with pytest.raises(ValueError):
            InvalidatorObservation1.from_dict(changed_wire, budget=budget())
