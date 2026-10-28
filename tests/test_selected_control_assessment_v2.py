# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — exact selected assessment inputs tests
"""Exercise actual owner references and original signed review bodies without gate admission."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from signing_fixtures import trust_store
from test_assessment_evidence_validation import attestation
from test_control_assessment import adapter_lock, evidence, pack
from test_control_definition_v2 import qualitative_control
from test_evidence_reference_v2 import evidence_record
from test_policy_model_inputs import budget
from test_quality_projection_v3 import projection
from test_standard_pack import control
from test_typed_object_reference import reference

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.control_assessment import AssessmentStatus, EvidenceReference
from rigor_foundry.effective_profile import AdapterLock
from rigor_foundry.policy_source_reads import read_policy_document
from rigor_foundry.quality_projection_v3 import QualityProjectionRowV3
from rigor_foundry.review_attestation import ReviewerAttestation
from rigor_foundry.rule_scope import RuleScope1
from rigor_foundry.selected_control_assessment_v2 import (
    AssessmentApplicability,
    SelectedControlAssessment2,
    validate_selected_legacy_pass,
)
from rigor_foundry.source_component_reader import PolicyComponent1
from rigor_foundry.standard_pack import ControlDefinition
from rigor_foundry.task_context import TASK_CONTEXT_EVENTS
from rigor_foundry.trust import TrustedPublicKey, VerificationTrustStore
from rigor_foundry.typed_object_reference import TypedObjectRef1


def assessment(
    *,
    qualitative: bool = True,
    applicability: AssessmentApplicability = "true",
    status: AssessmentStatus = "unassessed",
) -> SelectedControlAssessment2:
    """Bind actual source/control/evidence metadata without fabricating an enclosing profile lock."""
    row = projection(qualitative=qualitative)
    item = (
        evidence_record().object_reference(budget=budget())
        if qualitative
        else PolicyComponent1(evidence(), budget()).reference()
    )
    return SelectedControlAssessment2.build(
        lock_digest="1" * 64,
        quality_projection_digest="2" * 64,
        task_context_digest="3" * 64,
        event_request_digest="4" * 64,
        control=row.control,
        contract_case=row.contract_case,
        applicability=applicability,
        status=status,
        evidence=(item,),
        reviews=(),
        assessor="source-assessor",
        assessed_at="2026-07-15T12:00:00Z",
        reason_code="requires-current-owner-verification",
        budget=budget(),
    )


@pytest.mark.parametrize("qualitative", [False, True])
def test_actual_original_and_qualitative_bindings_keep_complete_wire(qualitative: bool) -> None:
    """The public declaration and binding preserve each actual control generation independently."""
    value = assessment(qualitative=qualitative)
    wire = value.to_dict(budget=budget())
    assert SelectedControlAssessment2.from_dict(wire, budget=budget()) == value
    value.verify_quality_binding(
        projection(qualitative=qualitative),
        qualitative_control() if qualitative else control(),
        budget=budget(),
    )
    assert wire.pop("assessment_digest") == canonical_digest(wire)
    assert not {"guard_admissible", "accepted", "authenticated", "effective_lock"}.intersection(
        wire
    )
    assert value.evidence[0].format_version == ("2.0" if qualitative else "1.0")


@pytest.mark.parametrize(
    "status", ["unassessed", "needs-evidence", "blocked", "fail", "pass", "accepted-risk"]
)
def test_explicit_statuses_remain_declarations_requiring_actual_contract_consumers(
    status: AssessmentStatus,
) -> None:
    """No metadata status or accepted-risk label grants current source or mandatory-floor approval."""
    value = assessment(status=status)
    assert (
        SelectedControlAssessment2.from_dict(
            value.to_dict(budget=budget()), budget=budget()
        ).status
        == status
    )


def test_unknown_cannot_pass_and_not_applicable_stays_explicitly_unassessed() -> None:
    """Tri-state strings never use string truthiness or silently become legacy Booleans."""
    assert assessment(applicability="false").applicability == "false"
    assert assessment(applicability="unknown").applicability == "unknown"
    with pytest.raises(ValueError, match="unknown selected applicability cannot pass"):
        assessment(applicability="unknown", status="pass")
    for state in ["pass", "needs-evidence", "blocked", "fail", "accepted-risk"]:
        with pytest.raises(ValueError, match="explicitly unassessed"):
            assessment(applicability="false", status=cast(AssessmentStatus, state))


def test_independent_selected_review_body_uses_real_original_ed25519_attestation() -> None:
    """Original signatures bind every independent selected input and do not create a digest cycle."""
    value = assessment(qualitative=False, status="pass")
    body = value.review_body_digest(budget=budget())
    signed = attestation(reviewer_id="Independent Source Reviewer", body=body)
    actual_ref = PolicyComponent1(signed, budget()).reference()
    wire = value.to_dict(budget=budget())
    wire["reviews"] = [actual_ref.to_dict()]
    wire.pop("assessment_digest")
    reviewed = SelectedControlAssessment2.from_dict(
        {**wire, "assessment_digest": canonical_digest(wire)}, budget=budget()
    )
    assert reviewed.review_body_digest(budget=budget()) == body
    assert reviewed.assessment_digest != value.assessment_digest != body
    instant = datetime(2026, 7, 15, 12, tzinfo=UTC)
    assert signed.verified_at(instant, "pass", body, trust_store("key-a"))
    for field in [
        "lock_digest",
        "quality_projection_digest",
        "task_context_digest",
        "event_request_digest",
    ]:
        changed = reviewed.to_dict(budget=budget())
        changed.pop("assessment_digest")
        changed[field] = "a" * 64
        parsed = SelectedControlAssessment2.from_dict(
            {**changed, "assessment_digest": canonical_digest(changed)}, budget=budget()
        )
        assert parsed.review_body_digest(budget=budget()) != body
        assert not signed.verified_at(
            instant, "pass", parsed.review_body_digest(budget=budget()), trust_store("key-a")
        )
    independent = reviewed.to_dict(budget=budget())
    independent.pop("assessment_digest")
    independent.pop("reviews")
    assert canonical_digest(independent) == body


def test_real_json_reader_retains_complete_selected_inputs_and_rejects_duplicate_keys(
    tmp_path: Path,
) -> None:
    """Actual bounded file parsing keeps all explicit context digests and original references."""
    value = assessment()
    path = tmp_path / "assessment.json"
    path.write_text(json.dumps(value.to_dict(budget=budget())), encoding="utf-8")
    assert (
        SelectedControlAssessment2.from_dict(
            read_policy_document(path, budget=budget()), budget=budget()
        )
        == value
    )
    path.write_text('{"status":"pass","status":"fail"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        read_policy_document(path, budget=budget())


@pytest.mark.parametrize(
    "field,invalid",
    [
        ("schema_version", "1.1"),
        ("object_kind", "control-assessment"),
        ("lock_digest", "bad"),
        ("quality_projection_digest", "bad"),
        ("task_context_digest", "bad"),
        ("event_request_digest", "bad"),
        ("control", {}),
        ("contract_case", "default"),
        ("applicability", True),
        ("applicability", "yes"),
        ("status", "approved"),
        ("assessor", "signed identity with spaces"),
        ("assessed_at", "yesterday"),
        ("reason_code", "bad reason"),
        ("evidence", {}),
        ("reviews", {}),
        ("assessment_digest", "0" * 64),
    ],
)
def test_rehashed_unknown_fields_and_invalid_contexts_never_become_selected_assessments(
    field: str, invalid: object
) -> None:
    """Hashing cannot relax exact schema, identity grammar, finite inputs or explicit tri-state fields."""
    body = assessment().to_dict(budget=budget())
    body.pop("assessment_digest")
    body[field] = invalid
    digest = "0" * 64 if field == "assessment_digest" else canonical_digest(body)
    with pytest.raises(ValueError):
        SelectedControlAssessment2.from_dict(
            {**body, "assessment_digest": digest}, budget=budget()
        )


def test_reference_generations_order_and_whole_allocation_limits_are_closed() -> None:
    """Supporting records cannot substitute control/evidence/review owners or bypass aggregate bounds."""
    value = assessment()
    for changed in [
        replace(value, control=assessment(qualitative=False).control),
        replace(value, evidence=assessment(qualitative=False).evidence),
        replace(value, reviews=(reference(),)),
        replace(value, evidence=cast(tuple[TypedObjectRef1, ...], list(value.evidence))),
        replace(value, evidence=value.evidence * 2),
        replace(
            value,
            evidence=(
                reference("evidence-reference", "2.0", "z"),
                reference("evidence-reference", "2.0", "a"),
            ),
        ),
        replace(value, reviews=(reference("review-attestation", "2.0"),) * 129),
    ]:
        with pytest.raises(ValueError):
            changed.to_dict(budget=budget())
    with pytest.raises(ValueError, match="aggregate reference budget"):
        value.to_dict(budget=budget(references=1))
    wire = value.to_dict(budget=budget())
    for field in ["evidence", "reviews"]:
        with pytest.raises(ValueError, match="reference allocation budget"):
            SelectedControlAssessment2.from_dict(
                {**wire, field: [None] * 129}, budget=budget(size=65536)
            )
    with pytest.raises(ValueError, match="digest differs"):
        replace(value, assessment_digest="0" * 64).to_dict(budget=budget())
    with pytest.raises(ValueError, match="timestamp wire must remain unchanged"):
        replace(value, assessed_at=value.assessed_at.replace("Z", "+00:00")).to_dict(
            budget=budget()
        )
    alias = {**wire, "assessed_at": value.assessed_at.replace("Z", "+00:00")}
    with pytest.raises(ValueError, match="wire must remain unchanged"):
        SelectedControlAssessment2.from_dict(alias, budget=budget())
    for invalid in [
        None,
        {**wire, "extension": True},
        {k: v for k, v in wire.items() if k != "assessor"},
    ]:
        with pytest.raises(ValueError):
            SelectedControlAssessment2.from_dict(invalid, budget=budget())


def test_row_binding_rejects_different_actual_owner_and_undeclared_row() -> None:
    """A complete valid row still cannot replace the declared assessment's control or contract case."""
    value = assessment()
    with pytest.raises(ValueError, match="actual complete quality row"):
        value.verify_quality_binding({}, {}, budget=budget())
    with pytest.raises(ValueError, match="exact quality row"):
        value.verify_quality_binding(projection(qualitative=False), control(), budget=budget())


def legacy_pass(
    *,
    evidence_rows: tuple[EvidenceReference, ...] | None = None,
    reviewer_ids: tuple[str, ...] = ("Independent Source Reviewer",),
    required_reviewers: int = 1,
) -> tuple[
    SelectedControlAssessment2,
    QualityProjectionRowV3,
    ControlDefinition,
    tuple[ReviewerAttestation, ...],
]:
    """Prepare real original controls, evidence and signed body without constructing a legacy lock."""
    original = pack(minimum_reviewers=required_reviewers).controls[0]
    row = QualityProjectionRowV3.build(
        control=PolicyComponent1(original, budget()).reference(),
        source_rule_ids=("source-rule",),
        scope=RuleScope1.build(
            scope_kind="global",
            condition=None,
            events=tuple(sorted(TASK_CONTEXT_EVENTS)),
            budget=budget(),
        ),
        contract_case="legacy1",
        evidence_contract=PolicyComponent1(original.evidence, budget()).reference(),
        review_policy=None,
        target_level=original.target_level,
        default_applicable=original.default_applicable,
        condition=original.condition,
        applicability_decisions=(),
        budget=budget(),
    )
    evidence_rows = (evidence(),) if evidence_rows is None else evidence_rows
    value = SelectedControlAssessment2.build(
        lock_digest="1" * 64,
        quality_projection_digest="2" * 64,
        task_context_digest="3" * 64,
        event_request_digest="4" * 64,
        control=row.control,
        contract_case="legacy1",
        applicability="true",
        status="pass",
        evidence=tuple(
            sorted(
                (PolicyComponent1(item, budget()).reference() for item in evidence_rows),
                key=lambda item: item.object_id,
            )
        ),
        reviews=(),
        assessor="source-assessor",
        assessed_at="2026-07-15T12:00:00Z",
        reason_code="original-positive-requirements",
        budget=budget(),
    )
    reviews = tuple(
        attestation(
            reviewer_id=identity,
            key_id=f"key-{chr(97 + index)}",
            body=value.review_body_digest(budget=budget()),
        )
        for index, identity in enumerate(reviewer_ids)
    )
    wire = value.to_dict(budget=budget())
    wire["reviews"] = [
        ref.to_dict()
        for ref in sorted(
            (PolicyComponent1(item, budget()).reference() for item in reviews),
            key=lambda item: item.object_id,
        )
    ]
    wire.pop("assessment_digest")
    return (
        SelectedControlAssessment2.from_dict(
            {**wire, "assessment_digest": canonical_digest(wire)}, budget=budget()
        ),
        row,
        original,
        reviews,
    )


@pytest.mark.parametrize("reviewers", [1, 2])
def test_selected_legacy_public_consumer_exercises_actual_positive_numeric_and_signed_predicates(
    reviewers: int,
) -> None:
    """Actual original Ed25519 reviews and required positive quorum qualify their exact independent body."""
    value, row, original, reviews = legacy_pass(
        reviewer_ids=("Reviewer One", "Reviewer Two")[:reviewers], required_reviewers=reviewers
    )
    validate_selected_legacy_pass(
        value,
        row,
        original,
        adapters=(adapter_lock(),),
        evidence=(evidence(),),
        reviews=reviews,
        review_trust_store=trust_store(*[f"key-{chr(97 + i)}" for i in range(reviewers)]),
        instant=datetime(2026, 7, 15, 12, tzinfo=UTC),
        budget=budget(),
    )


@pytest.mark.parametrize(
    "observed,expires",
    [
        ("2026-07-15T10:59:59Z", "2026-07-15T13:00:00Z"),
        ("2026-07-15T12:00:01Z", "2026-07-15T13:00:00Z"),
        ("2026-07-15T11:30:00Z", "2026-07-15T12:00:00Z"),
    ],
)
def test_selected_legacy_consumer_preserves_old_future_and_expired_evidence_refusal(
    observed: str, expires: str
) -> None:
    """A valid original signature never overrides the actual original evidence age or explicit expiry."""
    run = evidence(observed_at=observed, expires_at=expires)
    value, row, original, reviews = legacy_pass(evidence_rows=(run,))
    with pytest.raises(ValueError, match="only fresh"):
        validate_selected_legacy_pass(
            value,
            row,
            original,
            adapters=(adapter_lock(),),
            evidence=(run,),
            reviews=reviews,
            review_trust_store=trust_store("key-a"),
            instant=datetime(2026, 7, 15, 12, tzinfo=UTC),
            budget=budget(),
        )


def test_selected_legacy_consumer_never_infers_signature_trust_identity_or_coverage() -> None:
    """Missing stores, self review, insufficient quorum, foreign evidence and changed bodies all refuse."""
    value, row, original, reviews = legacy_pass()
    instant = datetime(2026, 7, 15, 12, tzinfo=UTC)
    for store in [None, trust_store("unknown-key")]:
        with pytest.raises(ValueError):
            validate_selected_legacy_pass(
                value,
                row,
                original,
                adapters=(adapter_lock(),),
                evidence=(evidence(),),
                reviews=reviews,
                review_trust_store=store,
                instant=instant,
                budget=budget(),
            )
    for identities, required in [(("source-assessor",), 1), (("Independent Reviewer",), 2)]:
        candidate, projected, owner, proofs = legacy_pass(
            reviewer_ids=identities, required_reviewers=required
        )
        with pytest.raises(ValueError, match="enough distinct verified"):
            validate_selected_legacy_pass(
                candidate,
                projected,
                owner,
                adapters=(adapter_lock(),),
                evidence=(evidence(),),
                reviews=proofs,
                review_trust_store=trust_store("key-a"),
                instant=instant,
                budget=budget(),
            )
    for submitted, proofs in [
        ((), reviews),
        ((evidence(evidence_id="foreign"),), reviews),
        ((evidence(),), ()),
        ((evidence(),), (attestation(body="0" * 64),)),
    ]:
        with pytest.raises(ValueError, match="complete declared evidence or reviews"):
            validate_selected_legacy_pass(
                value,
                row,
                original,
                adapters=(adapter_lock(),),
                evidence=submitted,
                reviews=proofs,
                review_trust_store=trust_store("key-a"),
                instant=instant,
                budget=budget(),
            )
    body = value.to_dict(budget=budget())
    body.pop("assessment_digest")
    body["event_request_digest"] = "a" * 64
    changed = SelectedControlAssessment2.from_dict(
        {**body, "assessment_digest": canonical_digest(body)}, budget=budget()
    )
    with pytest.raises(ValueError, match="enough distinct verified"):
        validate_selected_legacy_pass(
            changed,
            row,
            original,
            adapters=(adapter_lock(),),
            evidence=(evidence(),),
            reviews=reviews,
            review_trust_store=trust_store("key-a"),
            instant=instant,
            budget=budget(),
        )


def test_selected_legacy_consumer_revalidates_all_direct_owners_and_budgets() -> None:
    """Direct mutated dataclasses, duplicate owners and aggregate allocations cannot bypass parsing."""
    value, row, original, reviews = legacy_pass()
    instant = datetime(2026, 7, 15, 12, tzinfo=UTC)
    for candidate in [cast(SelectedControlAssessment2, {}), assessment()]:
        with pytest.raises(ValueError):
            validate_selected_legacy_pass(
                candidate,
                projection() if candidate is not value else row,
                cast(ControlDefinition, qualitative_control())
                if candidate is not value
                else original,
                adapters=(adapter_lock(),),
                evidence=(evidence(),),
                reviews=reviews,
                review_trust_store=trust_store("key-a"),
                instant=instant,
                budget=budget(),
            )
    for moment in [datetime(2026, 7, 15, 12), cast(datetime, {})]:
        with pytest.raises(ValueError, match="actual aware instant"):
            validate_selected_legacy_pass(
                value,
                row,
                original,
                adapters=(adapter_lock(),),
                evidence=(evidence(),),
                reviews=reviews,
                review_trust_store=trust_store("key-a"),
                instant=moment,
                budget=budget(),
            )

    for adapters in [
        cast(tuple[AdapterLock, ...], []),
        cast(tuple[AdapterLock, ...], ({},)),
        (adapter_lock(), adapter_lock()),
        (adapter_lock(),) * 129,
    ]:
        with pytest.raises(
            ValueError,
            match=r"immutable original|actual complete original|duplicate identity|aggregate owner reference",
        ):
            validate_selected_legacy_pass(
                value,
                row,
                original,
                adapters=adapters,
                evidence=(evidence(),),
                reviews=reviews,
                review_trust_store=trust_store("key-a"),
                instant=instant,
                budget=budget(),
            )
    for store in [
        cast(VerificationTrustStore, {}),
        replace(trust_store("key-a"), keys=cast(tuple[TrustedPublicKey, ...], [])),
        replace(trust_store("key-a"), keys=cast(tuple[TrustedPublicKey, ...], ({},))),
        replace(trust_store("key-a"), trust_store_digest="0" * 64),
        replace(trust_store("key-a"), keys=trust_store("key-a").keys * 129),
    ]:
        with pytest.raises(ValueError, match=r"original public trust store|public keys exceed"):
            validate_selected_legacy_pass(
                value,
                row,
                original,
                adapters=(adapter_lock(),),
                evidence=(evidence(),),
                reviews=reviews,
                review_trust_store=store,
                instant=instant,
                budget=budget(),
            )


def test_selected_legacy_original_cohort_byte_budget_is_aggregate() -> None:
    """Complete valid unrelated custody records cannot make aggregate byte limits disappear."""
    value, row, original, reviews = legacy_pass()
    adapters = [adapter_lock()]
    for index in range(8):
        wire = adapter_lock().to_dict()
        wire["adapter_id"] = f"unrelated-selected-adapter-{index}"
        wire.pop("adapter_digest")
        adapters.append(AdapterLock.from_dict({**wire, "adapter_digest": canonical_digest(wire)}))
    limits = budget(size=4096)
    value.to_dict(budget=limits)
    row.verify_control_binding(original, budget=limits)
    owners: tuple[AdapterLock | EvidenceReference | ReviewerAttestation, ...] = (
        *adapters,
        evidence(),
        *reviews,
    )
    for owner in owners:
        assert PolicyComponent1(owner, limits).to_dict() == owner.to_dict()
    with pytest.raises(ValueError, match="aggregate owner byte budget"):
        validate_selected_legacy_pass(
            value,
            row,
            original,
            adapters=tuple(adapters),
            evidence=(evidence(),),
            reviews=reviews,
            review_trust_store=trust_store("key-a"),
            instant=datetime(2026, 7, 15, 12, tzinfo=UTC),
            budget=limits,
        )
