# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — per-control assessment tests
"""Verify fresh evidence and independent review predicates for control states."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from typing import cast

import pytest
from signing_fixtures import pack_signature, sign_digest, trust_store

from rigor_foundry.control_assessment import (
    ControlAssessment,
    EvidenceReference,
    ReviewerAttestation,
)
from rigor_foundry.effective_profile import (
    AdapterLock,
    EffectiveControl,
    EffectiveProfileLock,
    PackVerification,
)
from rigor_foundry.project_profile import (
    REQUIRED_INTENT_CATEGORIES,
    PackSelection,
    ProjectIntent,
    ProjectProfile,
    RequirementBinding,
    RequirementCategory,
)
from rigor_foundry.standard_pack import (
    ControlDefinition,
    EvidenceContract,
    RemediationContract,
    StandardPack,
)

ASSESSED_AT = "2026-07-15T12:00:00Z"


def pack(*, minimum_reviewers: int = 1) -> StandardPack:
    """Return a signed pack with one evidence/reviewer contract."""
    control = ControlDefinition.build(
        control_id="core/no-godfiles",
        version="1.0.0",
        title="No unjustified GodFiles",
        domain="godfile-responsibility",
        severity="P1",
        target_level="production",
        mode="require",
        default_applicable=True,
        condition=None,
        evidence=EvidenceContract.build(
            contract_id="core/no-godfiles/evidence",
            required_adapters=("loc-adapter",),
            evidence_types=("loc-report",),
            freshness_seconds=3600,
            minimum_independent_reviewers=minimum_reviewers,
        ),
        remediation=RemediationContract.build(
            dependencies=(),
            procedure_ids=("split-module",),
            acceptance_gates=("loc-gate",),
            reopen_triggers=("source-change",),
            independent_verifier_required=True,
        ),
    )
    source_digest = "1" * 64
    payload = StandardPack.payload_digest(
        pack_id="core",
        version="1.0.0",
        source_uri="https://standards.example/core",
        source_digest=source_digest,
        licence="MIT",
        controls=(control,),
    )
    return StandardPack.build(
        pack_id="core",
        version="1.0.0",
        source_uri="https://standards.example/core",
        source_digest=source_digest,
        licence="MIT",
        signature=pack_signature(payload),
        controls=(control,),
    )


def adapter_lock() -> AdapterLock:
    """Return the exact adapter identity used by assessment evidence."""
    return AdapterLock.build(
        adapter_id="loc-adapter",
        version="1.0.0",
        executable_digest="5" * 64,
        config_digest="6" * 64,
        command_digest="7" * 64,
        environment_digest="8" * 64,
        domains=("godfile-responsibility",),
    )


def locked_control(
    *,
    applicable: bool = True,
    missing_adapters: tuple[str, ...] = (),
    waiver_ids: tuple[str, ...] = (),
    risk_waiver_ids: tuple[str, ...] = (),
    minimum_reviewers: int = 1,
) -> tuple[EffectiveProfileLock, EffectiveControl]:
    """Return one exact lock and its configured effective control."""
    standard = pack(minimum_reviewers=minimum_reviewers)
    requirements = tuple(
        RequirementBinding.build(cast(RequirementCategory, category), ("explicit",))
        for category in sorted(REQUIRED_INTENT_CATEGORIES)
    )
    intent = ProjectIntent.build(
        risk_class="production",
        regulatory_classes=(),
        target_maturity="production",
        requirements=requirements,
    )
    project = ProjectProfile.build(
        profile_id="rigor-foundry",
        intent=intent,
        packs=(
            PackSelection.build(
                pack_id=standard.pack_id,
                version=standard.version,
                source_digest=standard.source_digest,
                pack_digest=standard.pack_digest,
                trusted_key_ids=(standard.signature.key_id,),
            ),
        ),
        variables=(),
        assignments=(),
        applicability=(),
        overlays=(),
        waivers=(),
        created_by="profile-owner",
        created_at=ASSESSED_AT,
    )
    verification = PackVerification.build(
        pack=standard,
        trust_store=trust_store("trusted-key"),
        verified_at="2026-07-15T11:50:00Z",
    )
    adapter = adapter_lock()
    effective = EffectiveControl.build(
        source_pack=standard,
        control=standard.controls[0],
        applicable=applicable,
        applicability_rationale="explicit assessment scope",
        target_level="production",
        mode="require",
        active_waiver_ids=waiver_ids,
        missing_adapter_ids=missing_adapters,
        risk_acceptance_waiver_ids=risk_waiver_ids,
    )
    lock = EffectiveProfileLock.build(
        profile=project,
        packs=(standard,),
        verifications=(verification,),
        adapters=(adapter,),
        variables=(),
        controls=(effective,),
        warnings=(),
        trust_store=trust_store("trusted-key"),
        toolchain_digest="9" * 64,
        resolved_at=ASSESSED_AT,
    )
    return lock, effective


def evidence(
    *,
    evidence_id: str = "loc-run-1",
    adapter_digest: str | None = None,
    evidence_type: str = "loc-report",
    artifact_digest: str = "a" * 64,
    observed_at: str = "2026-07-15T11:30:00Z",
    expires_at: str = "2026-07-15T13:00:00Z",
) -> EvidenceReference:
    """Return one real artefact reference satisfying the control contract."""
    return EvidenceReference.build(
        evidence_id=evidence_id,
        evidence_type=evidence_type,
        adapter_id="loc-adapter",
        adapter_digest=adapter_lock().adapter_digest if adapter_digest is None else adapter_digest,
        artifact_digest=artifact_digest,
        artifact_size=512,
        classification="internal",
        reference="sha256:a/loc-report.json",
        observed_at=observed_at,
        expires_at=expires_at,
    )


def review(
    lock: EffectiveProfileLock,
    control: EffectiveControl,
    *,
    evidence_items: tuple[EvidenceReference, ...],
    rationale: str,
    reviewer_id: str = "independent-reviewer",
    key_id: str = "reviewer-key-1",
    decision: str = "pass",
    body_status: str | None = None,
    proof_level: str = "cryptographically-verified",
    assessor: str = "assessment-agent",
    limitations: tuple[str, ...] = (),
    accepted_waiver_id: str = "",
    trusted_key_ids: tuple[str, ...] | None = None,
) -> ReviewerAttestation:
    """Return one current reviewer attestation."""
    if proof_level not in {"asserted", "cryptographically-verified"}:
        raise ValueError("review.proof_level is unsupported")
    review_store = trust_store(*(trusted_key_ids or (key_id,)))
    body_digest = ControlAssessment.body_digest_for_review(
        lock,
        control,
        status=cast(object, decision if body_status is None else body_status),
        assessor=assessor,
        assessed_at=ASSESSED_AT,
        evidence=evidence_items,
        rationale=rationale,
        limitations=limitations,
        accepted_waiver_id=accepted_waiver_id,
        review_trust_store=review_store,
    )
    payload_digest = ReviewerAttestation.payload_digest(
        reviewer_id=reviewer_id,
        algorithm="ed25519",
        key_id=key_id,
        assessment_body_digest=body_digest,
        decision=cast(object, decision),
        reviewed_at="2026-07-15T11:45:00Z",
        expires_at="2026-07-15T13:00:00Z",
    )
    return ReviewerAttestation.build(
        reviewer_id=reviewer_id,
        key_id=key_id,
        assessment_body_digest=body_digest,
        decision=cast(object, decision),
        reviewed_at="2026-07-15T11:45:00Z",
        expires_at="2026-07-15T13:00:00Z",
        signature_hex=(
            sign_digest(key_id, payload_digest)
            if proof_level == "cryptographically-verified"
            else "0" * 128
        ),
    )


def test_pass_round_trips_only_with_fresh_covered_independent_evidence() -> None:
    """Pass is rederived from exact fresh evidence and cryptographic independent review."""
    lock, control = locked_control()
    run = evidence()
    rationale = "all contract predicates independently verified"
    assessment = ControlAssessment.build(
        lock,
        control,
        status="pass",
        assessor="assessment-agent",
        assessed_at=ASSESSED_AT,
        evidence=(run,),
        reviews=(review(lock, control, evidence_items=(run,), rationale=rationale),),
        rationale=rationale,
        review_trust_store=trust_store("reviewer-key-1"),
    )
    assert (
        ControlAssessment.from_dict(
            assessment.to_dict(),
            lock,
            trust_store("reviewer-key-1"),
        )
        == assessment
    )
    assert EvidenceReference.from_dict(assessment.evidence[0].to_dict()) == assessment.evidence[0]
    assert ReviewerAttestation.from_dict(assessment.reviews[0].to_dict()) == assessment.reviews[0]
    assert assessment.evidence[0].fresh_at(datetime(2026, 7, 15, 12, tzinfo=UTC), 3600)
    with pytest.raises(ValueError, match="verified independent"):
        ControlAssessment.from_dict(
            assessment.to_dict(),
            lock,
            trust_store("substituted-reviewer-key"),
        )
    forged_identity = replace(assessment.reviews[0], reviewer_id="fabricated-reviewer")
    with pytest.raises(ValueError, match="verified independent"):
        ControlAssessment.build(
            lock,
            control,
            status="pass",
            assessor="assessment-agent",
            assessed_at=ASSESSED_AT,
            evidence=(run,),
            reviews=(forged_identity,),
            rationale=rationale,
            review_trust_store=trust_store("reviewer-key-1"),
        )

    tampered = deepcopy(assessment.to_dict())
    tampered["assessor"] = "other-agent"
    with pytest.raises(ValueError):
        ControlAssessment.from_dict(tampered, lock, trust_store("reviewer-key-1"))


def test_evidence_and_reviews_bind_exact_lock_control_and_body() -> None:
    """Names-only adapters and attestations reused on another assessment never clear it."""
    lock, control = locked_control()
    first_run = evidence()
    rationale = "exact reviewed assessment"
    bound_review = review(
        lock,
        control,
        evidence_items=(first_run,),
        rationale=rationale,
    )
    changed_run = evidence(evidence_id="loc-run-2", artifact_digest="d" * 64)
    with pytest.raises(ValueError, match="verified independent"):
        ControlAssessment.build(
            lock,
            control,
            status="pass",
            assessor="assessment-agent",
            assessed_at=ASSESSED_AT,
            evidence=(changed_run,),
            reviews=(bound_review,),
            rationale=rationale,
            review_trust_store=trust_store("reviewer-key-1"),
        )
    other_lock, other_control = locked_control(waiver_ids=("different-body",))
    with pytest.raises(ValueError, match="verified independent"):
        ControlAssessment.build(
            other_lock,
            other_control,
            status="pass",
            assessor="assessment-agent",
            assessed_at=ASSESSED_AT,
            evidence=(first_run,),
            reviews=(bound_review,),
            rationale=rationale,
            review_trust_store=trust_store("reviewer-key-1"),
        )
    with pytest.raises(ValueError, match="exact locked adapter"):
        ControlAssessment.build(
            lock,
            control,
            status="fail",
            assessor="assessment-agent",
            assessed_at=ASSESSED_AT,
            evidence=(evidence(adapter_digest="0" * 64),),
            rationale="names-only adapter binding",
        )


def test_review_quorum_requires_distinct_identities_and_keys() -> None:
    """Reviewer, key-id, and public-key identities must all be independent."""
    lock, control = locked_control(minimum_reviewers=2)
    run = evidence()
    rationale = "two-party exact review"

    def attestation(reviewer_id: str, key_id: str) -> ReviewerAttestation:
        return review(
            lock,
            control,
            evidence_items=(run,),
            rationale=rationale,
            reviewer_id=reviewer_id,
            key_id=key_id,
            trusted_key_ids=("key-1", "key-2"),
        )

    for reviews in (
        (attestation("reviewer-a", "key-1"), attestation("reviewer-a", "key-2")),
        (attestation("reviewer-a", "key-1"), attestation("reviewer-b", "key-1")),
    ):
        with pytest.raises(ValueError, match="distinct verified independent"):
            ControlAssessment.build(
                lock,
                control,
                status="pass",
                assessor="assessment-agent",
                assessed_at=ASSESSED_AT,
                evidence=(run,),
                reviews=reviews,
                rationale=rationale,
                review_trust_store=trust_store("key-1", "key-2"),
            )
    accepted = ControlAssessment.build(
        lock,
        control,
        status="pass",
        assessor="assessment-agent",
        assessed_at=ASSESSED_AT,
        evidence=(run,),
        reviews=(attestation("reviewer-a", "key-1"), attestation("reviewer-b", "key-2")),
        rationale=rationale,
        review_trust_store=trust_store("key-1", "key-2"),
    )
    assert accepted.status == "pass"


def test_missing_adapter_stale_evidence_and_asserted_review_cannot_pass() -> None:
    """Names-only trust, stale artefacts, and incomplete adapter wiring remain non-pass."""
    missing_lock, missing_control = locked_control(missing_adapters=("loc-adapter",))
    current = evidence()
    with pytest.raises(ValueError, match="missing evidence adapters"):
        ControlAssessment.build(
            missing_lock,
            missing_control,
            status="pass",
            assessor="assessment-agent",
            assessed_at=ASSESSED_AT,
            evidence=(current,),
            reviews=(
                review(
                    missing_lock,
                    missing_control,
                    evidence_items=(current,),
                    rationale="must fail",
                ),
            ),
            rationale="must fail",
            review_trust_store=trust_store("reviewer-key-1"),
        )
    lock, control = locked_control()
    stale = evidence(
        observed_at="2026-07-15T09:00:00Z",
        expires_at="2026-07-15T13:00:00Z",
    )
    with pytest.raises(ValueError, match="fresh"):
        ControlAssessment.build(
            lock,
            control,
            status="pass",
            assessor="assessment-agent",
            assessed_at=ASSESSED_AT,
            evidence=(stale,),
            reviews=(review(lock, control, evidence_items=(stale,), rationale="must fail"),),
            rationale="must fail",
            review_trust_store=trust_store("reviewer-key-1"),
        )
    asserted = review(
        lock,
        control,
        evidence_items=(current,),
        rationale="must fail",
        proof_level="asserted",
    )
    with pytest.raises(ValueError, match="verified independent"):
        ControlAssessment.build(
            lock,
            control,
            status="pass",
            assessor="assessment-agent",
            assessed_at=ASSESSED_AT,
            evidence=(current,),
            reviews=(asserted,),
            rationale="must fail",
            review_trust_store=trust_store("reviewer-key-1"),
        )


def test_explicit_nonpass_states_preserve_evidence_limits() -> None:
    """Fail, needs-evidence, blocked, and unassessed states keep distinct predicates."""
    lock, control = locked_control()
    failed = ControlAssessment.build(
        lock,
        control,
        status="fail",
        assessor="assessment-agent",
        assessed_at=ASSESSED_AT,
        evidence=(evidence(),),
        rationale="module exceeds the verified threshold",
    )
    assert failed.status == "fail"
    needs = ControlAssessment.build(
        lock,
        control,
        status="needs-evidence",
        assessor="assessment-agent",
        assessed_at=ASSESSED_AT,
        rationale="adapter output is not yet available",
    )
    assert needs.status == "needs-evidence"
    with pytest.raises(ValueError, match="requires rationale or limitations"):
        ControlAssessment.build(
            lock,
            control,
            status="blocked",
            assessor="assessment-agent",
            assessed_at=ASSESSED_AT,
            rationale="",
        )
    with pytest.raises(ValueError, match="require factual evidence"):
        ControlAssessment.build(
            lock,
            control,
            status="fail",
            assessor="assessment-agent",
            assessed_at=ASSESSED_AT,
            rationale="unsupported assertion",
        )


def test_accepted_risk_requires_dedicated_active_waiver_evidence_and_review() -> None:
    """Only exact risk authorization, factual evidence, and bound review permit acceptance."""
    lock, control = locked_control(risk_waiver_ids=("risk-waiver",))
    run = evidence()
    rationale = "independently accepted bounded migration risk"
    limitations = ("expires with waiver",)
    accepted = ControlAssessment.build(
        lock,
        control,
        status="accepted-risk",
        assessor="assessment-agent",
        assessed_at=ASSESSED_AT,
        evidence=(run,),
        reviews=(
            review(
                lock,
                control,
                evidence_items=(run,),
                rationale=rationale,
                decision="accepted-risk",
                limitations=limitations,
                accepted_waiver_id="risk-waiver",
            ),
        ),
        rationale=rationale,
        limitations=limitations,
        accepted_waiver_id="risk-waiver",
        review_trust_store=trust_store("reviewer-key-1"),
    )
    assert accepted.status == "accepted-risk"
    for waiver_class in ("target", "mode", "applicability"):
        unrelated_id = f"{waiver_class}-waiver"
        unrelated_lock, unrelated_control = locked_control(waiver_ids=(unrelated_id,))
        unrelated_rationale = f"reject {waiver_class} waiver reuse"
        unrelated_review = review(
            unrelated_lock,
            unrelated_control,
            evidence_items=(run,),
            rationale=unrelated_rationale,
            decision="accepted-risk",
            accepted_waiver_id=unrelated_id,
        )
        with pytest.raises(ValueError, match="dedicated active risk-acceptance"):
            ControlAssessment.build(
                unrelated_lock,
                unrelated_control,
                status="accepted-risk",
                assessor="assessment-agent",
                assessed_at=ASSESSED_AT,
                evidence=(run,),
                reviews=(unrelated_review,),
                rationale=unrelated_rationale,
                accepted_waiver_id=unrelated_id,
                review_trust_store=trust_store("reviewer-key-1"),
            )
    with pytest.raises(ValueError, match="active"):
        wrong_risk_review = review(
            lock,
            control,
            evidence_items=(run,),
            rationale="wrong waiver",
            decision="accepted-risk",
            accepted_waiver_id="other-waiver",
        )
        ControlAssessment.build(
            lock,
            control,
            status="accepted-risk",
            assessor="assessment-agent",
            assessed_at=ASSESSED_AT,
            evidence=(run,),
            reviews=(wrong_risk_review,),
            rationale="wrong waiver",
            accepted_waiver_id="other-waiver",
            review_trust_store=trust_store("reviewer-key-1"),
        )


def test_not_applicable_control_must_remain_unassessed() -> None:
    """Not-applicable controls cannot receive cosmetic pass or clearance evidence."""
    lock, control = locked_control(applicable=False)
    unassessed = ControlAssessment.build(
        lock,
        control,
        status="unassessed",
        assessor="assessment-agent",
        assessed_at=ASSESSED_AT,
        rationale="not applicable by exact profile scope",
    )
    assert unassessed.status == "unassessed"
    run = evidence()
    with pytest.raises(ValueError, match="explicitly unassessed"):
        ControlAssessment.build(
            lock,
            control,
            status="pass",
            assessor="assessment-agent",
            assessed_at=ASSESSED_AT,
            evidence=(run,),
            reviews=(
                review(
                    lock,
                    control,
                    evidence_items=(run,),
                    rationale="invalid cosmetic pass",
                ),
            ),
            rationale="invalid cosmetic pass",
            review_trust_store=trust_store("reviewer-key-1"),
        )


def test_evidence_and_reviewer_metadata_edges_fail_closed() -> None:
    """Classification, time windows, opaque references, proof levels, and digests are strict."""
    with pytest.raises(ValueError, match="classification"):
        EvidenceReference.build(
            evidence_id="bad",
            evidence_type="loc-report",
            adapter_id="loc-adapter",
            adapter_digest=adapter_lock().adapter_digest,
            artifact_digest="a" * 64,
            artifact_size=1,
            classification=cast(object, "restricted"),
            reference="sha256:a",
            observed_at="2026-07-15T11:00:00Z",
            expires_at="2026-07-15T12:00:00Z",
        )
    with pytest.raises(ValueError, match="later than"):
        EvidenceReference.build(
            evidence_id="bad-window",
            evidence_type="loc-report",
            adapter_id="loc-adapter",
            adapter_digest=adapter_lock().adapter_digest,
            artifact_digest="a" * 64,
            artifact_size=1,
            classification="internal",
            reference="sha256:a",
            observed_at="2026-07-15T12:00:00Z",
            expires_at="2026-07-15T12:00:00Z",
        )
    with pytest.raises(ValueError, match="whitespace-free"):
        EvidenceReference.build(
            evidence_id="bad-reference",
            evidence_type="loc-report",
            adapter_id="loc-adapter",
            adapter_digest=adapter_lock().adapter_digest,
            artifact_digest="a" * 64,
            artifact_size=1,
            classification="internal",
            reference="local path/report.json",
            observed_at="2026-07-15T11:00:00Z",
            expires_at="2026-07-15T12:00:00Z",
        )
    with pytest.raises(ValueError, match="timezone-aware"):
        evidence().fresh_at(datetime(2026, 7, 15, 12), 3600)
    tampered_evidence = evidence().to_dict()
    tampered_evidence["evidence_digest"] = "0" * 64
    with pytest.raises(ValueError, match="digest"):
        EvidenceReference.from_dict(tampered_evidence)

    lock, control = locked_control()
    run = evidence()
    with pytest.raises(ValueError, match="proof_level"):
        review(
            lock,
            control,
            evidence_items=(run,),
            rationale="invalid proof level",
            proof_level="anonymous",
        )
    with pytest.raises(ValueError, match="decision"):
        review(
            lock,
            control,
            evidence_items=(run,),
            rationale="invalid decision",
            decision="unknown",
            body_status="pass",
        )
    with pytest.raises(ValueError, match="later than"):
        ReviewerAttestation.build(
            reviewer_id="reviewer",
            key_id="reviewer-key-1",
            assessment_body_digest="c" * 64,
            decision="fail",
            reviewed_at="2026-07-15T12:00:00Z",
            expires_at="2026-07-15T12:00:00Z",
            signature_hex="0" * 128,
        )
    current_review = review(
        lock,
        control,
        evidence_items=(run,),
        rationale="verified body",
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        current_review.verified_at(
            datetime(2026, 7, 15, 12),
            "pass",
            current_review.assessment_body_digest,
            trust_store("reviewer-key-1"),
        )
    tampered_review = current_review.to_dict()
    tampered_review["attestation_digest"] = "0" * 64
    with pytest.raises(ValueError, match="digest"):
        ReviewerAttestation.from_dict(tampered_review)


def test_remaining_assessment_state_and_coverage_edges_are_explicit() -> None:
    """Unknown state/control, hidden limits, missing coverage, and clearance on unassessed fail."""
    lock, control = locked_control()
    with pytest.raises(ValueError, match="status"):
        ControlAssessment.build(
            lock,
            control,
            status=cast(object, "unknown"),
            assessor="agent",
            assessed_at=ASSESSED_AT,
            rationale="invalid",
        )
    with pytest.raises(ValueError, match="not unique"):
        ControlAssessment.build(
            lock,
            replace(control, effective_digest="0" * 64),
            status="unassessed",
            assessor="agent",
            assessed_at=ASSESSED_AT,
            rationale="crosswired",
        )
    with pytest.raises(ValueError, match="cannot hide"):
        run = evidence()
        ControlAssessment.build(
            lock,
            control,
            status="pass",
            assessor="assessment-agent",
            assessed_at=ASSESSED_AT,
            evidence=(run,),
            reviews=(
                review(
                    lock,
                    control,
                    evidence_items=(run,),
                    rationale="verified",
                    limitations=("hidden",),
                ),
            ),
            rationale="verified",
            limitations=("hidden",),
            review_trust_store=trust_store("reviewer-key-1"),
        )
    waiver_lock, waiver_control = locked_control(risk_waiver_ids=("risk-waiver",))
    with pytest.raises(ValueError, match="factual evidence"):
        unsupported_review = review(
            waiver_lock,
            waiver_control,
            evidence_items=(),
            rationale="unsupported",
            decision="accepted-risk",
            accepted_waiver_id="risk-waiver",
        )
        ControlAssessment.build(
            waiver_lock,
            waiver_control,
            status="accepted-risk",
            assessor="assessment-agent",
            assessed_at=ASSESSED_AT,
            reviews=(unsupported_review,),
            rationale="unsupported",
            accepted_waiver_id="risk-waiver",
            review_trust_store=trust_store("reviewer-key-1"),
        )
    with pytest.raises(ValueError, match="clearance evidence"):
        ControlAssessment.build(
            lock,
            control,
            status="unassessed",
            assessor="assessment-agent",
            assessed_at=ASSESSED_AT,
            evidence=(evidence(),),
            rationale="",
        )
    wrong_type = evidence(evidence_type="other-report")
    with pytest.raises(ValueError, match="coverage"):
        ControlAssessment.build(
            lock,
            control,
            status="pass",
            assessor="assessment-agent",
            assessed_at=ASSESSED_AT,
            evidence=(wrong_type,),
            reviews=(
                review(
                    lock,
                    control,
                    evidence_items=(wrong_type,),
                    rationale="wrong evidence type",
                ),
            ),
            rationale="wrong evidence type",
            review_trust_store=trust_store("reviewer-key-1"),
        )


def test_assessment_parser_rechecks_schema_identity_arrays_and_digest() -> None:
    """Serialized assessment identity and nested arrays are never trusted as assertions."""
    lock, control = locked_control()
    assessment = ControlAssessment.build(
        lock,
        control,
        status="fail",
        assessor="assessment-agent",
        assessed_at=ASSESSED_AT,
        evidence=(evidence(),),
        rationale="verified failure",
    )
    for field, value, message in (
        ("schema_version", "9.0", "schema"),
        ("effective_control_digest", "0" * 64, "unknown effective control"),
        ("lock_digest", "0" * 64, "lock digest"),
        ("control_id", "core/other@1.0.0", "control id"),
        ("assessment_digest", "0" * 64, "assessment digest"),
    ):
        encoded = assessment.to_dict()
        encoded[field] = value
        with pytest.raises(ValueError, match=message):
            ControlAssessment.from_dict(encoded, lock)
    malformed = assessment.to_dict()
    malformed["evidence"] = "all"
    with pytest.raises(ValueError, match="array"):
        ControlAssessment.from_dict(malformed, lock)
