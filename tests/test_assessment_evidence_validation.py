# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — original evidence and review predicate tests
"""Exercise exact legacy numeric contracts and real Ed25519 proofs without a substitute profile lock."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest
from signing_fixtures import sign_message, trust_store
from test_control_assessment import (
    ASSESSED_AT,
    adapter_lock,
    evidence,
    locked_control,
    pack,
    review,
)

from rigor_foundry.assessment_evidence_validation import (
    validate_original_evidence_bindings,
    validate_original_pass_evidence,
    validate_original_reviewers,
)
from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.control_assessment import AssessmentStatus, ControlAssessment, EvidenceReference
from rigor_foundry.review_attestation import ReviewDecision, ReviewerAttestation
from rigor_foundry.standard_pack import EvidenceContract
from rigor_foundry.trust import (
    REVIEW_ATTESTATION_SIGNATURE_DOMAIN,
    TrustedPublicKey,
    VerificationTrustStore,
)

INSTANT = datetime(2026, 7, 15, 12, tzinfo=UTC)


def contract(*, reviewers: int = 1) -> EvidenceContract:
    """Obtain the complete validated original contract from an actual signed pack fixture."""
    return pack(minimum_reviewers=reviewers).controls[0].evidence


def subject(*, decision: ReviewDecision = "pass") -> str:
    """Derive an actual independent body without constructing or casting a v1 lock."""
    return canonical_digest(
        {
            "control": pack().controls[0].to_dict(),
            "evidence": [evidence().to_dict()],
            "decision": decision,
            "assessor": "assessor",
            "assessed_at": ASSESSED_AT,
        }
    )


def attestation(
    *,
    reviewer_id: str = "independent",
    key_id: str = "key-a",
    decision: ReviewDecision = "pass",
    body: str | None = None,
    reviewed_at: str = "2026-07-15T11:45:00Z",
    expires_at: str = "2026-07-15T13:00:00Z",
    valid_signature: bool = True,
) -> ReviewerAttestation:
    """Sign the complete actual original payload with a deterministic test-only Ed25519 key."""
    body = subject(decision=decision) if body is None else body
    payload = ReviewerAttestation.payload_digest(
        reviewer_id=reviewer_id,
        algorithm="ed25519",
        key_id=key_id,
        assessment_body_digest=body,
        decision=decision,
        reviewed_at=reviewed_at,
        expires_at=expires_at,
    )
    return ReviewerAttestation.build(
        reviewer_id=reviewer_id,
        key_id=key_id,
        assessment_body_digest=body,
        decision=decision,
        reviewed_at=reviewed_at,
        expires_at=expires_at,
        signature_hex=sign_message(key_id, REVIEW_ATTESTATION_SIGNATURE_DOMAIN, payload)
        if valid_signature
        else "0" * 128,
    )


def test_exact_original_adapter_binding_includes_digest_uniqueness_and_domain() -> None:
    """Every original reference requires one matching complete adapter identity and a covered domain."""
    actual = adapter_lock()
    run = evidence()
    validate_original_evidence_bindings(
        domain="godfile-responsibility", adapters=(actual,), evidence=(run,)
    )
    validate_original_evidence_bindings(domain="godfile-responsibility", adapters=(), evidence=())
    for adapters in [(), (actual, actual), (replace(actual, adapter_digest="0" * 64),)]:
        with pytest.raises(ValueError, match="exact locked adapter"):
            validate_original_evidence_bindings(
                domain="godfile-responsibility", adapters=adapters, evidence=(run,)
            )
    with pytest.raises(ValueError, match="control domain"):
        validate_original_evidence_bindings(
            domain="architecture-and-wiring", adapters=(actual,), evidence=(run,)
        )
    unrelated = replace(actual, adapter_id="other")
    validate_original_evidence_bindings(
        domain="godfile-responsibility", adapters=(unrelated, actual), evidence=(run,)
    )


@pytest.mark.parametrize(
    "observed,expires",
    [
        ("2026-07-15T12:00:00Z", "2026-07-15T13:00:00Z"),
        ("2026-07-15T11:00:00Z", "2026-07-15T13:00:00Z"),
    ],
)
def test_original_observation_and_numeric_maximum_age_boundaries_pass(
    observed: str, expires: str
) -> None:
    """Age zero and exactly the positive original maximum are accepted before explicit expiry."""
    run = evidence(observed_at=observed, expires_at=expires)
    validate_original_pass_evidence(
        contract=contract(), missing_adapter_ids=(), instant=INSTANT, evidence=(run,)
    )
    assert run.fresh_at(INSTANT, contract().freshness_seconds)


@pytest.mark.parametrize(
    "observed,expires",
    [
        ("2026-07-15T10:59:59Z", "2026-07-15T13:00:00Z"),
        ("2026-07-15T12:00:01Z", "2026-07-15T13:00:00Z"),
        ("2026-07-15T11:30:00Z", "2026-07-15T12:00:00Z"),
    ],
)
def test_original_old_future_or_expired_evidence_cannot_hide_behind_a_fresh_member(
    observed: str, expires: str
) -> None:
    """One invalid numeric interval refuses the whole submitted evidence cohort."""
    stale = evidence(evidence_id="other", observed_at=observed, expires_at=expires)
    with pytest.raises(ValueError, match="only fresh"):
        validate_original_pass_evidence(
            contract=contract(),
            missing_adapter_ids=(),
            instant=INSTANT,
            evidence=(evidence(), stale),
        )


def test_missing_empty_timezone_and_complete_original_adapter_type_requirements() -> None:
    """No empty evidence, unresolved adapter, naive clock or missing original set member passes."""
    with pytest.raises(ValueError, match="missing evidence adapters"):
        validate_original_pass_evidence(
            contract=contract(),
            missing_adapter_ids=("loc-adapter",),
            instant=INSTANT,
            evidence=(evidence(),),
        )
    with pytest.raises(ValueError, match="only fresh"):
        validate_original_pass_evidence(
            contract=contract(), missing_adapter_ids=(), instant=INSTANT, evidence=()
        )
    with pytest.raises(ValueError, match="timezone-aware"):
        validate_original_pass_evidence(
            contract=contract(),
            missing_adapter_ids=(),
            instant=datetime(2026, 7, 15, 12),
            evidence=(evidence(),),
        )
    original = contract()
    strict = EvidenceContract.build(
        contract_id=original.contract_id,
        required_adapters=("loc-adapter", "other-adapter"),
        evidence_types=("loc-report", "other-report"),
        freshness_seconds=original.freshness_seconds,
        minimum_independent_reviewers=original.minimum_independent_reviewers,
    )
    first = evidence()
    other_data = evidence(evidence_id="other", evidence_type="other-report").to_dict()
    other_data["adapter_id"] = "other-adapter"
    other_data.pop("evidence_digest")
    other_data["evidence_digest"] = canonical_digest(other_data)
    second = EvidenceReference.from_dict(other_data)
    for rows in [(first,), (second,)]:
        with pytest.raises(ValueError, match="adapter and type coverage"):
            validate_original_pass_evidence(
                contract=strict, missing_adapter_ids=(), instant=INSTANT, evidence=rows
            )
    validate_original_pass_evidence(
        contract=strict, missing_adapter_ids=(), instant=INSTANT, evidence=(first, second)
    )
    with pytest.raises(ValueError, match="adapter and type coverage"):
        validate_original_pass_evidence(
            contract=original,
            missing_adapter_ids=(),
            instant=INSTANT,
            evidence=(evidence(evidence_type="wrong"),),
        )


@pytest.mark.parametrize("decision", ["pass", "accepted-risk"])
def test_actual_original_signed_review_and_positive_count_are_reused_without_a_legacy_lock(
    decision: ReviewDecision,
) -> None:
    """Real original signatures bind the selected independent body and exact decision."""
    actual = attestation(decision=decision)
    validate_original_reviewers(
        contract=contract(),
        instant=INSTANT,
        reviews=(actual,),
        assessor="assessor",
        decision=decision,
        review_body_digest=subject(decision=decision),
        review_trust_store=trust_store("key-a"),
    )
    assert actual.verified_at(INSTANT, decision, subject(decision=decision), trust_store("key-a"))
    assert contract().minimum_independent_reviewers == 1


def test_original_review_quorum_counts_distinct_ids_keys_and_public_key_bytes() -> None:
    """Actual signatures cannot satisfy two required reviews by repeating either original identity axis."""
    store = trust_store("key-a", "key-b")
    first = attestation(reviewer_id="reviewer-a")
    second = attestation(reviewer_id="reviewer-b", key_id="key-b")
    validate_original_reviewers(
        contract=contract(reviewers=2),
        instant=INSTANT,
        reviews=(first, second),
        assessor="assessor",
        decision="pass",
        review_body_digest=subject(),
        review_trust_store=store,
    )
    for rows in [
        (first,),
        (first, first),
        (first, attestation(reviewer_id="reviewer-a", key_id="key-b")),
        (first, attestation(reviewer_id="reviewer-b")),
    ]:
        with pytest.raises(ValueError, match="distinct verified independent"):
            validate_original_reviewers(
                contract=contract(reviewers=2),
                instant=INSTANT,
                reviews=rows,
                assessor="assessor",
                decision="pass",
                review_body_digest=subject(),
                review_trust_store=store,
            )
    with pytest.raises(ValueError, match="public keys must be unique"):
        VerificationTrustStore.build(
            (
                store.keys[0],
                TrustedPublicKey.build(
                    key_id=store.keys[1].key_id, public_key_hex=store.keys[0].public_key_hex
                ),
            )
        )


@pytest.mark.parametrize(
    "review_value",
    [
        attestation(reviewer_id="assessor"),
        attestation(valid_signature=False),
        attestation(body="0" * 64),
        attestation(decision="fail"),
        attestation(reviewed_at="2026-07-15T12:00:01Z"),
        attestation(expires_at="2026-07-15T12:00:00Z"),
    ],
)
def test_own_asserted_wrong_body_decision_and_noncurrent_review_cannot_count(
    review_value: ReviewerAttestation,
) -> None:
    """Self identity, invalid Ed25519 and stale/foreign original signed subjects remain unqualified."""
    with pytest.raises(ValueError, match="distinct verified independent"):
        validate_original_reviewers(
            contract=contract(),
            instant=INSTANT,
            reviews=(review_value,),
            assessor="assessor",
            decision="pass",
            review_body_digest=subject(),
            review_trust_store=trust_store("key-a"),
        )


def test_explicit_trust_current_signature_and_original_case_sensitive_identity_are_preserved() -> (
    None
):
    """No store or an unknown key refuses; original identity comparison is unchanged."""
    actual = attestation()
    with pytest.raises(ValueError, match="explicit trust store"):
        validate_original_reviewers(
            contract=contract(),
            instant=INSTANT,
            reviews=(actual,),
            assessor="assessor",
            decision="pass",
            review_body_digest=subject(),
            review_trust_store=None,
        )
    with pytest.raises(ValueError, match="distinct verified independent"):
        validate_original_reviewers(
            contract=contract(),
            instant=INSTANT,
            reviews=(actual,),
            assessor="assessor",
            decision="pass",
            review_body_digest=subject(),
            review_trust_store=trust_store("unknown-key"),
        )
    validate_original_reviewers(
        contract=contract(),
        instant=INSTANT,
        reviews=(attestation(reviewer_id="Assessor"),),
        assessor="assessor",
        decision="pass",
        review_body_digest=subject(),
        review_trust_store=trust_store("key-a"),
    )


def test_original_contract_construction_keeps_positive_age_and_independent_count() -> None:
    """No new contract replaces the original owner's positive numeric validation with a zero default."""
    original = contract()
    for field in ["freshness_seconds", "minimum_independent_reviewers"]:
        data = original.to_dict()
        data[field] = 0
        data.pop("contract_digest")
        data["contract_digest"] = canonical_digest(data)
        with pytest.raises(ValueError):
            EvidenceContract.from_dict(data)


def test_original_public_assessment_path_consumes_shared_predicates_and_keeps_its_wire() -> None:
    """Real original selected legacy assessment still builds, verifies review and round-trips end to end."""
    lock, selected = locked_control()
    run = evidence()
    rationale = "original exact signed assessment"
    actual = ControlAssessment.build(
        lock,
        selected,
        status="pass",
        assessor="assessment-agent",
        assessed_at=ASSESSED_AT,
        evidence=(run,),
        reviews=(review(lock, selected, evidence_items=(run,), rationale=rationale),),
        rationale=rationale,
        review_trust_store=trust_store("reviewer-key-1"),
    )
    assert actual.status == "pass"
    assert (
        ControlAssessment.from_dict(actual.to_dict(), lock, trust_store("reviewer-key-1"))
        == actual
    )
    assert actual.to_dict()["schema_version"] == "1.1"


@pytest.mark.parametrize("status", ["unassessed", "needs-evidence", "blocked"])
def test_original_public_nonpassing_states_remain_explicit_without_clearance(
    status: AssessmentStatus,
) -> None:
    """An applicable unassessed/waiting control retains its state without invented evidence or review."""
    lock, selected = locked_control()
    value = ControlAssessment.build(
        lock,
        selected,
        status=status,
        assessor="assessment-agent",
        assessed_at=ASSESSED_AT,
        rationale="" if status == "unassessed" else "awaiting original required evidence",
    )
    assert value.status == status and value.evidence == () and value.reviews == ()
    assert ControlAssessment.from_dict(value.to_dict(), lock) == value


def test_original_public_review_store_and_rehashed_review_subject_fields_cannot_be_substituted() -> (
    None
):
    """Actual signatures and a recomputed enclosing hash cannot hide missing trust or altered review bindings."""
    lock, selected = locked_control()
    run = evidence()
    rationale = "exact original reviewed assessment"
    approval = review(lock, selected, evidence_items=(run,), rationale=rationale)
    with pytest.raises(ValueError, match="review attestations require an explicit trust store"):
        ControlAssessment.build(
            lock,
            selected,
            status="pass",
            assessor="assessment-agent",
            assessed_at=ASSESSED_AT,
            evidence=(run,),
            reviews=(approval,),
            rationale=rationale,
        )
    store = trust_store("reviewer-key-1")
    value = ControlAssessment.build(
        lock,
        selected,
        status="pass",
        assessor="assessment-agent",
        assessed_at=ASSESSED_AT,
        evidence=(run,),
        reviews=(approval,),
        rationale=rationale,
        review_trust_store=store,
    )
    for field, message in [
        ("review_body_digest", "review body digest"),
        ("review_trust_store_digest", "review trust-store digest"),
    ]:
        data = value.to_dict()
        data[field] = "0" * 64
        data.pop("assessment_digest")
        data["assessment_digest"] = canonical_digest(data)
        with pytest.raises(ValueError, match=message):
            ControlAssessment.from_dict(data, lock, store)
