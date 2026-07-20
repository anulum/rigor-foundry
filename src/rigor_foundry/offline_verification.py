# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — ubiquitous offline evidence verification
"""Verify signed, content-addressed evidence without network dependencies."""

from __future__ import annotations

from datetime import datetime
from typing import cast

from .model_primitives import parse_utc_timestamp
from .offline_verification_models import (
    EVIDENCE_SIGNATURE_DOMAINS,
    DetachedEvidenceSignature,
    EvidenceEntry,
    ReviewEvidence,
    VerificationBundle,
    VerificationStatus,
)
from .offline_verification_report import (
    EvidenceVerificationResult,
    OfflineVerificationReport,
)
from .standard_pack import StandardPack
from .verification_policy import KeyStatus, OfflineTrustPolicy

_REVIEW_DECISION_MAP = {
    "valid": "pass",
    "invalid": "fail",
    "accepted-boundary": "accepted-risk",
    "needs-evidence": "needs-evidence",
}


def _key_failure(
    key_id: str,
    policy: OfflineTrustPolicy,
    instant: datetime,
) -> tuple[VerificationStatus, str] | None:
    """Return a lifecycle failure without hiding revocation as mere staleness."""
    status: KeyStatus = policy.key_status(key_id, instant)
    if status == "active":
        return None
    if status == "expired":
        return "stale", f"verification key {key_id} is expired"
    return "invalid", f"verification key {key_id} is {status}"


def _verify_detached(
    entry: EvidenceEntry,
    signature: DetachedEvidenceSignature,
    policy: OfflineTrustPolicy,
    instant: datetime,
) -> EvidenceVerificationResult:
    """Verify a report or model-alias detached signature and time bounds."""
    if signature.artifact_kind != entry.kind or signature.artifact_digest != entry.expected_digest:
        return EvidenceVerificationResult.build(
            entry,
            "invalid",
            "detached signature is bound to different evidence",
        )
    signing_time = parse_utc_timestamp(signature.signed_at, "evidence signature.signed_at")
    if instant < signing_time:
        return EvidenceVerificationResult.build(
            entry,
            "invalid",
            "evidence signature is not yet effective",
        )
    key_failure = _key_failure(signature.key_id, policy, instant)
    if key_failure is not None:
        return EvidenceVerificationResult.build(entry, *key_failure)
    if policy.key_status(signature.key_id, signing_time) != "active":
        return EvidenceVerificationResult.build(
            entry,
            "invalid",
            "verification key was not active when evidence was signed",
        )
    if instant >= parse_utc_timestamp(signature.expires_at, "evidence signature.expires_at"):
        return EvidenceVerificationResult.build(entry, "stale", "evidence signature is expired")
    if not policy.trust_store().verify(
        key_id=signature.key_id,
        algorithm=signature.algorithm,
        signature_domain=signature.signature_domain,
        payload_digest=signature.signed_payload_digest,
        signature_hex=signature.signature_hex,
    ):
        return EvidenceVerificationResult.build(
            entry,
            "invalid",
            "detached evidence signature is not valid",
        )
    return EvidenceVerificationResult.build(entry, "verified", "signed evidence is current")


def _verify_review(
    entry: EvidenceEntry,
    policy: OfflineTrustPolicy,
    instant: datetime,
) -> EvidenceVerificationResult:
    """Verify review content, decision semantics, signature, and expiry."""
    document = cast(ReviewEvidence, entry.document)
    attestation = document.attestation
    expected_decision = _REVIEW_DECISION_MAP[document.review.decision]
    if attestation.assessment_body_digest != document.review.review_digest:
        return EvidenceVerificationResult.build(
            entry,
            "invalid",
            "review attestation is bound to a different review record",
        )
    if attestation.decision != expected_decision:
        return EvidenceVerificationResult.build(
            entry,
            "invalid",
            "review attestation decision contradicts the review record",
        )
    reviewed_at = parse_utc_timestamp(attestation.reviewed_at, "review.reviewed_at")
    if instant < reviewed_at:
        return EvidenceVerificationResult.build(entry, "invalid", "review is not yet effective")
    key_failure = _key_failure(attestation.key_id, policy, instant)
    if key_failure is not None:
        return EvidenceVerificationResult.build(entry, *key_failure)
    if policy.key_status(attestation.key_id, reviewed_at) != "active":
        return EvidenceVerificationResult.build(
            entry,
            "invalid",
            "verification key was not active when the review was signed",
        )
    expires = parse_utc_timestamp(attestation.expires_at, "review.expires_at")
    if instant >= expires:
        return EvidenceVerificationResult.build(entry, "stale", "review attestation is expired")
    if not attestation.verified_at(
        instant,
        expected_decision,
        document.review.review_digest,
        policy.trust_store(),
    ):
        return EvidenceVerificationResult.build(
            entry,
            "invalid",
            "review attestation signature is not valid",
        )
    return EvidenceVerificationResult.build(entry, "verified", "signed review is current")


def _verify_pack(
    entry: EvidenceEntry,
    policy: OfflineTrustPolicy,
    instant: datetime,
) -> EvidenceVerificationResult:
    """Verify a StandardPack's native signature under the current key policy."""
    document = cast(StandardPack, entry.document)
    key_failure = _key_failure(document.signature.key_id, policy, instant)
    if key_failure is not None:
        return EvidenceVerificationResult.build(entry, *key_failure)
    if not policy.trust_store().verify(
        key_id=document.signature.key_id,
        algorithm=document.signature.algorithm,
        signature_domain=document.signature.signature_domain,
        payload_digest=document.signature.payload_digest,
        signature_hex=document.signature.signature_hex,
    ):
        return EvidenceVerificationResult.build(
            entry,
            "invalid",
            "standard-pack signature is not valid",
        )
    return EvidenceVerificationResult.build(entry, "verified", "signed standard pack is current")


def verify_evidence_bundle(
    bundle: VerificationBundle,
    policy: OfflineTrustPolicy,
    *,
    evaluated_at: str,
) -> OfflineVerificationReport:
    """Verify every bundled record using only supplied bytes and public keys."""
    rebuilt_bundle = VerificationBundle.from_dict(bundle.to_dict())
    rebuilt_policy = OfflineTrustPolicy.from_dict(policy.to_dict())
    instant = parse_utc_timestamp(evaluated_at, "verification.evaluated_at")
    results: list[EvidenceVerificationResult] = []
    for entry in rebuilt_bundle.entries:
        if entry.availability == "unavailable":
            results.append(EvidenceVerificationResult.build(entry, "unavailable", entry.reason))
        elif entry.kind in EVIDENCE_SIGNATURE_DOMAINS:
            results.append(
                _verify_detached(
                    entry,
                    cast(DetachedEvidenceSignature, entry.signature),
                    rebuilt_policy,
                    instant,
                )
            )
        elif entry.kind == "review":
            results.append(_verify_review(entry, rebuilt_policy, instant))
        else:
            results.append(_verify_pack(entry, rebuilt_policy, instant))
    return OfflineVerificationReport.build(
        evaluated_at=evaluated_at,
        policy_digest=rebuilt_policy.policy_digest,
        bundle_digest=rebuilt_bundle.bundle_digest,
        results=tuple(results),
    )
