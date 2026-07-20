# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — offline verification test fixtures
"""Build deterministic real-signature fixtures for offline verification tests."""

from __future__ import annotations

from typing import cast

from repository_audit_git_repository import sample_git_provenance, sample_tree_anchor
from signing_fixtures import pack_signature, public_key_hex, sign_message

from rigor_foundry.campaign_identity import InferenceIdentity
from rigor_foundry.condition_language import ConditionExpression
from rigor_foundry.models import AuditPolicy, AuditReport, Candidate, ReviewRecord
from rigor_foundry.offline_verification_models import (
    EVIDENCE_SIGNATURE_DOMAINS,
    ArtifactKind,
    DetachedEvidenceSignature,
    EvidenceEntry,
    ModelAliasEvidence,
    ReviewEvidence,
    VerificationBundle,
)
from rigor_foundry.review_attestation import ReviewDecision, ReviewerAttestation
from rigor_foundry.standard_pack import (
    ControlDefinition,
    EvidenceContract,
    RemediationContract,
    StandardPack,
)
from rigor_foundry.trust import REVIEW_ATTESTATION_SIGNATURE_DOMAIN, TrustedPublicKey
from rigor_foundry.verification_policy import OfflineTrustPolicy, VerificationKeyPolicy

SIGNED_AT = "2026-07-19T12:00:00Z"
EVALUATED_AT = "2026-07-20T12:00:00Z"
EXPIRES_AT = "2026-07-25T12:00:00Z"
KEY_IDS = ("model-key", "report-key", "review-key", "standards-key")


def audit_report() -> AuditReport:
    """Return one integrity-bound report with a reviewable candidate."""
    candidate = Candidate.build(
        category="architecture",
        rule_id="AR003-broad-optional-import-boundary",
        anchor=sample_tree_anchor("src/pkg/optional.py"),
        symbol="pkg.optional",
        evidence="broad import guard",
        confidence="high",
        rationale="nested import errors may be hidden",
        verification="run present, absent, and internally broken imports",
    )
    return AuditReport.build(
        repository_root="/workspace/project",
        head="1" * 40,
        head_tree="2" * 40,
        git_object_format="sha1",
        branch="main",
        tracked_content_digest="3" * 64,
        dirty_paths=(),
        tracked_file_count=1,
        git_provenance=sample_git_provenance(),
        policy=AuditPolicy(),
        candidates=(candidate,),
    )


def review_record(report: AuditReport | None = None) -> ReviewRecord:
    """Return one complete review bound to the fixture report."""
    selected = report or audit_report()
    return ReviewRecord(
        report_digest=selected.report_digest,
        candidate_id=selected.candidates[0].candidate_id,
        decision="valid",
        reviewer="reviewer/independent",
        reviewed_at=SIGNED_AT,
        rationale="the production import reproduction confirms the candidate",
        evidence=("python -I reproduce.py -> nested failure hidden",),
        severity="P1",
        owner="architecture/import-boundary",
        dependencies=(),
        acceptance_gates=("real import matrix passes",),
        title="Narrow the optional import boundary",
        boundary_justification="",
        expires_at=EXPIRES_AT,
        reopen_triggers=("dependency import graph changes",),
    )


def review_evidence(
    *,
    signature_domain: str = REVIEW_ATTESTATION_SIGNATURE_DOMAIN,
    signature_hex: str | None = None,
    assessment_body_digest: str | None = None,
    decision: str = "pass",
) -> ReviewEvidence:
    """Return a review plus one real or explicitly supplied attestation."""
    review = review_record()
    assessment = assessment_body_digest or review.review_digest
    payload = ReviewerAttestation.payload_digest(
        reviewer_id="reviewer/independent",
        key_id="review-key",
        assessment_body_digest=assessment,
        decision=cast(ReviewDecision, decision),
        reviewed_at=SIGNED_AT,
        expires_at=EXPIRES_AT,
        algorithm="ed25519",
    )
    signature = signature_hex or sign_message("review-key", signature_domain, payload)
    attestation = ReviewerAttestation.build(
        reviewer_id="reviewer/independent",
        key_id="review-key",
        assessment_body_digest=assessment,
        decision=cast(ReviewDecision, decision),
        reviewed_at=SIGNED_AT,
        expires_at=EXPIRES_AT,
        signature_hex=signature,
    )
    return ReviewEvidence.build(review=review, attestation=attestation)


def standard_pack(*, signature_hex: str | None = None) -> StandardPack:
    """Return one natively signed StandardPack."""
    control = ControlDefinition.build(
        control_id="core/no-godfiles",
        version="1.0.0",
        title="Bound module ownership",
        domain="godfile-responsibility",
        severity="P1",
        target_level="production",
        mode="require",
        default_applicable=True,
        condition=ConditionExpression.build("eq", reference="profile.mode", value="production"),
        evidence=EvidenceContract.build(
            contract_id="core/no-godfiles/evidence",
            required_adapters=("python-loc",),
            evidence_types=("loc-report",),
            freshness_seconds=3600,
            minimum_independent_reviewers=1,
        ),
        remediation=RemediationContract.build(
            dependencies=(),
            procedure_ids=("split-module",),
            acceptance_gates=("focused-tests",),
            reopen_triggers=("source-tree-changed",),
            independent_verifier_required=True,
        ),
    )
    source_digest = "4" * 64
    payload = StandardPack.payload_digest(
        pack_id="core",
        version="1.0.0",
        source_uri="https://standards.example/core/1.0.0",
        source_digest=source_digest,
        licence="MIT",
        controls=(control,),
    )
    signature = pack_signature(payload, "standards-key")
    if signature_hex is not None:
        signature = type(signature).build(
            key_id="standards-key",
            payload_digest=payload,
            signature_hex=signature_hex,
        )
    return StandardPack.build(
        pack_id="core",
        version="1.0.0",
        source_uri="https://standards.example/core/1.0.0",
        source_digest=source_digest,
        licence="MIT",
        signature=signature,
        controls=(control,),
    )


def model_aliases() -> ModelAliasEvidence:
    """Return two names that correctly collapse to one correlated witness."""
    return ModelAliasEvidence.build(
        (
            (
                "run-a",
                InferenceIdentity.build(
                    provider="provider-a",
                    model="model-1",
                    model_family="family-shared",
                    operator="operator-a",
                ),
            ),
            (
                "run-b",
                InferenceIdentity.build(
                    provider="provider-b",
                    model="model-2",
                    model_family="family-shared",
                    operator="operator-b",
                ),
            ),
        )
    )


def detached_signature(
    kind: ArtifactKind,
    digest: str,
    key_id: str,
    *,
    signing_domain: str | None = None,
    signed_at: str = SIGNED_AT,
    expires_at: str = EXPIRES_AT,
) -> DetachedEvidenceSignature:
    """Return one real signature, optionally signed under a replay domain."""
    payload = DetachedEvidenceSignature.payload_digest(
        artifact_kind=kind,
        key_id=key_id,
        artifact_digest=digest,
        signed_at=signed_at,
        expires_at=expires_at,
    )
    expected_domain = EVIDENCE_SIGNATURE_DOMAINS[kind]
    return DetachedEvidenceSignature.build(
        artifact_kind=kind,
        key_id=key_id,
        artifact_digest=digest,
        signed_at=signed_at,
        expires_at=expires_at,
        signature_domain=expected_domain,
        signature_hex=sign_message(key_id, signing_domain or expected_domain, payload),
    )


def trust_policy(
    *,
    revoked_key: str = "",
    valid_from: str = "2026-07-01T00:00:00Z",
    valid_until: str = "2026-08-01T00:00:00Z",
) -> OfflineTrustPolicy:
    """Return a lifecycle-bound policy for every fixture signing key."""
    keys = tuple(
        VerificationKeyPolicy.build(
            key=TrustedPublicKey.build(
                key_id=key_id,
                public_key_hex=public_key_hex(key_id),
            ),
            valid_from=valid_from,
            valid_until=valid_until,
            revoked_at="2026-07-20T00:00:00Z" if key_id == revoked_key else "",
        )
        for key_id in KEY_IDS
    )
    return OfflineTrustPolicy.build(keys)


def verification_bundle() -> VerificationBundle:
    """Return a complete four-kind bundle with valid signatures."""
    report = audit_report()
    aliases = model_aliases()
    return VerificationBundle.build(
        (
            EvidenceEntry.available(
                "report",
                report,
                signature=detached_signature("audit-report", report.report_digest, "report-key"),
            ),
            EvidenceEntry.available("review", review_evidence()),
            EvidenceEntry.available("pack", standard_pack()),
            EvidenceEntry.available(
                "aliases",
                aliases,
                signature=detached_signature(
                    "model-aliases",
                    aliases.alias_digest,
                    "model-key",
                ),
            ),
        )
    )
