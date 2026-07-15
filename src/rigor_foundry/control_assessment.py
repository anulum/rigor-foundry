# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — per-control evidence assessments
"""Assess each effective control from fresh evidence without aggregate verdicts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, cast

from .effective_profile import EffectiveControl, EffectiveProfileLock
from .model_primitives import (
    parse_utc_timestamp,
    require_digest,
    require_identifier,
    require_optional_string,
    require_utc_timestamp,
    validate_unique_strings,
)
from .models import canonical_digest, require_integer, require_mapping, require_string
from .review_attestation import ReviewerAttestation
from .trust import VerificationTrustStore

ASSESSMENT_SCHEMA_VERSION = "1.1"

AssessmentStatus = Literal[
    "unassessed",
    "needs-evidence",
    "blocked",
    "fail",
    "pass",
    "accepted-risk",
]
Classification = Literal["public", "internal", "confidential", "secret"]

_STATUSES = {
    "unassessed",
    "needs-evidence",
    "blocked",
    "fail",
    "pass",
    "accepted-risk",
}
_CLASSIFICATIONS = {"public", "internal", "confidential", "secret"}


def _object_array(value: object, field: str) -> list[object]:
    """Return one JSON object array without coercion."""
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array")
    return cast(list[object], value)


@dataclass(frozen=True)
class EvidenceReference:
    """Opaque, classified evidence reference with bounded freshness."""

    evidence_id: str
    evidence_type: str
    adapter_id: str
    adapter_digest: str
    artifact_digest: str
    artifact_size: int
    classification: Classification
    reference: str
    observed_at: str
    expires_at: str
    evidence_digest: str

    @classmethod
    def build(
        cls,
        *,
        evidence_id: str,
        evidence_type: str,
        adapter_id: str,
        adapter_digest: str,
        artifact_digest: str,
        artifact_size: int,
        classification: Classification,
        reference: str,
        observed_at: str,
        expires_at: str,
    ) -> EvidenceReference:
        """Build one metadata-only evidence reference."""
        if classification not in _CLASSIFICATIONS:
            raise ValueError("evidence.classification is unsupported")
        observed = require_utc_timestamp(observed_at, "evidence.observed_at")
        expires = require_utc_timestamp(expires_at, "evidence.expires_at")
        if parse_utc_timestamp(expires, "evidence.expires_at") <= parse_utc_timestamp(
            observed,
            "evidence.observed_at",
        ):
            raise ValueError("evidence.expires_at must be later than observed_at")
        opaque_reference = require_string(reference, "evidence.reference")
        if any(character.isspace() for character in opaque_reference):
            raise ValueError("evidence.reference must be an opaque whitespace-free reference")
        fields: dict[str, object] = {
            "evidence_id": require_identifier(evidence_id, "evidence.evidence_id"),
            "evidence_type": require_identifier(evidence_type, "evidence.evidence_type"),
            "adapter_id": require_identifier(adapter_id, "evidence.adapter_id"),
            "adapter_digest": require_digest(adapter_digest, "evidence.adapter_digest"),
            "artifact_digest": require_digest(
                artifact_digest,
                "evidence.artifact_digest",
            ),
            "artifact_size": require_integer(
                artifact_size,
                "evidence.artifact_size",
                minimum=0,
            ),
            "classification": classification,
            "reference": opaque_reference,
            "observed_at": observed,
            "expires_at": expires,
        }
        return cls(
            evidence_id=cast(str, fields["evidence_id"]),
            evidence_type=cast(str, fields["evidence_type"]),
            adapter_id=cast(str, fields["adapter_id"]),
            adapter_digest=cast(str, fields["adapter_digest"]),
            artifact_digest=cast(str, fields["artifact_digest"]),
            artifact_size=cast(int, fields["artifact_size"]),
            classification=classification,
            reference=opaque_reference,
            observed_at=observed,
            expires_at=expires,
            evidence_digest=canonical_digest(fields),
        )

    def fresh_at(self, instant: datetime, maximum_age_seconds: int) -> bool:
        """Return whether evidence is unexpired and inside the contract age bound."""
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise ValueError("evidence evaluation time must be timezone-aware")
        observed = parse_utc_timestamp(self.observed_at, "evidence.observed_at")
        expires = parse_utc_timestamp(self.expires_at, "evidence.expires_at")
        age = (instant - observed).total_seconds()
        return 0 <= age <= maximum_age_seconds and instant < expires

    def to_dict(self) -> dict[str, object]:
        """Serialise metadata only, never raw evidence payloads."""
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "adapter_id": self.adapter_id,
            "adapter_digest": self.adapter_digest,
            "artifact_digest": self.artifact_digest,
            "artifact_size": self.artifact_size,
            "classification": self.classification,
            "reference": self.reference,
            "observed_at": self.observed_at,
            "expires_at": self.expires_at,
            "evidence_digest": self.evidence_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> EvidenceReference:
        """Parse and integrity-check one evidence reference."""
        data = require_mapping(value, "evidence")
        classification = require_string(data.get("classification"), "evidence.classification")
        evidence = cls.build(
            evidence_id=require_identifier(data.get("evidence_id"), "evidence.evidence_id"),
            evidence_type=require_identifier(
                data.get("evidence_type"),
                "evidence.evidence_type",
            ),
            adapter_id=require_identifier(data.get("adapter_id"), "evidence.adapter_id"),
            adapter_digest=require_digest(
                data.get("adapter_digest"),
                "evidence.adapter_digest",
            ),
            artifact_digest=require_digest(
                data.get("artifact_digest"),
                "evidence.artifact_digest",
            ),
            artifact_size=require_integer(
                data.get("artifact_size"),
                "evidence.artifact_size",
            ),
            classification=cast(Classification, classification),
            reference=require_string(data.get("reference"), "evidence.reference"),
            observed_at=require_utc_timestamp(
                data.get("observed_at"),
                "evidence.observed_at",
            ),
            expires_at=require_utc_timestamp(
                data.get("expires_at"),
                "evidence.expires_at",
            ),
        )
        if data.get("evidence_digest") != evidence.evidence_digest:
            raise ValueError("evidence digest does not match its content")
        return evidence


@dataclass(frozen=True)
class ControlAssessment:
    """Evidence state for one exact effective control; never an aggregate score."""

    lock_digest: str
    effective_control_digest: str
    control_id: str
    status: AssessmentStatus
    assessor: str
    assessed_at: str
    evidence: tuple[EvidenceReference, ...]
    reviews: tuple[ReviewerAttestation, ...]
    rationale: str
    limitations: tuple[str, ...]
    accepted_waiver_id: str
    review_trust_store_digest: str | None
    review_body_digest: str
    assessment_digest: str

    @classmethod
    def body_digest_for_review(
        cls,
        lock: EffectiveProfileLock,
        control: EffectiveControl,
        *,
        status: AssessmentStatus,
        assessor: str,
        assessed_at: str,
        evidence: tuple[EvidenceReference, ...] = (),
        rationale: str,
        limitations: tuple[str, ...] = (),
        accepted_waiver_id: str = "",
        review_trust_store: VerificationTrustStore | None = None,
    ) -> str:
        """Digest the exact assessment body that external reviewers must attest."""
        return canonical_digest(
            cls._subject_fields(
                lock,
                control,
                status=status,
                assessor=assessor,
                assessed_at=assessed_at,
                evidence=evidence,
                rationale=rationale,
                limitations=limitations,
                accepted_waiver_id=accepted_waiver_id,
                review_trust_store=review_trust_store,
            )
        )

    @staticmethod
    def _subject_fields(
        lock: EffectiveProfileLock,
        control: EffectiveControl,
        *,
        status: AssessmentStatus,
        assessor: str,
        assessed_at: str,
        evidence: tuple[EvidenceReference, ...],
        rationale: str,
        limitations: tuple[str, ...],
        accepted_waiver_id: str,
        review_trust_store: VerificationTrustStore | None,
    ) -> dict[str, object]:
        """Validate and return the non-circular body covered by review proofs."""
        if status not in _STATUSES:
            raise ValueError("assessment.status is unsupported")
        matches = tuple(
            item for item in lock.controls if item.effective_digest == control.effective_digest
        )
        if len(matches) != 1 or matches[0] != control:
            raise ValueError("assessment control is not unique in the effective profile lock")
        instant_text = require_utc_timestamp(assessed_at, "assessment.assessed_at")
        validated_rationale = require_string(
            rationale,
            "assessment.rationale",
            allow_empty=status in {"unassessed", "needs-evidence", "blocked"},
        )
        validated_limitations = validate_unique_strings(
            limitations,
            "assessment.limitations",
        )
        validate_unique_strings(
            tuple(item.evidence_id for item in evidence),
            "assessment.evidence_ids",
        )
        ControlAssessment._validate_evidence_bindings(lock, control, evidence)
        return {
            "schema_version": ASSESSMENT_SCHEMA_VERSION,
            "lock_digest": lock.lock_digest,
            "effective_control_digest": control.effective_digest,
            "control_id": control.control.versioned_id,
            "status": status,
            "assessor": require_string(assessor, "assessment.assessor"),
            "assessed_at": instant_text,
            "evidence": [item.to_dict() for item in evidence],
            "rationale": validated_rationale,
            "limitations": list(validated_limitations),
            "accepted_waiver_id": require_optional_string(
                accepted_waiver_id,
                "assessment.accepted_waiver_id",
            ),
            "review_trust_store_digest": (
                review_trust_store.trust_store_digest if review_trust_store else None
            ),
        }

    @staticmethod
    def _validate_evidence_bindings(
        lock: EffectiveProfileLock,
        control: EffectiveControl,
        evidence: tuple[EvidenceReference, ...],
    ) -> None:
        """Require every reference to bind one exact domain-compatible adapter lock."""
        for item in evidence:
            matches = tuple(
                adapter for adapter in lock.adapters if adapter.adapter_id == item.adapter_id
            )
            if len(matches) != 1 or matches[0].adapter_digest != item.adapter_digest:
                raise ValueError("assessment evidence does not bind an exact locked adapter")
            if control.control.domain not in matches[0].domains:
                raise ValueError("assessment evidence adapter does not cover the control domain")

    @classmethod
    def build(
        cls,
        lock: EffectiveProfileLock,
        control: EffectiveControl,
        *,
        status: AssessmentStatus,
        assessor: str,
        assessed_at: str,
        evidence: tuple[EvidenceReference, ...] = (),
        reviews: tuple[ReviewerAttestation, ...] = (),
        rationale: str,
        limitations: tuple[str, ...] = (),
        accepted_waiver_id: str = "",
        review_trust_store: VerificationTrustStore | None = None,
    ) -> ControlAssessment:
        """Build and rederive every pass or accepted-risk precondition."""
        subject = cls._subject_fields(
            lock,
            control,
            status=status,
            assessor=assessor,
            assessed_at=assessed_at,
            evidence=evidence,
            rationale=rationale,
            limitations=limitations,
            accepted_waiver_id=accepted_waiver_id,
            review_trust_store=review_trust_store,
        )
        instant_text = cast(str, subject["assessed_at"])
        instant = parse_utc_timestamp(instant_text, "assessment.assessed_at")
        validated_rationale = cast(str, subject["rationale"])
        validated_limitations = tuple(cast(list[str], subject["limitations"]))
        waiver_id = cast(str, subject["accepted_waiver_id"])
        review_body_digest = canonical_digest(subject)
        validate_unique_strings(
            tuple(item.attestation_digest for item in reviews),
            "assessment.review_digests",
        )
        if reviews and review_trust_store is None:
            raise ValueError("review attestations require an explicit trust store")
        if not control.applicable:
            if status != "unassessed" or evidence or reviews or waiver_id:
                raise ValueError("not-applicable controls must remain explicitly unassessed")
        elif status == "pass":
            cls._validate_pass(
                control,
                instant,
                evidence,
                reviews,
                cast(str, subject["assessor"]),
                review_body_digest,
                review_trust_store,
            )
            if validated_limitations or waiver_id:
                raise ValueError("pass cannot hide limitations or accepted risk")
        elif status == "accepted-risk":
            if waiver_id not in control.risk_acceptance_waiver_ids:
                raise ValueError(
                    "accepted risk requires a dedicated active risk-acceptance waiver"
                )
            if not evidence:
                raise ValueError("accepted risk requires factual evidence")
            cls._validate_reviewers(
                control,
                instant,
                reviews,
                cast(str, subject["assessor"]),
                status,
                review_body_digest,
                review_trust_store,
            )
        elif status == "fail":
            if not evidence:
                raise ValueError("failed controls require factual evidence")
        elif status in {"needs-evidence", "blocked"}:
            if not validated_rationale and not validated_limitations:
                raise ValueError(f"{status} requires rationale or limitations")
        elif evidence or reviews or waiver_id:
            raise ValueError("unassessed controls cannot carry clearance evidence")
        fields: dict[str, object] = {
            **subject,
            "reviews": [item.to_dict() for item in reviews],
            "review_body_digest": review_body_digest,
        }
        return cls(
            lock_digest=lock.lock_digest,
            effective_control_digest=control.effective_digest,
            control_id=control.control.versioned_id,
            status=status,
            assessor=cast(str, subject["assessor"]),
            assessed_at=instant_text,
            evidence=evidence,
            reviews=reviews,
            rationale=validated_rationale,
            limitations=validated_limitations,
            accepted_waiver_id=waiver_id,
            review_trust_store_digest=cast(
                str | None,
                subject["review_trust_store_digest"],
            ),
            review_body_digest=review_body_digest,
            assessment_digest=canonical_digest(fields),
        )

    @staticmethod
    def _validate_pass(
        control: EffectiveControl,
        instant: datetime,
        evidence: tuple[EvidenceReference, ...],
        reviews: tuple[ReviewerAttestation, ...],
        assessor: str,
        review_body_digest: str,
        review_trust_store: VerificationTrustStore | None,
    ) -> None:
        """Validate evidence and review contracts for a pass."""
        if control.missing_adapter_ids:
            raise ValueError("control with missing evidence adapters cannot pass")
        contract = control.control.evidence
        fresh = tuple(
            item for item in evidence if item.fresh_at(instant, contract.freshness_seconds)
        )
        if len(fresh) != len(evidence) or not fresh:
            raise ValueError("pass requires only fresh, non-empty evidence")
        missing_adapters = set(contract.required_adapters).difference(
            item.adapter_id for item in fresh
        )
        missing_types = set(contract.evidence_types).difference(
            item.evidence_type for item in fresh
        )
        if missing_adapters or missing_types:
            raise ValueError("pass evidence does not satisfy adapter and type coverage")
        ControlAssessment._validate_reviewers(
            control,
            instant,
            reviews,
            assessor,
            "pass",
            review_body_digest,
            review_trust_store,
        )

    @staticmethod
    def _validate_reviewers(
        control: EffectiveControl,
        instant: datetime,
        reviews: tuple[ReviewerAttestation, ...],
        assessor: str,
        decision: AssessmentStatus,
        review_body_digest: str,
        review_trust_store: VerificationTrustStore | None,
    ) -> None:
        """Count distinct identities and keys bound to the exact assessment body."""
        if review_trust_store is None:
            raise ValueError("verified independent reviewers require an explicit trust store")
        verified = tuple(
            item
            for item in reviews
            if item.reviewer_id != assessor
            and item.verified_at(
                instant,
                decision,
                review_body_digest,
                review_trust_store,
            )
        )
        key_ids = {item.key_id for item in verified}
        reviewer_ids = {item.reviewer_id for item in verified}
        required = control.control.evidence.minimum_independent_reviewers
        if len(key_ids) < required or len(reviewer_ids) < required:
            raise ValueError("assessment lacks enough distinct verified independent reviewers")

    def to_dict(self) -> dict[str, object]:
        """Serialise one per-control assessment."""
        return {
            "schema_version": ASSESSMENT_SCHEMA_VERSION,
            "lock_digest": self.lock_digest,
            "effective_control_digest": self.effective_control_digest,
            "control_id": self.control_id,
            "status": self.status,
            "assessor": self.assessor,
            "assessed_at": self.assessed_at,
            "evidence": [item.to_dict() for item in self.evidence],
            "reviews": [item.to_dict() for item in self.reviews],
            "rationale": self.rationale,
            "limitations": list(self.limitations),
            "accepted_waiver_id": self.accepted_waiver_id,
            "review_trust_store_digest": self.review_trust_store_digest,
            "review_body_digest": self.review_body_digest,
            "assessment_digest": self.assessment_digest,
        }

    @classmethod
    def from_dict(
        cls,
        value: object,
        lock: EffectiveProfileLock,
        review_trust_store: VerificationTrustStore | None = None,
    ) -> ControlAssessment:
        """Parse an assessment and rederive all clearance predicates."""
        data = require_mapping(value, "assessment")
        if data.get("schema_version") != ASSESSMENT_SCHEMA_VERSION:
            raise ValueError("unsupported assessment schema version")
        effective_digest = require_digest(
            data.get("effective_control_digest"),
            "assessment.effective_control_digest",
        )
        matches = tuple(
            item for item in lock.controls if item.effective_digest == effective_digest
        )
        if len(matches) != 1:
            raise ValueError("assessment references an unknown effective control")
        status = require_string(data.get("status"), "assessment.status")
        assessment = cls.build(
            lock,
            matches[0],
            status=cast(AssessmentStatus, status),
            assessor=require_string(data.get("assessor"), "assessment.assessor"),
            assessed_at=require_utc_timestamp(
                data.get("assessed_at"),
                "assessment.assessed_at",
            ),
            evidence=tuple(
                EvidenceReference.from_dict(item)
                for item in _object_array(data.get("evidence"), "assessment.evidence")
            ),
            reviews=tuple(
                ReviewerAttestation.from_dict(item)
                for item in _object_array(data.get("reviews"), "assessment.reviews")
            ),
            rationale=require_string(
                data.get("rationale", ""),
                "assessment.rationale",
                allow_empty=True,
            ),
            limitations=tuple(
                require_string(item, "assessment.limitations[]")
                for item in _object_array(
                    data.get("limitations"),
                    "assessment.limitations",
                )
            ),
            accepted_waiver_id=require_optional_string(
                data.get("accepted_waiver_id", ""),
                "assessment.accepted_waiver_id",
            ),
            review_trust_store=review_trust_store,
        )
        if data.get("lock_digest") != lock.lock_digest:
            raise ValueError("assessment lock digest does not match")
        if data.get("control_id") != assessment.control_id:
            raise ValueError("assessment control id does not match")
        if data.get("review_body_digest") != assessment.review_body_digest:
            raise ValueError("assessment review body digest does not match")
        if data.get("review_trust_store_digest") != assessment.review_trust_store_digest:
            raise ValueError("assessment review trust-store digest does not match")
        recorded = require_digest(data.get("assessment_digest"), "assessment.assessment_digest")
        if recorded != assessment.assessment_digest:
            raise ValueError("assessment digest does not match its content")
        return assessment
