# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — offline verification result records
"""Represent replay-verifiable per-evidence and aggregate outcomes."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import cast

from .model_primitives import require_digest, require_identifier, require_utc_timestamp
from .models import canonical_digest, require_mapping, require_string
from .offline_verification_models import (
    OFFLINE_VERIFICATION_SCHEMA_VERSION,
    ArtifactKind,
    EvidenceEntry,
    VerificationStatus,
)

_ARTIFACT_KINDS = frozenset({"audit-report", "review", "standard-pack", "model-aliases"})
_RESULT_STATUSES = frozenset({"verified", "invalid", "stale", "unavailable"})


def _artifact_kind(value: object) -> ArtifactKind:
    """Return one supported result kind."""
    kind = require_string(value, "verification result.kind")
    if kind not in _ARTIFACT_KINDS:
        raise ValueError("verification result.kind is unsupported")
    return cast(ArtifactKind, kind)


@dataclass(frozen=True)
class EvidenceVerificationResult:
    """One deterministic verification outcome with a bounded explanation."""

    evidence_id: str
    kind: ArtifactKind
    status: VerificationStatus
    artifact_digest: str
    detail: str
    result_digest: str

    @classmethod
    def build(
        cls,
        entry: EvidenceEntry,
        status: VerificationStatus,
        detail: str,
    ) -> EvidenceVerificationResult:
        """Build one content-addressed result for an exact evidence entry."""
        if status not in _RESULT_STATUSES:
            raise ValueError("verification result status is unsupported")
        fields = {
            "evidence_id": entry.evidence_id,
            "kind": entry.kind,
            "status": status,
            "artifact_digest": entry.expected_digest,
            "detail": require_string(detail, "verification result.detail"),
        }
        return cls(
            evidence_id=entry.evidence_id,
            kind=entry.kind,
            status=status,
            artifact_digest=entry.expected_digest,
            detail=fields["detail"],
            result_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, str]:
        """Serialise one evidence verification result."""
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "status": self.status,
            "artifact_digest": self.artifact_digest,
            "detail": self.detail,
            "result_digest": self.result_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> EvidenceVerificationResult:
        """Parse and integrity-check one verification result."""
        data = require_mapping(value, "verification result")
        expected = {
            "evidence_id",
            "kind",
            "status",
            "artifact_digest",
            "detail",
            "result_digest",
        }
        if set(data) != expected:
            raise ValueError("verification result fields do not match the schema")
        status = require_string(data.get("status"), "verification result.status")
        if status not in _RESULT_STATUSES:
            raise ValueError("verification result status is unsupported")
        entry = EvidenceEntry.unavailable(
            require_identifier(data.get("evidence_id"), "verification result.evidence_id"),
            _artifact_kind(data.get("kind")),
            expected_digest=require_digest(
                data.get("artifact_digest"),
                "verification result.artifact_digest",
            ),
            reason="result reconstruction",
        )
        result = cls.build(
            entry,
            cast(VerificationStatus, status),
            require_string(data.get("detail"), "verification result.detail"),
        )
        if data.get("result_digest") != result.result_digest:
            raise ValueError("verification result digest does not match its content")
        return result


@dataclass(frozen=True)
class OfflineVerificationReport:
    """Replay-verifiable aggregate result of one offline verification pass."""

    evaluated_at: str
    policy_digest: str
    bundle_digest: str
    status: VerificationStatus
    results: tuple[EvidenceVerificationResult, ...]
    report_digest: str

    @classmethod
    def build(
        cls,
        *,
        evaluated_at: str,
        policy_digest: str,
        bundle_digest: str,
        results: tuple[EvidenceVerificationResult, ...],
    ) -> OfflineVerificationReport:
        """Build one deterministic aggregate without upgrading partial evidence."""
        statuses = {item.status for item in results}
        status: VerificationStatus = "verified"
        for candidate in ("invalid", "stale", "unavailable"):
            if candidate in statuses:
                status = cast(VerificationStatus, candidate)
                break
        fields: dict[str, object] = {
            "schema_version": OFFLINE_VERIFICATION_SCHEMA_VERSION,
            "evaluated_at": require_utc_timestamp(evaluated_at, "verification.evaluated_at"),
            "policy_digest": require_digest(policy_digest, "verification.policy_digest"),
            "bundle_digest": require_digest(bundle_digest, "verification.bundle_digest"),
            "status": status,
            "results": [item.to_dict() for item in results],
        }
        return cls(
            evaluated_at=cast(str, fields["evaluated_at"]),
            policy_digest=cast(str, fields["policy_digest"]),
            bundle_digest=cast(str, fields["bundle_digest"]),
            status=status,
            results=results,
            report_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the complete offline verification report."""
        return {
            "schema_version": OFFLINE_VERIFICATION_SCHEMA_VERSION,
            "evaluated_at": self.evaluated_at,
            "policy_digest": self.policy_digest,
            "bundle_digest": self.bundle_digest,
            "status": self.status,
            "results": [item.to_dict() for item in self.results],
            "report_digest": self.report_digest,
        }

    def to_json(self) -> str:
        """Render deterministic human-readable JSON."""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_dict(cls, value: object) -> OfflineVerificationReport:
        """Parse and integrity-check a persisted verification report."""
        data = require_mapping(value, "offline verification report")
        expected = {
            "schema_version",
            "evaluated_at",
            "policy_digest",
            "bundle_digest",
            "status",
            "results",
            "report_digest",
        }
        if set(data) != expected:
            raise ValueError("offline verification report fields do not match the schema")
        if data.get("schema_version") != OFFLINE_VERIFICATION_SCHEMA_VERSION:
            raise ValueError("unsupported offline verification-report schema version")
        raw_results = data.get("results")
        if not isinstance(raw_results, list):
            raise ValueError("offline verification report.results must be an array")
        report = cls.build(
            evaluated_at=require_string(data.get("evaluated_at"), "verification.evaluated_at"),
            policy_digest=require_digest(
                data.get("policy_digest"),
                "verification.policy_digest",
            ),
            bundle_digest=require_digest(
                data.get("bundle_digest"),
                "verification.bundle_digest",
            ),
            results=tuple(EvidenceVerificationResult.from_dict(item) for item in raw_results),
        )
        if data.get("status") != report.status:
            raise ValueError("offline verification status does not match its results")
        if data.get("report_digest") != report.report_digest:
            raise ValueError("offline verification report digest does not match its content")
        return report
