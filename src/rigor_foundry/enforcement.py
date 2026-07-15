# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — repository-audit conformance ratchet
"""Evaluate reviewed candidates under observe, ratchet, or zero enforcement."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from .adapters import AdapterResult
from .models import (
    AuditReport,
    EnforcementMode,
    ReviewRecord,
    canonical_digest,
    require_integer,
    require_mapping,
    require_string,
    require_string_tuple,
)
from .review import validate_reviews

ENFORCEMENT_SCHEMA_VERSION = "1.0"


def _digest(value: object, field: str, *, lengths: tuple[int, ...] = (64,)) -> str:
    """Return one lowercase hexadecimal content identifier."""
    result = require_string(value, field)
    if len(result) not in lengths or any(
        character not in "0123456789abcdef" for character in result
    ):
        raise ValueError(f"{field} must be a lowercase hexadecimal digest")
    return result


@dataclass(frozen=True)
class EnforcementResult:
    """Content-addressed conformance decision for one exact repository state."""

    mode: EnforcementMode
    head: str
    head_tree: str
    tracked_content_digest: str
    policy_digest: str
    report_digest: str
    candidate_count: int
    reviewed_count: int
    valid_debt_count: int
    adapter_results: tuple[AdapterResult, ...]
    adapter_evidence_digest: str
    blockers: tuple[str, ...]
    gate_digest: str

    @classmethod
    def build(
        cls,
        *,
        report: AuditReport,
        mode: EnforcementMode,
        reviewed_count: int,
        valid_debt_count: int,
        adapter_results: tuple[AdapterResult, ...],
        blockers: tuple[str, ...],
    ) -> EnforcementResult:
        """Build a decision and bind every report and adapter identity."""
        adapter_evidence = [item.to_dict() for item in adapter_results]
        fields: dict[str, object] = {
            "schema_version": ENFORCEMENT_SCHEMA_VERSION,
            "mode": mode,
            "head": report.head,
            "head_tree": report.head_tree,
            "tracked_content_digest": report.tracked_content_digest,
            "policy_digest": report.policy_digest,
            "report_digest": report.report_digest,
            "candidate_count": len(report.candidates),
            "reviewed_count": reviewed_count,
            "valid_debt_count": valid_debt_count,
            "adapter_results": adapter_evidence,
            "adapter_evidence_digest": canonical_digest(adapter_evidence),
            "blockers": list(blockers),
            "passed": not blockers,
        }
        return cls._from_fields(fields, canonical_digest(fields))

    @classmethod
    def _from_fields(cls, fields: dict[str, object], digest: str) -> EnforcementResult:
        """Construct one decision from canonical validated fields."""
        raw_results = cast(list[object], fields["adapter_results"])
        return cls(
            mode=cast(EnforcementMode, fields["mode"]),
            head=cast(str, fields["head"]),
            head_tree=cast(str, fields["head_tree"]),
            tracked_content_digest=cast(str, fields["tracked_content_digest"]),
            policy_digest=cast(str, fields["policy_digest"]),
            report_digest=cast(str, fields["report_digest"]),
            candidate_count=cast(int, fields["candidate_count"]),
            reviewed_count=cast(int, fields["reviewed_count"]),
            valid_debt_count=cast(int, fields["valid_debt_count"]),
            adapter_results=tuple(
                AdapterResult.from_dict(item, index) for index, item in enumerate(raw_results)
            ),
            adapter_evidence_digest=cast(str, fields["adapter_evidence_digest"]),
            blockers=tuple(cast(list[str], fields["blockers"])),
            gate_digest=digest,
        )

    @property
    def passed(self) -> bool:
        """Return whether the configured conformance gate passes."""
        return not self.blockers

    def to_dict(self) -> dict[str, object]:
        """Serialise the exact-state conformance decision."""
        return {
            "schema_version": ENFORCEMENT_SCHEMA_VERSION,
            "mode": self.mode,
            "head": self.head,
            "head_tree": self.head_tree,
            "tracked_content_digest": self.tracked_content_digest,
            "policy_digest": self.policy_digest,
            "report_digest": self.report_digest,
            "candidate_count": self.candidate_count,
            "reviewed_count": self.reviewed_count,
            "valid_debt_count": self.valid_debt_count,
            "adapter_results": [item.to_dict() for item in self.adapter_results],
            "adapter_evidence_digest": self.adapter_evidence_digest,
            "blockers": list(self.blockers),
            "passed": self.passed,
            "gate_digest": self.gate_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> EnforcementResult:
        """Parse an enforcement artifact and reject any content tampering."""
        data = require_mapping(value, "enforcement")
        if data.get("schema_version") != ENFORCEMENT_SCHEMA_VERSION:
            raise ValueError("unsupported enforcement schema version")
        mode = require_string(data.get("mode"), "enforcement.mode")
        if mode not in {"observe", "ratchet", "zero"}:
            raise ValueError("unsupported enforcement mode")
        raw_results = data.get("adapter_results")
        if not isinstance(raw_results, list):
            raise ValueError("enforcement.adapter_results must be an array")
        adapter_results = [
            AdapterResult.from_dict(item, index).to_dict()
            for index, item in enumerate(raw_results)
        ]
        recorded_adapter_digest = _digest(
            data.get("adapter_evidence_digest"),
            "enforcement.adapter_evidence_digest",
        )
        if recorded_adapter_digest != canonical_digest(adapter_results):
            raise ValueError("adapter evidence digest does not match its content")
        blockers = list(require_string_tuple(data.get("blockers"), "enforcement.blockers"))
        passed = data.get("passed")
        if not isinstance(passed, bool) or passed is not (not blockers):
            raise ValueError("enforcement.passed does not match blockers")
        fields: dict[str, object] = {
            "schema_version": ENFORCEMENT_SCHEMA_VERSION,
            "mode": mode,
            "head": _digest(data.get("head"), "enforcement.head", lengths=(40, 64)),
            "head_tree": _digest(
                data.get("head_tree"),
                "enforcement.head_tree",
                lengths=(40, 64),
            ),
            "tracked_content_digest": _digest(
                data.get("tracked_content_digest"),
                "enforcement.tracked_content_digest",
            ),
            "policy_digest": _digest(data.get("policy_digest"), "enforcement.policy_digest"),
            "report_digest": _digest(data.get("report_digest"), "enforcement.report_digest"),
            "candidate_count": require_integer(
                data.get("candidate_count"),
                "enforcement.candidate_count",
                minimum=0,
            ),
            "reviewed_count": require_integer(
                data.get("reviewed_count"),
                "enforcement.reviewed_count",
                minimum=0,
            ),
            "valid_debt_count": require_integer(
                data.get("valid_debt_count"),
                "enforcement.valid_debt_count",
                minimum=0,
            ),
            "adapter_results": adapter_results,
            "adapter_evidence_digest": recorded_adapter_digest,
            "blockers": blockers,
            "passed": passed,
        }
        recorded_gate_digest = _digest(
            data.get("gate_digest"),
            "enforcement.gate_digest",
        )
        if recorded_gate_digest != canonical_digest(fields):
            raise ValueError("gate digest does not match enforcement content")
        return cls._from_fields(fields, recorded_gate_digest)

    def assert_report(self, report: AuditReport) -> None:
        """Reject use of this artifact for a different or stale report."""
        observed = (
            report.head,
            report.head_tree,
            report.tracked_content_digest,
            report.policy_digest,
            report.report_digest,
            len(report.candidates),
        )
        expected = (
            self.head,
            self.head_tree,
            self.tracked_content_digest,
            self.policy_digest,
            self.report_digest,
            self.candidate_count,
        )
        if observed != expected:
            raise ValueError("enforcement artifact belongs to a different repository report")


def _parse_utc(value: str) -> datetime:
    """Parse an already schema-validated UTC timestamp."""
    normalised = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalised)
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError("review expiry must use UTC")
    return parsed


def _completed_review_by_candidate(
    reviews: tuple[ReviewRecord, ...],
) -> dict[str, ReviewRecord]:
    """Return unique completed reviews keyed by candidate identifier."""
    completed: dict[str, ReviewRecord] = {}
    for review in reviews:
        if review.decision == "needs-evidence":
            continue
        if review.candidate_id in completed:
            raise ValueError("candidate has multiple completed reviews")
        completed[review.candidate_id] = review
    return completed


def evaluate_enforcement(
    report: AuditReport,
    reviews: tuple[ReviewRecord, ...],
    mode: EnforcementMode,
    *,
    adapter_results: tuple[AdapterResult, ...] = (),
    now: datetime | None = None,
) -> EnforcementResult:
    """Evaluate one exact report and review ledger.

    Parameters
    ----------
    report:
        Integrity-verified current repository report.
    reviews:
        Candidate decisions bound to ``report``.
    mode:
        ``observe`` records evidence, ``ratchet`` rejects new unreviewed debt,
        and ``zero`` additionally rejects reviewed valid debt.
    adapter_results:
        Repository-native audit results for the same scope.
    now:
        Optional UTC decision time for deterministic verification.

    Returns
    -------
    EnforcementResult
        Counts, native evidence, and exact blocking conditions.

    """
    if mode not in {"observe", "ratchet", "zero"}:
        raise ValueError(f"unsupported enforcement mode: {mode}")
    decision_time = now or datetime.now(UTC)
    if decision_time.tzinfo is None or decision_time.utcoffset() != UTC.utcoffset(decision_time):
        raise ValueError("enforcement time must use UTC")
    validation_errors = validate_reviews(report, reviews)
    blockers = list(validation_errors)
    completed = _completed_review_by_candidate(reviews)
    current_ids = {candidate.candidate_id for candidate in report.candidates}
    completed = {
        candidate_id: review
        for candidate_id, review in completed.items()
        if candidate_id in current_ids
    }
    expired: set[str] = set()
    for candidate_id, review in completed.items():
        if review.expires_at and _parse_utc(review.expires_at) <= decision_time:
            expired.add(candidate_id)
    required_adapter_failures = tuple(
        result for result in adapter_results if result.required and not result.passed
    )
    blockers.extend(
        f"native audit {result.name} failed with exit {result.returncode}"
        for result in required_adapter_failures
    )
    if mode != "observe":
        for candidate in report.candidates:
            candidate_review = completed.get(candidate.candidate_id)
            if candidate_review is None:
                blockers.append(
                    f"unreviewed current candidate {candidate.candidate_id} ({candidate.rule_id})"
                )
            elif candidate.candidate_id in expired:
                blockers.append(f"review expired for candidate {candidate.candidate_id}")
            elif mode == "zero" and candidate_review.decision == "valid":
                blockers.append(f"valid remediation debt remains: {candidate.candidate_id}")
    return EnforcementResult.build(
        report=report,
        mode=mode,
        reviewed_count=len(completed),
        valid_debt_count=sum(1 for review in completed.values() if review.decision == "valid"),
        adapter_results=adapter_results,
        blockers=tuple(blockers),
    )
