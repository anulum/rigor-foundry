# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — repository-audit conformance ratchet
"""Evaluate reviewed candidates under observe, ratchet, or zero enforcement."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from .adapters import AdapterResult
from .models import AuditReport, EnforcementMode, ReviewRecord
from .review import validate_reviews


@dataclass(frozen=True)
class EnforcementResult:
    """One repository conformance decision.

    Parameters
    ----------
    mode:
        Configured forward-only enforcement state.
    candidate_count:
        Total candidates in the exact report.
    reviewed_count:
        Candidates with one completed current review.
    valid_debt_count:
        Reviewed findings still requiring remediation.
    adapter_results:
        Repository-native audit execution evidence.
    blockers:
        Conditions that prevent conformance in the configured mode.

    """

    mode: EnforcementMode
    candidate_count: int
    reviewed_count: int
    valid_debt_count: int
    adapter_results: tuple[AdapterResult, ...]
    blockers: tuple[str, ...]

    @property
    def passed(self) -> bool:
        """Return whether the configured conformance gate passes."""
        return not self.blockers

    def to_dict(self) -> dict[str, object]:
        """Serialise the conformance decision."""
        return {
            "mode": self.mode,
            "candidate_count": self.candidate_count,
            "reviewed_count": self.reviewed_count,
            "valid_debt_count": self.valid_debt_count,
            "adapter_results": [item.to_dict() for item in self.adapter_results],
            "blockers": list(self.blockers),
            "passed": self.passed,
        }


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
    return EnforcementResult(
        mode=mode,
        candidate_count=len(report.candidates),
        reviewed_count=len(completed),
        valid_debt_count=sum(1 for review in completed.values() if review.decision == "valid"),
        adapter_results=adapter_results,
        blockers=tuple(blockers),
    )
