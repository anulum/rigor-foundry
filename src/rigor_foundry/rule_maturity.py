# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — adjudicated rule-maturity evidence
"""Calibrate per-rule enforcement from adjudicated review evidence."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from .audit_primitives import (
    canonical_digest,
    require_exact_fields,
    require_integer,
    require_mapping,
    require_string,
)
from .model_primitives import (
    require_digest,
    require_git_object,
    require_identifier,
    require_nonempty_strings,
    require_utc_timestamp,
)
from .models import AuditReport, ReviewRecord
from .review import review_errors
from .rules import RULE_PACK_VERSION, RULES, RULES_BY_ID, rule_pack_digest

RULE_MATURITY_SCHEMA_VERSION = "1.0"

RuleMaturityStatus = Literal["probation", "active"]
RuleMaturityReason = Literal[
    "insufficient-reviews",
    "insufficient-repositories",
    "insufficient-reviewers",
    "insufficient-positive-reviews",
    "false-positive-rate-exceeded",
    "median-effort-exceeded",
    "p90-effort-exceeded",
]

_POLICY_FIELDS = frozenset(
    {
        "minimum_adjudicated_reviews",
        "minimum_distinct_repositories",
        "minimum_distinct_reviewers",
        "minimum_positive_reviews",
        "maximum_false_positive_basis_points",
        "maximum_median_effort_seconds",
        "maximum_p90_effort_seconds",
        "policy_digest",
    }
)
_EVIDENCE_FIELDS = frozenset(
    {
        "repository_id",
        "head_tree",
        "tracked_content_digest",
        "policy_digest",
        "report_digest",
        "candidate_id",
        "rule_id",
        "review_digest",
        "decision",
        "reviewer",
        "reviewed_at",
        "reviewer_effort_seconds",
        "effort_evidence",
        "evidence_digest",
    }
)
_ASSESSMENT_FIELDS = frozenset(
    {
        "rule_id",
        "status",
        "review_count",
        "repository_count",
        "reviewer_count",
        "positive_review_count",
        "false_positive_count",
        "false_positive_basis_points",
        "median_effort_seconds",
        "p90_effort_seconds",
        "evidence_digest",
        "probation_reasons",
    }
)
_REPORT_FIELDS = frozenset(
    {
        "schema_version",
        "rule_pack_version",
        "rule_pack_digest",
        "policy",
        "evidence",
        "assessments",
        "maturity_digest",
    }
)
_COMPLETED_DECISIONS = frozenset({"valid", "invalid", "accepted-boundary"})


@dataclass(frozen=True)
class RuleMaturityPolicy:
    """Explicit evidence thresholds for activating one audit rule.

    Thresholds are adopter policy, not universal quality claims. The false-
    positive threshold uses basis points so canonical records avoid floating-
    point ambiguity.
    """

    minimum_adjudicated_reviews: int
    minimum_distinct_repositories: int
    minimum_distinct_reviewers: int
    minimum_positive_reviews: int
    maximum_false_positive_basis_points: int
    maximum_median_effort_seconds: int
    maximum_p90_effort_seconds: int
    policy_digest: str

    @classmethod
    def build(
        cls,
        *,
        minimum_adjudicated_reviews: int,
        minimum_distinct_repositories: int,
        minimum_distinct_reviewers: int,
        minimum_positive_reviews: int,
        maximum_false_positive_basis_points: int,
        maximum_median_effort_seconds: int,
        maximum_p90_effort_seconds: int,
    ) -> RuleMaturityPolicy:
        """Build a content-addressed threshold policy.

        Parameters
        ----------
        minimum_adjudicated_reviews:
            Minimum completed candidate reviews required for each rule.
        minimum_distinct_repositories:
            Minimum declared repository identities represented by the reviews.
        minimum_distinct_reviewers:
            Minimum reviewer identities represented by the reviews.
        minimum_positive_reviews:
            Minimum ``valid`` or ``accepted-boundary`` decisions.
        maximum_false_positive_basis_points:
            Greatest allowed proportion of ``invalid`` decisions, in basis
            points from zero through ten thousand.
        maximum_median_effort_seconds:
            Greatest allowed conservative integer median review effort.
        maximum_p90_effort_seconds:
            Greatest allowed nearest-rank 90th-percentile review effort.
        """
        fields = cls._validated_fields(
            {
                "minimum_adjudicated_reviews": minimum_adjudicated_reviews,
                "minimum_distinct_repositories": minimum_distinct_repositories,
                "minimum_distinct_reviewers": minimum_distinct_reviewers,
                "minimum_positive_reviews": minimum_positive_reviews,
                "maximum_false_positive_basis_points": maximum_false_positive_basis_points,
                "maximum_median_effort_seconds": maximum_median_effort_seconds,
                "maximum_p90_effort_seconds": maximum_p90_effort_seconds,
            }
        )
        return cls(**fields, policy_digest=canonical_digest(fields))

    @staticmethod
    def _validated_fields(value: dict[str, object]) -> dict[str, int]:
        """Return validated threshold fields without their digest."""
        fields = {
            "minimum_adjudicated_reviews": require_integer(
                value.get("minimum_adjudicated_reviews"),
                "maturity policy.minimum_adjudicated_reviews",
                minimum=1,
            ),
            "minimum_distinct_repositories": require_integer(
                value.get("minimum_distinct_repositories"),
                "maturity policy.minimum_distinct_repositories",
                minimum=1,
            ),
            "minimum_distinct_reviewers": require_integer(
                value.get("minimum_distinct_reviewers"),
                "maturity policy.minimum_distinct_reviewers",
                minimum=1,
            ),
            "minimum_positive_reviews": require_integer(
                value.get("minimum_positive_reviews"),
                "maturity policy.minimum_positive_reviews",
                minimum=1,
            ),
            "maximum_false_positive_basis_points": require_integer(
                value.get("maximum_false_positive_basis_points"),
                "maturity policy.maximum_false_positive_basis_points",
            ),
            "maximum_median_effort_seconds": require_integer(
                value.get("maximum_median_effort_seconds"),
                "maturity policy.maximum_median_effort_seconds",
                minimum=1,
            ),
            "maximum_p90_effort_seconds": require_integer(
                value.get("maximum_p90_effort_seconds"),
                "maturity policy.maximum_p90_effort_seconds",
                minimum=1,
            ),
        }
        if fields["maximum_false_positive_basis_points"] > 10_000:
            raise ValueError(
                "maturity policy.maximum_false_positive_basis_points must be <= 10000"
            )
        if fields["minimum_positive_reviews"] > fields["minimum_adjudicated_reviews"]:
            raise ValueError(
                "maturity policy.minimum_positive_reviews cannot exceed "
                "minimum_adjudicated_reviews"
            )
        if fields["maximum_median_effort_seconds"] > fields["maximum_p90_effort_seconds"]:
            raise ValueError(
                "maturity policy maximum median effort cannot exceed maximum p90 effort"
            )
        return fields

    def to_dict(self) -> dict[str, object]:
        """Serialise the threshold policy and its identity."""
        return {
            "minimum_adjudicated_reviews": self.minimum_adjudicated_reviews,
            "minimum_distinct_repositories": self.minimum_distinct_repositories,
            "minimum_distinct_reviewers": self.minimum_distinct_reviewers,
            "minimum_positive_reviews": self.minimum_positive_reviews,
            "maximum_false_positive_basis_points": self.maximum_false_positive_basis_points,
            "maximum_median_effort_seconds": self.maximum_median_effort_seconds,
            "maximum_p90_effort_seconds": self.maximum_p90_effort_seconds,
            "policy_digest": self.policy_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> RuleMaturityPolicy:
        """Parse a threshold policy and reject field or digest tampering."""
        data = require_mapping(value, "maturity policy")
        require_exact_fields(data, _POLICY_FIELDS, "maturity policy")
        fields = cls._validated_fields(data)
        recorded = require_digest(data.get("policy_digest"), "maturity policy.policy_digest")
        if recorded != canonical_digest(fields):
            raise ValueError("maturity policy digest does not match its content")
        return cls(**fields, policy_digest=recorded)


@dataclass(frozen=True)
class RuleReviewEvidence:
    """One completed review projected into rule-calibration evidence."""

    repository_id: str
    head_tree: str
    tracked_content_digest: str
    policy_digest: str
    report_digest: str
    candidate_id: str
    rule_id: str
    review_digest: str
    decision: Literal["valid", "invalid", "accepted-boundary"]
    reviewer: str
    reviewed_at: str
    reviewer_effort_seconds: int
    effort_evidence: tuple[str, ...]
    evidence_digest: str

    @classmethod
    def build(
        cls,
        report: AuditReport,
        review: ReviewRecord,
        *,
        repository_id: str,
        reviewer_effort_seconds: int,
        effort_evidence: tuple[str, ...],
    ) -> RuleReviewEvidence:
        """Project one validated report/review pair into calibration evidence.

        Parameters
        ----------
        report:
            Integrity-verified report containing the reviewed candidate.
        review:
            Complete evidence decision bound to ``report``.
        repository_id:
            Operator-declared portable repository identity. This declaration
            is recorded but is not authenticated by this schema.
        reviewer_effort_seconds:
            Measured active review effort. The measurement method remains an
            evidence-collection responsibility outside this record.
        effort_evidence:
            Non-empty references to the timer, work record, or other retained
            source supporting the measured duration.
        """
        errors = review_errors(report, review)
        if errors:
            raise ValueError("review is not adjudicated: " + "; ".join(errors))
        if review.decision not in _COMPLETED_DECISIONS:
            raise ValueError("maturity evidence requires a completed review decision")
        candidates = tuple(
            candidate
            for candidate in report.candidates
            if candidate.candidate_id == review.candidate_id
        )
        if len(candidates) != 1:
            raise ValueError("maturity evidence candidate must occur exactly once")
        fields: dict[str, object] = {
            "repository_id": require_identifier(repository_id, "repository_id"),
            "head_tree": report.head_tree,
            "tracked_content_digest": report.tracked_content_digest,
            "policy_digest": report.policy_digest,
            "report_digest": report.report_digest,
            "candidate_id": review.candidate_id,
            "rule_id": candidates[0].rule_id,
            "review_digest": review.review_digest,
            "decision": review.decision,
            "reviewer": require_identifier(review.reviewer, "reviewer"),
            "reviewed_at": require_utc_timestamp(review.reviewed_at, "reviewed_at"),
            "reviewer_effort_seconds": require_integer(
                reviewer_effort_seconds,
                "reviewer_effort_seconds",
                minimum=1,
            ),
            "effort_evidence": list(
                require_nonempty_strings(list(effort_evidence), "effort_evidence", minimum=1)
            ),
        }
        return cls._from_fields(fields, canonical_digest(fields))

    @classmethod
    def _from_fields(cls, fields: dict[str, object], digest: str) -> RuleReviewEvidence:
        """Construct one evidence record from validated canonical fields."""
        return cls(
            repository_id=cast(str, fields["repository_id"]),
            head_tree=cast(str, fields["head_tree"]),
            tracked_content_digest=cast(str, fields["tracked_content_digest"]),
            policy_digest=cast(str, fields["policy_digest"]),
            report_digest=cast(str, fields["report_digest"]),
            candidate_id=cast(str, fields["candidate_id"]),
            rule_id=cast(str, fields["rule_id"]),
            review_digest=cast(str, fields["review_digest"]),
            decision=cast(
                Literal["valid", "invalid", "accepted-boundary"],
                fields["decision"],
            ),
            reviewer=cast(str, fields["reviewer"]),
            reviewed_at=cast(str, fields["reviewed_at"]),
            reviewer_effort_seconds=cast(int, fields["reviewer_effort_seconds"]),
            effort_evidence=tuple(cast(list[str], fields["effort_evidence"])),
            evidence_digest=digest,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one content-addressed calibration observation."""
        return {
            "repository_id": self.repository_id,
            "head_tree": self.head_tree,
            "tracked_content_digest": self.tracked_content_digest,
            "policy_digest": self.policy_digest,
            "report_digest": self.report_digest,
            "candidate_id": self.candidate_id,
            "rule_id": self.rule_id,
            "review_digest": self.review_digest,
            "decision": self.decision,
            "reviewer": self.reviewer,
            "reviewed_at": self.reviewed_at,
            "reviewer_effort_seconds": self.reviewer_effort_seconds,
            "effort_evidence": list(self.effort_evidence),
            "evidence_digest": self.evidence_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> RuleReviewEvidence:
        """Parse one observation and reject malformed or changed fields."""
        data = require_mapping(value, "maturity evidence")
        require_exact_fields(data, _EVIDENCE_FIELDS, "maturity evidence")
        decision = require_string(data.get("decision"), "maturity evidence.decision")
        if decision not in _COMPLETED_DECISIONS:
            raise ValueError("maturity evidence.decision is unsupported")
        rule_id = require_string(data.get("rule_id"), "maturity evidence.rule_id")
        if rule_id not in RULES_BY_ID:
            raise ValueError("maturity evidence.rule_id is absent from the rule pack")
        fields: dict[str, object] = {
            "repository_id": require_identifier(
                data.get("repository_id"), "maturity evidence.repository_id"
            ),
            "head_tree": require_git_object(data.get("head_tree"), "maturity evidence.head_tree"),
            "tracked_content_digest": require_digest(
                data.get("tracked_content_digest"),
                "maturity evidence.tracked_content_digest",
            ),
            "policy_digest": require_digest(
                data.get("policy_digest"), "maturity evidence.policy_digest"
            ),
            "report_digest": require_digest(
                data.get("report_digest"), "maturity evidence.report_digest"
            ),
            "candidate_id": require_digest(
                data.get("candidate_id"), "maturity evidence.candidate_id"
            ),
            "rule_id": rule_id,
            "review_digest": require_digest(
                data.get("review_digest"), "maturity evidence.review_digest"
            ),
            "decision": decision,
            "reviewer": require_identifier(data.get("reviewer"), "maturity evidence.reviewer"),
            "reviewed_at": require_utc_timestamp(
                data.get("reviewed_at"), "maturity evidence.reviewed_at"
            ),
            "reviewer_effort_seconds": require_integer(
                data.get("reviewer_effort_seconds"),
                "maturity evidence.reviewer_effort_seconds",
                minimum=1,
            ),
            "effort_evidence": list(
                require_nonempty_strings(
                    data.get("effort_evidence"),
                    "maturity evidence.effort_evidence",
                    minimum=1,
                )
            ),
        }
        recorded = require_digest(data.get("evidence_digest"), "maturity evidence.evidence_digest")
        if recorded != canonical_digest(fields):
            raise ValueError("maturity evidence digest does not match its content")
        return cls._from_fields(fields, recorded)


@dataclass(frozen=True)
class RuleMaturityAssessment:
    """Derived maturity decision for one immutable rule identifier."""

    rule_id: str
    status: RuleMaturityStatus
    review_count: int
    repository_count: int
    reviewer_count: int
    positive_review_count: int
    false_positive_count: int
    false_positive_basis_points: int | None
    median_effort_seconds: int | None
    p90_effort_seconds: int | None
    evidence_digest: str
    probation_reasons: tuple[RuleMaturityReason, ...]

    def to_dict(self) -> dict[str, object]:
        """Serialise the derived rule decision."""
        return {
            "rule_id": self.rule_id,
            "status": self.status,
            "review_count": self.review_count,
            "repository_count": self.repository_count,
            "reviewer_count": self.reviewer_count,
            "positive_review_count": self.positive_review_count,
            "false_positive_count": self.false_positive_count,
            "false_positive_basis_points": self.false_positive_basis_points,
            "median_effort_seconds": self.median_effort_seconds,
            "p90_effort_seconds": self.p90_effort_seconds,
            "evidence_digest": self.evidence_digest,
            "probation_reasons": list(self.probation_reasons),
        }


@dataclass(frozen=True)
class RuleMaturityReport:
    """Content-addressed maturity decisions for the complete built-in rule pack."""

    policy: RuleMaturityPolicy
    evidence: tuple[RuleReviewEvidence, ...]
    assessments: tuple[RuleMaturityAssessment, ...]
    rule_pack_version: str
    rule_pack_digest: str
    maturity_digest: str

    @classmethod
    def build(
        cls,
        policy: RuleMaturityPolicy,
        evidence: tuple[RuleReviewEvidence, ...],
    ) -> RuleMaturityReport:
        """Evaluate every built-in rule under one explicit threshold policy."""
        validated_policy = RuleMaturityPolicy.from_dict(policy.to_dict())
        validated_evidence = tuple(
            RuleReviewEvidence.from_dict(item.to_dict()) for item in evidence
        )
        ordered = tuple(
            sorted(
                validated_evidence,
                key=lambda item: (
                    item.rule_id,
                    item.repository_id,
                    item.report_digest,
                    item.candidate_id,
                    item.review_digest,
                ),
            )
        )
        keys = tuple((item.report_digest, item.candidate_id) for item in ordered)
        if len(keys) != len(set(keys)):
            raise ValueError("maturity evidence contains a duplicate reviewed candidate")
        assessments = tuple(
            _assess_rule(
                rule.rule_id,
                tuple(item for item in ordered if item.rule_id == rule.rule_id),
                validated_policy,
            )
            for rule in RULES
        )
        body: dict[str, object] = {
            "schema_version": RULE_MATURITY_SCHEMA_VERSION,
            "rule_pack_version": RULE_PACK_VERSION,
            "rule_pack_digest": rule_pack_digest(),
            "policy": validated_policy.to_dict(),
            "evidence": [item.to_dict() for item in ordered],
            "assessments": [item.to_dict() for item in assessments],
        }
        return cls(
            policy=validated_policy,
            evidence=ordered,
            assessments=assessments,
            rule_pack_version=RULE_PACK_VERSION,
            rule_pack_digest=rule_pack_digest(),
            maturity_digest=canonical_digest(body),
        )

    @property
    def active_rule_ids(self) -> tuple[str, ...]:
        """Return active rule identifiers in registry order."""
        return tuple(item.rule_id for item in self.assessments if item.status == "active")

    def assessment_for(self, rule_id: str) -> RuleMaturityAssessment:
        """Return the unique assessment for one built-in rule identifier.

        Raises
        ------
        ValueError
            If ``rule_id`` is not present in the bound rule pack.
        """
        matches = tuple(item for item in self.assessments if item.rule_id == rule_id)
        if len(matches) != 1:
            raise ValueError(f"rule maturity assessment is unavailable: {rule_id}")
        return matches[0]

    def to_dict(self) -> dict[str, object]:
        """Serialise the complete maturity report."""
        return {
            "schema_version": RULE_MATURITY_SCHEMA_VERSION,
            "rule_pack_version": self.rule_pack_version,
            "rule_pack_digest": self.rule_pack_digest,
            "policy": self.policy.to_dict(),
            "evidence": [item.to_dict() for item in self.evidence],
            "assessments": [item.to_dict() for item in self.assessments],
            "maturity_digest": self.maturity_digest,
        }

    def to_json(self) -> str:
        """Render deterministic human-readable JSON."""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_dict(cls, value: object) -> RuleMaturityReport:
        """Parse a maturity report and recompute every derived decision."""
        data = require_mapping(value, "rule maturity report")
        require_exact_fields(data, _REPORT_FIELDS, "rule maturity report")
        if data.get("schema_version") != RULE_MATURITY_SCHEMA_VERSION:
            raise ValueError("unsupported rule maturity schema version")
        if data.get("rule_pack_version") != RULE_PACK_VERSION:
            raise ValueError("rule maturity report uses an unsupported rule-pack version")
        if data.get("rule_pack_digest") != rule_pack_digest():
            raise ValueError("rule maturity report rule-pack digest does not match this scanner")
        raw_evidence = data.get("evidence")
        raw_assessments = data.get("assessments")
        if not isinstance(raw_evidence, list):
            raise ValueError("rule maturity report.evidence must be an array")
        if not isinstance(raw_assessments, list):
            raise ValueError("rule maturity report.assessments must be an array")
        report = cls.build(
            RuleMaturityPolicy.from_dict(data.get("policy")),
            tuple(RuleReviewEvidence.from_dict(item) for item in raw_evidence),
        )
        for index, item in enumerate(raw_assessments):
            assessment = require_mapping(item, f"rule maturity report.assessments[{index}]")
            require_exact_fields(
                assessment,
                _ASSESSMENT_FIELDS,
                f"rule maturity report.assessments[{index}]",
            )
        if raw_assessments != [item.to_dict() for item in report.assessments]:
            raise ValueError("rule maturity assessments do not match source evidence and policy")
        recorded = require_digest(
            data.get("maturity_digest"), "rule maturity report.maturity_digest"
        )
        if recorded != report.maturity_digest:
            raise ValueError("rule maturity digest does not match report content")
        return report

    @classmethod
    def from_path(cls, path: Path) -> RuleMaturityReport:
        """Read and verify one UTF-8 maturity report."""
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read rule maturity report {path}") from exc
        return cls.from_dict(value)


def _conservative_median(values: tuple[int, ...]) -> int | None:
    """Return the ceiling integer median, or ``None`` for no evidence."""
    if not values:
        return None
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[midpoint]
    return (ordered[midpoint - 1] + ordered[midpoint] + 1) // 2


def _nearest_rank_p90(values: tuple[int, ...]) -> int | None:
    """Return the nearest-rank 90th percentile, or ``None`` when empty."""
    if not values:
        return None
    ordered = sorted(values)
    rank = (9 * len(ordered) + 9) // 10
    return ordered[rank - 1]


def _assess_rule(
    rule_id: str,
    evidence: tuple[RuleReviewEvidence, ...],
    policy: RuleMaturityPolicy,
) -> RuleMaturityAssessment:
    """Derive one rule decision from canonical observations."""
    review_count = len(evidence)
    false_positive_count = sum(item.decision == "invalid" for item in evidence)
    positive_count = sum(item.decision in {"valid", "accepted-boundary"} for item in evidence)
    basis_points = (
        (false_positive_count * 10_000 + review_count - 1) // review_count
        if review_count
        else None
    )
    efforts = tuple(item.reviewer_effort_seconds for item in evidence)
    median_effort = _conservative_median(efforts)
    p90_effort = _nearest_rank_p90(efforts)
    reasons: list[RuleMaturityReason] = []
    if review_count < policy.minimum_adjudicated_reviews:
        reasons.append("insufficient-reviews")
    repository_count = len({item.repository_id for item in evidence})
    if repository_count < policy.minimum_distinct_repositories:
        reasons.append("insufficient-repositories")
    reviewer_count = len({item.reviewer for item in evidence})
    if reviewer_count < policy.minimum_distinct_reviewers:
        reasons.append("insufficient-reviewers")
    if positive_count < policy.minimum_positive_reviews:
        reasons.append("insufficient-positive-reviews")
    if (
        review_count
        and false_positive_count * 10_000
        > policy.maximum_false_positive_basis_points * review_count
    ):
        reasons.append("false-positive-rate-exceeded")
    if median_effort is not None and median_effort > policy.maximum_median_effort_seconds:
        reasons.append("median-effort-exceeded")
    if p90_effort is not None and p90_effort > policy.maximum_p90_effort_seconds:
        reasons.append("p90-effort-exceeded")
    return RuleMaturityAssessment(
        rule_id=rule_id,
        status="active" if not reasons else "probation",
        review_count=review_count,
        repository_count=repository_count,
        reviewer_count=reviewer_count,
        positive_review_count=positive_count,
        false_positive_count=false_positive_count,
        false_positive_basis_points=basis_points,
        median_effort_seconds=median_effort,
        p90_effort_seconds=p90_effort,
        evidence_digest=canonical_digest([item.evidence_digest for item in evidence]),
        probation_reasons=tuple(reasons),
    )
