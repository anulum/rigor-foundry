# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — adjudicated rule-maturity tests
"""Verify rule activation from exact report and review evidence."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from repository_audit_git_repository import sample_git_provenance, sample_tree_anchor

from rigor_foundry.models import (
    AuditPolicy,
    AuditReport,
    Candidate,
    ReviewRecord,
    reviews_to_json,
)
from rigor_foundry.rule_maturity import (
    RULE_MATURITY_SCHEMA_VERSION,
    RuleMaturityPolicy,
    RuleMaturityReport,
    RuleReviewEvidence,
)
from rigor_foundry.rule_maturity_manifest import (
    MATURITY_CASE_MANIFEST_SCHEMA_VERSION,
    evaluate_rule_maturity_manifest,
)
from rigor_foundry.rules import RULE_PACK_VERSION, RULES, rule_pack_digest


def _report(index: int, *, rule_id: str = "AR002-wildcard-import-boundary") -> AuditReport:
    """Return one exact report with a unique candidate and repository tree."""
    candidate = Candidate.build(
        category="architecture",
        rule_id=rule_id,
        anchor=sample_tree_anchor(f"src/pkg_{index}/public.py"),
        symbol=f"pkg_{index}.public",
        evidence="wildcard import crosses a package boundary",
        confidence="high",
        rationale="export ownership needs explicit review",
        verification="replace the wildcard and run the package import contract",
    )
    digit = format(index % 15 + 1, "x")
    return AuditReport.build(
        repository_root=f"/evidence/repository-{index}",
        head=digit * 40,
        head_tree=sample_tree_anchor("tree").tree_oid,
        git_object_format="sha1",
        branch="main",
        tracked_content_digest=format((index + 1) % 15 + 1, "x") * 64,
        dirty_paths=(),
        tracked_file_count=2,
        git_provenance=sample_git_provenance(),
        policy=AuditPolicy(),
        candidates=(candidate,),
    )


def _review(
    report: AuditReport,
    decision: str,
    *,
    reviewer: str,
) -> ReviewRecord:
    """Return one complete evidence decision for the report candidate."""
    base = ReviewRecord(
        report_digest=report.report_digest,
        candidate_id=report.candidates[0].candidate_id,
        decision="invalid",
        reviewer=reviewer,
        reviewed_at="2026-07-17T08:00:00Z",
        rationale="reproduced against the exact report tree",
        evidence=("report anchor and public import contract inspected",),
        severity=None,
        owner="",
        dependencies=(),
        acceptance_gates=(),
        title="",
        boundary_justification="",
        expires_at="2026-08-17T08:00:00Z",
        reopen_triggers=("candidate anchor changes",),
    )
    if decision == "valid":
        return replace(
            base,
            decision="valid",
            severity="P2",
            owner="architecture-owner",
            acceptance_gates=("explicit imports pass the package contract",),
            title="Replace wildcard import boundary",
        )
    if decision == "accepted-boundary":
        return replace(
            base,
            decision="accepted-boundary",
            boundary_justification="generated namespace requires the documented export boundary",
        )
    if decision != "invalid":
        raise ValueError("unsupported test decision")
    return base


def _policy(
    *,
    reviews: int = 4,
    repositories: int = 2,
    reviewers: int = 2,
    positives: int = 2,
    false_positive_basis_points: int = 2_500,
    median_effort: int = 60,
    p90_effort: int = 90,
) -> RuleMaturityPolicy:
    """Return one explicit calibration policy."""
    return RuleMaturityPolicy.build(
        minimum_adjudicated_reviews=reviews,
        minimum_distinct_repositories=repositories,
        minimum_distinct_reviewers=reviewers,
        minimum_positive_reviews=positives,
        maximum_false_positive_basis_points=false_positive_basis_points,
        maximum_median_effort_seconds=median_effort,
        maximum_p90_effort_seconds=p90_effort,
    )


def _evidence(
    index: int,
    decision: str,
    *,
    repository_id: str,
    reviewer: str,
    effort: int,
) -> RuleReviewEvidence:
    """Build one source-validated rule observation."""
    report = _report(index)
    return RuleReviewEvidence.build(
        report,
        _review(report, decision, reviewer=reviewer),
        repository_id=repository_id,
        reviewer_effort_seconds=effort,
        effort_evidence=(f"timer:review-session-{index}",),
    )


def _active_evidence() -> tuple[RuleReviewEvidence, ...]:
    """Return evidence that meets the default test policy exactly."""
    return (
        _evidence(1, "valid", repository_id="repo/one", reviewer="reviewer/one", effort=10),
        _evidence(2, "valid", repository_id="repo/one", reviewer="reviewer/two", effort=20),
        _evidence(
            3,
            "accepted-boundary",
            repository_id="repo/two",
            reviewer="reviewer/one",
            effort=30,
        ),
        _evidence(4, "invalid", repository_id="repo/two", reviewer="reviewer/two", effort=40),
    )


def test_policy_is_explicit_content_addressed_and_bool_safe() -> None:
    """Threshold policy round-trips and rejects ambiguous or contradictory values."""
    policy = _policy()
    assert RuleMaturityPolicy.from_dict(policy.to_dict()) == policy
    tampered = policy.to_dict()
    tampered["minimum_adjudicated_reviews"] = 5
    with pytest.raises(ValueError, match="digest"):
        RuleMaturityPolicy.from_dict(tampered)

    invalid = (
        ({"minimum_adjudicated_reviews": True}, "integer"),
        ({"maximum_false_positive_basis_points": 10_001}, "<= 10000"),
        ({"minimum_positive_reviews": 5}, "cannot exceed"),
        ({"maximum_median_effort_seconds": 91}, "cannot exceed"),
    )
    for changes, message in invalid:
        values = {
            "minimum_adjudicated_reviews": 4,
            "minimum_distinct_repositories": 2,
            "minimum_distinct_reviewers": 2,
            "minimum_positive_reviews": 2,
            "maximum_false_positive_basis_points": 2_500,
            "maximum_median_effort_seconds": 60,
            "maximum_p90_effort_seconds": 90,
            **changes,
        }
        with pytest.raises(ValueError, match=message):
            RuleMaturityPolicy.build(**values)

    unknown = policy.to_dict()
    unknown["unbound"] = 1
    with pytest.raises(ValueError, match="fields do not match"):
        RuleMaturityPolicy.from_dict(unknown)


def test_evidence_is_derived_from_one_complete_exact_review() -> None:
    """Calibration evidence binds report, candidate, decision, reviewer, and effort."""
    report = _report(1)
    review = _review(report, "valid", reviewer="reviewer/one")
    evidence = RuleReviewEvidence.build(
        report,
        review,
        repository_id="repo/one",
        reviewer_effort_seconds=37,
        effort_evidence=("timer:review-session-1",),
    )
    assert RuleReviewEvidence.from_dict(evidence.to_dict()) == evidence
    assert evidence.rule_id == report.candidates[0].rule_id
    assert evidence.review_digest == review.review_digest
    assert evidence.reviewer_effort_seconds == 37

    with pytest.raises(ValueError, match="completed review"):
        RuleReviewEvidence.build(
            report,
            ReviewRecord.template(report.report_digest, report.candidates[0].candidate_id),
            repository_id="repo/one",
            reviewer_effort_seconds=1,
            effort_evidence=("timer:review-session-1",),
        )
    stale = replace(review, report_digest="f" * 64)
    with pytest.raises(ValueError, match="not adjudicated"):
        RuleReviewEvidence.build(
            report,
            stale,
            repository_id="repo/one",
            reviewer_effort_seconds=1,
            effort_evidence=("timer:review-session-1",),
        )
    duplicate_candidate_report = replace(
        report,
        candidates=(report.candidates[0], report.candidates[0]),
    )
    with pytest.raises(ValueError, match="must occur exactly once"):
        RuleReviewEvidence.build(
            duplicate_candidate_report,
            review,
            repository_id="repo/one",
            reviewer_effort_seconds=1,
            effort_evidence=("timer:review-session-1",),
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("decision", "needs-evidence", "decision is unsupported"),
        ("rule_id", "AR999-unknown", "absent from the rule pack"),
        ("head_tree", "not-an-object", "Git object"),
        ("candidate_id", "f" * 63, "SHA-256"),
        ("reviewer_effort_seconds", False, "integer"),
        ("effort_evidence", [], "at least 1"),
        ("reviewer", "bad reviewer", "portable identifier"),
        ("reviewed_at", "2026-07-17T08:00:00+02:00", "use UTC"),
        ("evidence_digest", "0" * 64, "digest does not match"),
    ],
)
def test_evidence_parser_rejects_malformed_or_changed_fields(
    field: str,
    value: object,
    message: str,
) -> None:
    """Every attacker-controlled evidence field fails closed."""
    document = _active_evidence()[0].to_dict()
    document[field] = value
    with pytest.raises(ValueError, match=message):
        RuleReviewEvidence.from_dict(document)


def test_report_activates_only_the_calibrated_rule() -> None:
    """Exact threshold evidence activates one rule while all others remain probationary."""
    report = RuleMaturityReport.build(_policy(), _active_evidence())
    assessment = report.assessment_for("AR002-wildcard-import-boundary")
    assert assessment.status == "active"
    assert assessment.review_count == 4
    assert assessment.repository_count == 2
    assert assessment.reviewer_count == 2
    assert assessment.positive_review_count == 3
    assert assessment.false_positive_count == 1
    assert assessment.false_positive_basis_points == 2_500
    assert assessment.median_effort_seconds == 25
    assert assessment.p90_effort_seconds == 40
    assert assessment.probation_reasons == ()
    assert report.active_rule_ids == ("AR002-wildcard-import-boundary",)
    assert len(report.assessments) == len(RULES)
    untouched = report.assessment_for("TA001-test-double")
    assert untouched.status == "probation"
    assert untouched.false_positive_basis_points is None
    assert untouched.median_effort_seconds is None
    assert untouched.p90_effort_seconds is None
    assert untouched.probation_reasons == (
        "insufficient-reviews",
        "insufficient-repositories",
        "insufficient-reviewers",
        "insufficient-positive-reviews",
    )
    assert RuleMaturityReport.from_dict(report.to_dict()) == report
    assert json.loads(report.to_json())["maturity_digest"] == report.maturity_digest


def test_probation_reasons_cover_rate_and_effort_without_rounding_down() -> None:
    """False-positive and reviewer-cost limits use conservative integer statistics."""
    evidence = (
        _evidence(1, "valid", repository_id="repo/one", reviewer="reviewer/one", effort=10),
        _evidence(2, "invalid", repository_id="repo/two", reviewer="reviewer/two", effort=20),
        _evidence(3, "invalid", repository_id="repo/two", reviewer="reviewer/two", effort=101),
    )
    report = RuleMaturityReport.build(
        _policy(
            reviews=3,
            repositories=2,
            reviewers=2,
            positives=1,
            false_positive_basis_points=6_666,
            median_effort=19,
            p90_effort=100,
        ),
        evidence,
    )
    assessment = report.assessment_for("AR002-wildcard-import-boundary")
    assert assessment.false_positive_basis_points == 6_667
    assert assessment.median_effort_seconds == 20
    assert assessment.p90_effort_seconds == 101
    assert assessment.probation_reasons == (
        "false-positive-rate-exceeded",
        "median-effort-exceeded",
        "p90-effort-exceeded",
    )


def test_report_rejects_duplicate_direct_constructed_and_tampered_records() -> None:
    """Derived assessments cannot be supplied, duplicated, or detached from evidence."""
    evidence = _active_evidence()[0]
    with pytest.raises(ValueError, match="duplicate reviewed candidate"):
        RuleMaturityReport.build(
            _policy(reviews=1, repositories=1, reviewers=1, positives=1), (evidence, evidence)
        )

    invalid_evidence = replace(evidence, evidence_digest="0" * 64)
    with pytest.raises(ValueError, match="digest does not match"):
        RuleMaturityReport.build(
            _policy(reviews=1, repositories=1, reviewers=1, positives=1),
            (invalid_evidence,),
        )
    with pytest.raises(ValueError, match="unavailable"):
        RuleMaturityReport.build(_policy(), ()).assessment_for("AR999-unknown")

    report = RuleMaturityReport.build(_policy(), _active_evidence())
    mutations = (
        ("schema_version", "2.0", "unsupported rule maturity schema"),
        ("rule_pack_version", "rigor-foundry/9.0.0", "unsupported rule-pack version"),
        ("rule_pack_digest", "0" * 64, "rule-pack digest"),
        ("evidence", {}, "evidence must be an array"),
        ("assessments", {}, "assessments must be an array"),
        ("maturity_digest", "0" * 64, "maturity digest"),
    )
    for field, value, message in mutations:
        document = report.to_dict()
        document[field] = value
        with pytest.raises(ValueError, match=message):
            RuleMaturityReport.from_dict(document)

    changed_assessment = report.to_dict()
    assessments = changed_assessment["assessments"]
    assert isinstance(assessments, list)
    assert isinstance(assessments[0], dict)
    assessments[0]["status"] = "active"
    with pytest.raises(ValueError, match="assessments do not match"):
        RuleMaturityReport.from_dict(changed_assessment)

    unknown_assessment = report.to_dict()
    raw_assessments = unknown_assessment["assessments"]
    assert isinstance(raw_assessments, list)
    assert isinstance(raw_assessments[0], dict)
    raw_assessments[0]["unbound"] = True
    with pytest.raises(ValueError, match="fields do not match"):
        RuleMaturityReport.from_dict(unknown_assessment)


def test_case_manifest_rebuilds_source_validated_evidence(tmp_path: Path) -> None:
    """Explicit file references rebuild the same report through the public workflow."""
    source_report = _report(1)
    source_review = _review(source_report, "valid", reviewer="reviewer/one")
    report_path = tmp_path / "report.json"
    review_path = tmp_path / "reviews.json"
    manifest_path = tmp_path / "cases.json"
    report_path.write_text(source_report.to_json(), encoding="utf-8")
    review_path.write_text(reviews_to_json((source_review,)), encoding="utf-8")
    policy = _policy(reviews=1, repositories=1, reviewers=1, positives=1)
    document = {
        "schema_version": MATURITY_CASE_MANIFEST_SCHEMA_VERSION,
        "policy": policy.to_dict(),
        "cases": [
            {
                "repository_id": "repo/one",
                "report": report_path.name,
                "review": str(review_path),
                "candidate_id": source_report.candidates[0].candidate_id,
                "reviewer_effort_seconds": 42,
                "effort_evidence": ["timer:review-session-1"],
            }
        ],
    }
    manifest_path.write_text(json.dumps(document), encoding="utf-8")
    maturity = evaluate_rule_maturity_manifest(manifest_path)
    assert maturity.assessment_for(source_report.candidates[0].rule_id).status == "active"
    assert maturity.evidence[0].report_digest == source_report.report_digest

    malformed = json.loads(manifest_path.read_text(encoding="utf-8"))
    malformed["schema_version"] = "2.0"
    manifest_path.write_text(json.dumps(malformed), encoding="utf-8")
    with pytest.raises(ValueError, match=r"unsupported.*case-manifest"):
        evaluate_rule_maturity_manifest(manifest_path)

    document["cases"] = {}
    manifest_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="cases must be an array"):
        evaluate_rule_maturity_manifest(manifest_path)

    document["cases"] = [
        {
            "repository_id": "repo/one",
            "report": report_path.name,
            "review": str(review_path),
            "candidate_id": "f" * 64,
            "reviewer_effort_seconds": 42,
            "effort_evidence": ["timer:review-session-1"],
        }
    ]
    manifest_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="select exactly one review"):
        evaluate_rule_maturity_manifest(manifest_path)


def test_case_manifest_and_report_file_errors_are_explicit(tmp_path: Path) -> None:
    """Malformed manifests and reports fail without emitting a maturity claim."""
    manifest = tmp_path / "cases.json"
    manifest.write_text("not json", encoding="utf-8")
    with pytest.raises(ValueError, match="cannot read rule maturity case manifest"):
        evaluate_rule_maturity_manifest(manifest)

    report = RuleMaturityReport.build(_policy(), ())
    report_path = tmp_path / "maturity.json"
    report_path.write_text(report.to_json(), encoding="utf-8")
    assert RuleMaturityReport.from_path(report_path) == report
    report_path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="must be an object"):
        RuleMaturityReport.from_path(report_path)
    report_path.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match="cannot read rule maturity report"):
        RuleMaturityReport.from_path(report_path)


def test_protocol_versions_and_rule_pack_are_bound() -> None:
    """The maturity schema records the exact built-in registry identity."""
    report = RuleMaturityReport.build(_policy(), ())
    assert RULE_MATURITY_SCHEMA_VERSION == "1.0"
    assert report.rule_pack_version == RULE_PACK_VERSION
    assert report.rule_pack_digest == rule_pack_digest()
