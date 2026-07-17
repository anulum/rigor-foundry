# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — rule-maturity CLI boundary tests
"""Exercise maturity calibration and enforcement through the installed CLI surface."""

from __future__ import annotations

import json
from pathlib import Path

from cli_test_support import POLICY, cli_repository

from rigor_foundry.models import AuditReport
from rigor_foundry.rule_maturity import (
    RuleMaturityPolicy,
    RuleMaturityReport,
)
from rigor_foundry.rule_maturity_manifest import MATURITY_CASE_MANIFEST_SCHEMA_VERSION


def test_cli_calibrates_one_rule_and_gates_only_active_candidates(tmp_path: Path) -> None:
    """Real scan/review files activate one rule without laundering probation candidates."""
    repository = cli_repository(tmp_path / "repository")
    policy = RuleMaturityPolicy.build(
        minimum_adjudicated_reviews=1,
        minimum_distinct_repositories=1,
        minimum_distinct_reviewers=1,
        minimum_positive_reviews=1,
        maximum_false_positive_basis_points=10_000,
        maximum_median_effort_seconds=300,
        maximum_p90_effort_seconds=300,
    )
    repository.write_policy(maturity_policy_digest=policy.policy_digest)
    report_path = repository.root / ".coordination/report.json"
    review_path = repository.root / ".coordination/reviews.json"
    assert (
        repository.run_audit(
            "scan",
            "--root",
            ".",
            "--policy",
            POLICY,
            "--json-out",
            str(report_path),
        ).returncode
        == 0
    )
    assert (
        repository.run_audit(
            "review-template",
            "--report",
            str(report_path),
            "--output",
            str(review_path),
        ).returncode
        == 0
    )
    report = AuditReport.from_path(report_path)
    selected = next(
        candidate
        for candidate in report.candidates
        if candidate.rule_id == "AR003-broad-optional-import-boundary"
    )
    review_document = json.loads(review_path.read_text(encoding="utf-8"))
    review = next(
        item
        for item in review_document["reviews"]
        if item["candidate_id"] == selected.candidate_id
    )
    review.update(
        {
            "decision": "accepted-boundary",
            "reviewer": "reviewer/cli-one",
            "reviewed_at": "2026-07-17T08:00:00Z",
            "rationale": "the explicit optional import is bounded to the dependency",
            "evidence": ["exact report anchor and public package import inspected"],
            "boundary_justification": "dependency boundary is explicit and narrowly scoped",
            "expires_at": "2026-08-17T08:00:00Z",
            "reopen_triggers": ["optional import body changes"],
        }
    )
    review_path.write_text(json.dumps(review_document), encoding="utf-8")

    case_path = repository.root / ".coordination/maturity-cases.json"
    maturity_path = repository.root / ".coordination/maturity.json"
    case_path.write_text(
        json.dumps(
            {
                "schema_version": MATURITY_CASE_MANIFEST_SCHEMA_VERSION,
                "policy": policy.to_dict(),
                "cases": [
                    {
                        "repository_id": "fixture/cli",
                        "report": report_path.name,
                        "review": review_path.name,
                        "candidate_id": selected.candidate_id,
                        "reviewer_effort_seconds": 45,
                        "effort_evidence": ["timer:cli-review-session"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    calibrated = repository.run_audit(
        "maturity-evaluate",
        "--cases",
        str(case_path),
        "--output",
        str(maturity_path),
    )
    assert calibrated.returncode == 0, calibrated.stderr
    maturity = RuleMaturityReport.from_path(maturity_path)
    assert maturity.active_rule_ids == (selected.rule_id,)
    assessment = maturity.assessment_for(selected.rule_id)
    assert assessment.status == "active"
    assert assessment.probation_reasons == ()

    no_maturity = repository.run_audit(
        "gate",
        "--root",
        ".",
        "--policy",
        POLICY,
        "--review",
        str(review_path),
        "--mode",
        "ratchet",
    )
    assert no_maturity.returncode == 2
    assert "require rule maturity evidence" in no_maturity.stderr

    gated = repository.run_audit(
        "gate",
        "--root",
        ".",
        "--policy",
        POLICY,
        "--review",
        str(review_path),
        "--maturity",
        str(maturity_path),
        "--mode",
        "ratchet",
    )
    assert gated.returncode == 0, gated.stderr
    gate = json.loads(gated.stdout)
    assert gate["candidate_count"] == len(report.candidates)
    assert gate["active_candidate_count"] == 1
    assert gate["probation_candidate_count"] == len(report.candidates) - 1
    assert selected.rule_id not in gate["probation_rule_ids"]
    assert gate["maturity_digest"] == maturity.maturity_digest


def test_cli_rejects_changed_maturity_and_repeats_deterministically(tmp_path: Path) -> None:
    """Repeated evaluation is byte-identical and changed evidence fails closed."""
    repository = cli_repository(tmp_path / "repository")
    policy = RuleMaturityPolicy.build(
        minimum_adjudicated_reviews=1,
        minimum_distinct_repositories=1,
        minimum_distinct_reviewers=1,
        minimum_positive_reviews=1,
        maximum_false_positive_basis_points=0,
        maximum_median_effort_seconds=60,
        maximum_p90_effort_seconds=60,
    )
    repository.write_policy(maturity_policy_digest=policy.policy_digest)
    cases = repository.root / ".coordination/empty-cases.json"
    output = repository.root / ".coordination/maturity.json"
    cases.write_text(
        json.dumps(
            {
                "schema_version": MATURITY_CASE_MANIFEST_SCHEMA_VERSION,
                "policy": policy.to_dict(),
                "cases": [],
            }
        ),
        encoding="utf-8",
    )
    first = repository.run_audit(
        "maturity-evaluate",
        "--cases",
        str(cases),
        "--output",
        str(output),
    )
    assert first.returncode == 0, first.stderr
    before = output.read_bytes()
    second = repository.run_audit(
        "maturity-evaluate",
        "--cases",
        str(cases),
        "--output",
        str(output),
    )
    assert second.returncode == 0, second.stderr
    assert output.read_bytes() == before

    document = json.loads(output.read_text(encoding="utf-8"))
    document["assessments"][0]["status"] = "active"
    output.write_text(json.dumps(document), encoding="utf-8")
    rejected = repository.run_audit(
        "gate",
        "--root",
        ".",
        "--policy",
        POLICY,
        "--maturity",
        str(output),
        "--mode",
        "ratchet",
    )
    assert rejected.returncode == 2
    assert "assessments do not match" in rejected.stderr
