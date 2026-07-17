# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — conformance ratchet tests
"""Verify observe, ratchet, and zero decisions with explicit current evidence."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import cast

import pytest
from repository_audit_git_repository import sample_git_provenance, sample_tree_anchor

from rigor_foundry.adapters import AdapterResult
from rigor_foundry.enforcement import ENFORCEMENT_SCHEMA_VERSION, evaluate_enforcement
from rigor_foundry.models import (
    AuditPolicy,
    AuditReport,
    Candidate,
    EnforcementMode,
    ReviewRecord,
    canonical_digest,
)
from rigor_foundry.rule_maturity import (
    RuleMaturityPolicy,
    RuleMaturityReport,
    RuleReviewEvidence,
)
from rigor_foundry.sandbox_provenance import (
    BubblewrapCompatibilityPolicy,
    BubblewrapProvenance,
)


def _report(*, maturity_policy_digest: str | None = None) -> AuditReport:
    """Return one current report with a single governance candidate."""
    candidate = Candidate.build(
        category="governance",
        rule_id="GV004-uncontrolled-required-domain",
        anchor=sample_tree_anchor("docs/internal/audit/policy.json"),
        symbol="application-security",
        evidence="required domain has no control",
        confidence="high",
        rationale="conformance requires evidence",
        verification="wire and run a repository-specific security control",
    )
    return AuditReport.build(
        repository_root="/tmp/repository",
        head="1" * 40,
        head_tree="2" * 40,
        git_object_format="sha1",
        branch="main",
        tracked_content_digest="3" * 64,
        dirty_paths=(),
        tracked_file_count=1,
        git_provenance=sample_git_provenance(),
        policy=AuditPolicy(maturity_policy_digest=maturity_policy_digest),
        candidates=(candidate,),
    )


def _review(report: AuditReport, decision: str) -> ReviewRecord:
    """Return a completed evidence record for one supported decision."""
    base = ReviewRecord(
        report_digest=report.report_digest,
        candidate_id=report.candidates[0].candidate_id,
        decision="invalid",
        reviewer="agent/reviewer",
        reviewed_at="2026-07-15T10:00:00Z",
        rationale="reproduced against current policy",
        evidence=("audit command and source path inspected",),
        severity=None,
        owner="",
        dependencies=(),
        acceptance_gates=(),
        title="",
        boundary_justification="",
        expires_at="2026-08-15T10:00:00Z",
        reopen_triggers=("policy changes",),
    )
    if decision == "valid":
        return replace(
            base,
            decision="valid",
            severity="P1",
            owner="security-lane",
            acceptance_gates=("real security audit passes",),
            title="Add missing application security control",
        )
    if decision != "invalid":
        raise ValueError("unsupported test decision")
    return base


def _adapter_result(*, returncode: int = 0) -> AdapterResult:
    """Return secret-free content-addressed native evidence."""
    return AdapterResult(
        name="security",
        returncode=returncode,
        output_digest="0" * 64,
        output_bytes=6,
        output_truncated=False,
        timed_out=False,
        required=True,
        spec_digest="4" * 64,
        executable_digest="5" * 64,
        command_digest="6" * 64,
        environment_digest="7" * 64,
        sandbox_digest="8" * 64,
        sandbox_provenance=BubblewrapProvenance.build(
            policy=BubblewrapCompatibilityPolicy(),
            executable_digest="9" * 64,
            semantic_version="0.9.0",
            package_query_digest="a" * 64,
            package_name="bubblewrap",
            package_version="0.9.0-1ubuntu0.1",
            package_architecture="amd64",
            package_status="install ok installed",
            capability_digest="b" * 64,
        ),
    )


def _maturity_policy() -> RuleMaturityPolicy:
    """Return the explicit calibration thresholds used by active test evidence."""
    return RuleMaturityPolicy.build(
        minimum_adjudicated_reviews=1,
        minimum_distinct_repositories=1,
        minimum_distinct_reviewers=1,
        minimum_positive_reviews=1,
        maximum_false_positive_basis_points=10_000,
        maximum_median_effort_seconds=60,
        maximum_p90_effort_seconds=60,
    )


def _maturity() -> RuleMaturityReport:
    """Return active maturity evidence for the governance rule under test."""
    report = _report()
    evidence = RuleReviewEvidence.build(
        report,
        _review(report, "valid"),
        repository_id="fixture/enforcement",
        reviewer_effort_seconds=30,
        effort_evidence=("timer:enforcement-calibration",),
    )
    policy = _maturity_policy()
    return RuleMaturityReport.build(policy, (evidence,))


def test_observe_records_candidates_but_native_required_failure_blocks() -> None:
    """Observe does not verdict candidates, while execution failures remain fail-closed."""
    report = _report()
    observed = evaluate_enforcement(report, (), "observe")
    assert observed.passed
    assert observed.candidate_count == 1
    failed_adapter = _adapter_result(returncode=1)
    blocked = evaluate_enforcement(
        report,
        (),
        "observe",
        adapter_results=(failed_adapter,),
    )
    assert not blocked.passed
    assert "native audit security failed" in blocked.blockers[0]


def test_enforcement_schema_version_declares_sandbox_provenance_migration() -> None:
    """Enforcement 1.3 binds maturity policy alongside maturity evidence."""
    assert ENFORCEMENT_SCHEMA_VERSION == "1.3"


def test_ratchet_requires_current_unexpired_unique_review() -> None:
    """Unreviewed, expired, and duplicate decisions cannot enter the legacy ledger."""
    now = datetime(2026, 7, 16, tzinfo=UTC)
    maturity = _maturity()
    report = _report(maturity_policy_digest=maturity.policy.policy_digest)
    with pytest.raises(ValueError, match="require rule maturity evidence"):
        evaluate_enforcement(report, (), "ratchet", now=now)
    unreviewed = evaluate_enforcement(report, (), "ratchet", maturity=maturity, now=now)
    assert not unreviewed.passed
    reviewed = evaluate_enforcement(
        report,
        (_review(report, "invalid"),),
        "ratchet",
        maturity=maturity,
        now=now,
    )
    assert reviewed.passed
    expired = replace(_review(report, "invalid"), expires_at="2026-07-15T10:30:00Z")
    assert not evaluate_enforcement(
        report, (expired,), "ratchet", maturity=maturity, now=now
    ).passed
    with pytest.raises(ValueError, match="multiple completed"):
        evaluate_enforcement(
            report,
            (_review(report, "invalid"), _review(report, "invalid")),
            "ratchet",
            maturity=maturity,
            now=now,
        )


def test_zero_rejects_verified_valid_debt_until_remediated() -> None:
    """A verified finding may remain under ratchet but cannot pass zero mode."""
    now = datetime(2026, 7, 16, tzinfo=UTC)
    maturity = _maturity()
    report = _report(maturity_policy_digest=maturity.policy.policy_digest)
    valid = _review(report, "valid")
    ratchet = evaluate_enforcement(report, (valid,), "ratchet", maturity=maturity, now=now)
    assert ratchet.passed
    zero = evaluate_enforcement(report, (valid,), "zero", maturity=maturity, now=now)
    assert not zero.passed
    assert zero.valid_debt_count == 1
    assert any("valid remediation debt" in blocker for blocker in zero.blockers)
    with pytest.raises(ValueError, match="UTC"):
        evaluate_enforcement(
            report,
            (),
            "observe",
            maturity=maturity,
            now=datetime(2026, 7, 16),
        )


def test_ratchet_requires_repository_bound_matching_maturity_policy() -> None:
    """Repository policy, not an operator-selected calibration, controls activation."""
    maturity = _maturity()
    with pytest.raises(ValueError, match="require a repository maturity policy"):
        evaluate_enforcement(_report(), (), "ratchet", maturity=maturity)

    expected_report = _report(maturity_policy_digest=maturity.policy.policy_digest)
    different_policy = RuleMaturityPolicy.build(
        minimum_adjudicated_reviews=2,
        minimum_distinct_repositories=1,
        minimum_distinct_reviewers=1,
        minimum_positive_reviews=1,
        maximum_false_positive_basis_points=10_000,
        maximum_median_effort_seconds=60,
        maximum_p90_effort_seconds=60,
    )
    mismatched = RuleMaturityReport.build(different_policy, ())
    with pytest.raises(ValueError, match="different repository maturity policy"):
        evaluate_enforcement(expected_report, (), "ratchet", maturity=mismatched)


def test_gate_artifact_binds_exact_report_and_rejects_tampering() -> None:
    """A saved verdict is content-addressed and cannot be reused for stale input."""
    report = _report()
    gate = evaluate_enforcement(
        report,
        (),
        "observe",
        adapter_results=(_adapter_result(),),
    )
    recovered = type(gate).from_dict(gate.to_dict())
    recovered.assert_report(report)
    assert recovered.gate_digest == gate.gate_digest
    assert recovered.adapter_evidence_digest == gate.adapter_evidence_digest

    tampered = gate.to_dict()
    tampered["tracked_content_digest"] = "9" * 64
    with pytest.raises(ValueError, match="gate digest"):
        type(gate).from_dict(tampered)

    stale = replace(report, head="a" * 40)
    with pytest.raises(ValueError, match="different repository report"):
        recovered.assert_report(stale)

    unrecognised = gate.to_dict()
    unrecognised["unbound"] = "discarded"
    with pytest.raises(ValueError, match="fields do not match schema"):
        type(gate).from_dict(unrecognised)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema_version", "2.0", "unsupported enforcement schema"),
        ("mode", "unsupported", "unsupported enforcement mode"),
        ("adapter_results", {}, "adapter_results must be an array"),
        ("adapter_evidence_digest", "f" * 64, "adapter evidence digest"),
        ("passed", False, "passed does not match blockers"),
        ("head", "G" * 40, "lowercase hexadecimal digest"),
    ],
)
def test_gate_artifact_rejects_malformed_protocol_fields(
    field: str,
    value: object,
    message: str,
) -> None:
    """Every attacker-controlled gate envelope field is validated before reuse."""
    gate = evaluate_enforcement(_report(), (), "observe")
    document = gate.to_dict()
    document[field] = value

    with pytest.raises(ValueError, match=message):
        type(gate).from_dict(document)


def test_gate_parser_rejects_inconsistent_maturity_projection() -> None:
    """Maturity identifiers and candidate partitions cannot be recanonicalised inconsistently."""
    plain = evaluate_enforcement(_report(), (), "observe").to_dict()
    plain["active_candidate_count"] = 1
    plain["gate_digest"] = canonical_digest(
        {key: value for key, value in plain.items() if key != "gate_digest"}
    )
    with pytest.raises(ValueError, match="counts require a maturity artifact"):
        type(evaluate_enforcement(_report(), (), "observe")).from_dict(plain)

    missing_maturity = evaluate_enforcement(_report(), (), "observe").to_dict()
    missing_maturity["mode"] = "ratchet"
    missing_maturity["gate_digest"] = canonical_digest(
        {key: value for key, value in missing_maturity.items() if key != "gate_digest"}
    )
    with pytest.raises(ValueError, match="require rule maturity evidence"):
        type(evaluate_enforcement(_report(), (), "observe")).from_dict(missing_maturity)

    unpaired_digest = evaluate_enforcement(_report(), (), "observe").to_dict()
    unpaired_digest["maturity_policy_digest"] = "a" * 64
    unpaired_digest["gate_digest"] = canonical_digest(
        {key: value for key, value in unpaired_digest.items() if key != "gate_digest"}
    )
    with pytest.raises(ValueError, match="digests must occur together"):
        type(evaluate_enforcement(_report(), (), "observe")).from_dict(unpaired_digest)

    probation = RuleMaturityReport.build(
        RuleMaturityPolicy.build(
            minimum_adjudicated_reviews=1,
            minimum_distinct_repositories=1,
            minimum_distinct_reviewers=1,
            minimum_positive_reviews=1,
            maximum_false_positive_basis_points=0,
            maximum_median_effort_seconds=60,
            maximum_p90_effort_seconds=60,
        ),
        (),
    )
    report = _report(maturity_policy_digest=probation.policy.policy_digest)
    partitioned = evaluate_enforcement(report, (), "ratchet", maturity=probation).to_dict()
    partitioned["probation_candidate_count"] = 0
    partitioned["gate_digest"] = canonical_digest(
        {key: value for key, value in partitioned.items() if key != "gate_digest"}
    )
    with pytest.raises(ValueError, match="counts do not match"):
        type(evaluate_enforcement(_report(), (), "observe")).from_dict(partitioned)

    partitioned["probation_candidate_count"] = 1
    partitioned["probation_rule_ids"] = [
        "GV004-uncontrolled-required-domain",
        "GV004-uncontrolled-required-domain",
    ]
    partitioned["gate_digest"] = canonical_digest(
        {key: value for key, value in partitioned.items() if key != "gate_digest"}
    )
    with pytest.raises(ValueError, match="sorted and unique"):
        type(evaluate_enforcement(_report(), (), "observe")).from_dict(partitioned)

    for rule_ids, message in (
        ([], "do not match probation candidate count"),
        (["AR999-unknown"], "contain an unknown rule"),
        (
            ["AR001-first-party-import-cycle", "GV004-uncontrolled-required-domain"],
            "exceed probation candidate count",
        ),
    ):
        changed = evaluate_enforcement(report, (), "ratchet", maturity=probation).to_dict()
        changed["probation_rule_ids"] = rule_ids
        changed["gate_digest"] = canonical_digest(
            {key: value for key, value in changed.items() if key != "gate_digest"}
        )
        with pytest.raises(ValueError, match=message):
            type(evaluate_enforcement(_report(), (), "observe")).from_dict(changed)


def test_gate_assertion_binds_repository_maturity_policy() -> None:
    """A recanonicalised artifact cannot detach calibration from its repository policy."""
    maturity = _maturity()
    report = _report(maturity_policy_digest=maturity.policy.policy_digest)
    ratchet = evaluate_enforcement(report, (), "ratchet", maturity=maturity).to_dict()
    ratchet["maturity_policy_digest"] = "b" * 64
    ratchet["gate_digest"] = canonical_digest(
        {key: value for key, value in ratchet.items() if key != "gate_digest"}
    )
    with pytest.raises(ValueError, match="different maturity policy"):
        type(evaluate_enforcement(_report(), (), "observe")).from_dict(ratchet).assert_report(
            report
        )

    observed = evaluate_enforcement(report, (), "observe", maturity=maturity).to_dict()
    observed["maturity_policy_digest"] = "b" * 64
    observed["gate_digest"] = canonical_digest(
        {key: value for key, value in observed.items() if key != "gate_digest"}
    )
    with pytest.raises(ValueError, match="different maturity policy"):
        type(evaluate_enforcement(_report(), (), "observe")).from_dict(observed).assert_report(
            report
        )


def test_ratchet_ignores_templates_and_optional_native_failures() -> None:
    """Needs-evidence records do not count as reviews and optional tools do not block."""
    maturity = _maturity()
    report = _report(maturity_policy_digest=maturity.policy.policy_digest)
    template = ReviewRecord.template(report.report_digest, report.candidates[0].candidate_id)
    decision = evaluate_enforcement(
        report,
        (template,),
        "ratchet",
        maturity=maturity,
        adapter_results=(replace(_adapter_result(returncode=9), required=False),),
        now=datetime(2026, 7, 16, tzinfo=UTC),
    )

    assert decision.reviewed_count == 0
    assert decision.valid_debt_count == 0
    assert decision.blockers == (
        "unreviewed current candidate "
        f"{report.candidates[0].candidate_id} ({report.candidates[0].rule_id})",
    )


def test_probation_candidates_remain_visible_without_affecting_ratchet() -> None:
    """A probationary signal is counted but cannot become enforcement debt."""
    probation = RuleMaturityReport.build(
        RuleMaturityPolicy.build(
            minimum_adjudicated_reviews=1,
            minimum_distinct_repositories=1,
            minimum_distinct_reviewers=1,
            minimum_positive_reviews=1,
            maximum_false_positive_basis_points=0,
            maximum_median_effort_seconds=60,
            maximum_p90_effort_seconds=60,
        ),
        (),
    )
    report = _report(maturity_policy_digest=probation.policy.policy_digest)
    decision = evaluate_enforcement(report, (), "ratchet", maturity=probation)
    recovered = type(decision).from_dict(decision.to_dict())

    assert decision.passed
    assert decision.active_candidate_count == 0
    assert decision.probation_candidate_count == 1
    assert decision.probation_rule_ids == ("GV004-uncontrolled-required-domain",)
    assert decision.maturity_digest == probation.maturity_digest
    assert recovered == decision

    incompatible_report = replace(report, rule_pack_digest="0" * 64)
    with pytest.raises(ValueError, match="different rule pack"):
        evaluate_enforcement(
            incompatible_report,
            (),
            "ratchet",
            maturity=probation,
        )


def test_enforcement_rejects_non_utc_expiry_and_unknown_runtime_mode() -> None:
    """Decision time and review expiry stay UTC while runtime mode input fails closed."""
    maturity = _maturity()
    report = _report(maturity_policy_digest=maturity.policy.policy_digest)
    non_utc = replace(
        _review(report, "invalid"),
        expires_at="2026-08-15T12:00:00+02:00",
    )
    with pytest.raises(ValueError, match="review expiry must use UTC"):
        evaluate_enforcement(
            report,
            (non_utc,),
            "ratchet",
            maturity=maturity,
            now=datetime(2026, 7, 16, tzinfo=UTC),
        )

    with pytest.raises(ValueError, match="unsupported enforcement mode"):
        evaluate_enforcement(report, (), cast(EnforcementMode, "unsupported"))
