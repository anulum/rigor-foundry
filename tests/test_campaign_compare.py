# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — independent campaign comparison tests
"""Verify comparison records expose missing independent evidence as unresolved."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from campaign_compare_support import (
    adapter_result as _adapter_result,
)
from campaign_compare_support import (
    build_inference_identity as _inference_identity,
)
from campaign_compare_support import (
    campaign_runs as _campaign_runs,
)
from campaign_compare_support import (
    report_with as _report_with,
)
from campaign_compare_support import (
    stored_run as _stored_run,
)
from campaign_compare_support import (
    toolchain_with_changed_platform as _toolchain_with_changed_platform,
)
from campaign_compare_support import (
    tree_anchor as _tree_anchor,
)
from repository_audit_git_repository import GitRepository

from rigor_foundry.adapter_profiles import AdapterProfileEvidence, profile_by_name
from rigor_foundry.campaign_compare import compare_campaign
from rigor_foundry.campaign_models import (
    AuditCampaign,
)
from rigor_foundry.campaign_store import (
    load_comparison_record,
    store_campaign,
    store_comparison_record,
)
from rigor_foundry.campaign_workflow import create_campaign
from rigor_foundry.models import (
    AdapterSpec,
    Candidate,
    Decision,
    ReviewRecord,
    Severity,
    canonical_digest,
)


def test_comparison_never_turns_absent_independent_runs_into_consensus(tmp_path: Path) -> None:
    """A zero-run comparison is deterministic evidence of a diligence gap."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    repository.write_text(
        "tests/test_core.py",
        "from pkg.core import VALUE\n\ndef test_value() -> None:\n    assert VALUE == 1\n",
    )
    repository.write_policy()
    repository.commit()
    _path, campaign = create_campaign(
        repository.root,
        Path("rigor-foundry-policy.json"),
        audit_root=Path(".rigor/audits"),
        project="SAMPLE-PROJECT",
        campaign_id="campaign-one",
        actor="coordinator/one",
        expected_runs=2,
    )

    comparison = compare_campaign(
        campaign,
        (),
        (),
        comparison_id="comparison-one",
        created_by="coordinator/one",
        created_at="2026-07-15T12:00:00Z",
    )

    assert comparison.actual_run_count == 0
    assert comparison.unresolved
    assert comparison.diligence_gaps == (
        "expected 1 model-family witnesses, found 0",
        "expected 2 runs, found 0",
        "no independent review records were supplied",
    )
    assert len(comparison.comparison_digest) == 64


def test_promotion_comparison_collapses_same_model_family_to_one_witness(
    tmp_path: Path,
) -> None:
    """Agent and session diversity cannot multiply one correlated model witness."""
    _diagnostic, runs = _campaign_runs(tmp_path)
    baseline = runs[0]
    campaign = AuditCampaign.build(
        baseline.report,
        campaign_id="promotion-correlated",
        project="SAMPLE-PROJECT",
        policy_path="rigor-foundry-policy.json",
        toolchain=baseline.attestation.toolchain,
        created_by="coordinator/one",
        created_at="2026-07-15T12:00:00Z",
        purpose="promotion",
        expected_runs=2,
        required_model_witnesses=2,
    )
    correlated = tuple(
        _stored_run(
            campaign,
            baseline,
            run_id=f"correlated-{index}",
            report=baseline.report,
            toolchain=campaign.toolchain,
            agent_identity=f"SAMPLE-PROJECT/agent-{index}",
            inference_identity=_inference_identity(
                "shared-family",
                operator=f"operator-{index}",
            ),
        )
        for index in (1, 2)
    )

    comparison = compare_campaign(
        campaign,
        correlated,
        ((),),
        comparison_id="correlated-comparison",
        created_by="coordinator/one",
        created_at="2026-07-15T13:00:00Z",
    )

    assert comparison.actual_run_count == 2
    assert comparison.actual_model_witnesses == 1
    assert comparison.model_witnesses[0].run_ids == ("correlated-1", "correlated-2")
    assert comparison.unresolved
    assert not comparison.promotion_eligible
    assert "expected 2 model-family witnesses, found 1" in comparison.diligence_gaps


def test_comparison_reports_contract_domain_and_diligence_divergence(tmp_path: Path) -> None:
    """A self-consistent run still exposes disagreement with its frozen campaign."""
    campaign, runs = _campaign_runs(tmp_path)
    baseline = runs[0]
    omitted = campaign.required_domains[-1]
    divergent = _stored_run(
        campaign,
        baseline,
        run_id="divergent-input",
        report=_report_with(baseline.report, head="f" * 40),
        toolchain=_toolchain_with_changed_platform(campaign.toolchain),
        agent_identity="SAMPLE-PROJECT/reused-agent",
        status="incomplete",
        covered_domains=campaign.required_domains[:-1],
        omitted_domains=(omitted,),
    )
    repeated_identity = _stored_run(
        campaign,
        baseline,
        run_id="matching-input",
        report=baseline.report,
        toolchain=campaign.toolchain,
        agent_identity="SAMPLE-PROJECT/reused-agent",
        covered_domains=campaign.required_domains,
    )

    comparison = compare_campaign(
        campaign,
        (divergent, repeated_identity),
        (),
        comparison_id="comparison-contract",
        created_by="coordinator/one",
        created_at="2026-07-15T13:00:00Z",
    )

    assert comparison.input_divergence == (
        "run divergent-input: head differs from campaign contract",
        "run divergent-input: toolchain differs from campaign contract",
    )
    assert any("omitted required domains" in item for item in comparison.coverage_divergence)
    assert any("declared omitted domains" in item for item in comparison.coverage_divergence)
    assert any("covered different domain sets" in item for item in comparison.coverage_divergence)
    assert "multiple runs reuse the same agent identity" in comparison.diligence_gaps
    assert "one or more runs are incomplete" in comparison.diligence_gaps


def test_comparison_distinguishes_candidate_and_report_digest_changes(tmp_path: Path) -> None:
    """Scanner comparison identifies changed candidates separately from metadata drift."""
    campaign, runs = _campaign_runs(tmp_path)
    baseline = runs[0]
    added = Candidate.build(
        category="architecture",
        rule_id="AR003-broad-optional-import-boundary",
        anchor=_tree_anchor(baseline.report, "src/pkg/optional.py"),
        symbol="pkg.optional",
        evidence="optional import catches a broad exception",
        confidence="high",
        rationale="nested dependency failures may be hidden",
        verification="exercise present, absent, and internally broken imports",
    )
    changed_candidates = _stored_run(
        campaign,
        baseline,
        run_id="changed-candidates",
        report=_report_with(baseline.report, candidates=(*baseline.report.candidates, added)),
        toolchain=campaign.toolchain,
        agent_identity="SAMPLE-PROJECT/changed-candidates",
    )
    changed_digest = _stored_run(
        campaign,
        baseline,
        run_id="changed-digest",
        report=_report_with(baseline.report, head="e" * 40),
        toolchain=campaign.toolchain,
        agent_identity="SAMPLE-PROJECT/changed-digest",
    )

    comparison = compare_campaign(
        campaign,
        (baseline, changed_candidates, changed_digest),
        (),
        comparison_id="comparison-scanner",
        created_by="coordinator/one",
        created_at="2026-07-15T13:00:00Z",
    )

    assert any("candidate sets differ" in item for item in comparison.scanner_divergence)
    assert any(
        "candidate sets match but report digests differ" in item
        for item in comparison.scanner_divergence
    )


def test_comparison_reports_native_adapter_evidence_divergence(tmp_path: Path) -> None:
    """The same adapter cannot conceal status, output, or sandbox provenance drift."""
    campaign, runs = _campaign_runs(tmp_path)
    baseline = runs[0]
    expected_adapter = AdapterSpec.from_dict(
        {
            "name": "repository-check",
            "command": ["{python}", "controls/check.py"],
            "timeout_seconds": 30,
            "scope": "full",
            "working_directory": ".",
            "required": True,
            "domains": ["application-security"],
        },
        0,
    )
    report = _report_with(baseline.report, native_audits=(expected_adapter,))
    spec_digest = canonical_digest(expected_adapter.to_dict())
    passed = _stored_run(
        campaign,
        baseline,
        run_id="adapter-pass",
        report=report,
        toolchain=campaign.toolchain,
        agent_identity="SAMPLE-PROJECT/adapter-pass",
        adapters=(
            _adapter_result(
                output_digest="a" * 64,
                returncode=0,
                spec_digest=spec_digest,
            ),
        ),
    )
    failed = _stored_run(
        campaign,
        baseline,
        run_id="adapter-fail",
        report=report,
        toolchain=campaign.toolchain,
        agent_identity="SAMPLE-PROJECT/adapter-fail",
        adapters=(
            _adapter_result(
                output_digest="b" * 64,
                returncode=1,
                spec_digest=spec_digest,
            ),
        ),
    )
    changed_sandbox = _stored_run(
        campaign,
        baseline,
        run_id="adapter-package-drift",
        report=report,
        toolchain=campaign.toolchain,
        agent_identity="SAMPLE-PROJECT/adapter-package-drift",
        adapters=(
            _adapter_result(
                output_digest="a" * 64,
                returncode=0,
                package_version="0.9.0-1ubuntu0.2",
                spec_digest=spec_digest,
            ),
        ),
    )
    changed_contract = _stored_run(
        campaign,
        baseline,
        run_id="adapter-contract-drift",
        report=report,
        toolchain=campaign.toolchain,
        agent_identity="SAMPLE-PROJECT/adapter-contract-drift",
        adapters=(
            _adapter_result(
                output_digest="a" * 64,
                returncode=0,
                command_digest="9" * 64,
                spec_digest=spec_digest,
            ),
        ),
    )

    comparison = compare_campaign(
        campaign,
        (passed, failed, changed_sandbox, changed_contract),
        (),
        comparison_id="comparison-adapter",
        created_by="coordinator/one",
        created_at="2026-07-15T13:00:00Z",
    )

    assert comparison.adapter_divergence == (
        "native adapter repository-check produced divergent execution/status/output evidence",
    )


def test_comparison_reports_omitted_native_adapter_evidence(tmp_path: Path) -> None:
    """Campaign comparison rejects a required full-scope adapter omitted by one run."""
    campaign, runs = _campaign_runs(tmp_path)
    baseline = runs[0]
    expected_adapter = AdapterSpec.from_dict(
        {
            "name": "repository-check",
            "command": ["{python}", "controls/check.py"],
            "timeout_seconds": 30,
            "scope": "both",
            "working_directory": ".",
            "required": True,
            "domains": ["application-security"],
        },
        0,
    )
    report = _report_with(baseline.report, native_audits=(expected_adapter,))
    spec_digest = canonical_digest(expected_adapter.to_dict())
    complete = _stored_run(
        campaign,
        baseline,
        run_id="adapter-complete",
        report=report,
        toolchain=campaign.toolchain,
        agent_identity="SAMPLE-PROJECT/adapter-complete",
        adapters=(
            _adapter_result(
                output_digest="a" * 64,
                returncode=0,
                spec_digest=spec_digest,
            ),
        ),
    )
    omitted = _stored_run(
        campaign,
        baseline,
        run_id="adapter-omitted",
        report=report,
        toolchain=campaign.toolchain,
        agent_identity="SAMPLE-PROJECT/adapter-omitted",
        contextual_validation=False,
    )

    comparison = compare_campaign(
        campaign,
        (complete, omitted),
        (),
        comparison_id="comparison-adapter-omission",
        created_by="coordinator/one",
        created_at="2026-07-15T13:00:00Z",
    )

    assert comparison.adapter_divergence == (
        "run adapter-omitted: adapter evidence violates report policy: "
        "adapter evidence count does not match full policy declarations",
        "run adapter-omitted: omitted native adapters repository-check",
    )


def test_comparison_reports_unexpected_and_duplicate_adapter_evidence(
    tmp_path: Path,
) -> None:
    """An undeclared duplicated adapter cannot inflate diligence evidence."""
    campaign, runs = _campaign_runs(tmp_path)
    baseline = runs[0]
    evidence = _adapter_result(output_digest="a" * 64, returncode=0)
    duplicated = _stored_run(
        campaign,
        baseline,
        run_id="adapter-duplicate",
        report=baseline.report,
        toolchain=campaign.toolchain,
        agent_identity="SAMPLE-PROJECT/adapter-duplicate",
        adapters=(evidence, evidence),
        contextual_validation=False,
    )

    comparison = compare_campaign(
        campaign,
        (duplicated,),
        ((),),
        comparison_id="comparison-adapter-duplicate",
        created_by="coordinator/one",
        created_at="2026-07-15T13:00:00Z",
    )

    assert comparison.adapter_divergence == (
        "run adapter-duplicate: adapter evidence violates report policy: "
        "adapter evidence count does not match full policy declarations",
        "run adapter-duplicate: duplicated native adapters repository-check",
        "run adapter-duplicate: reported unexpected native adapters repository-check",
    )


def test_promotion_rejects_context_free_adapter_policy_forgery(tmp_path: Path) -> None:
    """Structurally valid forged adapter records cannot produce a promotion."""
    _diagnostic, baseline_runs = _campaign_runs(tmp_path)
    baseline = baseline_runs[0]

    def command_spec(name: str) -> AdapterSpec:
        return AdapterSpec.from_dict(
            {
                "name": name,
                "command": ["{python}", f"controls/{name}.py"],
                "timeout_seconds": 30,
                "scope": "full",
                "working_directory": ".",
                "required": True,
                "domains": ["application-security"],
            },
            0,
        )

    first_spec = command_spec("repository-first")
    second_spec = command_spec("repository-second")
    semgrep_spec = AdapterSpec.from_dict(
        {
            "name": "semgrep-security",
            "profile": "semgrep-local-json-v1",
            "configuration_path": "config/semgrep.yml",
            "target_paths": ["src"],
            "timeout_seconds": 30,
            "scope": "full",
            "working_directory": ".",
            "required": True,
        },
        0,
    )
    trivy_profile = AdapterProfileEvidence.build(
        profile=profile_by_name("trivy-repository-json-v1"),
        status="clean",
        reason="clean",
        tool_version="0.72.0",
        version_output_digest="1" * 64,
        configuration_digest="2" * 64,
        input_digest="3" * 64,
        output_digest="4" * 64,
        finding_count=0,
        scanned_target_count=1,
    )
    valid_first = _adapter_result(
        name=first_spec.name,
        output_digest="a" * 64,
        returncode=0,
        spec_digest=canonical_digest(first_spec.to_dict()),
    )
    valid_second = _adapter_result(
        name=second_spec.name,
        output_digest="b" * 64,
        returncode=0,
        spec_digest=canonical_digest(second_spec.to_dict()),
    )
    cases = (
        (
            "spec-digest",
            (first_spec,),
            (replace(valid_first, spec_digest="0" * 64),),
            "spec_digest does not match policy declaration",
        ),
        (
            "required-flag",
            (first_spec,),
            (replace(valid_first, required=False),),
            "required does not match policy declaration",
        ),
        (
            "profile",
            (semgrep_spec,),
            (
                _adapter_result(
                    name=semgrep_spec.name,
                    output_digest="4" * 64,
                    returncode=0,
                    spec_digest=canonical_digest(semgrep_spec.to_dict()),
                    profile_evidence=trivy_profile,
                ),
            ),
            "profile does not match policy declaration",
        ),
        (
            "order",
            (first_spec, second_spec),
            (valid_second, valid_first),
            "name does not match policy declaration",
        ),
    )
    for case_name, specifications, forged_evidence, expected_message in cases:
        report = _report_with(baseline.report, native_audits=specifications)
        campaign = AuditCampaign.build(
            report,
            campaign_id=f"promotion-{case_name}",
            project="SAMPLE-PROJECT",
            policy_path="rigor-foundry-policy.json",
            toolchain=baseline.attestation.toolchain,
            created_by="coordinator/one",
            created_at="2026-07-15T12:00:00Z",
            purpose="promotion",
            expected_runs=2,
            required_model_witnesses=2,
        )
        forged_runs = tuple(
            _stored_run(
                campaign,
                baseline,
                run_id=f"{case_name}-{index}",
                report=report,
                toolchain=campaign.toolchain,
                agent_identity=f"SAMPLE-PROJECT/{case_name}-{index}",
                adapters=forged_evidence,
                inference_identity=_inference_identity(f"{case_name}-family-{index}"),
                contextual_validation=False,
            )
            for index in (1, 2)
        )
        comparison = compare_campaign(
            campaign,
            forged_runs,
            ((),),
            comparison_id=f"comparison-{case_name}",
            created_by="coordinator/one",
            created_at="2026-07-15T13:00:00Z",
        )

        assert any(expected_message in problem for problem in comparison.adapter_divergence)
        assert comparison.unresolved
        assert not comparison.promotion_eligible

        if case_name == "spec-digest":
            campaign_path = store_campaign(
                Path(campaign.repository_root),
                Path(".rigor/audits"),
                campaign,
            )
            comparison_path = store_comparison_record(
                campaign_path,
                comparison.comparison_id,
                comparison.to_dict(),
            )
            reloaded = load_comparison_record(campaign_path, comparison_path)
            assert reloaded.adapter_divergence == comparison.adapter_divergence
            assert reloaded.unresolved
            assert not reloaded.promotion_eligible


def test_comparison_reports_review_decision_and_priority_divergence(tmp_path: Path) -> None:
    """Independent reviewers retain both validity and remediation disagreements."""
    campaign, runs = _campaign_runs(tmp_path)
    candidate = Candidate.build(
        category="architecture",
        rule_id="AR003-broad-optional-import-boundary",
        anchor=_tree_anchor(runs[0].report, "src/pkg/optional.py"),
        symbol="pkg.optional",
        evidence="optional import catches a broad exception",
        confidence="high",
        rationale="nested dependency failures may be hidden",
        verification="exercise present, absent, and internally broken imports",
    )
    report = _report_with(runs[0].report, candidates=(candidate,))
    review_runs = tuple(
        _stored_run(
            campaign,
            runs[0],
            run_id=f"review-run-{index}",
            report=report,
            toolchain=campaign.toolchain,
            agent_identity=f"SAMPLE-PROJECT/review-run-{index}",
        )
        for index in (1, 2)
    )
    candidate_id = candidate.candidate_id

    def review_record(
        *,
        decision: Decision,
        reviewer: str,
        severity: Severity | None,
        owner: str,
        acceptance_gates: tuple[str, ...],
        title: str,
    ) -> ReviewRecord:
        return ReviewRecord(
            report_digest=report.report_digest,
            candidate_id=candidate_id,
            decision=decision,
            reviewer=reviewer,
            reviewed_at="2026-07-15T13:00:00Z",
            rationale="independent reproduction over the exact campaign tree",
            evidence=("repository command reproduced the candidate",),
            severity=severity,
            owner=owner,
            dependencies=(),
            acceptance_gates=acceptance_gates,
            title=title,
            boundary_justification="",
            expires_at="2026-08-15T13:00:00Z",
            reopen_triggers=("campaign input digest changes",),
        )

    first = review_record(
        decision="valid",
        reviewer="reviewer/one",
        severity="P1",
        owner="lane/one",
        acceptance_gates=("focused regression passes",),
        title="Repair the reproduced boundary",
    )
    rejected = review_record(
        decision="invalid",
        reviewer="reviewer/two",
        severity=None,
        owner="",
        acceptance_gates=(),
        title="",
    )
    reprioritised = review_record(
        decision="valid",
        reviewer="reviewer/three",
        severity="P2",
        owner="lane/two",
        acceptance_gates=("real CLI reproduction passes",),
        title="Repair the reproduced boundary",
    )
    pending = ReviewRecord.template(report.report_digest, candidate_id)

    comparison = compare_campaign(
        campaign,
        review_runs,
        ((first,), (rejected,), (reprioritised,), (pending,)),
        comparison_id="comparison-review",
        created_by="coordinator/one",
        created_at="2026-07-15T13:00:00Z",
    )

    assert comparison.review_divergence == (
        f"candidate {candidate_id}: decisions differ (invalid, valid)",
    )
    assert comparison.priority_divergence == (
        f"candidate {candidate_id}: severity, owner, or acceptance gates differ",
    )
    assert "no independent review records were supplied" not in comparison.diligence_gaps
