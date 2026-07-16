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

from repository_audit_git_repository import GitRepository

from rigor_foundry.adapters import AdapterResult
from rigor_foundry.campaign_compare import compare_campaign
from rigor_foundry.campaign_models import (
    AuditCampaign,
    AuditRunAttestation,
    RunStatus,
    ToolchainIdentity,
)
from rigor_foundry.campaign_store import StoredAuditRun, load_runs
from rigor_foundry.campaign_workflow import create_campaign, execute_campaign
from rigor_foundry.models import (
    AdapterSpec,
    AuditReport,
    Candidate,
    Decision,
    ReviewRecord,
    Severity,
    canonical_digest,
)
from rigor_foundry.sandbox_provenance import (
    BubblewrapCompatibilityPolicy,
    BubblewrapProvenance,
)


def _campaign_runs(tmp_path: Path) -> tuple[AuditCampaign, tuple[StoredAuditRun, ...]]:
    """Create one frozen campaign and two real, integrity-verified runs."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    repository.write_text(
        "tests/test_core.py",
        "from pkg.core import VALUE\n\ndef test_value() -> None:\n    assert VALUE == 1\n",
    )
    repository.write_policy()
    repository.commit()
    campaign_path, campaign = create_campaign(
        repository.root,
        Path("rigor-foundry-policy.json"),
        audit_root=Path(".rigor/audits"),
        project="SAMPLE-PROJECT",
        campaign_id="campaign-divergence",
        actor="coordinator/one",
        expected_independent_runs=2,
    )
    for number in (1, 2):
        execute_campaign(
            campaign_path,
            run_id=f"agent-{number}",
            agent_identity=f"SAMPLE-PROJECT/agent-{number}",
            session_identity=f"terminal/{number}",
        )
    return campaign, load_runs(campaign_path)


def _report_with(
    report: AuditReport,
    *,
    head: str | None = None,
    candidates: tuple[Candidate, ...] | None = None,
    native_audits: tuple[AdapterSpec, ...] | None = None,
) -> AuditReport:
    """Rebuild a digest-consistent report with selected changed observations."""
    return AuditReport.build(
        repository_root=report.repository_root,
        head=head or report.head,
        head_tree=report.head_tree,
        branch=report.branch,
        tracked_content_digest=report.tracked_content_digest,
        dirty_paths=report.dirty_paths,
        tracked_file_count=report.tracked_file_count,
        git_provenance=report.git_provenance,
        policy=(
            report.policy
            if native_audits is None
            else replace(report.policy, native_audits=native_audits)
        ),
        candidates=report.candidates if candidates is None else candidates,
    )


def _toolchain_with_changed_platform(toolchain: ToolchainIdentity) -> ToolchainIdentity:
    """Return a second internally consistent runtime identity."""
    fields = {
        "python_implementation": toolchain.python_implementation,
        "python_version": toolchain.python_version,
        "platform": toolchain.platform + "-other",
        "executable_digest": toolchain.executable_digest,
    }
    return ToolchainIdentity(**fields, identity_digest=canonical_digest(fields))


def _adapter_result(
    *,
    output_digest: str,
    returncode: int,
    package_version: str = "0.9.0-1ubuntu0.1",
    command_digest: str = "3" * 64,
) -> AdapterResult:
    """Build bounded native evidence for comparison protocol tests."""
    return AdapterResult(
        name="repository-check",
        returncode=returncode,
        output_digest=output_digest,
        output_bytes=10,
        output_truncated=False,
        timed_out=False,
        required=True,
        spec_digest="1" * 64,
        executable_digest="2" * 64,
        command_digest=command_digest,
        environment_digest="4" * 64,
        sandbox_digest="5" * 64,
        sandbox_provenance=BubblewrapProvenance.build(
            policy=BubblewrapCompatibilityPolicy(),
            executable_digest="6" * 64,
            semantic_version="0.9.0",
            package_query_digest="7" * 64,
            package_name="bubblewrap",
            package_version=package_version,
            package_architecture="amd64",
            package_status="install ok installed",
            capability_digest="8" * 64,
        ),
    )


def _stored_run(
    campaign: AuditCampaign,
    baseline: StoredAuditRun,
    *,
    run_id: str,
    report: AuditReport,
    toolchain: ToolchainIdentity,
    agent_identity: str,
    status: RunStatus = "complete",
    covered_domains: tuple[str, ...] | None = None,
    omitted_domains: tuple[str, ...] = (),
    adapters: tuple[AdapterResult, ...] = (),
) -> StoredAuditRun:
    """Build a parser-valid adversarial run for comparison-only divergence tests."""
    source_campaign = AuditCampaign.build(
        report,
        campaign_id=campaign.campaign_id,
        project=campaign.project,
        policy_path=campaign.policy_path,
        toolchain=toolchain,
        created_by=campaign.created_by,
        created_at=campaign.created_at,
        expected_independent_runs=campaign.expected_independent_runs,
    )
    source_attestation = AuditRunAttestation.build(
        run_id=run_id,
        campaign=source_campaign,
        agent_identity=agent_identity,
        session_identity=f"terminal/{run_id}",
        started_at="2026-07-15T12:00:00Z",
        finished_at="2026-07-15T12:01:00Z",
        status=status,
        report_relative_path=f"runs/{run_id}/report.json",
        report=report,
        covered_domains=(
            baseline.attestation.covered_domains if covered_domains is None else covered_domains
        ),
        omitted_domains=omitted_domains,
        adapter_results=adapters,
        toolchain=toolchain,
        command_digest="6" * 64,
        limitations=(),
    )
    document = source_attestation.to_dict()
    document["campaign_id"] = campaign.campaign_id
    document["input_contract_digest"] = campaign.contract_digest
    document.pop("attestation_digest")
    document["attestation_digest"] = canonical_digest(document)
    attestation = AuditRunAttestation.from_dict(document)
    return StoredAuditRun(attestation=attestation, report=report)


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
        expected_independent_runs=2,
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
        "expected 2 independent runs, found 0",
        "no independent review records were supplied",
    )
    assert len(comparison.comparison_digest) == 64


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
        path="src/pkg/optional.py",
        line=2,
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
    passed = _stored_run(
        campaign,
        baseline,
        run_id="adapter-pass",
        report=report,
        toolchain=campaign.toolchain,
        agent_identity="SAMPLE-PROJECT/adapter-pass",
        adapters=(_adapter_result(output_digest="a" * 64, returncode=0),),
    )
    failed = _stored_run(
        campaign,
        baseline,
        run_id="adapter-fail",
        report=report,
        toolchain=campaign.toolchain,
        agent_identity="SAMPLE-PROJECT/adapter-fail",
        adapters=(_adapter_result(output_digest="b" * 64, returncode=1),),
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
    complete = _stored_run(
        campaign,
        baseline,
        run_id="adapter-complete",
        report=report,
        toolchain=campaign.toolchain,
        agent_identity="SAMPLE-PROJECT/adapter-complete",
        adapters=(_adapter_result(output_digest="a" * 64, returncode=0),),
    )
    omitted = _stored_run(
        campaign,
        baseline,
        run_id="adapter-omitted",
        report=report,
        toolchain=campaign.toolchain,
        agent_identity="SAMPLE-PROJECT/adapter-omitted",
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
        "run adapter-omitted: omitted native adapters repository-check",
    )


def test_comparison_reports_review_decision_and_priority_divergence(tmp_path: Path) -> None:
    """Independent reviewers retain both validity and remediation disagreements."""
    campaign, runs = _campaign_runs(tmp_path)
    candidate = Candidate.build(
        category="architecture",
        rule_id="AR003-broad-optional-import-boundary",
        path="src/pkg/optional.py",
        line=2,
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
