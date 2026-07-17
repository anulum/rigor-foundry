# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — shared campaign comparison test support
"""Build real campaign records for comparison owner tests."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from repository_audit_git_repository import GitRepository

from rigor_foundry.adapters import AdapterResult
from rigor_foundry.campaign_identity import InferenceIdentity
from rigor_foundry.campaign_models import (
    AuditCampaign,
    AuditRunAttestation,
    RunStatus,
    ToolchainIdentity,
)
from rigor_foundry.campaign_store import StoredAuditRun, load_runs
from rigor_foundry.campaign_workflow import create_campaign, execute_campaign
from rigor_foundry.candidate_anchor import RepositoryTreeAnchor
from rigor_foundry.models import AdapterSpec, AuditReport, Candidate, canonical_digest
from rigor_foundry.sandbox_provenance import (
    BubblewrapCompatibilityPolicy,
    BubblewrapProvenance,
)


def build_inference_identity(
    model_family: str,
    *,
    operator: str | None = None,
) -> InferenceIdentity:
    """Return one explicit inference identity for a comparison run."""
    return InferenceIdentity.build(
        provider=f"provider-{model_family}",
        model=f"{model_family}-v1",
        model_family=model_family,
        operator=operator or f"operator-{model_family}",
    )


def campaign_runs(tmp_path: Path) -> tuple[AuditCampaign, tuple[StoredAuditRun, ...]]:
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
        expected_runs=2,
    )
    for number in (1, 2):
        execute_campaign(
            campaign_path,
            run_id=f"agent-{number}",
            agent_identity=f"SAMPLE-PROJECT/agent-{number}",
            session_identity=f"terminal/{number}",
            inference_identity=build_inference_identity(f"family-{number}"),
        )
    return campaign, load_runs(campaign_path)


def report_with(
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
        git_object_format=report.git_object_format,
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


def tree_anchor(report: AuditReport, path: str) -> RepositoryTreeAnchor:
    """Return an exact state anchor for a rebuilt campaign report."""
    return RepositoryTreeAnchor(
        path=path,
        line_start=1,
        line_end=1,
        tree_oid=report.head_tree,
        tracked_content_sha256=report.tracked_content_digest,
    )


def toolchain_with_changed_platform(toolchain: ToolchainIdentity) -> ToolchainIdentity:
    """Return a second internally consistent runtime identity."""
    fields = {
        "python_implementation": toolchain.python_implementation,
        "python_version": toolchain.python_version,
        "platform": toolchain.platform + "-other",
        "executable_digest": toolchain.executable_digest,
    }
    return ToolchainIdentity(**fields, identity_digest=canonical_digest(fields))


def adapter_result(
    *,
    output_digest: str,
    returncode: int,
    package_version: str = "0.9.0-1ubuntu0.1",
    command_digest: str = "3" * 64,
    spec_digest: str = "1" * 64,
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
        spec_digest=spec_digest,
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


def stored_run(
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
    inference_identity: InferenceIdentity | None = None,
    contextual_validation: bool = True,
) -> StoredAuditRun:
    """Build a parser-valid adversarial run for comparison-only divergence tests."""
    construction_report = report if contextual_validation else baseline.report
    source_campaign = AuditCampaign.build(
        construction_report,
        campaign_id=campaign.campaign_id,
        project=campaign.project,
        policy_path=campaign.policy_path,
        toolchain=toolchain,
        created_by=campaign.created_by,
        created_at=campaign.created_at,
        expected_runs=campaign.expected_runs,
    )
    source_attestation = AuditRunAttestation.build(
        run_id=run_id,
        campaign=source_campaign,
        agent_identity=agent_identity,
        session_identity=f"terminal/{run_id}",
        inference_identity=inference_identity or build_inference_identity(run_id),
        started_at="2026-07-15T12:00:00Z",
        finished_at="2026-07-15T12:01:00Z",
        status=status,
        report_relative_path=f"runs/{run_id}/report.json",
        report=construction_report,
        covered_domains=(
            baseline.attestation.covered_domains if covered_domains is None else covered_domains
        ),
        omitted_domains=omitted_domains,
        adapter_results=adapters if contextual_validation else (),
        toolchain=toolchain,
        command_digest="6" * 64,
        limitations=(),
    )
    document = source_attestation.to_dict()
    document["campaign_id"] = campaign.campaign_id
    document["input_contract_digest"] = campaign.contract_digest
    document["report_digest"] = report.report_digest
    document["candidate_count"] = len(report.candidates)
    if not contextual_validation:
        document["adapter_evidence"] = [adapter.to_dict() for adapter in adapters]
    document.pop("attestation_digest")
    document["attestation_digest"] = canonical_digest(document)
    attestation = AuditRunAttestation.from_dict(document)
    return StoredAuditRun(attestation=attestation, report=report)
