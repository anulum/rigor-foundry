# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — adapter-profile digest propagation tests
"""Prove profile evidence belongs to run attestations, not campaign identity."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from test_digest_dependencies import _campaign, _comparison, _report

from rigor_foundry.adapter_profiles import AdapterProfileEvidence, profile_by_name
from rigor_foundry.adapters import AdapterResult
from rigor_foundry.campaign_identity import InferenceIdentity
from rigor_foundry.campaign_models import AuditCampaign, AuditRunAttestation
from rigor_foundry.digest_dependencies import transitive_dependents
from rigor_foundry.models import AdapterSpec, AuditReport, canonical_digest
from rigor_foundry.sandbox_provenance import (
    BubblewrapCompatibilityPolicy,
    BubblewrapProvenance,
)


def _profile_spec() -> AdapterSpec:
    """Return the exact policy declaration represented by profile evidence."""
    return AdapterSpec.from_dict(
        {
            "name": "semgrep-security",
            "profile": "semgrep-local-json-v1",
            "configuration_path": "security/semgrep.yml",
            "target_paths": ["src"],
            "timeout_seconds": 60,
            "scope": "full",
            "working_directory": ".",
            "required": True,
        },
        0,
    )


def _profile_result(*, input_digest: str, output_digest: str) -> AdapterResult:
    """Build one valid profile result through public evidence constructors."""
    policy = BubblewrapCompatibilityPolicy()
    provenance = BubblewrapProvenance.build(
        policy=policy,
        executable_digest="2" * 64,
        semantic_version="0.9.0",
        package_query_digest="3" * 64,
        package_name=policy.package_name,
        package_version="0.9.0-1",
        package_architecture="amd64",
        package_status=policy.required_package_status,
        capability_digest="4" * 64,
    )
    profile = profile_by_name("semgrep-local-json-v1")
    evidence = AdapterProfileEvidence.build(
        profile=profile,
        status="clean",
        reason="clean",
        tool_version="1.170.0",
        version_output_digest="5" * 64,
        configuration_digest="6" * 64,
        input_digest=input_digest,
        output_digest=output_digest,
        finding_count=0,
        scanned_target_count=1,
    )
    return AdapterResult(
        name="semgrep-security",
        returncode=0,
        output_digest=output_digest,
        output_bytes=128,
        output_truncated=False,
        timed_out=False,
        required=True,
        spec_digest=canonical_digest(_profile_spec().to_dict()),
        executable_digest="8" * 64,
        command_digest="9" * 64,
        environment_digest="a" * 64,
        sandbox_digest="b" * 64,
        sandbox_provenance=provenance,
        profile_evidence=evidence,
    )


def _attestation(
    campaign: AuditCampaign,
    report: AuditReport,
    result: AdapterResult,
    *,
    command_digest: str = "1" * 64,
) -> AuditRunAttestation:
    """Build one run attestation containing the exact profile result."""
    return AuditRunAttestation.build(
        run_id="adapter-profile-run",
        campaign=campaign,
        agent_identity="RIGOR-FOUNDRY/profile-agent",
        session_identity="terminal/profile",
        inference_identity=InferenceIdentity.build(
            provider="provider.example",
            model="model-v1",
            model_family="model-family",
            operator="operator-one",
        ),
        started_at="2026-07-15T12:01:00Z",
        finished_at="2026-07-15T12:02:00Z",
        status="complete",
        report_relative_path="runs/adapter-profile-run/report.json",
        report=report,
        covered_domains=campaign.required_domains,
        omitted_domains=(),
        adapter_results=(result,),
        toolchain=campaign.toolchain,
        command_digest=command_digest,
        limitations=(),
    )


def test_inventory_and_profile_mutations_rebind_only_declared_run_identities(
    tmp_path: Path,
) -> None:
    """Profile input/output mutations change evidence and the containing run only."""
    base_report = _report(tmp_path)
    report = _report(
        tmp_path,
        policy=replace(base_report.policy, native_audits=(_profile_spec(),)),
    )
    campaign = _campaign(report)
    comparison = _comparison(campaign)
    baseline = _profile_result(input_digest="c" * 64, output_digest="d" * 64)
    changed_input = _profile_result(input_digest="e" * 64, output_digest="d" * 64)
    changed_output = _profile_result(input_digest="c" * 64, output_digest="f" * 64)
    assert baseline.profile_evidence is not None
    assert changed_input.profile_evidence is not None
    assert changed_output.profile_evidence is not None

    baseline_attestation = _attestation(campaign, report, baseline)
    input_attestation = _attestation(campaign, report, changed_input)
    output_attestation = _attestation(campaign, report, changed_output)

    assert baseline.profile_evidence.evidence_digest != (
        changed_input.profile_evidence.evidence_digest
    )
    assert baseline.profile_evidence.evidence_digest != (
        changed_output.profile_evidence.evidence_digest
    )
    assert baseline_attestation.attestation_digest != input_attestation.attestation_digest
    assert baseline_attestation.attestation_digest != output_attestation.attestation_digest
    assert transitive_dependents("adapter-profile") == ("attestation",)
    assert campaign.contract_digest == _campaign(report).contract_digest
    assert comparison.comparison_digest == _comparison(campaign).comparison_digest

    changed_run = _attestation(campaign, report, baseline, command_digest="0" * 64)
    assert changed_run.attestation_digest != baseline_attestation.attestation_digest
    assert transitive_dependents("attestation") == ()
    assert campaign.contract_digest == _campaign(report).contract_digest
    assert comparison.comparison_digest == _comparison(campaign).comparison_digest
