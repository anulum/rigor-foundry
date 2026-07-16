# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — audit campaign protocol model tests
"""Verify toolchain identity and content-addressed campaign record integrity."""

from __future__ import annotations

import shutil
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from repository_audit_git_repository import GitRepository

import rigor_foundry
from rigor_foundry.campaign_identity import InferenceIdentity
from rigor_foundry.campaign_inputs import (
    campaign_input_divergence,
    validate_campaign_input,
)
from rigor_foundry.campaign_models import (
    CAMPAIGN_SCHEMA_VERSION,
    AuditCampaign,
    AuditRunAttestation,
    RunStatus,
    ToolchainIdentity,
)
from rigor_foundry.campaign_store import load_runs
from rigor_foundry.campaign_workflow import create_campaign, execute_campaign
from rigor_foundry.git_provenance import GitTrustPolicy
from rigor_foundry.models import AuditReport, canonical_digest
from rigor_foundry.scanner import scan_repository


def _inference_identity() -> InferenceIdentity:
    """Return one explicit model correlation identity for protocol tests."""
    return InferenceIdentity.build(
        provider="provider.example",
        model="model-v1",
        model_family="model-family",
        operator="operator-one",
    )


def _protocol_records(
    tmp_path: Path,
) -> tuple[AuditCampaign, AuditRunAttestation, AuditReport]:
    """Create real persisted campaign records for parser integrity tests."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    repository.write_policy()
    repository.commit()
    campaign_path, campaign = create_campaign(
        repository.root,
        Path("rigor-foundry-policy.json"),
        audit_root=Path(".rigor/audits"),
        project="SAMPLE-PROJECT",
        campaign_id="model-contract",
        actor="coordinator/one",
        expected_runs=1,
    )
    _directory, attestation = execute_campaign(
        campaign_path,
        run_id="agent-one",
        agent_identity="SAMPLE-PROJECT/agent-one",
        session_identity="terminal/one",
        inference_identity=_inference_identity(),
    )
    report = load_runs(campaign_path)[0].report
    return campaign, attestation, report


def _build_attestation(
    campaign: AuditCampaign,
    report: AuditReport,
    *,
    status: RunStatus,
    started_at: str,
    finished_at: str,
) -> AuditRunAttestation:
    """Build one run record through the public content-addressing API."""
    return AuditRunAttestation.build(
        run_id="model-run",
        campaign=campaign,
        agent_identity="SAMPLE-PROJECT/agent-one",
        session_identity="terminal/one",
        inference_identity=_inference_identity(),
        started_at=started_at,
        finished_at=finished_at,
        status=status,
        report_relative_path="runs/model-run/report.json",
        report=report,
        covered_domains=campaign.required_domains,
        omitted_domains=(),
        adapter_results=(),
        toolchain=campaign.toolchain,
        command_digest="1" * 64,
        limitations=(),
    )


def test_toolchain_identity_round_trip_binds_the_runtime_executable() -> None:
    """Runtime identity survives round-trip and rejects altered executable evidence."""
    identity = ToolchainIdentity.current()

    assert ToolchainIdentity.from_dict(identity.to_dict()) == identity
    assert len(identity.executable_digest) == 64
    assert len(identity.identity_digest) == 64

    changed = identity.to_dict()
    changed["executable_digest"] = "0" * 64
    try:
        ToolchainIdentity.from_dict(changed)
    except ValueError as exc:
        assert "identity digest" in str(exc)
    else:
        raise AssertionError("altered toolchain evidence was accepted")

    unrecognised = identity.to_dict()
    unrecognised["unbound"] = "discarded"
    with pytest.raises(ValueError, match="fields do not match schema"):
        ToolchainIdentity.from_dict(unrecognised)


def test_campaign_schema_version_declares_cross_model_identity_migration() -> None:
    """Campaign 1.8 binds explicit identity and strict correlation witnesses."""
    assert CAMPAIGN_SCHEMA_VERSION == "1.8"
    assert rigor_foundry.campaign_input_divergence is campaign_input_divergence
    assert rigor_foundry.validate_campaign_input is validate_campaign_input


def test_campaign_contract_binds_git_executable_provenance(tmp_path: Path) -> None:
    """Campaign identity changes or fails parsing when Git evidence is altered."""
    campaign, _attestation, report = _protocol_records(tmp_path)

    assert campaign.git_provenance == report.git_provenance
    assert AuditCampaign.from_dict(campaign.to_dict()) == campaign
    changed = campaign.to_dict()
    provenance = dict(cast(dict[str, object], changed["git_provenance"]))
    provenance["version"] = "2.42.0"
    changed["git_provenance"] = provenance
    with pytest.raises(ValueError, match="identity digest"):
        AuditCampaign.from_dict(changed)

    unrecognised = campaign.to_dict()
    unrecognised["unbound"] = "discarded"
    with pytest.raises(ValueError, match="fields do not match schema"):
        AuditCampaign.from_dict(unrecognised)


def test_campaign_recomputes_ignored_inventory_digest_before_contract_digest(
    tmp_path: Path,
) -> None:
    """A recomputed outer contract cannot conceal a mismatched ignored evidence digest."""
    campaign, _attestation, _report = _protocol_records(tmp_path)
    changed = campaign.to_dict()
    changed["ignored_inventory_digest"] = "0" * 64
    changed.pop("contract_digest")
    changed["contract_digest"] = canonical_digest(changed)
    with pytest.raises(ValueError, match="ignored inventory digest"):
        AuditCampaign.from_dict(changed)

    malformed = campaign.to_dict()
    malformed["ignored_inventory_evidence"] = {}
    malformed.pop("contract_digest")
    malformed["contract_digest"] = canonical_digest(malformed)
    with pytest.raises(ValueError, match="must be an array"):
        AuditCampaign.from_dict(malformed)


def test_campaign_contract_rejects_unsafe_identifiers_paths_and_times(tmp_path: Path) -> None:
    """A persisted input contract fails closed on unsafe or ambiguous identity fields."""
    campaign, _attestation, _report = _protocol_records(tmp_path)
    cases = (
        ("schema_version", "2.0", "schema version"),
        ("campaign_id", "../campaign", "portable identifier"),
        ("policy_path", "../policy.json", "repository-relative"),
        ("policy_path", "/outside/policy.json", "repository-relative"),
        ("created_at", "not-a-time", "ISO-8601 UTC timestamp"),
        ("created_at", "2026-07-15T12:00:00+02:00", "must use UTC"),
    )
    for field, value, message in cases:
        changed = campaign.to_dict()
        changed[field] = value
        with pytest.raises(ValueError, match=message):
            AuditCampaign.from_dict(changed)

    equivalent = campaign.to_dict()
    created_at = campaign.created_at
    equivalent["created_at"] = created_at[:-1] + "+00:00"
    assert AuditCampaign.from_dict(equivalent) == campaign


def test_campaign_contract_enforces_purpose_witness_counts_and_outer_digest(
    tmp_path: Path,
) -> None:
    """Promotion thresholds and the complete outer campaign digest fail closed."""
    campaign, _attestation, report = _protocol_records(tmp_path)
    common = {
        "campaign_id": "promotion-contract",
        "project": campaign.project,
        "policy_path": campaign.policy_path,
        "toolchain": campaign.toolchain,
        "created_by": campaign.created_by,
        "created_at": campaign.created_at,
    }
    with pytest.raises(ValueError, match="at least two runs and model witnesses"):
        AuditCampaign.build(
            report,
            **common,
            purpose="promotion",
            expected_runs=1,
            required_model_witnesses=1,
        )
    with pytest.raises(ValueError, match="must not exceed"):
        AuditCampaign.build(
            report,
            **common,
            expected_runs=1,
            required_model_witnesses=2,
        )

    unsupported = campaign.to_dict()
    unsupported["purpose"] = "release"
    with pytest.raises(ValueError, match="campaign purpose"):
        AuditCampaign.from_dict(unsupported)

    changed = campaign.to_dict()
    changed["created_by"] = "coordinator/two"
    with pytest.raises(ValueError, match="contract digest"):
        AuditCampaign.from_dict(changed)

    inconsistent_report = replace(report, ignored_inventory_digest="0" * 64)
    with pytest.raises(ValueError, match="ignored inventory digest"):
        AuditCampaign.build(
            inconsistent_report,
            **common,
            expected_runs=1,
        )


def test_attestation_build_rejects_reversed_time_and_unknown_status(tmp_path: Path) -> None:
    """Runtime construction enforces monotonic time and the closed status vocabulary."""
    campaign, _attestation, report = _protocol_records(tmp_path)

    with pytest.raises(ValueError, match="must not precede"):
        _build_attestation(
            campaign,
            report,
            status="complete",
            started_at="2026-07-15T12:01:00Z",
            finished_at="2026-07-15T12:00:00Z",
        )
    with pytest.raises(ValueError, match="unsupported audit run status"):
        _build_attestation(
            campaign,
            report,
            status=cast(RunStatus, "paused"),
            started_at="2026-07-15T12:00:00Z",
            finished_at="2026-07-15T12:01:00Z",
        )


def test_attestation_build_rejects_report_from_another_real_git_executable(
    tmp_path: Path,
) -> None:
    """Attestation construction rejects a report from a different trusted Git path."""
    campaign, _attestation, report = _protocol_records(tmp_path)
    tools = tmp_path / "alternate-tools"
    tools.mkdir()
    shutil.copy2(report.git_provenance.resolved_path, tools / "git")
    alternate = scan_repository(
        Path(report.repository_root),
        Path("rigor-foundry-policy.json"),
        git_trust_policy=GitTrustPolicy(trusted_roots=(str(tools),)),
    )

    with pytest.raises(ValueError, match="git_provenance"):
        _build_attestation(
            campaign,
            alternate,
            status="complete",
            started_at="2026-07-15T12:00:00Z",
            finished_at="2026-07-15T12:01:00Z",
        )


def test_attestation_parser_rejects_schema_shape_time_and_digest_tampering(
    tmp_path: Path,
) -> None:
    """Durable attestation parsing rejects malformed and self-inconsistent evidence."""
    _campaign, attestation, _report = _protocol_records(tmp_path)
    cases: tuple[tuple[str, object, str], ...] = (
        ("schema_version", "2.0", "schema version"),
        ("status", "paused", "unsupported audit run status"),
        ("adapter_evidence", {}, "must be an array"),
        ("inference_identity", {}, "fields do not match schema"),
    )
    for field, value, message in cases:
        changed = attestation.to_dict()
        changed[field] = value
        with pytest.raises(ValueError, match=message):
            AuditRunAttestation.from_dict(changed)

    reversed_time = attestation.to_dict()
    reversed_time["started_at"] = "2026-07-15T12:01:00Z"
    reversed_time["finished_at"] = "2026-07-15T12:00:00Z"
    with pytest.raises(ValueError, match="must not precede"):
        AuditRunAttestation.from_dict(reversed_time)

    changed_digest = attestation.to_dict()
    changed_digest["command_digest"] = "f" * 64
    with pytest.raises(ValueError, match="digest does not match"):
        AuditRunAttestation.from_dict(changed_digest)

    unrecognised = attestation.to_dict()
    unrecognised["unbound"] = "discarded"
    with pytest.raises(ValueError, match="fields do not match schema"):
        AuditRunAttestation.from_dict(unrecognised)
