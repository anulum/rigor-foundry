# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — immutable multi-agent audit campaign tests
"""Verify real campaign creation, per-agent runs, and divergence comparison."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.campaign_models import AuditCampaign, AuditRunAttestation
from rigor_foundry.campaign_store import load_campaign, load_runs
from rigor_foundry.campaign_workflow import (
    compare_campaign_runs,
    create_campaign,
    execute_campaign,
)

_POLICY = Path("rigor-foundry-policy.json")


def _repository(path: Path) -> GitRepository:
    """Create one small real repository with a real public contract test."""
    repository = GitRepository.create(path)
    repository.write_text("src/pkg/core.py", "def value() -> int:\n    return 1\n")
    repository.write_text(
        "tests/test_core.py",
        "from pkg.core import value\n\ndef test_value() -> None:\n    assert value() == 1\n",
    )
    repository.write_policy()
    repository.commit()
    return repository


def test_campaign_workflow_persists_two_independent_real_runs(tmp_path: Path) -> None:
    """Each agent receives one exact contract and writes a distinct immutable run."""
    repository = _repository(tmp_path / "repository")
    campaign_path, created = create_campaign(
        repository.root,
        _POLICY,
        audit_root=Path(".coordination/audits"),
        project="SAMPLE-PROJECT",
        campaign_id="audit-20260715",
        actor="coordinator/one",
        expected_independent_runs=2,
    )
    assert load_campaign(campaign_path) == created
    first_path, first = execute_campaign(
        campaign_path,
        run_id="agent-one",
        agent_identity="SAMPLE-PROJECT/agent-one",
        session_identity="terminal/one",
    )
    second_path, second = execute_campaign(
        campaign_path,
        run_id="agent-two",
        agent_identity="SAMPLE-PROJECT/agent-two",
        session_identity="terminal/two",
    )
    assert first_path != second_path
    assert first.report_digest == second.report_digest
    assert first.attestation_digest != second.attestation_digest
    assert first.omitted_domains == ()
    runs = load_runs(campaign_path)
    assert tuple(item.attestation.run_id for item in runs) == ("agent-one", "agent-two")

    comparison_path, comparison = compare_campaign_runs(
        campaign_path,
        comparison_id="comparison-1",
        actor="coordinator/one",
    )
    assert comparison_path.is_file()
    assert comparison.actual_run_count == 2
    assert comparison.input_divergence == ()
    assert comparison.scanner_divergence == ()
    assert comparison.unresolved
    assert comparison.diligence_gaps == ("no independent review records were supplied",)
    with pytest.raises(FileExistsError):
        execute_campaign(
            campaign_path,
            run_id="agent-one",
            agent_identity="SAMPLE-PROJECT/agent-one",
            session_identity="terminal/one",
        )


def test_campaign_rejects_changed_tracked_input_and_tampered_records(tmp_path: Path) -> None:
    """HEAD-equivalent worktree drift and content edits cannot reuse a frozen campaign."""
    repository = _repository(tmp_path / "repository")
    campaign_path, campaign = create_campaign(
        repository.root,
        _POLICY,
        audit_root=Path(".coordination/audits"),
        project="SAMPLE-PROJECT",
        campaign_id="audit-20260715",
        actor="coordinator/one",
        expected_independent_runs=1,
    )
    value = campaign.to_dict()
    value["head"] = "0" * 40
    with pytest.raises(ValueError, match="contract digest"):
        AuditCampaign.from_dict(value)

    repository.write_text("src/pkg/core.py", "def value() -> int:\n    return 2\n")
    with pytest.raises(ValueError, match="input divergence"):
        execute_campaign(
            campaign_path,
            run_id="changed-input",
            agent_identity="SAMPLE-PROJECT/agent-one",
            session_identity="terminal/one",
        )


def test_campaign_requires_native_consent_and_binds_secret_free_adapter_identity(
    tmp_path: Path,
) -> None:
    """Campaign evidence binds the sandbox contract without retaining raw output."""
    sentinel = "RIGOR_CAMPAIGN_SENTINEL_a094eed2"
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    repository.write_text("controls/native.py", f"print('{sentinel}')\n")
    repository.write_policy(
        native_audits=[
            {
                "name": "native-boundary",
                "command": ["{python}", "controls/native.py"],
                "timeout_seconds": 10,
                "scope": "full",
                "working_directory": ".",
                "required": True,
                "domains": ["application-security"],
            }
        ]
    )
    repository.commit()
    campaign_path, _campaign = create_campaign(
        repository.root,
        _POLICY,
        audit_root=Path(".coordination/audits"),
        project="SAMPLE-PROJECT",
        campaign_id="native-campaign",
        actor="coordinator/one",
        expected_independent_runs=1,
    )
    with pytest.raises(ValueError, match="explicit trusted consent"):
        execute_campaign(
            campaign_path,
            run_id="refused",
            agent_identity="SAMPLE-PROJECT/agent-one",
            session_identity="terminal/one",
        )
    directory, attestation = execute_campaign(
        campaign_path,
        run_id="consented",
        agent_identity="SAMPLE-PROJECT/agent-one",
        session_identity="terminal/one",
        trusted_native_audits=True,
    )
    evidence = attestation.adapter_evidence[0]
    assert len(evidence.executable_digest) == 64
    assert len(evidence.environment_digest) == 64
    serialised = json.dumps(attestation.to_dict(), sort_keys=True)
    assert sentinel not in serialised
    assert sentinel not in (directory / "attestation.json").read_text(encoding="utf-8")


def test_real_cli_creates_runs_and_reports_missing_independent_review(tmp_path: Path) -> None:
    """The public CLI performs the complete internal campaign workflow in subprocesses."""
    repository = _repository(tmp_path / "repository")
    created = repository.run_audit(
        "campaign-create",
        "--root",
        ".",
        "--policy",
        _POLICY.as_posix(),
        "--project",
        "SAMPLE-PROJECT",
        "--campaign-id",
        "cli-campaign",
        "--actor",
        "coordinator/cli",
        "--expected-runs",
        "1",
    )
    assert created.returncode == 0, created.stderr
    campaign = (
        repository.root / ".rigor/audits/SAMPLE-PROJECT/campaigns/cli-campaign/campaign.json"
    )
    run = repository.run_audit(
        "campaign-run",
        "--campaign",
        str(campaign),
        "--run-id",
        "cli-agent",
        "--agent",
        "SAMPLE-PROJECT/cli-agent",
        "--session",
        "terminal/cli",
    )
    assert run.returncode == 0, run.stderr
    compared = repository.run_audit(
        "campaign-compare",
        "--campaign",
        str(campaign),
        "--comparison-id",
        "cli-comparison",
        "--actor",
        "coordinator/cli",
    )
    assert compared.returncode == 1
    comparison_path = campaign.parent / "comparisons/cli-comparison.json"
    comparison = json.loads(comparison_path.read_text(encoding="utf-8"))
    assert comparison["diligence_gaps"] == ["no independent review records were supplied"]
    attestation_path = campaign.parent / "runs/cli-agent/attestation.json"
    attestation = AuditRunAttestation.from_dict(
        json.loads(attestation_path.read_text(encoding="utf-8"))
    )
    assert attestation.agent_identity == "SAMPLE-PROJECT/cli-agent"
