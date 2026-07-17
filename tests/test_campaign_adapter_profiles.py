# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — built-in adapter campaign integration tests
"""Run Semgrep and Trivy through the public durable campaign boundary."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.adapters import AdapterResult
from rigor_foundry.campaign_evidence import validate_adapter_evidence
from rigor_foundry.campaign_identity import InferenceIdentity
from rigor_foundry.campaign_models import AuditRunAttestation
from rigor_foundry.campaign_store import load_runs, store_run
from rigor_foundry.campaign_workflow import create_campaign, execute_campaign
from rigor_foundry.models import canonical_digest


def _profile(
    name: str,
    profile: str,
    configuration_path: str,
    target_path: str,
) -> dict[str, object]:
    """Return one strict built-in profile declaration for a real fixture."""
    return {
        "name": name,
        "profile": profile,
        "configuration_path": configuration_path,
        "target_paths": [target_path],
        "timeout_seconds": 60,
        "scope": "full",
        "working_directory": ".",
        "required": True,
    }


def test_campaign_attests_both_real_profiles_and_complete_domain_coverage(
    tmp_path: Path,
) -> None:
    """A durable campaign binds both tools and counts only complete profile evidence."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "security/semgrep.yml",
        "rules:\n"
        "  - id: dangerous-eval\n"
        "    languages: [python]\n"
        "    message: dynamic evaluation is forbidden\n"
        "    severity: ERROR\n"
        "    pattern: eval(...)\n",
    )
    repository.write_text("security/trivy.yaml", "format: json\n")
    repository.write_text("src/pkg/core.py", "def value() -> int:\n    return 1\n")
    repository.write_text(
        "infra/Dockerfile",
        "FROM alpine:latest\nRUN apk add --no-cache curl\nUSER root\n",
    )
    repository.write_policy(
        native_audits=[
            _profile(
                "semgrep-security",
                "semgrep-local-json-v1",
                "security/semgrep.yml",
                "src",
            ),
            _profile(
                "trivy-repository-security",
                "trivy-repository-json-v1",
                "security/trivy.yaml",
                "infra",
            ),
        ],
        required_domains=frozenset(
            {
                "test-authenticity",
                "architecture-and-wiring",
                "godfile-responsibility",
                "ownership-and-maintenance",
                "application-security",
            }
        ),
    )
    repository.commit()
    campaign_path, _campaign = create_campaign(
        repository.root,
        Path("rigor-foundry-policy.json"),
        audit_root=Path(".rigor/audits"),
        project="PROFILE-ADOPTER",
        campaign_id="profile-e2e",
        actor="coordinator/one",
        expected_runs=1,
    )

    run_path, attestation = execute_campaign(
        campaign_path,
        run_id="profile-agent",
        agent_identity="PROFILE-ADOPTER/profile-agent",
        session_identity="terminal/profile",
        inference_identity=InferenceIdentity.build(
            provider="provider.example",
            model="model-v1",
            model_family="model-family",
            operator="operator-one",
        ),
        trusted_native_audits=True,
    )

    assert attestation.status == "complete"
    assert "application-security" in attestation.covered_domains
    assert "application-security" not in attestation.omitted_domains
    assert tuple(item.name for item in attestation.adapter_evidence) == (
        "semgrep-security",
        "trivy-repository-security",
    )
    assert all(item.profile_evidence is not None for item in attestation.adapter_evidence)
    assert all(
        item.profile_evidence is not None and item.profile_evidence.complete
        for item in attestation.adapter_evidence
    )
    stored = load_runs(campaign_path)[0].attestation
    assert AuditRunAttestation.from_dict(stored.to_dict()) == stored
    stored_report = load_runs(campaign_path)[0].report

    with pytest.raises(ValueError, match="count does not match"):
        validate_adapter_evidence(stored_report.policy, attestation.adapter_evidence[:-1])
    for changed, message in (
        (replace(attestation.adapter_evidence[0], name="cross-wired"), "name does not match"),
        (
            replace(
                attestation.adapter_evidence[0],
                required=not attestation.adapter_evidence[0].required,
            ),
            "required does not match",
        ),
    ):
        with pytest.raises(ValueError, match=message):
            validate_adapter_evidence(
                stored_report.policy,
                (changed, *attestation.adapter_evidence[1:]),
            )
    first_profile = attestation.adapter_evidence[0].profile_evidence
    assert first_profile is not None
    wrong_profile = replace(first_profile, profile="trivy-repository-json-v1")
    with pytest.raises(ValueError, match="profile does not match"):
        validate_adapter_evidence(
            stored_report.policy,
            (
                replace(attestation.adapter_evidence[0], profile_evidence=wrong_profile),
                *attestation.adapter_evidence[1:],
            ),
        )

    first_result = AdapterResult.from_dict(attestation.adapter_evidence[0].to_dict())
    forged_result = replace(first_result, spec_digest="0" * 64)
    with pytest.raises(ValueError, match="spec_digest does not match policy declaration"):
        AuditRunAttestation.build(
            run_id="forged-build",
            campaign=_campaign,
            agent_identity=attestation.agent_identity,
            session_identity=attestation.session_identity,
            inference_identity=attestation.inference_identity,
            started_at=attestation.started_at,
            finished_at=attestation.finished_at,
            status=attestation.status,
            report_relative_path="runs/forged-build/report.json",
            report=stored_report,
            covered_domains=attestation.covered_domains,
            omitted_domains=attestation.omitted_domains,
            adapter_results=(
                forged_result,
                AdapterResult.from_dict(attestation.adapter_evidence[1].to_dict(), 1),
            ),
            toolchain=attestation.toolchain,
            command_digest=attestation.command_digest,
            limitations=attestation.limitations,
        )

    forged_document = attestation.to_dict()
    forged_document["run_id"] = "forged-store"
    forged_document["report_relative_path"] = "runs/forged-store/report.json"
    raw_evidence = forged_document["adapter_evidence"]
    assert isinstance(raw_evidence, list)
    assert isinstance(raw_evidence[0], dict)
    raw_evidence[0]["spec_digest"] = "0" * 64
    forged_document.pop("attestation_digest")
    forged_document["attestation_digest"] = canonical_digest(forged_document)
    forged_attestation = AuditRunAttestation.from_dict(forged_document)
    with pytest.raises(ValueError, match="spec_digest does not match policy declaration"):
        store_run(campaign_path, stored_report, forged_attestation)

    persisted_document = attestation.to_dict()
    persisted_evidence = persisted_document["adapter_evidence"]
    assert isinstance(persisted_evidence, list)
    assert isinstance(persisted_evidence[0], dict)
    persisted_evidence[0]["spec_digest"] = "0" * 64
    persisted_document.pop("attestation_digest")
    persisted_document["attestation_digest"] = canonical_digest(persisted_document)
    (run_path / "attestation.json").write_text(
        json.dumps(persisted_document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="adapter evidence divergence"):
        load_runs(campaign_path)
