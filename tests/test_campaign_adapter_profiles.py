# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — built-in adapter campaign integration tests
"""Run Semgrep and Trivy through the public durable campaign boundary."""

from __future__ import annotations

from pathlib import Path

from repository_audit_git_repository import GitRepository

from rigor_foundry.campaign_identity import InferenceIdentity
from rigor_foundry.campaign_models import AuditRunAttestation
from rigor_foundry.campaign_store import load_runs
from rigor_foundry.campaign_workflow import create_campaign, execute_campaign


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

    _run_path, attestation = execute_campaign(
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
