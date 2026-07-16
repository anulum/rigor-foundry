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
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.campaign_identity import InferenceIdentity
from rigor_foundry.campaign_models import AuditCampaign, AuditRunAttestation
from rigor_foundry.campaign_store import StoredAuditRun, load_campaign, load_runs
from rigor_foundry.campaign_workflow import (
    compare_campaign_runs,
    create_campaign,
    execute_campaign,
)
from rigor_foundry.git_provenance import GitTrustPolicy
from rigor_foundry.models import AuditReport, ReviewRecord, reviews_to_json

_POLICY = Path("rigor-foundry-policy.json")


def _inference_identity(
    model_family: str = "model-family",
    operator: str = "operator-one",
) -> InferenceIdentity:
    """Return one explicit inference identity for campaign workflow tests."""
    return InferenceIdentity.build(
        provider="provider.example",
        model=f"{model_family}-v1",
        model_family=model_family,
        operator=operator,
    )


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


def _campaign_with_candidate(
    path: Path,
) -> tuple[GitRepository, Path, StoredAuditRun]:
    """Create one real campaign run whose report has a reviewable candidate."""
    repository = _repository(path / "repository")
    repository.write_text(
        "src/pkg/optional.py",
        "try:\n    import pkg.absent\nexcept Exception:\n    ABSENT = None\n",
    )
    repository.commit()
    campaign_path, _campaign = create_campaign(
        repository.root,
        _POLICY,
        audit_root=Path(".rigor/audits"),
        project="SAMPLE-PROJECT",
        campaign_id="review-campaign",
        actor="coordinator/one",
        expected_runs=1,
    )
    execute_campaign(
        campaign_path,
        run_id="review-agent",
        agent_identity="SAMPLE-PROJECT/review-agent",
        session_identity="terminal/review",
        inference_identity=_inference_identity(),
    )
    return repository, campaign_path, load_runs(campaign_path)[0]


def _valid_review(report: AuditReport, candidate_id: str, reviewer: str) -> ReviewRecord:
    """Return one completed evidence decision for a campaign report candidate."""
    return ReviewRecord(
        report_digest=report.report_digest,
        candidate_id=candidate_id,
        decision="valid",
        reviewer=reviewer,
        reviewed_at="2026-07-15T13:00:00Z",
        rationale="the exact campaign report reproduces this candidate",
        evidence=("reviewed the candidate against the frozen campaign tree",),
        severity="P1",
        owner="lane/campaign-review",
        dependencies=(),
        acceptance_gates=("focused regression over the frozen tree passes",),
        title="Repair the reproduced campaign finding",
        boundary_justification="",
        expires_at="2026-08-15T13:00:00Z",
        reopen_triggers=("campaign input digest changes",),
    )


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
        expected_runs=2,
    )
    assert load_campaign(campaign_path) == created
    first_path, first = execute_campaign(
        campaign_path,
        run_id="agent-one",
        agent_identity="SAMPLE-PROJECT/agent-one",
        session_identity="terminal/one",
        inference_identity=_inference_identity(),
    )
    second_path, second = execute_campaign(
        campaign_path,
        run_id="agent-two",
        agent_identity="SAMPLE-PROJECT/agent-two",
        session_identity="terminal/two",
        inference_identity=_inference_identity(),
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
            inference_identity=_inference_identity(),
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
        expected_runs=1,
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
            inference_identity=_inference_identity(),
        )


def test_campaign_rejects_policy_outside_repository(tmp_path: Path) -> None:
    """A frozen campaign cannot depend on an external mutable policy file."""
    repository = _repository(tmp_path / "repository")
    external_policy = tmp_path / "external-policy.json"
    external_policy.write_bytes((repository.root / _POLICY).read_bytes())

    with pytest.raises(ValueError, match="tracked repository-relative path"):
        create_campaign(
            repository.root,
            external_policy,
            audit_root=Path(".coordination/audits"),
            project="SAMPLE-PROJECT",
            campaign_id="external-policy",
            actor="coordinator/one",
            expected_runs=1,
        )


def test_campaign_rejects_git_executable_provenance_divergence(tmp_path: Path) -> None:
    """A run cannot substitute another trusted Git path for the frozen executable."""
    repository = _repository(tmp_path / "repository")
    campaign_path, _campaign = create_campaign(
        repository.root,
        _POLICY,
        audit_root=Path(".coordination/audits"),
        project="SAMPLE-PROJECT",
        campaign_id="git-provenance",
        actor="coordinator/one",
        expected_runs=1,
    )
    tools = tmp_path / "trusted-tools"
    tools.mkdir()
    executable = tools / "git"
    shutil.copy2(repository.git, executable)
    policy = GitTrustPolicy(trusted_roots=(str(tools),))

    with pytest.raises(ValueError, match="git_provenance"):
        execute_campaign(
            campaign_path,
            run_id="different-git",
            agent_identity="SAMPLE-PROJECT/agent-one",
            session_identity="terminal/one",
            inference_identity=_inference_identity(),
            git_trust_policy=policy,
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
        expected_runs=1,
    )
    with pytest.raises(ValueError, match="explicit trusted consent"):
        execute_campaign(
            campaign_path,
            run_id="refused",
            agent_identity="SAMPLE-PROJECT/agent-one",
            session_identity="terminal/one",
            inference_identity=_inference_identity(),
        )
    directory, attestation = execute_campaign(
        campaign_path,
        run_id="consented",
        agent_identity="SAMPLE-PROJECT/agent-one",
        session_identity="terminal/one",
        inference_identity=_inference_identity(),
        trusted_native_audits=True,
    )
    evidence = attestation.adapter_evidence[0]
    assert len(evidence.executable_digest) == 64
    assert len(evidence.environment_digest) == 64
    assert evidence.sandbox_provenance.package_name == "bubblewrap"
    assert evidence.sandbox_provenance.semantic_version == "0.9.0"
    assert len(evidence.sandbox_provenance.identity_digest) == 64
    serialised = json.dumps(attestation.to_dict(), sort_keys=True)
    assert sentinel not in serialised
    assert sentinel not in (directory / "attestation.json").read_text(encoding="utf-8")


def test_campaign_rejects_ignored_inventory_mutation_during_native_adapter(
    tmp_path: Path,
) -> None:
    """Post-adapter recollection rejects a real externally mutated ignored input."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    repository.write_text(
        "controls/native.py",
        """
import pathlib
import time

with pathlib.Path(".rigor/adapter-ready").open("w", encoding="utf-8") as marker:
    marker.write("ready")
time.sleep(0.5)
print("complete")
""".lstrip(),
    )
    mutator = repository.write_text(
        "controls/mutate.py",
        """
import pathlib
import sys

ready, target = map(pathlib.Path, sys.argv[1:])
with ready.open("r", encoding="utf-8") as marker:
    if marker.read() != "ready":
        raise RuntimeError("adapter readiness marker is invalid")
target.write_text("changed-during-adapter", encoding="utf-8")
""".lstrip(),
    )
    repository.write_policy(
        ignored_inventory=[
            {
                "evidence_id": "native-state",
                "path": ".rigor/native-state.txt",
                "capture": "file-sha256",
            }
        ],
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
        ],
    )
    repository.commit()
    target = repository.root / ".rigor/native-state.txt"
    target.parent.mkdir(exist_ok=True)
    campaign_path, _campaign = create_campaign(
        repository.root,
        _POLICY,
        audit_root=Path(".coordination/audits"),
        project="SAMPLE-PROJECT",
        campaign_id="ignored-mutation",
        actor="coordinator/one",
        expected_runs=1,
    )
    ready = repository.root / ".rigor/adapter-ready"
    os.mkfifo(ready, mode=0o666)
    process = subprocess.Popen(  # nosec B603
        [sys.executable, str(mutator), str(ready), str(target)],
        cwd=repository.root,
        shell=False,
    )
    try:
        with pytest.raises(RuntimeError, match="mutated ignored inventory state"):
            execute_campaign(
                campaign_path,
                run_id="mutated",
                agent_identity="SAMPLE-PROJECT/agent-one",
                session_identity="terminal/one",
                inference_identity=_inference_identity(),
                trusted_native_audits=True,
            )
    finally:
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=10)
            raise


def test_campaign_rejects_concurrent_tracked_mutation_during_native_adapter(
    tmp_path: Path,
) -> None:
    """An external tracked-file mutation during native execution rejects attestation."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    repository.write_text(
        "controls/native.py",
        """
import pathlib
import time

with pathlib.Path(".rigor/adapter-ready").open("w", encoding="utf-8") as marker:
    marker.write("ready")
time.sleep(0.5)
print("complete")
""".lstrip(),
    )
    mutator = repository.write_text(
        "controls/mutate.py",
        """
import pathlib
import sys

ready, target = map(pathlib.Path, sys.argv[1:])
with ready.open("r", encoding="utf-8") as marker:
    if marker.read() != "ready":
        raise RuntimeError("adapter readiness marker is invalid")
target.write_text("VALUE = 2\\n", encoding="utf-8")
""".lstrip(),
    )
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
        campaign_id="tracked-mutation",
        actor="coordinator/one",
        expected_runs=1,
    )
    ready = repository.root / ".rigor/adapter-ready"
    ready.parent.mkdir(exist_ok=True)
    os.mkfifo(ready, mode=0o666)
    process = subprocess.Popen(  # nosec B603
        [sys.executable, str(mutator), str(ready), str(repository.root / "src/pkg/core.py")],
        cwd=repository.root,
        shell=False,
    )
    try:
        with pytest.raises(RuntimeError, match="mutated tracked repository state"):
            execute_campaign(
                campaign_path,
                run_id="mutated",
                agent_identity="SAMPLE-PROJECT/agent-one",
                session_identity="terminal/one",
                inference_identity=_inference_identity(),
                trusted_native_audits=True,
            )
    finally:
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=10)
            raise


def test_campaign_freezes_ignored_evidence_after_creating_its_storage_root(
    tmp_path: Path,
) -> None:
    """Campaign-owned ignored directories cannot create first-run input divergence."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    repository.write_policy(
        ignored_inventory=[
            {
                "evidence_id": "runtime-state",
                "path": ".rigor/runtime-state.json",
                "capture": "file-sha256",
            }
        ]
    )
    repository.commit()

    campaign_path, campaign = create_campaign(
        repository.root,
        _POLICY,
        audit_root=Path(".rigor/audits"),
        project="SAMPLE-PROJECT",
        campaign_id="shared-ignored-parent",
        actor="coordinator/one",
        expected_runs=1,
    )
    _directory, attestation = execute_campaign(
        campaign_path,
        run_id="model-one",
        agent_identity="SAMPLE-PROJECT/agent-one",
        session_identity="terminal/one",
        inference_identity=_inference_identity(),
    )

    assert campaign.ignored_inventory_evidence[0].status == "missing"
    assert attestation.report_digest == load_runs(campaign_path)[0].report.report_digest


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
        "--provider",
        "provider.example",
        "--model",
        "model-v1",
        "--model-family",
        "model-family",
        "--operator",
        "operator-one",
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


def test_campaign_comparison_rejects_mixed_unmatched_and_invalid_reviews(
    tmp_path: Path,
) -> None:
    """Persisted reviews must bind one known report and pass candidate validation."""
    cases = ("mixed", "unmatched", "invalid")
    for case in cases:
        _repository, campaign_path, stored = _campaign_with_candidate(tmp_path / case)
        candidate_id = stored.report.candidates[0].candidate_id
        reviews_directory = campaign_path.parent / "reviews"
        reviews_directory.mkdir()
        reviews: tuple[ReviewRecord, ...]
        if case == "mixed":
            reviews = (
                ReviewRecord.template(stored.report.report_digest, candidate_id),
                ReviewRecord.template("0" * 64, candidate_id),
            )
            message = "mixes report digests"
        elif case == "unmatched":
            reviews = (ReviewRecord.template("0" * 64, candidate_id),)
            message = "no matching campaign report"
        else:
            reviews = (ReviewRecord.template(stored.report.report_digest, "absent-candidate"),)
            message = "review document 0 is invalid"
        (reviews_directory / "review.json").write_text(
            reviews_to_json(reviews),
            encoding="utf-8",
        )

        with pytest.raises(ValueError, match=message):
            compare_campaign_runs(
                campaign_path,
                comparison_id=f"comparison-{case}",
                actor="coordinator/one",
            )


def test_campaign_comparison_accepts_complete_valid_review_documents(tmp_path: Path) -> None:
    """Completed candidate reviews produce a durable resolved comparison."""
    _repository, campaign_path, stored = _campaign_with_candidate(tmp_path)
    reviews = tuple(
        _valid_review(stored.report, candidate.candidate_id, f"reviewer/{index}")
        for index, candidate in enumerate(stored.report.candidates, start=1)
    )
    reviews_directory = campaign_path.parent / "reviews"
    reviews_directory.mkdir()
    (reviews_directory / "review.json").write_text(
        reviews_to_json(reviews),
        encoding="utf-8",
    )

    comparison_path, comparison = compare_campaign_runs(
        campaign_path,
        comparison_id="comparison-reviewed",
        actor="coordinator/one",
    )

    assert comparison_path.is_file()
    assert not comparison.unresolved
    assert comparison.review_divergence == ()
    assert comparison.diligence_gaps == ()
