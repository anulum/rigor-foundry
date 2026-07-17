# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real repository audit CLI tests
"""Verify scan, review, promotion, and gate commands through real subprocesses."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cli_test_support import POLICY, cli_repository, promotion_campaign
from repository_audit_git_repository import GitRepository

from rigor_foundry.cli import main, report_markdown
from rigor_foundry.models import AuditReport
from tools.check_consumer_outputs import consumer_output_errors


def test_scan_is_read_only_deterministic_and_labels_candidates(tmp_path: Path) -> None:
    """Repeated scans produce identical reports and never change tracked state."""
    repository = cli_repository(tmp_path / "repository")
    before = repository.git_command("status", "--porcelain=v1").stdout
    first_path = repository.root / ".coordination/report-1.json"
    second_path = repository.root / ".coordination/report-2.json"
    first = repository.run_audit(
        "scan",
        "--root",
        ".",
        "--policy",
        POLICY,
        "--json-out",
        str(first_path),
    )
    second = repository.run_audit(
        "scan",
        "--root",
        ".",
        "--policy",
        POLICY,
        "--json-out",
        str(second_path),
    )
    assert first.returncode == second.returncode == 0
    assert first_path.read_bytes() == second_path.read_bytes()
    report = AuditReport.from_path(first_path)
    assert Path(report.git_provenance.resolved_path).is_absolute()
    assert tuple(int(part) for part in report.git_provenance.version.split(".")) >= (2, 35, 2)
    assert any(
        item.rule_id == "AR003-broad-optional-import-boundary" for item in report.candidates
    )
    assert repository.git_command("status", "--porcelain=v1").stdout == before
    failed = repository.run_audit(
        "scan",
        "--root",
        ".",
        "--policy",
        POLICY,
        "--fail-on-candidates",
    )
    assert failed.returncode == 1

    explicit_path = repository.root / ".coordination/report-explicit-git.json"
    explicit = repository.run_audit(
        "scan",
        "--root",
        ".",
        "--policy",
        POLICY,
        "--git-executable",
        repository.git,
        "--git-trust-root",
        str(Path(repository.git).parent),
        "--json-out",
        str(explicit_path),
    )
    assert explicit.returncode == 0, explicit.stderr
    assert AuditReport.from_path(explicit_path).git_provenance.resolved_path == repository.git


def test_scan_cli_rejects_implicit_root_for_absolute_git(tmp_path: Path) -> None:
    """An absolute executable cannot silently make its parent trusted."""
    repository = cli_repository(tmp_path / "repository")

    result = repository.run_audit(
        "scan",
        "--root",
        ".",
        "--policy",
        POLICY,
        "--git-executable",
        repository.git,
    )

    assert result.returncode == 2
    assert "requires --git-trust-root" in result.stderr


def test_scan_output_rejects_symlink_introduced_after_action_guard(tmp_path: Path) -> None:
    """The real CLI cannot follow a target introduced after the Action precheck."""
    repository = cli_repository(tmp_path / "repository")
    output = repository.root / ".coordination/action.json"
    victim = tmp_path / "victim.json"
    victim.write_text("preserve\n", encoding="utf-8")
    assert consumer_output_errors(repository.root, (output,)) == []
    output.symlink_to(victim)

    result = repository.run_audit(
        "scan",
        "--root",
        ".",
        "--policy",
        POLICY,
        "--json-out",
        str(output),
    )

    assert result.returncode == 2
    assert "output path already exists" in result.stderr
    assert output.is_symlink()
    assert victim.read_text(encoding="utf-8") == "preserve\n"


def test_review_validation_and_explicit_promotion_use_current_tree(tmp_path: Path) -> None:
    """Dry run is non-mutating, apply is internal, and content drift rejects reuse."""
    repository = cli_repository(tmp_path / "repository")
    report_path = repository.root / ".coordination/report.json"
    review_path = repository.root / ".coordination/reviews.json"
    assert (
        repository.run_audit(
            "scan",
            "--root",
            ".",
            "--policy",
            POLICY,
            "--json-out",
            str(report_path),
        ).returncode
        == 0
    )
    assert (
        repository.run_audit(
            "review-template",
            "--report",
            str(report_path),
            "--output",
            str(review_path),
        ).returncode
        == 0
    )
    report = AuditReport.from_path(report_path)
    selected = next(
        item
        for item in report.candidates
        if item.rule_id == "AR003-broad-optional-import-boundary"
    )
    document = json.loads(review_path.read_text(encoding="utf-8"))
    review = next(
        item for item in document["reviews"] if item["candidate_id"] == selected.candidate_id
    )
    review.update(
        {
            "decision": "valid",
            "reviewer": "agent/reviewer",
            "reviewed_at": "2026-07-15T10:00:00Z",
            "rationale": "real absent dependency hides nested import failures",
            "evidence": ["python -I reproduce_import.py -> hidden nested failure"],
            "severity": "P1",
            "owner": "architecture-lane",
            "dependencies": [],
            "acceptance_gates": ["present, absent, and broken real imports pass"],
            "title": "Narrow optional import exception",
            "expires_at": "2026-08-15T10:00:00Z",
            "reopen_triggers": ["dependency import graph changes"],
        }
    )
    review_path.write_text(json.dumps(document), encoding="utf-8")
    validated = repository.run_audit(
        "validate-review",
        "--report",
        str(report_path),
        "--review",
        str(review_path),
    )
    assert validated.returncode == 0, validated.stderr
    campaign_path, comparison_path = promotion_campaign(
        report_path,
        review_path,
        campaign_id="subprocess-promotion",
    )

    todo = repository.root / "docs/internal/work/INDEX.md"
    before = todo.read_text(encoding="utf-8")
    arguments = (
        "promote",
        "--root",
        ".",
        "--policy",
        POLICY,
        "--report",
        str(report_path),
        "--review",
        str(review_path),
        "--campaign",
        str(campaign_path),
        "--comparison",
        str(comparison_path),
        "--candidate-id",
        selected.candidate_id,
        "--todo",
        "docs/internal/work/INDEX.md",
    )
    provenance_drift = repository.run_audit(
        *arguments,
        "--git-executable",
        repository.git,
        "--git-trust-root",
        str(Path(repository.git).parent),
    )
    assert provenance_drift.returncode == 2
    assert "Git executable provenance is stale" in provenance_drift.stderr
    preview = repository.run_audit(*arguments)
    assert preview.returncode == 0
    assert todo.read_text(encoding="utf-8") == before
    applied = repository.run_audit(*arguments, "--apply")
    assert applied.returncode == 0, applied.stderr
    assert selected.candidate_id in todo.read_text(encoding="utf-8")

    repository.write_text(
        "tests/test_optional.py",
        "import pkg.optional\n\ndef test_import() -> None:\n"
        "    assert pkg.optional is not None\n    assert pkg.optional.extension is None\n",
    )
    stale = repository.run_audit(*arguments)
    assert stale.returncode == 2
    assert "tracked content is stale" in stale.stderr


def test_observe_gate_emits_evidence_without_blocking(tmp_path: Path) -> None:
    """Observe mode records current evidence without claiming zero-candidate conformance."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    policy = repository.write_policy()
    repository.commit()
    gate = repository.run_audit(
        "gate",
        "--root",
        ".",
        "--policy",
        policy.name,
        "--mode",
        "observe",
    )
    assert gate.returncode == 0
    gate_value = json.loads(gate.stdout)
    assert gate_value["mode"] == "observe"
    assert gate_value["passed"] is True


def test_source_sentinel_never_reaches_reports_cli_or_campaign_artifacts(
    tmp_path: Path,
) -> None:
    """Source-derived evidence is location and digest metadata, never raw content."""
    sentinel = "RIGOR_SOURCE_SENTINEL_2ac61b30"
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    repository.write_text(
        "tests/test_core.py",
        f"{sentinel} = 'private'\n\ndef test_value() -> None:\n"
        f"    assert {sentinel} == 'private'\n",
    )
    repository.write_policy()
    repository.commit()
    scanned = repository.run_audit("scan", "--root", ".", "--policy", POLICY)
    assert scanned.returncode == 0
    assert sentinel not in scanned.stdout
    assert sentinel not in scanned.stderr
    created = repository.run_audit(
        "campaign-create",
        "--root",
        ".",
        "--policy",
        POLICY,
        "--project",
        "SAMPLE-PROJECT",
        "--campaign-id",
        "sentinel-campaign",
        "--actor",
        "coordinator/cli",
        "--expected-runs",
        "1",
    )
    assert created.returncode == 0, created.stderr
    campaign = repository.root / (
        ".rigor/audits/SAMPLE-PROJECT/campaigns/sentinel-campaign/campaign.json"
    )
    run = repository.run_audit(
        "campaign-run",
        "--campaign",
        str(campaign),
        "--run-id",
        "sentinel-agent",
        "--agent",
        "SAMPLE-PROJECT/sentinel-agent",
        "--session",
        "terminal/sentinel",
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
    assert sentinel not in created.stdout + created.stderr + run.stdout + run.stderr
    for artifact in campaign.parent.rglob("*.json"):
        assert sentinel not in artifact.read_text(encoding="utf-8")


def test_direct_cli_contracts_cover_every_command_handler(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """In-process CLI calls retain real Git, filesystem, and process behaviour."""
    repository = cli_repository(tmp_path / "repository")
    policy = POLICY
    report_path = repository.root / ".coordination/direct-report.json"
    markdown_path = repository.root / ".coordination/direct-report.md"
    review_path = repository.root / ".coordination/direct-reviews.json"
    assert (
        main(
            [
                "scan",
                "--root",
                str(repository.root),
                "--policy",
                str(policy),
                "--json-out",
                str(report_path),
                "--markdown-out",
                str(markdown_path),
            ]
        )
        == 0
    )
    report = AuditReport.from_path(report_path)
    rendered = report_markdown(report)
    assert rendered == markdown_path.read_text(encoding="utf-8")
    assert "Static candidates are not defect verdicts" in rendered
    assert f"Git object format: `{report.git_object_format}`" in rendered
    assert "- Anchor: blob `" in rendered
    assert main(["scan", "--root", str(repository.root), "--policy", str(policy)]) == 0
    assert json.loads(capsys.readouterr().out)["report_digest"] == report.report_digest
    assert (
        main(
            [
                "review-template",
                "--report",
                str(report_path),
                "--output",
                str(review_path),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "validate-review",
                "--report",
                str(report_path),
                "--review",
                str(review_path),
            ]
        )
        == 0
    )
    assert "PASS" in capsys.readouterr().out
    document = json.loads(review_path.read_text(encoding="utf-8"))
    selected = next(
        item
        for item in report.candidates
        if item.rule_id == "AR003-broad-optional-import-boundary"
    )
    review = next(
        item for item in document["reviews"] if item["candidate_id"] == selected.candidate_id
    )
    review.update(
        {
            "decision": "valid",
            "reviewer": "agent/direct-reviewer",
            "reviewed_at": "2026-07-15T10:00:00Z",
            "rationale": "direct reproduction confirms nested failure masking",
            "evidence": ["python -I reproduce_import.py -> nested error hidden"],
            "severity": "P1",
            "owner": "architecture-lane",
            "acceptance_gates": ["present, absent, and broken imports pass"],
            "title": "Narrow optional import boundary",
            "expires_at": "2026-08-15T10:00:00Z",
            "reopen_triggers": ["import graph changes"],
        }
    )
    review_path.write_text(json.dumps(document), encoding="utf-8")
    promotion_paths = promotion_campaign(
        report_path,
        review_path,
        campaign_id="direct-promotion",
    )
    promote = [
        "promote",
        "--root",
        str(repository.root),
        "--policy",
        str(policy),
        "--report",
        str(report_path),
        "--review",
        str(review_path),
        "--campaign",
        str(promotion_paths[0]),
        "--comparison",
        str(promotion_paths[1]),
        "--candidate-id",
        selected.candidate_id,
        "--todo",
        "docs/internal/work/INDEX.md",
    ]
    assert main(promote) == 0
    assert selected.candidate_id in capsys.readouterr().out
    assert main([*promote, "--apply"]) == 0
    assert selected.candidate_id in (repository.root / "docs/internal/work/INDEX.md").read_text(
        encoding="utf-8"
    )

    gate_path = repository.root / ".coordination/gate.json"
    assert (
        main(
            [
                "gate",
                "--root",
                str(repository.root),
                "--policy",
                str(policy),
                "--scope",
                "staged",
                "--output",
                str(gate_path),
            ]
        )
        == 0
    )
    assert json.loads(gate_path.read_text(encoding="utf-8"))["passed"] is True

    campaign_id = "direct-campaign"
    campaign_path = (
        repository.root / ".rigor/audits/SAMPLE-PROJECT/campaigns" / campaign_id / "campaign.json"
    )
    assert (
        main(
            [
                "campaign-create",
                "--root",
                str(repository.root),
                "--policy",
                str(policy),
                "--project",
                "SAMPLE-PROJECT",
                "--campaign-id",
                campaign_id,
                "--actor",
                "coordinator/direct",
                "--expected-runs",
                "1",
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "campaign-run",
                "--campaign",
                str(campaign_path),
                "--run-id",
                "direct-agent",
                "--agent",
                "SAMPLE-PROJECT/direct-agent",
                "--session",
                "terminal/direct",
                "--provider",
                "provider.example",
                "--model",
                "model-v1",
                "--model-family",
                "model-family",
                "--operator",
                "operator-one",
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "campaign-compare",
                "--campaign",
                str(campaign_path),
                "--comparison-id",
                "direct-comparison",
                "--actor",
                "coordinator/direct",
            ]
        )
        == 1
    )
    assert main(["scan", "--root", str(repository.root), "--policy", "missing.json"]) == 2
    assert "repository audit error" in capsys.readouterr().err
