# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
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
from repository_audit_git_repository import GitRepository

from rigor_foundry.cli import main, report_markdown
from rigor_foundry.models import AuditReport

_POLICY = "rigor-foundry-policy.json"


def _repository(path: Path) -> GitRepository:
    """Create one repository containing a reproducible architecture candidate."""
    repository = GitRepository.create(path)
    repository.write_text(
        "src/pkg/optional.py",
        "try:\n    import pkg.extension\nexcept Exception:\n    extension = None\n",
    )
    repository.write_text(
        "tests/test_optional.py",
        "import pkg.optional\n\ndef test_import() -> None:\n    assert pkg.optional is not None\n",
    )
    repository.write_policy()
    repository.commit()
    (repository.root / ".coordination").mkdir()
    repository.write_text("docs/internal/work/INDEX.md", "# Active work\n")
    return repository


def test_scan_is_read_only_deterministic_and_labels_candidates(tmp_path: Path) -> None:
    """Repeated scans produce identical reports and never change tracked state."""
    repository = _repository(tmp_path / "repository")
    before = repository.git_command("status", "--porcelain=v1").stdout
    first_path = repository.root / ".coordination/report-1.json"
    second_path = repository.root / ".coordination/report-2.json"
    first = repository.run_audit(
        "scan",
        "--root",
        ".",
        "--policy",
        _POLICY,
        "--json-out",
        str(first_path),
    )
    second = repository.run_audit(
        "scan",
        "--root",
        ".",
        "--policy",
        _POLICY,
        "--json-out",
        str(second_path),
    )
    assert first.returncode == second.returncode == 0
    assert first_path.read_bytes() == second_path.read_bytes()
    report = AuditReport.from_path(first_path)
    assert any(
        item.rule_id == "AR003-broad-optional-import-boundary" for item in report.candidates
    )
    assert repository.git_command("status", "--porcelain=v1").stdout == before
    failed = repository.run_audit(
        "scan",
        "--root",
        ".",
        "--policy",
        _POLICY,
        "--fail-on-candidates",
    )
    assert failed.returncode == 1


def test_review_validation_and_explicit_promotion_use_current_tree(tmp_path: Path) -> None:
    """Dry run is non-mutating, apply is internal, and content drift rejects reuse."""
    repository = _repository(tmp_path / "repository")
    report_path = repository.root / ".coordination/report.json"
    review_path = repository.root / ".coordination/reviews.json"
    assert (
        repository.run_audit(
            "scan",
            "--root",
            ".",
            "--policy",
            _POLICY,
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

    todo = repository.root / "docs/internal/work/INDEX.md"
    before = todo.read_text(encoding="utf-8")
    arguments = (
        "promote",
        "--root",
        ".",
        "--policy",
        _POLICY,
        "--report",
        str(report_path),
        "--review",
        str(review_path),
        "--candidate-id",
        selected.candidate_id,
        "--todo",
        "docs/internal/work/INDEX.md",
    )
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
    repository.commit()
    policy = repository.write_policy()
    gate = repository.run_audit(
        "gate",
        "--root",
        ".",
        "--policy",
        str(policy),
        "--mode",
        "observe",
    )
    assert gate.returncode == 0
    gate_value = json.loads(gate.stdout)
    assert gate_value["mode"] == "observe"
    assert gate_value["passed"] is True


def test_direct_cli_contracts_cover_every_command_handler(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """In-process CLI calls retain real Git, filesystem, and process behaviour."""
    repository = _repository(tmp_path / "repository")
    policy = repository.root / _POLICY
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
