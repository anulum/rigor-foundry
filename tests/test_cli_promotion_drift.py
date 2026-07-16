# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — CLI promotion state-binding tests
"""Verify promotion rejects repository, content, HEAD, and policy drift."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.campaign_identity import InferenceIdentity
from rigor_foundry.campaign_workflow import (
    compare_campaign_runs,
    create_campaign,
    execute_campaign,
)
from rigor_foundry.cli import main
from rigor_foundry.models import AuditReport, reviews_to_json
from rigor_foundry.review import review_templates

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
    (repository.root / ".coordination").mkdir()
    repository.write_text("docs/internal/work/INDEX.md", "# Active work\n")
    return repository


def _write_valid_review(report_path: Path, review_path: Path) -> str:
    """Write one evidence-complete valid decision for the architecture candidate."""
    report = AuditReport.from_path(report_path)
    selected = next(
        item
        for item in report.candidates
        if item.rule_id == "AR003-broad-optional-import-boundary"
    )
    template = next(
        item for item in review_templates(report) if item.candidate_id == selected.candidate_id
    )
    valid = replace(
        template,
        decision="valid",
        reviewer="agent/cli-reviewer",
        reviewed_at="2026-07-15T10:00:00Z",
        rationale="real absent dependency hides a nested import failure",
        evidence=("python -I reproduce_import.py -> nested failure hidden",),
        severity="P1",
        owner="architecture-lane",
        acceptance_gates=("present, absent, and broken imports pass",),
        title="Narrow optional import boundary",
        expires_at="2026-08-15T10:00:00Z",
        reopen_triggers=("import graph changes",),
    )
    review_path.write_text(reviews_to_json((valid,)), encoding="utf-8")
    return selected.candidate_id


def _promotion_arguments(
    repository: GitRepository,
    report_path: Path,
    review_path: Path,
    candidate_id: str,
    *,
    policy: Path | None = None,
) -> list[str]:
    """Return the public promotion command for one prepared repository report."""
    report = AuditReport.from_path(report_path)
    source_root = Path(report.repository_root)
    campaign_id = f"promotion-{report.report_digest[:16]}"
    campaign_path, _campaign = create_campaign(
        source_root,
        Path(_POLICY),
        audit_root=Path(".coordination/audits"),
        project="SAMPLE-PROJECT",
        campaign_id=campaign_id,
        actor="coordinator/drift",
        expected_runs=2,
        purpose="promotion",
        required_model_witnesses=2,
    )
    for index in (1, 2):
        execute_campaign(
            campaign_path,
            run_id=f"model-{index}",
            agent_identity=f"SAMPLE-PROJECT/agent-{index}",
            session_identity=f"terminal/{index}",
            inference_identity=InferenceIdentity.build(
                provider=f"provider-{index}",
                model=f"family-{index}-v1",
                model_family=f"family-{index}",
                operator=f"operator-{index}",
            ),
        )
    reviews_directory = campaign_path.parent / "reviews"
    reviews_directory.mkdir()
    (reviews_directory / "selected.json").write_bytes(review_path.read_bytes())
    comparison_path, comparison = compare_campaign_runs(
        campaign_path,
        comparison_id="promotion-comparison",
        actor="coordinator/drift",
    )
    assert comparison.promotion_eligible
    return [
        "promote",
        "--root",
        str(repository.root),
        "--policy",
        str(policy or Path(_POLICY)),
        "--report",
        str(report_path),
        "--review",
        str(review_path),
        "--campaign",
        str(campaign_path),
        "--comparison",
        str(comparison_path),
        "--candidate-id",
        candidate_id,
        "--todo",
        "docs/internal/work/INDEX.md",
    ]


def test_cli_promotion_rejects_repository_head_content_and_policy_drift(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Promotion cannot reuse findings after any bound repository state drifts."""
    source = _repository(tmp_path / "source")
    source_report = source.root / ".coordination/report.json"
    source_review = source.root / ".coordination/review.json"
    assert (
        main(
            [
                "scan",
                "--root",
                str(source.root),
                "--policy",
                _POLICY,
                "--json-out",
                str(source_report),
            ]
        )
        == 0
    )
    source_candidate = _write_valid_review(source_report, source_review)
    other = _repository(tmp_path / "other")
    wrong_root = _promotion_arguments(
        other,
        source_report,
        source_review,
        source_candidate,
    )
    assert main(wrong_root) == 2
    assert "different repository root" in capsys.readouterr().err

    changed_head = _repository(tmp_path / "changed-head")
    head_report = changed_head.root / ".coordination/report.json"
    head_review = changed_head.root / ".coordination/review.json"
    assert (
        main(
            [
                "scan",
                "--root",
                str(changed_head.root),
                "--policy",
                _POLICY,
                "--json-out",
                str(head_report),
            ]
        )
        == 0
    )
    head_candidate = _write_valid_review(head_report, head_review)
    head_arguments = _promotion_arguments(
        changed_head,
        head_report,
        head_review,
        head_candidate,
    )
    changed_head.write_text("src/pkg/new_owner.py", "VALUE = 1\n")
    changed_head.commit("test: change head")
    assert main(head_arguments) == 2
    assert "report HEAD is stale" in capsys.readouterr().err

    changed_content = _repository(tmp_path / "changed-content")
    content_report = changed_content.root / ".coordination/report.json"
    content_review = changed_content.root / ".coordination/review.json"
    assert (
        main(
            [
                "scan",
                "--root",
                str(changed_content.root),
                "--policy",
                _POLICY,
                "--json-out",
                str(content_report),
            ]
        )
        == 0
    )
    content_candidate = _write_valid_review(content_report, content_review)
    content_arguments = _promotion_arguments(
        changed_content,
        content_report,
        content_review,
        content_candidate,
    )
    changed_content.write_text(
        "tests/test_optional.py",
        "import pkg.optional\n\ndef test_import() -> None:\n"
        "    assert pkg.optional.extension is None\n",
    )
    assert main(content_arguments) == 2
    assert "tracked content is stale" in capsys.readouterr().err

    changed_policy = _repository(tmp_path / "changed-policy")
    primary_policy = changed_policy.root / _POLICY
    alternate_policy = changed_policy.root / "alternate-policy.json"
    alternate_document = json.loads(primary_policy.read_text(encoding="utf-8"))
    alternate_document["source_line_threshold"] = 999
    alternate_policy.write_text(json.dumps(alternate_document), encoding="utf-8")
    changed_policy.commit("test: add alternate policy")
    policy_report = changed_policy.root / ".coordination/report.json"
    policy_review = changed_policy.root / ".coordination/review.json"
    assert (
        main(
            [
                "scan",
                "--root",
                str(changed_policy.root),
                "--policy",
                _POLICY,
                "--json-out",
                str(policy_report),
            ]
        )
        == 0
    )
    policy_candidate = _write_valid_review(policy_report, policy_review)
    assert (
        main(
            _promotion_arguments(
                changed_policy,
                policy_report,
                policy_review,
                policy_candidate,
                policy=Path("alternate-policy.json"),
            )
        )
        == 2
    )
    assert "report policy is stale" in capsys.readouterr().err


def test_cli_promotion_rejects_ignored_inventory_drift(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Promotion cannot reuse a review after declared ignored evidence changes."""
    repository = _repository(tmp_path / "ignored-drift")
    report_path = repository.root / ".coordination/report.json"
    review_path = repository.root / ".coordination/review.json"
    assert (
        main(
            [
                "scan",
                "--root",
                str(repository.root),
                "--policy",
                _POLICY,
                "--json-out",
                str(report_path),
            ]
        )
        == 0
    )
    candidate_id = _write_valid_review(report_path, review_path)
    arguments = _promotion_arguments(
        repository,
        report_path,
        review_path,
        candidate_id,
    )
    repository.write_text(".rigor/runtime-state.json", '{"state":"changed"}\n')
    assert main(arguments) == 2
    assert "ignored inventory is stale" in capsys.readouterr().err
