# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — cross-model campaign promotion tests
"""Verify promotion admission against real durable campaign evidence."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.campaign_identity import InferenceIdentity
from rigor_foundry.campaign_models import CampaignPurpose
from rigor_foundry.campaign_promotion import validate_promotion_campaign
from rigor_foundry.campaign_store import StoredAuditRun, load_runs
from rigor_foundry.campaign_workflow import (
    compare_campaign_runs,
    create_campaign,
    execute_campaign,
)
from rigor_foundry.models import AuditReport, ReviewRecord, reviews_to_json


def _repository(path: Path) -> GitRepository:
    """Create one real repository containing a reviewable candidate."""
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
    return repository


def _valid_review(report: AuditReport, *, reviewer: str = "reviewer/one") -> ReviewRecord:
    """Return one valid review for the report's architecture candidate."""
    candidate = next(
        item
        for item in report.candidates
        if item.rule_id == "AR003-broad-optional-import-boundary"
    )
    return ReviewRecord(
        report_digest=report.report_digest,
        candidate_id=candidate.candidate_id,
        decision="valid",
        reviewer=reviewer,
        reviewed_at="2026-07-15T13:00:00Z",
        rationale="the exact campaign tree reproduces the optional-import boundary",
        evidence=("python -I reproduction confirms nested failure masking",),
        severity="P1",
        owner="architecture-lane",
        dependencies=(),
        acceptance_gates=("present, absent, and internally broken imports pass",),
        title="Narrow the optional import boundary",
        boundary_justification="",
        expires_at="2026-08-15T13:00:00Z",
        reopen_triggers=("import dependency graph changes",),
    )


def _promotion_bundle(
    tmp_path: Path,
    *,
    families: tuple[str, str] = ("family-one", "family-two"),
    operators: tuple[str, str] = ("operator-one", "operator-two"),
    purpose: CampaignPurpose = "promotion",
) -> tuple[Path, Path, StoredAuditRun, ReviewRecord]:
    """Persist a complete two-run campaign and one exact review document."""
    repository = _repository(tmp_path / "repository")
    campaign_path, _campaign = create_campaign(
        repository.root,
        Path("rigor-foundry-policy.json"),
        audit_root=Path(".rigor/audits"),
        project="SAMPLE-PROJECT",
        campaign_id="promotion-campaign",
        actor="coordinator/one",
        expected_runs=2,
        purpose=purpose,
        required_model_witnesses=2 if purpose == "promotion" else 1,
    )
    for index, (family, operator) in enumerate(zip(families, operators, strict=True), start=1):
        execute_campaign(
            campaign_path,
            run_id=f"run-{index}",
            agent_identity=f"SAMPLE-PROJECT/agent-{index}",
            session_identity=f"terminal/{index}",
            inference_identity=InferenceIdentity.build(
                provider=f"provider-{index}",
                model=f"{family}-v1",
                model_family=family,
                operator=operator,
            ),
        )
    stored = load_runs(campaign_path)[0]
    review = _valid_review(stored.report)
    reviews_directory = campaign_path.parent / "reviews"
    reviews_directory.mkdir()
    (reviews_directory / "selected.json").write_text(
        reviews_to_json((review,)),
        encoding="utf-8",
    )
    comparison_path, _comparison = compare_campaign_runs(
        campaign_path,
        comparison_id="promotion-comparison",
        actor="coordinator/one",
    )
    return campaign_path, comparison_path, stored, review


def test_promotion_campaign_accepts_exact_cross_model_durable_evidence(
    tmp_path: Path,
) -> None:
    """Two model families and operators admit the exact compared report and review."""
    campaign_path, comparison_path, stored, review = _promotion_bundle(tmp_path)

    comparison = validate_promotion_campaign(
        campaign_path,
        comparison_path,
        stored.report,
        review,
    )

    assert comparison.promotion_eligible
    assert comparison.actual_model_witnesses == 2
    assert stored.attestation.attestation_digest in comparison.attestation_digests
    assert stored.report.report_digest in comparison.report_digests
    assert review.review_digest in comparison.review_digests


def test_promotion_campaign_rejects_correlated_or_diagnostic_campaigns(
    tmp_path: Path,
) -> None:
    """Same-family runs and diagnostic campaigns cannot authorize promotion."""
    correlated = _promotion_bundle(
        tmp_path / "correlated",
        families=("shared-family", "shared-family"),
    )
    with pytest.raises(ValueError, match="not eligible"):
        validate_promotion_campaign(
            correlated[0],
            correlated[1],
            correlated[2].report,
            correlated[3],
        )

    diagnostic = _promotion_bundle(tmp_path / "diagnostic", purpose="diagnostic")
    with pytest.raises(ValueError, match="requires a promotion campaign"):
        validate_promotion_campaign(
            diagnostic[0],
            diagnostic[1],
            diagnostic[2].report,
            diagnostic[3],
        )


def test_promotion_campaign_rejects_review_not_present_in_comparison(
    tmp_path: Path,
) -> None:
    """A valid but unreviewed-after-comparison record cannot borrow prior diligence."""
    campaign_path, comparison_path, stored, review = _promotion_bundle(tmp_path)
    foreign = replace(review, reviewer="reviewer/two")

    with pytest.raises(ValueError, match="did not participate"):
        validate_promotion_campaign(
            campaign_path,
            comparison_path,
            stored.report,
            foreign,
        )


def test_promotion_campaign_revalidates_review_documents_and_selected_inputs(
    tmp_path: Path,
) -> None:
    """Mixed, unmatched, invalid, and non-participating evidence fail closed."""
    mixed = _promotion_bundle(tmp_path / "mixed")
    mixed_path = mixed[0].parent / "reviews/selected.json"
    mixed_path.write_text(
        reviews_to_json(
            (
                mixed[3],
                replace(mixed[3], report_digest="0" * 64),
            )
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="mixes report digests"):
        validate_promotion_campaign(mixed[0], mixed[1], mixed[2].report, mixed[3])

    unmatched = _promotion_bundle(tmp_path / "unmatched")
    unmatched_path = unmatched[0].parent / "reviews/selected.json"
    unmatched_path.write_text(
        reviews_to_json((replace(unmatched[3], report_digest="0" * 64),)),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="no matching campaign report"):
        validate_promotion_campaign(
            unmatched[0],
            unmatched[1],
            unmatched[2].report,
            unmatched[3],
        )

    invalid = _promotion_bundle(tmp_path / "invalid")
    invalid_path = invalid[0].parent / "reviews/selected.json"
    invalid_path.write_text(
        reviews_to_json((replace(invalid[3], candidate_id="absent-candidate"),)),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="review document 0 is invalid"):
        validate_promotion_campaign(invalid[0], invalid[1], invalid[2].report, invalid[3])

    campaign_path, comparison_path, stored, review = _promotion_bundle(tmp_path / "selected")
    foreign_report = AuditReport.build(
        repository_root=stored.report.repository_root,
        head=stored.report.head,
        head_tree=stored.report.head_tree,
        git_object_format=stored.report.git_object_format,
        branch=stored.report.branch,
        tracked_content_digest=stored.report.tracked_content_digest,
        dirty_paths=stored.report.dirty_paths,
        tracked_file_count=stored.report.tracked_file_count,
        git_provenance=stored.report.git_provenance,
        policy=stored.report.policy,
        candidates=(),
    )
    with pytest.raises(ValueError, match="report did not participate"):
        validate_promotion_campaign(
            campaign_path,
            comparison_path,
            foreign_report,
            review,
        )
    with pytest.raises(ValueError, match="review validation failed"):
        validate_promotion_campaign(
            campaign_path,
            comparison_path,
            stored.report,
            replace(review, reviewer=""),
        )


def test_promotion_campaign_rejects_tampered_or_stale_comparison_evidence(
    tmp_path: Path,
) -> None:
    """Digest rewriting and durable-run removal fail closed at promotion admission."""
    campaign_path, comparison_path, stored, review = _promotion_bundle(tmp_path)
    document = json.loads(comparison_path.read_text(encoding="utf-8"))
    document["promotion_eligible"] = False
    comparison_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match=r"eligibility|digest"):
        validate_promotion_campaign(
            campaign_path,
            comparison_path,
            stored.report,
            review,
        )

    fresh = _promotion_bundle(tmp_path / "removed")
    run_directory = fresh[0].parent / "runs" / "run-2"
    for path in run_directory.iterdir():
        path.unlink()
    run_directory.rmdir()
    with pytest.raises(ValueError, match="no longer matches"):
        validate_promotion_campaign(
            fresh[0],
            fresh[1],
            fresh[2].report,
            fresh[3],
        )
