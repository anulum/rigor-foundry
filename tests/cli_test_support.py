# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — shared real CLI test construction
"""Build real repositories and promotion campaigns for CLI owner tests."""

from __future__ import annotations

from pathlib import Path

from repository_audit_git_repository import GitRepository

from rigor_foundry.campaign_identity import InferenceIdentity
from rigor_foundry.campaign_workflow import (
    compare_campaign_runs,
    create_campaign,
    execute_campaign,
)
from rigor_foundry.models import AuditReport

POLICY = "rigor-foundry-policy.json"


def cli_repository(path: Path) -> GitRepository:
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


def promotion_arguments(
    repository: GitRepository,
    report_path: Path,
    review_path: Path,
    candidate_id: str,
    *,
    policy: Path | None = None,
    campaign_paths: tuple[Path, Path] | None = None,
) -> list[str]:
    """Return the public promotion command for one prepared repository report."""
    campaign, comparison = campaign_paths or (
        repository.root / ".rigor/missing-campaign.json",
        repository.root / ".rigor/missing-comparison.json",
    )
    return [
        "promote",
        "--root",
        str(repository.root),
        "--policy",
        str(policy or Path(POLICY)),
        "--report",
        str(report_path),
        "--review",
        str(review_path),
        "--campaign",
        str(campaign),
        "--comparison",
        str(comparison),
        "--candidate-id",
        candidate_id,
        "--todo",
        "docs/internal/work/INDEX.md",
    ]


def promotion_campaign(
    report_path: Path,
    review_path: Path,
    *,
    campaign_id: str,
) -> tuple[Path, Path]:
    """Create real durable cross-model evidence for one prepared review."""
    report = AuditReport.from_path(report_path)
    repository = Path(report.repository_root)
    campaign_path, _campaign = create_campaign(
        repository,
        Path(POLICY),
        audit_root=Path(".rigor/audits"),
        project="SAMPLE-PROJECT",
        campaign_id=campaign_id,
        actor="coordinator/cli",
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
                model=f"model-family-{index}-v1",
                model_family=f"model-family-{index}",
                operator=f"operator-{index}",
            ),
        )
    reviews_directory = campaign_path.parent / "reviews"
    reviews_directory.mkdir()
    (reviews_directory / "selected.json").write_bytes(review_path.read_bytes())
    comparison_path, comparison = compare_campaign_runs(
        campaign_path,
        comparison_id="promotion-comparison",
        actor="coordinator/cli",
    )
    assert comparison.promotion_eligible
    return campaign_path, comparison_path
