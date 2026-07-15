# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — independent campaign comparison tests
"""Verify comparison records expose missing independent evidence as unresolved."""

from __future__ import annotations

from pathlib import Path

from repository_audit_git_repository import GitRepository

from rigor_foundry.campaign_compare import compare_campaign
from rigor_foundry.campaign_workflow import create_campaign


def test_comparison_never_turns_absent_independent_runs_into_consensus(tmp_path: Path) -> None:
    """A zero-run comparison is deterministic evidence of a diligence gap."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    repository.write_text(
        "tests/test_core.py",
        "from pkg.core import VALUE\n\ndef test_value() -> None:\n    assert VALUE == 1\n",
    )
    repository.write_policy()
    repository.commit()
    _path, campaign = create_campaign(
        repository.root,
        Path("rigor-foundry-policy.json"),
        audit_root=Path(".rigor/audits"),
        project="SAMPLE-PROJECT",
        campaign_id="campaign-one",
        actor="coordinator/one",
        expected_independent_runs=2,
    )

    comparison = compare_campaign(
        campaign,
        (),
        (),
        comparison_id="comparison-one",
        created_by="coordinator/one",
        created_at="2026-07-15T12:00:00Z",
    )

    assert comparison.actual_run_count == 0
    assert comparison.unresolved
    assert comparison.diligence_gaps == (
        "expected 2 independent runs, found 0",
        "no independent review records were supplied",
    )
    assert len(comparison.comparison_digest) == 64
