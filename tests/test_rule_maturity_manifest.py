# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — rule-maturity manifest tests
"""Verify explicit case-manifest loading as its own production boundary."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from rigor_foundry.rule_maturity import RuleMaturityPolicy
from rigor_foundry.rule_maturity_manifest import (
    MATURITY_CASE_MANIFEST_SCHEMA_VERSION,
    evaluate_rule_maturity_manifest,
)
from rigor_foundry.rules import RULES


def test_empty_case_manifest_keeps_the_complete_rule_pack_in_probation(
    tmp_path: Path,
) -> None:
    """An explicit zero-evidence baseline is valid but activates no rule."""
    policy = RuleMaturityPolicy.build(
        minimum_adjudicated_reviews=1,
        minimum_distinct_repositories=1,
        minimum_distinct_reviewers=1,
        minimum_positive_reviews=1,
        maximum_false_positive_basis_points=0,
        maximum_median_effort_seconds=60,
        maximum_p90_effort_seconds=60,
    )
    manifest = tmp_path / "cases.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": MATURITY_CASE_MANIFEST_SCHEMA_VERSION,
                "policy": policy.to_dict(),
                "cases": [],
            }
        ),
        encoding="utf-8",
    )

    report = evaluate_rule_maturity_manifest(manifest)

    assert report.active_rule_ids == ()
    assert len(report.assessments) == len(RULES)
    assert {item.status for item in report.assessments} == {"probation"}


def test_manifest_rejects_unknown_fields_before_reading_case_references(
    tmp_path: Path,
) -> None:
    """An unversioned extension cannot redirect report or review input."""
    manifest = tmp_path / "cases.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": MATURITY_CASE_MANIFEST_SCHEMA_VERSION,
                "policy": {},
                "cases": [],
                "report_root": "/untrusted",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="fields do not match"):
        evaluate_rule_maturity_manifest(manifest)
