# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — public CLI rejection routing tests
"""Verify cross-command exit and diagnostic routing through real repository state."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cli_test_support import (
    POLICY,
    cli_repository,
    promotion_arguments,
)

from rigor_foundry.cli import main


def test_cli_rejects_invalid_outputs_reviews_selection_and_weaker_mode(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLI validation rejects unsafe output, review ambiguity, and policy weakening."""
    repository = cli_repository(tmp_path / "repository")
    policy_path = repository.root / POLICY
    missing_output = repository.root / "missing-parent/report.json"
    assert (
        main(
            [
                "scan",
                "--root",
                str(repository.root),
                "--policy",
                POLICY,
                "--json-out",
                str(missing_output),
            ]
        )
        == 2
    )
    assert "output parent does not exist" in capsys.readouterr().err

    report_path = repository.root / ".coordination/error-report.json"
    review_path = repository.root / ".coordination/error-reviews.json"
    assert (
        main(
            [
                "scan",
                "--root",
                str(repository.root),
                "--policy",
                POLICY,
                "--json-out",
                str(report_path),
            ]
        )
        == 0
    )
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
    contradictory_document = json.loads(review_path.read_text(encoding="utf-8"))
    contradictory_document["reviews"][0]["severity"] = "P0"
    contradictory_path = repository.root / ".coordination/contradictory-reviews.json"
    contradictory_path.write_text(json.dumps(contradictory_document), encoding="utf-8")
    assert (
        main(
            [
                "validate-review",
                "--report",
                str(report_path),
                "--review",
                str(contradictory_path),
            ]
        )
        == 1
    )
    assert "only a valid finding may carry severity" in capsys.readouterr().out
    assert (
        main(
            [
                "sarif",
                "--report",
                str(report_path),
                "--review",
                str(contradictory_path),
            ]
        )
        == 2
    )
    assert "only a valid finding may carry severity" in capsys.readouterr().err
    assert (
        main(
            [
                "scan",
                "--root",
                str(repository.root),
                "--policy",
                POLICY,
                "--fail-on-candidates",
            ]
        )
        == 1
    )
    capsys.readouterr()

    document = json.loads(review_path.read_text(encoding="utf-8"))
    selected = document["reviews"][0]
    selected["decision"] = "valid"
    invalid_path = repository.root / ".coordination/invalid-review.json"
    invalid_path.write_text(json.dumps(document), encoding="utf-8")
    assert (
        main(
            [
                "validate-review",
                "--report",
                str(report_path),
                "--review",
                str(invalid_path),
            ]
        )
        == 1
    )
    assert "repository audit review: FAIL" in capsys.readouterr().out

    invalid_promote = promotion_arguments(
        repository,
        report_path,
        invalid_path,
        str(selected["candidate_id"]),
    )
    assert main(invalid_promote) == 2
    assert "review validation failed" in capsys.readouterr().err

    assert (
        main(promotion_arguments(repository, report_path, review_path, "missing-candidate")) == 2
    )
    assert "select exactly one review" in capsys.readouterr().err

    duplicate_document = json.loads(review_path.read_text(encoding="utf-8"))
    duplicate_document["reviews"].append(dict(duplicate_document["reviews"][0]))
    duplicate_path = repository.root / ".coordination/duplicate-reviews.json"
    duplicate_path.write_text(json.dumps(duplicate_document), encoding="utf-8")
    duplicate_id = str(duplicate_document["reviews"][0]["candidate_id"])
    assert main(promotion_arguments(repository, report_path, duplicate_path, duplicate_id)) == 2
    assert "select exactly one review" in capsys.readouterr().err

    repository.write_text(
        "docs/internal/audit/reviews.json",
        review_path.read_text(encoding="utf-8"),
    )
    assert (
        main(
            [
                "gate",
                "--root",
                str(repository.root),
                "--policy",
                POLICY,
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["passed"] is True

    policy_document = json.loads(policy_path.read_text(encoding="utf-8"))
    policy_document["enforcement_mode"] = "zero"
    policy_document["maturity_policy_digest"] = "a" * 64
    policy_path.write_text(json.dumps(policy_document), encoding="utf-8")
    assert (
        main(
            [
                "gate",
                "--root",
                str(repository.root),
                "--policy",
                POLICY,
                "--mode",
                "observe",
            ]
        )
        == 2
    )
    assert "cannot weaken repository enforcement" in capsys.readouterr().err
