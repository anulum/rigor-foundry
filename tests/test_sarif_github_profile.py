# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — GitHub code-scanning SARIF profile tests
"""Verify the GitHub profile through real scans, real reviews, the CLI and its limit boundaries."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from repository_audit_git_repository import GitRepository

import rigor_foundry
from rigor_foundry.models import AuditReport, ReviewRecord, reviews_to_json
from rigor_foundry.rules import RULES
from rigor_foundry.sarif_github_profile import (
    GITHUB_CODE_SCANNING_PROFILE,
    GITHUB_GZIP_LIMIT_BYTES,
    GITHUB_RESULT_LIMIT,
    require_github_limits,
)


def _reviewed_report(tmp_path: Path) -> tuple[AuditReport, tuple[ReviewRecord, ...]]:
    """Scan a real repository and review its candidates into every non-valid state and one valid."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "src/pkg/optional.py",
        "try:\n    import pkg.extension\nexcept Exception:\n    extension = None\n",
    )
    repository.write_text("src/pkg/wild.py", "from pkg.optional import *\n")
    repository.write_text(
        "src/pkg/runner.py", "def run(command):\n    eval(command)\n    print(command)\n"
    )
    repository.write_text(
        "tests/test_core.py",
        "import pytest\n\n@pytest.mark.skip(reason='contract')\ndef test_value() -> None:\n"
        "    assert True\n",
    )
    repository.write_policy()
    repository.commit()
    report = rigor_foundry.scan_repository(repository.root, Path("rigor-foundry-policy.json"))
    assert len(report.candidates) >= 5
    first, second, third, fourth = (candidate.candidate_id for candidate in report.candidates[:4])
    reviews = (
        _decided(report, first, "valid", severity="P2"),
        _decided(report, second, "invalid"),
        _decided(report, third, "accepted-boundary"),
        ReviewRecord.template(report.report_digest, fourth),
    )
    return report, reviews


def _decided(
    report: AuditReport, candidate_id: str, decision: str, *, severity: str | None = None
) -> ReviewRecord:
    """Return one model-parsed completed review for a real candidate."""
    value = ReviewRecord.template(report.report_digest, candidate_id).to_dict()
    value.update(
        {
            "decision": decision,
            "reviewer": "RIGOR-FOUNDRY/reviewer",
            "reviewed_at": "2026-11-24T00:00:00Z",
            "rationale": "Reproduced against the exact anchored object.",
            "evidence": ["python -m rigor_foundry scan"],
            "severity": severity,
            "owner": "team/platform" if decision == "valid" else "",
            "acceptance_gates": ["focused regression passes"] if decision == "valid" else [],
            "title": "Remove the verified broad import boundary" if decision == "valid" else "",
            "boundary_justification": (
                "Required compatibility boundary." if decision == "accepted-boundary" else ""
            ),
            "reopen_triggers": ["anchored bytes change"],
        }
    )
    return ReviewRecord.from_dict(value)


def test_profile_keeps_only_reviewed_valid_results_and_declares_every_omission(
    tmp_path: Path,
) -> None:
    """The profile drops every non-valid result, counts each state, and binds the canonical text.

    Parameters
    ----------
    tmp_path : Path
        Owned real Git repository allocation.
    """
    report, reviews = _reviewed_report(tmp_path)
    canonical = rigor_foundry.report_sarif(report, reviews)
    profiled = rigor_foundry.report_sarif(report, reviews, profile=GITHUB_CODE_SCANNING_PROFILE)
    assert profiled == rigor_foundry.report_sarif(
        report, tuple(reversed(reviews)), profile=GITHUB_CODE_SCANNING_PROFILE
    )
    (run,) = json.loads(profiled)["runs"]
    (canonical_run,) = json.loads(canonical)["runs"]
    assert [result["properties"]["rigorFoundry/verdictState"] for result in run["results"]] == [
        "valid"
    ]
    assert run["results"][0] == next(
        result
        for result in canonical_run["results"]
        if result["properties"]["rigorFoundry/candidateId"] == reviews[0].candidate_id
    )
    unreviewed = len(report.candidates) - len(reviews)
    assert run["properties"]["rigorFoundry/omittedResults"] == {
        "unreviewed": unreviewed,
        "needs-evidence": 1,
        "invalid": 1,
        "accepted-boundary": 1,
    }
    assert run["properties"]["rigorFoundry/consumerProfile"] == "github-code-scanning"
    assert (
        run["properties"]["rigorFoundry/canonicalDocumentDigest"]
        == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    )
    assert run["tool"] == canonical_run["tool"]
    assert len(run["tool"]["driver"]["rules"]) == len(RULES)
    assert canonical_run["results"] and len(canonical_run["results"]) == len(report.candidates)


def test_an_unknown_profile_is_refused_by_the_api_and_the_command(tmp_path: Path) -> None:
    """Neither the library nor the CLI accepts a profile it does not define.

    Parameters
    ----------
    tmp_path : Path
        Owned real Git repository and report allocation.
    """
    report, reviews = _reviewed_report(tmp_path)
    with pytest.raises(ValueError, match="unknown SARIF profile: github"):
        rigor_foundry.report_sarif(report, reviews, profile="github")
    report_path = tmp_path / "report.json"
    report_path.write_text(report.to_json(), encoding="utf-8")
    refused = _command("sarif", "--report", str(report_path), "--profile", "github")
    assert refused.returncode == 2
    assert "invalid choice: 'github'" in refused.stderr


def test_the_command_writes_exactly_the_library_profile(tmp_path: Path) -> None:
    """The real CLI writes the same profile bytes as the library for the same inputs.

    Parameters
    ----------
    tmp_path : Path
        Owned real Git repository, report, review and output allocation.
    """
    report, reviews = _reviewed_report(tmp_path)
    report_path = tmp_path / "report.json"
    review_path = tmp_path / "reviews.json"
    output = tmp_path / "github.sarif"
    report_path.write_text(report.to_json(), encoding="utf-8")
    review_path.write_text(reviews_to_json(reviews), encoding="utf-8")
    completed = _command(
        "sarif",
        "--report",
        str(report_path),
        "--review",
        str(review_path),
        "--profile",
        GITHUB_CODE_SCANNING_PROFILE,
        "--output",
        str(output),
    )
    assert completed.returncode == 0, completed.stderr
    assert output.read_text(encoding="utf-8") == rigor_foundry.report_sarif(
        report, reviews, profile=GITHUB_CODE_SCANNING_PROFILE
    )


def _command(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Run the real package command line."""
    return subprocess.run(
        [sys.executable, "-m", "rigor_foundry", *arguments],
        env=dict(os.environ),
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


@pytest.fixture(scope="module")
def profiled_document(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Return one real GitHub profile document with a valid result to replicate.

    Parameters
    ----------
    tmp_path_factory : pytest.TempPathFactory
        Owned real Git repository allocation for the module.

    Returns
    -------
    dict[str, Any]
        The parsed profile document of a real scan and review.
    """
    report, reviews = _reviewed_report(tmp_path_factory.mktemp("profile"))
    document: dict[str, Any] = json.loads(
        rigor_foundry.report_sarif(report, reviews, profile=GITHUB_CODE_SCANNING_PROFILE)
    )
    return document


@pytest.mark.parametrize(
    ("label", "limit"),
    [
        ("runs per file", 20),
        ("rules per run", 25_000),
        ("results per run", GITHUB_RESULT_LIMIT),
        ("tags per rule", 20),
        ("locations per result", 1_000),
    ],
)
def test_each_counted_limit_admits_its_boundary_and_refuses_one_more(
    profiled_document: dict[str, Any], label: str, limit: int
) -> None:
    """A real profile scaled to a documented limit passes, and one more item is refused.

    Parameters
    ----------
    profiled_document : dict[str, Any]
        A real GitHub profile document.
    label : str
        The limit's error label.
    limit : int
        GitHub's documented maximum, or the 5,000-result refusal.
    """
    for count, refused in ((limit, False), (limit + 1, True)):
        document = _scaled(profiled_document, label, count)
        if refused:
            with pytest.raises(ValueError) as failure:
                require_github_limits(document, "{}")
            assert str(failure.value) == (
                f"GitHub code-scanning profile refuses {count} {label}; the limit is {limit}"
            )
        else:
            require_github_limits(document, "{}")


def _scaled(document: dict[str, Any], label: str, count: int) -> dict[str, Any]:
    """Return a copy of a real profile document whose counted item appears ``count`` times."""
    scaled = copy.deepcopy(document)
    run = scaled["runs"][0]
    rule = run["tool"]["driver"]["rules"][0]
    result = run["results"][0]
    if label == "runs per file":
        scaled["runs"] = [run] * count
    elif label == "rules per run":
        run["tool"]["driver"]["rules"] = [rule] * count
    elif label == "results per run":
        run["results"] = [result] * count
    elif label == "tags per rule":
        rule["properties"]["tags"] = [f"tag-{index}" for index in range(count)]
    else:
        result["locations"] = [result["locations"][0]] * count
    return scaled


def test_a_profile_above_ten_megabytes_of_gzip_is_refused(
    profiled_document: dict[str, Any],
) -> None:
    """A rendered profile whose gzip exceeds 10 MB is refused, and a small one is not.

    Parameters
    ----------
    profiled_document : dict[str, Any]
        A real GitHub profile document.
    """
    require_github_limits(profiled_document, json.dumps(profiled_document))
    incompressible = base64.b64encode(os.urandom(GITHUB_GZIP_LIMIT_BYTES)).decode("ascii")
    with pytest.raises(
        ValueError, match=r"refuses \d+ gzip bytes per file; the limit is 10485760"
    ):
        require_github_limits(profiled_document, incompressible)


def test_the_command_refuses_more_than_five_thousand_valid_results_before_writing(
    tmp_path: Path,
) -> None:
    """A real report with 5,001 reviewed valid results is refused and no output file appears.

    Parameters
    ----------
    tmp_path : Path
        Owned real Git repository, report, review and output allocation.
    """
    repository = GitRepository.create(tmp_path / "repository")
    for index in range(GITHUB_RESULT_LIMIT + 1):
        repository.write_text(
            f"src/pkg/module_{index:04d}.py",
            "# SPDX-License-" + "Identifier: Apache-2.0\ndef run(command):\n    eval(command)\n",
        )
    repository.write_policy()
    repository.commit()
    report = rigor_foundry.scan_repository(repository.root, Path("rigor-foundry-policy.json"))
    dynamic = [
        candidate.candidate_id
        for candidate in report.candidates
        if candidate.rule_id == "AS001-dynamic-code-execution"
    ]
    assert len(dynamic) == GITHUB_RESULT_LIMIT + 1
    reviews = tuple(
        _decided(report, candidate_id, "valid", severity="P3") for candidate_id in dynamic
    )
    report_path = tmp_path / "report.json"
    review_path = tmp_path / "reviews.json"
    output = tmp_path / "github.sarif"
    report_path.write_text(report.to_json(), encoding="utf-8")
    review_path.write_text(reviews_to_json(reviews), encoding="utf-8")
    refused = _command(
        "sarif",
        "--report",
        str(report_path),
        "--review",
        str(review_path),
        "--profile",
        GITHUB_CODE_SCANNING_PROFILE,
        "--output",
        str(output),
    )
    assert refused.returncode == 2
    assert refused.stderr == (
        "repository audit error: GitHub code-scanning profile refuses 5001 results per run; "
        "the limit is 5000\n"
    )
    assert not output.exists()
    canonical = _command("sarif", "--report", str(report_path), "--review", str(review_path))
    assert canonical.returncode == 0, canonical.stderr
    assert len(json.loads(canonical.stdout)["runs"][0]["results"]) == len(report.candidates)
