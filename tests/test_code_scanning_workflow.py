# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — hosted code-scanning upload workflow tests
"""Verify the code-scanning upload's trigger, privileges, order, pins and category."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tools.ci_workflows import read_workflow

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/code-scanning.yml"
REPORT = '"$RUNNER_TEMP/rigor-report.json"'
PROFILE = '"$RUNNER_TEMP/rigor-foundry.sarif"'


def _upload_job() -> dict[str, Any]:
    """Return the only job of the code-scanning workflow after checking the workflow frame."""
    document = read_workflow(WORKFLOW)
    assert document["on"] == {"push": {"branches": ["main"]}}
    assert document["permissions"] == {"contents": "read"}
    (job,) = document["jobs"].values()
    assert list(document["jobs"]) == ["upload"]
    result: dict[str, Any] = job
    return result


def _upload_sarif_pin(path: Path) -> str:
    """Return the one pinned ``upload-sarif`` reference that a workflow uses."""
    document = read_workflow(path)
    (reference,) = {
        step["uses"]
        for job in document["jobs"].values()
        for step in job["steps"]
        if step.get("uses", "").startswith("github/codeql-action/upload-sarif@")
    }
    return str(reference)


def test_the_upload_runs_only_on_main_with_only_its_own_privileges() -> None:
    """A push to main, never a pull request, with contents read and security-events write."""
    job = _upload_job()
    assert job["permissions"] == {"contents": "read", "security-events": "write"}
    assert "needs" not in job and "if" not in job
    assert all("if" not in step and "continue-on-error" not in step for step in job["steps"])
    assert "continue-on-error" not in job
    assert "pull_request" not in WORKFLOW.read_text(encoding="utf-8")


def test_the_upload_checks_the_checkout_before_it_writes_and_uploads_the_profile() -> None:
    """The scan, the checkout guard, the GitHub profile and the upload run in that order."""
    steps = _upload_job()["steps"]
    runs = [step.get("run", "") for step in steps]
    order = [
        next(index for index, run in enumerate(runs) if needle in run)
        for needle in (
            f"python -m rigor_foundry scan --root . --policy rigor-foundry-policy.json --json-out {REPORT}",
            f"python -m tools.check_sarif_upload_checkout {REPORT} --root .",
            f"python -m rigor_foundry sarif --report {REPORT} --profile github-code-scanning "
            f"--output {PROFILE}",
        )
    ]
    upload = next(
        index
        for index, step in enumerate(steps)
        if step.get("uses", "").startswith("github/codeql-action/upload-sarif@")
    )
    assert order == sorted(order) and order[-1] < upload == len(steps) - 1
    assert steps[upload]["with"] == {
        "sarif_file": "${{ runner.temp }}/rigor-foundry.sarif",
        "category": "rigor-foundry",
    }
    assert steps[0]["uses"].startswith("actions/checkout@")
    assert steps[0]["with"] == {"persist-credentials": False}
    install = runs[2]
    assert "--require-hashes -r requirements/bootstrap.txt" in install
    assert "--require-hashes --no-build-isolation -r requirements/runtime.txt" in install
    assert "pip install --no-build-isolation --no-deps ." not in install


def test_the_upload_uses_the_scorecard_upload_pin_and_is_inventoried() -> None:
    """One pinned upload action for both SARIF producers, and one inventory record."""
    pin = _upload_sarif_pin(WORKFLOW)
    assert pin == _upload_sarif_pin(ROOT / ".github/workflows/scorecard.yml")
    assert len(pin.partition("@")[2]) == 40
    inventory = json.loads((ROOT / ".github/ci-workflows.json").read_text(encoding="utf-8"))
    assert inventory["workflows"][".github/workflows/code-scanning.yml"] == {
        "owner": "@anulum",
        "category": "security",
        "jobs": ["upload"],
    }
