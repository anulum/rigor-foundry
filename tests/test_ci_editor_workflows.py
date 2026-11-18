# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Editor native workflow boundary tests
"""Exercise actual workflow admission through the public API and repository guard CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from test_ci_workflows import copy_workflow_repository

from tools._repository import ROOT
from tools.check_ci_workflows import ci_workflow_errors
from tools.ci_editor_workflows import check_editor_jobs
from tools.ci_workflows import CI_WORKFLOWS, read_workflow


def test_actual_editor_native_workflow_is_required_before_tests(tmp_path: Path) -> None:
    """Admit the actual same-revision producer and its source-bound downstream consumer.

    Parameters
    ----------
    tmp_path : Path
        Independent real workflow copy.
    """
    root = copy_workflow_repository(tmp_path)
    jobs = read_workflow(root / CI_WORKFLOWS["vscode"])["jobs"]
    check_editor_jobs(jobs, root)
    assert ci_workflow_errors(root) == []


@pytest.mark.parametrize(
    "change",
    [
        "producer-missing",
        "producer-platform",
        "producer-optional",
        "execution-missing",
        "prerequisite-missing",
        "steps-missing",
        "step-invalid",
        "download-missing",
        "download-attempt",
        "admission-optional",
        "admission-repeated",
        "node-differs",
        "admission-late",
        "coverage-missing",
        "coverage-repeated",
        "host-definitions-list",
        "host-definitions-version",
        "host-definitions-bool",
        "host-profiles-empty",
        "host-profile-invalid",
        "host-profile-identity-invalid",
        "host-profile-id-duplicate",
        "host-platform-missing",
        "host-version-missing",
        "host-matrix-missing",
        "host-optional",
        "union-prerequisite-missing",
        "union-optional",
        "union-gate-reduced",
        "union-steps-invalid",
        "packaging-time-unbound",
    ],
)
def test_real_editor_workflow_changes_refuse_api_and_cli(tmp_path: Path, change: str) -> None:
    """Refuse altered actual sources at both the role API and complete command boundary.

    Parameters
    ----------
    tmp_path : Path
        Independent workflow and guard checkout.
    change : str
        Named change to the actual producer or consumer contract.
    """
    root = copy_workflow_repository(tmp_path)
    workflow = root / CI_WORKFLOWS["vscode"]
    for source in (root / "tools").glob("*.py"):
        assert source.read_bytes() == (ROOT / "tools" / source.name).read_bytes()
    document = read_workflow(workflow)
    jobs = document["jobs"]
    execution = jobs["vscode-host"]
    steps = execution["steps"]
    admission = next(
        step for step in steps if step.get("name") == "Admit exact source and run native artifact"
    )
    download = next(
        step for step in steps if step.get("uses", "").startswith("actions/download-artifact@")
    )
    coverage = next(
        step
        for step in steps
        if step.get("name") == "Execute complete real supported host profile"
    )
    if change == "producer-missing":
        del jobs["vscode-native"]
    elif change == "producer-platform":
        jobs["vscode-native"]["runs-on"] = "ubuntu-24.04"
    elif change == "producer-optional":
        jobs["vscode-native"]["continue-on-error"] = True
    elif change == "execution-missing":
        jobs["vscode-host"] = []
    elif change == "prerequisite-missing":
        del execution["needs"]
    elif change == "steps-missing":
        execution["steps"] = None
    elif change == "step-invalid":
        steps.append(None)
    elif change == "download-missing":
        steps.remove(download)
    elif change == "download-attempt":
        download["with"]["name"] = "native-previous-attempt"
    elif change == "admission-optional":
        admission["continue-on-error"] = True
    elif change == "admission-repeated":
        steps.append(dict(admission))
    elif change == "node-differs":
        setup = next(
            step for step in steps if step.get("uses", "").startswith("actions/setup-node@")
        )
        setup["with"]["node-version"] = "26.13.0"
    elif change == "admission-late":
        steps.remove(admission)
        steps.append(admission)
    elif change == "coverage-missing":
        steps.remove(coverage)
    elif change == "coverage-repeated":
        steps.append(dict(coverage))
    elif change.startswith(("host-definition", "host-profile")) or change in {
        "host-platform-missing",
        "host-version-missing",
    }:
        definition_path = root / "editors/vscode/native/editor-hosts.json"
        definitions = json.loads(definition_path.read_text())
        if change == "host-definitions-list":
            definitions = []
        elif change == "host-definitions-version":
            definitions["schema"] = 2
        elif change == "host-definitions-bool":
            definitions["schema"] = True
        elif change == "host-profiles-empty":
            definitions["profiles"] = []
        elif change == "host-profile-invalid":
            definitions["profiles"][0] = None
        elif change == "host-profile-identity-invalid":
            definitions["profiles"][0]["version"] = []
        elif change == "host-profile-id-duplicate":
            for profile in definitions["profiles"]:
                profile["id"] = "repeated-producer"
        elif change == "host-platform-missing":
            for profile in definitions["profiles"]:
                profile["platform"] = "linux"
        else:
            for profile in definitions["profiles"]:
                profile["version"] = "1.125.0"
        definition_path.write_text(json.dumps(definitions))
    elif change == "host-matrix-missing":
        execution["strategy"]["matrix"]["include"].pop()
    elif change == "host-optional":
        execution["continue-on-error"] = True
    elif change == "union-prerequisite-missing":
        jobs["vscode"]["needs"] = ["vscode-native"]
    elif change == "union-optional":
        jobs["vscode"]["if"] = "${{ always() }}"
    elif change == "union-gate-reduced":
        gate = next(
            step
            for step in jobs["vscode"]["steps"]
            if step.get("name") == "Require complete whole-owner editor coverage"
        )
        gate["run"] = gate["run"].replace("c8.config.json", "weaker-config.json")
    elif change == "packaging-time-unbound":
        package = next(
            step
            for step in jobs["vscode"]["steps"]
            if step.get("name") == "Package both qualified platform extensions"
        )
        package["run"] = package["run"].replace("git log -1 --format=%ct", "date +%s")
    else:
        jobs["vscode"]["steps"] = None
    with pytest.raises(ValueError):
        check_editor_jobs(jobs, root)
    workflow.write_text(yaml.safe_dump(document, sort_keys=False))
    assert ci_workflow_errors(root)
    child = subprocess.run(
        [sys.executable, "-m", "tools.check_ci_workflows"],
        cwd=root,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert child.returncode == 1
    assert (
        child.stdout
        == "CI workflow guard failed; finding details are redacted from process output.\n"
    )
    assert child.stderr == ""
