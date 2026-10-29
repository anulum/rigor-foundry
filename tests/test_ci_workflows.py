# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Distributed CI source reader tests
"""Exercise real workflow files and refuse ambiguous category projections."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from tools._repository import ROOT
from tools.ci_workflows import CI_CATEGORY_JOBS, CI_WORKFLOWS, ci_jobs, read_workflow


def copy_workflow_repository(destination: Path) -> Path:
    """Copy actual inventory, workflows, owners and guard sources.

    Parameters
    ----------
    destination : Path
        Empty independent repository directory.

    Returns
    -------
    Path
        Repository with byte-identical current workflow and guard inputs.
    """
    for relative in (
        ".github/ci-workflows.json",
        ".github/CODEOWNERS",
        "pyproject.toml",
        "tools/__init__.py",
        "tools/_repository.py",
        "tools/ci_workflows.py",
        "tools/check_ci_workflows.py",
        "tools/check_action_pins.py",
        *[str(path.relative_to(ROOT)) for path in (ROOT / ".github/workflows").glob("*.yml")],
    ):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    return destination


def test_category_projection_reads_all_actual_jobs_and_caller_needs(tmp_path: Path) -> None:
    """Resolve the whole actual graph from an independent unchanged source copy.

    Parameters
    ----------
    tmp_path : Path
        Independent copied repository.
    """
    root = copy_workflow_repository(tmp_path)
    jobs = ci_jobs(root)
    assert list(jobs) == [job for names in CI_CATEGORY_JOBS.values() for job in names]
    for name, relative in CI_WORKFLOWS.items():
        for identifier in CI_CATEGORY_JOBS[name]:
            actual = read_workflow(root / relative)["jobs"][identifier]
            if name == "coverage":
                assert jobs[identifier] == {**actual, "needs": ["test", "test-coverage"]}
            else:
                assert jobs[identifier] == actual
    assert jobs["test"]["strategy"]["matrix"]["python-version"] == [
        "3.11.15",
        "3.12.13",
        "3.13.14",
    ]
    assert jobs["test"]["strategy"]["matrix"]["shard"] == [0, 1, 2, 3]
    assert jobs["test-coverage"]["needs"] == "test"


@pytest.mark.parametrize(
    "text",
    ["[", "[]", "jobs: {}\njobs: {}", "on: !!python/object:a {}", "on: {}\ntrue: {}", "true: {}"],
)
def test_reader_refuses_ambiguous_or_nonmapping_yaml(tmp_path: Path, text: str) -> None:
    """Reject real invalid sources without silently projecting a partial mapping.

    Parameters
    ----------
    tmp_path : Path
        Actual file directory.
    text : str
        Invalid YAML input.
    """
    path = tmp_path / "workflow.yml"
    path.write_text(text)
    with pytest.raises(ValueError):
        read_workflow(path)


def test_reader_retains_literal_events_and_refuses_links(tmp_path: Path) -> None:
    """Interpret literal GitHub keys and keep source authority at the actual file.

    Parameters
    ----------
    tmp_path : Path
        Actual file directory.
    """
    path = tmp_path / "workflow.yml"
    path.write_text("on:\n  push:\njobs: {}\n")
    assert read_workflow(path) == {"on": {"push": None}, "jobs": {}}
    path.write_text("jobs: {}\n")
    assert read_workflow(path) == {"jobs": {}}
    link = tmp_path / "linked.yml"
    link.symlink_to(path)
    with pytest.raises(ValueError, match="linked"):
        read_workflow(link)
    with pytest.raises(OSError):
        read_workflow(tmp_path / "absent.yml")


@pytest.mark.parametrize(
    ("relative", "replacement"),
    [
        (".github/workflows/ci.yml", {}),
        (".github/workflows/ci.yml", {"jobs": []}),
        (".github/workflows/ci.yml", {"jobs": {}}),
        (CI_WORKFLOWS["quality"], {"jobs": []}),
        (CI_WORKFLOWS["quality"], {"jobs": {}}),
        (CI_WORKFLOWS["quality"], {"jobs": {"quality": {}, "other": {}}}),
        (CI_WORKFLOWS["quality"], {"jobs": {"quality": None}}),
        (CI_WORKFLOWS["quality"], {"jobs": {"quality": {"uses": "./another.yml"}}}),
    ],
)
def test_category_projection_refuses_incomplete_real_graph(
    tmp_path: Path,
    relative: str,
    replacement: dict[str, object],
) -> None:
    """The compatibility reader cannot erase or redirect actual execution.

    Parameters
    ----------
    tmp_path : Path
        Independent copied repository.
    relative : str
        Actual graph input to replace.
    replacement : dict[str, object]
        Structurally invalid graph document.
    """
    root = copy_workflow_repository(tmp_path)
    (root / relative).write_text(yaml.safe_dump(replacement))
    with pytest.raises(ValueError):
        ci_jobs(root)
