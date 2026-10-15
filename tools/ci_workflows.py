# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Distributed CI source reader
"""Read the actual same-revision CI categories for repository contract checks."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import yaml

from rigor_foundry.workflow_yaml import parse_workflow_yaml
from tools._repository import ROOT

CI_WORKFLOWS = {
    "quality": ".github/workflows/ci-quality.yml",
    "test": ".github/workflows/ci-tests.yml",
    "coverage": ".github/workflows/ci-coverage.yml",
    "distribution": ".github/workflows/ci-distribution.yml",
    "vscode": ".github/workflows/ci-vscode.yml",
}


def read_workflow(path: Path) -> dict[str, Any]:
    """Read one real YAML mapping with bounded, duplicate-aware validation.

    Parameters
    ----------
    path : Path
        Actual workflow source file.

    Returns
    -------
    dict[str, Any]
        Parsed workflow with literal event names retained.

    Raises
    ------
    OSError
        The source file cannot be read.
    ValueError
        YAML is ambiguous, unsupported, malformed, or not a mapping.
    """
    if path.is_symlink():
        raise ValueError("linked workflow")
    text = path.read_text(encoding="utf-8")
    literal = parse_workflow_yaml(text).mapping()
    document = cast(dict[object, Any], yaml.safe_load(text))
    # PyYAML's YAML 1.1 resolver treats the literal GitHub event key as True.
    if True in document:
        document["on"] = document.pop(True)
    if set(document) != set(literal):
        raise ValueError("ambiguous workflow keys")
    return cast(dict[str, Any], document)


def ci_jobs(root: Path = ROOT) -> dict[str, Any]:
    """Resolve all five actual CI jobs and their caller-level dependencies.

    Parameters
    ----------
    root : Path
        Repository containing the coordinator and current reusable workflows.

    Returns
    -------
    dict[str, Any]
        Effective category jobs, in coordinator order. This is a job projection,
        not a substitute for checking the coordinator's aggregate gate.

    Raises
    ------
    OSError
        A required workflow source cannot be read.
    ValueError
        A category is absent, conditional, redirected, or structurally invalid.
    """
    callers = read_workflow(root / ".github/workflows/ci.yml").get("jobs")
    if not isinstance(callers, dict):
        raise ValueError("missing CI callers")
    result: dict[str, Any] = {}
    for name, relative in CI_WORKFLOWS.items():
        expected: dict[str, Any] = {"uses": "./" + relative}
        if name == "coverage":
            expected.update(needs="test", permissions={"contents": "read", "id-token": "write"})
        if callers.get(name) != expected:
            raise ValueError("unexpected CI call surface")
        document = read_workflow(root / relative)
        jobs = document.get("jobs")
        if not isinstance(jobs, dict) or set(jobs) != {name}:
            raise ValueError("unexpected CI category jobs")
        job = jobs[name]
        if not isinstance(job, dict) or "uses" in job:
            raise ValueError("CI category must execute its own job")
        result[name] = dict(job)
        if "needs" in expected:
            result[name]["needs"] = expected["needs"]
    return result
