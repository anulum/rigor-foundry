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
CI_CATEGORY_JOBS: dict[str, tuple[str, ...]] = {name: (name,) for name in CI_WORKFLOWS}
CI_CATEGORY_JOBS["test"] = ("test", "test-coverage")
CI_CALL_NAMES = {
    "quality": "Repository quality",
    "test": "Interpreter tests",
    "coverage": "Coverage publication",
    "distribution": "Distribution integrations",
    "vscode": "Editor integration",
}
PYTHON_VERSIONS = ["3.11.15", "3.12.13", "3.13.14"]
SHARD_COUNT = 8
REQUIRED_CONTEXTS = [
    {"context": name, "category": name} for name in ("quality", "distribution", "coverage")
] + [{"context": f"test ({version})", "category": "test"} for version in PYTHON_VERSIONS]
REQUIRED_JOB = {
    "name": "${{ matrix.context }}",
    "if": "${{ always() }}",
    "needs": list(CI_WORKFLOWS),
    "runs-on": "ubuntu-24.04",
    "timeout-minutes": 5,
    "strategy": {"fail-fast": False, "matrix": {"include": REQUIRED_CONTEXTS}},
    "env": {"CATEGORY_RESULT": "${{ needs[matrix.category].result }}"},
    "steps": [
        {
            "name": "Require complete category",
            "shell": "bash",
            "run": 'set -euo pipefail\ntest "$CATEGORY_RESULT" = success\n',
        }
    ],
}
SHARD_STEP = {
    "name": "Run exhaustive CI-owned suite",
    "env": {"RIGOR_DOCUMENTATION_PYTHON": "${{ runner.temp }}/rigor-docs-venv/bin/python"},
    "run": "python -m tools.run_test_shard --index ${{ matrix.shard }} --count 8",
}
SHARD_UPLOAD = {
    "uses": "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
    "with": {
        "name": "test-shard-${{ matrix.python-version }}-${{ github.run_attempt }}-${{ matrix.shard }}",
        "path": ".rigor-test-shard/",
        "include-hidden-files": True,
        "if-no-files-found": "error",
        "retention-days": 14,
    },
}
UNION_DOWNLOAD = {
    "uses": "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333",
    "with": {
        "pattern": "test-shard-${{ matrix.python-version }}-${{ github.run_attempt }}-*",
        "path": "test-shards",
    },
}
UNION_STEP = {
    "name": "Combine complete interpreter coverage",
    "shell": "bash",
    "run": 'set -euo pipefail\nfor index in 0 1 2 3 4 5 6 7; do\n  mv "test-shards/test-shard-${{ matrix.python-version }}-${{ github.run_attempt }}-$index" "test-shards/shard-$index"\ndone\npython -m tools.combine_test_shards --directory test-shards --count 8\n',
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
    """Resolve every actual inner CI job and its effective dependencies.

    Parameters
    ----------
    root : Path
        Repository containing the coordinator and current reusable workflows.

    Returns
    -------
    dict[str, Any]
        Effective executable jobs, in category and actual job order. This is a job projection,
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
        expected: dict[str, Any] = {"name": CI_CALL_NAMES[name], "uses": "./" + relative}
        if name == "coverage":
            expected.update(needs="test", permissions={"contents": "read", "id-token": "write"})
        if callers.get(name) != expected:
            raise ValueError("unexpected CI call surface")
        document = read_workflow(root / relative)
        jobs = document.get("jobs")
        if not isinstance(jobs, dict) or list(jobs) != list(CI_CATEGORY_JOBS[name]):
            raise ValueError("unexpected CI category jobs")
        for identifier in CI_CATEGORY_JOBS[name]:
            job = jobs[identifier]
            if not isinstance(job, dict) or "uses" in job:
                raise ValueError("CI category must execute its own job")
            result[identifier] = dict(job)
            if name == "coverage":
                result[identifier]["needs"] = list(CI_CATEGORY_JOBS["test"])
    return result
