# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Complete CI workflow inventory and graph guard
"""Enforce cohesive workflow ownership, bounded sources and the required CI gate."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast

from tools._repository import ROOT, redacted_guard_exit_code
from tools.ci_workflows import CI_WORKFLOWS, ci_jobs, read_workflow

WORKFLOW_VALIDATION_STEP = {
    "name": "Validate distributed CI workflows",
    "shell": "bash",
    "run": r"""set -euo pipefail
curl --proto '=https' --tlsv1.2 --fail --location --connect-timeout 10 --max-time 60 \
  --output "$RUNNER_TEMP/actionlint.tar.gz" \
https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz
printf '%s  %s\n' \
  8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8 \
  "$RUNNER_TEMP/actionlint.tar.gz" | sha256sum --check --strict
mkdir "$RUNNER_TEMP/rigor-actionlint"
tar -xzf "$RUNNER_TEMP/actionlint.tar.gz" -C "$RUNNER_TEMP/rigor-actionlint" actionlint
"$RUNNER_TEMP/rigor-actionlint/actionlint" -version
"$RUNNER_TEMP/rigor-actionlint/actionlint"
python -m tools.check_ci_workflows
python -m pytest tests/test_ci_workflows.py tests/test_check_ci_workflows.py --cov=tools.ci_workflows --cov=tools.check_ci_workflows --cov-branch --cov-report=term-missing --cov-fail-under=100
""",
}

MAX_WORKFLOW_LINES = 1_000
MAX_WORKFLOW_BYTES = 100 * 1_024
MAX_COORDINATOR_LINES = 200
MAX_COORDINATOR_BYTES = 32 * 1_024
MAX_REUSABLE_WORKFLOWS = 16
GATE_COMMAND = "set -euo pipefail\n" + "".join(
    'test "$' + name.upper() + '_RESULT" = success\n' for name in CI_WORKFLOWS
)
GATE_JOB = {
    "name": "CI gate",
    "if": "${{ always() }}",
    "needs": list(CI_WORKFLOWS),
    "runs-on": "ubuntu-24.04",
    "timeout-minutes": 5,
    "env": {name.upper() + "_RESULT": "${{ needs." + name + ".result }}" for name in CI_WORKFLOWS},
    "steps": [{"name": "Require every CI category", "shell": "bash", "run": GATE_COMMAND}],
}
CATEGORIES = {
    "coordination",
    *CI_WORKFLOWS,
    "security",
    "container",
    "documentation",
    "fuzz",
    "hooks",
    "publication",
    "metrics",
    "release",
    "maintenance",
}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse duplicate JSON fields rather than silently replacing ownership."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate inventory field")
        result[key] = value
    return result


def _require(condition: bool) -> None:
    """Stop qualification on the first incomplete contract."""
    if not condition:
        raise ValueError("invalid CI workflow contract")


def _inventory(root: Path) -> dict[str, Any]:
    """Read the versioned inventory and validate its closed schema."""
    path = root / ".github/ci-workflows.json"
    _require(not path.is_symlink())
    document: Any = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    _require(isinstance(document, dict))
    _require(set(document) == {"schema_version", "coordinator", "aggregate", "workflows"})
    _require(type(document["schema_version"]) is int and document["schema_version"] == 1)
    _require(document["coordinator"] == ".github/workflows/ci.yml")
    _require(document["aggregate"] == "ci-gate")
    records = document["workflows"]
    _require(isinstance(records, dict) and bool(records))
    for relative, record in records.items():
        _require(re.fullmatch(r"\.github/workflows/[\w-]+\.ya?ml", relative) is not None)
        _require(isinstance(record, dict))
        _require(set(record) == {"owner", "category", "jobs"})
        _require(record["owner"] == "@anulum")
        _require(isinstance(record["category"], str))
        _require(record["category"] in CATEGORIES)
        jobs = record["jobs"]
        _require(isinstance(jobs, list) and bool(jobs))
        _require(all(isinstance(job, str) for job in jobs))
        _require(all(re.fullmatch(r"[A-Za-z_][\w-]*", job) for job in jobs))
        _require(len(jobs) == len(set(jobs)))
    return dict(records)


def _check_graph(root: Path, documents: dict[str, Any], records: dict[str, Any]) -> None:
    """Require the complete original category graph and one strict aggregate."""
    coordinator = documents[".github/workflows/ci.yml"]
    _require(set(coordinator) == {"name", "on", "permissions", "concurrency", "jobs"})
    _require(coordinator["name"] == "CI")
    _require(
        coordinator["on"]
        == {
            "push": {"branches": ["main"]},
            "pull_request": {"branches": ["main"]},
            "workflow_dispatch": None,
        }
    )
    _require(coordinator["permissions"] == {"contents": "read"})
    _require(
        coordinator["concurrency"]
        == {
            "group": "ci-${{ github.workflow }}-${{ github.ref }}",
            "cancel-in-progress": True,
        }
    )
    callers = coordinator["jobs"]
    _require(set(callers) == {*CI_WORKFLOWS, "ci-gate"})
    _require(callers["ci-gate"] == GATE_JOB)
    _require(records[".github/workflows/ci.yml"]["category"] == "coordination")
    ci_jobs(root)
    reusables = {
        relative
        for relative, document in documents.items()
        if "workflow_call" in document.get("on", {})
    }
    _require(len(reusables) <= MAX_REUSABLE_WORKFLOWS)
    _require(reusables == set(CI_WORKFLOWS.values()))
    for name, relative in CI_WORKFLOWS.items():
        document = documents[relative]
        _require(set(document) == {"name", "on", "permissions", "concurrency", "jobs"})
        _require(document["on"] == {"workflow_call": None})
        _require(document["permissions"] == {"contents": "read"})
        _require(
            document["concurrency"]
            == {
                "group": "ci-" + name + "-${{ github.workflow }}-${{ github.ref }}",
                "cancel-in-progress": True,
            }
        )
        _require(records[relative]["category"] == name)
        job = document["jobs"][name]
        _require(not set(job).intersection({"needs", "if", "continue-on-error", "defaults"}))
        expected = {"contents": "read", "id-token": "write"} if name == "coverage" else None
        _require(job.get("permissions") == expected)
    quality_steps = documents[CI_WORKFLOWS["quality"]]["jobs"]["quality"]["steps"]
    _require(quality_steps.count(WORKFLOW_VALIDATION_STEP) == 1)
    # Only the coordinator may introduce reusable or cross-category calls.
    for relative, document in documents.items():
        if relative == ".github/workflows/ci.yml":
            continue
        for job in document["jobs"].values():
            _require("uses" not in job)


def ci_workflow_errors(root: Path = ROOT) -> list[str]:
    """Audit every real workflow job and the complete distributed CI graph.

    Parameters
    ----------
    root : Path
        Repository containing the versioned inventory and actual workflow files.

    Returns
    -------
    list[str]
        Fixed, source-free findings. No workflow command or provider is executed.
    """
    try:
        records = _inventory(root)
        _require("* @anulum" in (root / ".github/CODEOWNERS").read_text().splitlines())
        paths = sorted((root / ".github/workflows").glob("*.y*ml"))
        _require({str(path.relative_to(root)) for path in paths} == set(records))
        documents: dict[str, Any] = {}
        # Import locally because the normal action-pin guard also invokes us.
        from tools.check_action_pins import workflow_errors

        for path in paths:
            relative = path.relative_to(root).as_posix()
            raw = path.read_bytes()
            coordinator = relative == ".github/workflows/ci.yml"
            _require(len(raw) <= (MAX_COORDINATOR_BYTES if coordinator else MAX_WORKFLOW_BYTES))
            _require(
                len(raw.splitlines())
                <= (MAX_COORDINATOR_LINES if coordinator else MAX_WORKFLOW_LINES)
            )
            document = read_workflow(path)
            jobs = document.get("jobs")
            _require(isinstance(jobs, dict) and bool(jobs))
            actual_jobs = cast(dict[str, Any], jobs)
            _require(all(isinstance(job, dict) for job in actual_jobs.values()))
            _require(list(actual_jobs) == records[relative]["jobs"])
            _require(not workflow_errors(path))
            documents[relative] = document
        _check_graph(root, documents, records)
    except (OSError, UnicodeError, ValueError, TypeError, KeyError):
        return ["CI workflow inventory or graph is invalid"]
    return []


def main() -> int:
    """Run the ordinary repository guard with fixed redacted output."""
    return redacted_guard_exit_code("CI workflow guard", ci_workflow_errors)


if __name__ == "__main__":
    raise SystemExit(main())
