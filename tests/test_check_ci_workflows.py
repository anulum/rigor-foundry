# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Complete workflow inventory qualification
"""Exercise the real inventory, graph, aggregate shell and copied guard CLIs."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from test_ci_workflows import copy_workflow_repository

from tools._repository import ROOT
from tools.check_action_pins import action_pin_errors
from tools.check_ci_workflows import ci_workflow_errors
from tools.ci_workflows import CI_WORKFLOWS, read_workflow


def test_complete_actual_inventory_and_normal_action_guard() -> None:
    """Both public entrypoints enroll every actual job with unchanged sources."""
    assert ci_workflow_errors() == []
    assert action_pin_errors() == []
    inventory = json.loads((ROOT / ".github/ci-workflows.json").read_text())
    assert len(inventory["workflows"]) == 17
    for relative, record in inventory["workflows"].items():
        assert record["jobs"] == list(read_workflow(ROOT / relative)["jobs"])
        assert record["owner"] == "@anulum"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("coordinator", "../outside"),
        ("aggregate", "quality"),
        ("workflows", []),
        ("workflows", {}),
        ("extra", 1),
    ],
)
def test_inventory_refuses_unknown_version_fields_and_empty_ownership(
    tmp_path: Path,
    field: str,
    value: Any,
) -> None:
    """A real altered policy cannot silently change the coordinator contract.

    Parameters
    ----------
    tmp_path : Path
        Independent actual repository copy.
    field : str
        Policy field to alter.
    value : Any
        Unsupported field value.
    """
    root = copy_workflow_repository(tmp_path)
    path = root / ".github/ci-workflows.json"
    document = json.loads(path.read_text())
    document[field] = value
    path.write_text(json.dumps(document))
    assert ci_workflow_errors(root)


@pytest.mark.parametrize("text", ["[", "[]", '{"schema_version":1,"schema_version":1}'])
def test_inventory_refuses_invalid_or_duplicate_json(tmp_path: Path, text: str) -> None:
    """Malformed and duplicate fields refuse before any workflow is accepted.

    Parameters
    ----------
    tmp_path : Path
        Actual copied repository.
    text : str
        Invalid actual policy text.
    """
    root = copy_workflow_repository(tmp_path)
    (root / ".github/ci-workflows.json").write_text(text)
    assert ci_workflow_errors(root)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("owner", ""),
        ("owner", "@other"),
        ("category", []),
        ("category", "unowned"),
        ("jobs", []),
        ("jobs", None),
        ("jobs", [1]),
        ("jobs", ["bad/name"]),
        ("jobs", ["quality", "quality"]),
        ("jobs", ["absent"]),
        ("extra", True),
    ],
)
def test_inventory_refuses_unowned_duplicate_or_undeclared_jobs(
    tmp_path: Path,
    field: str,
    value: Any,
) -> None:
    """Every executable job must have one explicit eligible owner and category.

    Parameters
    ----------
    tmp_path : Path
        Actual copied repository.
    field : str
        Workflow ownership field to alter.
    value : Any
        Unsupported ownership value.
    """
    root = copy_workflow_repository(tmp_path)
    path = root / ".github/ci-workflows.json"
    document = json.loads(path.read_text())
    document["workflows"][CI_WORKFLOWS["quality"]][field] = value
    path.write_text(json.dumps(document))
    assert ci_workflow_errors(root)


@pytest.mark.parametrize(
    "case",
    [
        "missing-policy",
        "linked-policy",
        "missing-owner",
        "wrong-owner",
        "invalid-record",
        "escape-path",
        "missing-workflow",
        "extra-workflow",
        "linked-workflow",
        "invalid-utf8",
        "unknown-yaml-syntax",
        "empty-jobs",
        "list-jobs",
        "null-job",
        "coordinator-bytes",
        "coordinator-lines",
        "reusable-bytes",
        "reusable-lines",
        "mutable-action",
        "extra-reusable",
        "nested-call",
    ],
)
def test_actual_inventory_refuses_missing_sources_and_budget_or_graph_drift(
    tmp_path: Path,
    case: str,
) -> None:
    """Use actual filesystem, source and graph changes without producer mocks.

    Parameters
    ----------
    tmp_path : Path
        Actual copied repository.
    case : str
        Real source mutation that violates the declared inventory.
    """
    root = copy_workflow_repository(tmp_path)
    policy = root / ".github/ci-workflows.json"
    owner = root / ".github/CODEOWNERS"
    quality = root / CI_WORKFLOWS["quality"]
    coordinator = root / ".github/workflows/ci.yml"
    document = json.loads(policy.read_text())
    if case == "missing-policy":
        policy.unlink()
    elif case == "linked-policy":
        target = root / "retained-policy"
        policy.rename(target)
        policy.symlink_to(target)
    elif case == "missing-owner":
        owner.unlink()
    elif case == "wrong-owner":
        owner.write_text("* @other\n")
    elif case == "invalid-record":
        document["workflows"][CI_WORKFLOWS["quality"]] = []
        policy.write_text(json.dumps(document))
    elif case == "escape-path":
        document["workflows"]["../outside.yml"] = document["workflows"].pop(
            CI_WORKFLOWS["quality"]
        )
        policy.write_text(json.dumps(document))
    elif case == "missing-workflow":
        quality.unlink()
    elif case == "extra-workflow":
        (root / ".github/workflows/unknown.yml").write_text("jobs: {}")
    elif case == "linked-workflow":
        target = root / "retained-workflow"
        quality.rename(target)
        quality.symlink_to(target)
    elif case == "invalid-utf8":
        quality.write_bytes(b"\xff")
    elif case == "unknown-yaml-syntax":
        quality.write_text("jobs:\n  quality: &x {steps: *x}")
    elif case in {"empty-jobs", "list-jobs", "null-job"}:
        workflow = read_workflow(quality)
        workflow["jobs"] = {"empty-jobs": {}, "list-jobs": [], "null-job": {"quality": None}}[case]
        quality.write_text(yaml.safe_dump(workflow))
    elif case in {"coordinator-bytes", "coordinator-lines", "reusable-bytes", "reusable-lines"}:
        path = coordinator if case.startswith("coordinator") else quality
        suffix = "#" + "a" * 102_401 if case.endswith("bytes") else "\n#" * 1_001
        path.write_text(path.read_text() + suffix)
    elif case == "mutable-action":
        quality.write_text(
            quality.read_text().replace(
                "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0", "actions/checkout@v4"
            )
        )
    elif case == "extra-reusable":
        workflow = read_workflow(root / ".github/workflows/stale.yml")
        workflow["on"] = {"workflow_call": None}
        (root / ".github/workflows/stale.yml").write_text(yaml.safe_dump(workflow))
    else:
        workflow = read_workflow(root / ".github/workflows/stale.yml")
        job = next(iter(workflow["jobs"]))
        workflow["jobs"][job]["uses"] = "./.github/workflows/ci-quality.yml"
        (root / ".github/workflows/stale.yml").write_text(yaml.safe_dump(workflow))
    assert ci_workflow_errors(root)


@pytest.mark.parametrize(
    ("workflow", "field", "value"),
    [
        ("ci.yml", "env", {"X": "override"}),
        ("ci.yml", "name", "other"),
        ("ci.yml", "on", {"push": {"paths": ["src/**"]}}),
        ("ci.yml", "permissions", {"contents": "write"}),
        ("ci.yml", "concurrency", {"group": "shared", "cancel-in-progress": True}),
        ("ci-quality.yml", "env", {"X": "override"}),
        ("ci-quality.yml", "on", {"workflow_call": {"secrets": {"TOKEN": {"required": True}}}}),
        ("ci-quality.yml", "permissions", {"contents": "write"}),
        (
            "ci-quality.yml",
            "concurrency",
            {"group": "ci-${{ github.workflow }}-${{ github.ref }}", "cancel-in-progress": True},
        ),
    ],
)
def test_real_workflow_call_surfaces_and_event_policy_are_closed(
    tmp_path: Path,
    workflow: str,
    field: str,
    value: Any,
) -> None:
    """Refuse implicit inputs, inherited secrets, filters and widened authority.

    Parameters
    ----------
    tmp_path : Path
        Actual copied repository.
    workflow : str
        Workflow source filename.
    field : str
        Top-level policy field.
    value : Any
        Actual replacement policy.
    """
    root = copy_workflow_repository(tmp_path)
    path = root / ".github/workflows" / workflow
    document = read_workflow(path)
    document[field] = value
    path.write_text(yaml.safe_dump(document))
    assert ci_workflow_errors(root)


@pytest.mark.parametrize(
    ("job", "field", "value"),
    [
        ("quality", "if", "false"),
        ("quality", "uses", "owner/repo/.github/workflows/ci.yml@main"),
        ("quality", "secrets", "inherit"),
        ("quality", "needs", "test"),
        ("coverage", "needs", "quality"),
        ("quality", "permissions", {"contents": "write"}),
        ("ci-gate", "if", "success()"),
        ("ci-gate", "needs", ["quality"]),
        ("ci-gate", "continue-on-error", True),
        ("ci-gate", "env", {}),
        ("ci-gate", "steps", [{"run": "true"}]),
    ],
)
def test_actual_caller_graph_and_aggregate_cannot_omit_a_category(
    tmp_path: Path,
    job: str,
    field: str,
    value: Any,
) -> None:
    """Alter actual callers and gate structure; no decoy commands satisfy them.

    Parameters
    ----------
    tmp_path : Path
        Actual copied repository.
    job : str
        Coordinator job identifier.
    field : str
        Job setting.
    value : Any
        Actual weakening or undeclared dependency.
    """
    root = copy_workflow_repository(tmp_path)
    path = root / ".github/workflows/ci.yml"
    document = read_workflow(path)
    document["jobs"][job][field] = value
    path.write_text(yaml.safe_dump(document))
    assert ci_workflow_errors(root)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("needs", "test"),
        ("if", "false"),
        ("continue-on-error", True),
        ("defaults", {}),
        ("permissions", {"id-token": "write"}),
    ],
)
def test_reusable_job_cannot_introduce_cross_category_or_privilege_drift(
    tmp_path: Path,
    field: str,
    value: Any,
) -> None:
    """All cross-category dependencies belong to the reviewed coordinator.

    Parameters
    ----------
    tmp_path : Path
        Actual copied repository.
    field : str
        Job setting.
    value : Any
        Actual undeclared override.
    """
    root = copy_workflow_repository(tmp_path)
    path = root / CI_WORKFLOWS["quality"]
    document = read_workflow(path)
    document["jobs"]["quality"][field] = value
    path.write_text(yaml.safe_dump(document))
    assert ci_workflow_errors(root)


@pytest.mark.parametrize("category", list(CI_WORKFLOWS))
@pytest.mark.parametrize("state", ["failure", "cancelled", "skipped", "", "unknown"])
def test_actual_aggregate_shell_requires_every_category(
    category: str,
    state: str,
) -> None:
    """Execute the real aggregate command with success and each failing outcome.

    Parameters
    ----------
    category : str
        Actual upstream category.
    state : str
        Non-success upstream result.
    """
    gate = read_workflow(ROOT / ".github/workflows/ci.yml")["jobs"]["ci-gate"]
    command = gate["steps"][0]["run"]
    environment = {**os.environ, **{name.upper() + "_RESULT": "success" for name in CI_WORKFLOWS}}
    valid = subprocess.run(
        ["bash", "-c", command], env=environment, capture_output=True, timeout=10
    )
    assert valid.returncode == 0
    environment[category.upper() + "_RESULT"] = state
    invalid = subprocess.run(
        ["bash", "-c", command], env=environment, capture_output=True, timeout=10
    )
    assert invalid.returncode != 0
    assert not valid.stdout + valid.stderr + invalid.stdout + invalid.stderr


@pytest.mark.parametrize("module", ["tools.check_ci_workflows", "tools.check_action_pins"])
def test_actual_guard_cli_accepts_workflow_inventory(tmp_path: Path, module: str) -> None:
    """Execute actual copied guard modules, accept restoration, redact refusals.

    Parameters
    ----------
    tmp_path : Path
        Independent copied workflow and actual tool sources.
    module : str
        Actual normal guard entrypoint.
    """
    root = copy_workflow_repository(tmp_path)
    environment = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    path = root / CI_WORKFLOWS["quality"]
    original = path.read_bytes()
    for bad in (False, True, False):
        path.write_bytes(original + (b"\njobs: {}\n" if bad else b""))
        result = subprocess.run(
            [sys.executable, "-m", module],
            cwd=root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == int(bad)
        label = (
            "CI workflow guard" if module.endswith("check_ci_workflows") else "Action pin guard"
        )
        expected = label + (
            " failed; finding details are redacted from process output.\n" if bad else " passed\n"
        )
        assert result.stdout == expected
        assert result.stderr == ""
        assert str(root) not in result.stdout


@pytest.mark.parametrize(
    "case",
    [
        "missing",
        "duplicate",
        "conditional",
        "category",
        "coordinator-category",
        "extra-call",
        "extra-category-job",
    ],
)
def test_complete_workflow_contract_cannot_be_satisfied_by_partial_ownership(
    tmp_path: Path,
    case: str,
) -> None:
    """Reject realistic policy rewrites as well as simple undeclared-file drift.

    Parameters
    ----------
    tmp_path : Path
        Independent actual repository copy.
    case : str
        Real change to mandatory validation or category ownership.
    """
    root = copy_workflow_repository(tmp_path)
    path = root / CI_WORKFLOWS["quality"]
    document = read_workflow(path)
    steps = document["jobs"]["quality"]["steps"]
    index = next(
        i
        for i, step in enumerate(steps)
        if step.get("name") == "Validate distributed CI workflows"
    )
    if case == "missing":
        steps.pop(index)
    elif case == "duplicate":
        steps.append(dict(steps[index]))
    elif case == "conditional":
        steps[index]["if"] = "false"
    elif case == "extra-category-job":
        document["jobs"]["other"] = {"runs-on": "ubuntu-24.04", "steps": []}
    elif case == "extra-call":
        path = root / ".github/workflows/ci.yml"
        document = read_workflow(path)
        document["jobs"]["extra"] = {"uses": "./.github/workflows/ci-quality.yml"}
    else:
        policy = root / ".github/ci-workflows.json"
        inventory = json.loads(policy.read_text())
        relative = (
            ".github/workflows/ci.yml"
            if case == "coordinator-category"
            else CI_WORKFLOWS["quality"]
        )
        inventory["workflows"][relative]["category"] = "security"
        policy.write_text(json.dumps(inventory))
    path.write_text(yaml.safe_dump(document))
    if case in {"extra-call", "extra-category-job"}:
        policy = root / ".github/ci-workflows.json"
        inventory = json.loads(policy.read_text())
        inventory["workflows"][path.relative_to(root).as_posix()]["jobs"] = list(document["jobs"])
        policy.write_text(json.dumps(inventory))
    assert ci_workflow_errors(root)


def test_real_reusable_count_budget_precedes_provider_limit(tmp_path: Path) -> None:
    """A fully inventoried excess of actual reusable files must still refuse.

    Parameters
    ----------
    tmp_path : Path
        Actual independent repository copy.
    """
    root = copy_workflow_repository(tmp_path)
    policy = root / ".github/ci-workflows.json"
    inventory = json.loads(policy.read_text())
    template = (root / CI_WORKFLOWS["quality"]).read_text()
    for number in range(12):
        relative = f".github/workflows/additional-{number}.yml"
        (root / relative).write_text(template)
        inventory["workflows"][relative] = {
            "owner": "@anulum",
            "category": "quality",
            "jobs": ["quality"],
        }
    policy.write_text(json.dumps(inventory))
    assert ci_workflow_errors(root)
