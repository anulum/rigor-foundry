# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — GitHub Action pin guard tests
"""Verify mutable actions and checkout credentials fail closed."""

import runpy
import sys
from pathlib import Path

import pytest

from tools.check_action_pins import (
    action_metadata_errors,
    action_pin_errors,
    workflow_errors,
)


def test_action_guard_rejects_mutable_checkout_and_credential_persistence(tmp_path: Path) -> None:
    """A tag pin and default checkout credentials fail the workflow contract."""
    workflow = tmp_path / "ci.yml"
    workflow.write_text(
        "permissions:\n"
        "  contents: read\n"
        "concurrency:\n"
        "  group: test\n"
        "jobs:\n"
        "  check:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    errors = workflow_errors(workflow)
    assert "action is not pinned to a full commit: actions/checkout" in errors
    assert "line 8: checkout must disable persisted credentials" in errors


def test_repository_workflows_use_immutable_actions() -> None:
    """Every production workflow and composite action passes the public guard."""
    assert action_pin_errors() == []


def test_action_guard_rejects_mutable_uses_and_direct_input_interpolation(
    tmp_path: Path,
) -> None:
    """Composite actions pin nested actions and pass inputs through environment values."""
    action = tmp_path / "action.yml"
    action.write_text(
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - uses: actions/setup-python@v6\n"
        "    - shell: bash\n"
        "      run: echo '${{ inputs.policy-path }}'\n",
        encoding="utf-8",
    )

    assert action_metadata_errors(action) == [
        "action is not pinned to a full commit: actions/setup-python",
        "line 6: action inputs must enter shell commands through env",
    ]


def test_workflow_guard_rejects_missing_controls_target_context_and_unversioned_action(
    tmp_path: Path,
) -> None:
    """Workflow-level authority and absent revisions fail independently."""
    absent_controls = tmp_path / "absent.yml"
    absent_controls.write_text("jobs: {}\n", encoding="utf-8")
    assert workflow_errors(absent_controls) == [
        "explicit permissions block is required",
        "concurrency control is required",
    ]

    unsafe = tmp_path / "unsafe.yml"
    unsafe.write_text(
        "pull_request_target:\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  check:\n"
        "    steps:\n"
        "      - uses: owner/unversioned-action\n",
        encoding="utf-8",
    )
    assert workflow_errors(unsafe) == [
        "pull_request_target is forbidden",
        "concurrency control is required",
        "write-all permissions are forbidden",
        "action has no immutable revision: owner/unversioned-action",
    ]


def test_action_guard_rejects_non_composite_runtime_but_accepts_env_and_output_inputs(
    tmp_path: Path,
) -> None:
    """Only composite actions may expose inputs through env or output values."""
    action = tmp_path / "action.yaml"
    action.write_text(
        "runs:\n"
        "  using: node20\n"
        "env:\n"
        "  RF_POLICY_PATH: ${{ inputs.policy-path }}\n"
        "outputs:\n"
        "  report:\n"
        "    value: ${{ inputs.report-path }}\n",
        encoding="utf-8",
    )
    assert action_metadata_errors(action) == ["action must use the composite runtime"]


def test_repository_guard_reports_absent_workflows_and_prefixes_nested_failures(
    tmp_path: Path,
) -> None:
    """Repository aggregation covers YAML variants and attributes every failure."""
    assert action_pin_errors(tmp_path) == [".github/workflows: no YAML workflows found"]

    workflows = tmp_path / ".github/workflows"
    actions = tmp_path / ".github/actions/example"
    workflows.mkdir(parents=True)
    actions.mkdir(parents=True)
    (workflows / "ci.yaml").write_text(
        "permissions:\n"
        "  contents: read\n"
        "concurrency:\n"
        "  group: test\n"
        "jobs:\n"
        "  check:\n"
        "    steps:\n"
        "      - uses: owner/unversioned\n",
        encoding="utf-8",
    )
    (actions / "action.yaml").write_text(
        "runs:\n  using: node20\n",
        encoding="utf-8",
    )

    assert action_pin_errors(tmp_path) == [
        ".github/workflows/ci.yaml: action has no immutable revision: owner/unversioned",
        ".github/actions/example/action.yaml: action must use the composite runtime",
    ]


def test_module_entrypoint_reports_success_without_disclosing_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The module entrypoint delegates to the fixed redacted guard renderer."""
    monkeypatch.delitem(sys.modules, "tools.check_action_pins")
    with pytest.raises(SystemExit) as raised:
        runpy.run_module("tools.check_action_pins", run_name="__main__")
    assert raised.value.code == 0
