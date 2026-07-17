# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — GitHub Action pin guard tests
"""Verify mutable actions and checkout credentials fail closed."""

from pathlib import Path

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
