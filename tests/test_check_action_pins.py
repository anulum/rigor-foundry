# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — GitHub Action pin guard tests
"""Verify mutable actions and checkout credentials fail closed."""

from pathlib import Path

from tools.check_action_pins import action_pin_errors, workflow_errors


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
    """Every production workflow passes the same public guard."""
    assert action_pin_errors() == []
