# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — the command boundary module-size-decisions.json records for cli.py
"""Keep ``cli.py`` to the frozen 1.0 commands; every later command registers from its own module.

``module-size-decisions.json`` records ``cli.py``'s responsibility on that boundary. These
checks read the source, so a new command handler written into ``cli.py`` fails here, whatever
the file's length.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "src" / "rigor_foundry" / "cli.py"
FROZEN_COMMANDS = frozenset(
    {
        "bootstrap",
        "campaign-compare",
        "campaign-create",
        "campaign-run",
        "contract",
        "gate",
        "maturity-evaluate",
        "promote",
        "residuals-check",
        "review-template",
        "sarif",
        "scan",
        "scan-revision",
        "validate-review",
    }
)
FROZEN_HANDLERS = frozenset(
    {
        "_bootstrap_command",
        "_campaign_compare_command",
        "_campaign_create_command",
        "_campaign_run_command",
        "_contract_command",
        "_gate_command",
        "_maturity_evaluate_command",
        "_promote_command",
        "_residuals_check_command",
        "_review_template_command",
        "_sarif_command",
        "_scan_command",
        "_validate_review_command",
    }
)


def _tree() -> ast.Module:
    """Parse the entry point's source."""
    return ast.parse(CLI.read_text(encoding="utf-8"))


def test_the_entry_point_adds_only_the_frozen_commands_itself() -> None:
    """Every ``add_parser`` written in ``cli.py`` names a frozen 1.0 command."""
    names = {
        node.args[0].value
        for node in ast.walk(_tree())
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "add_parser"
        and node.args
        and isinstance(node.args[0], ast.Constant)
    }
    assert names == FROZEN_COMMANDS


def test_the_entry_point_defines_only_the_frozen_handlers() -> None:
    """No module-level command handler beyond the frozen ones lives in ``cli.py``."""
    handlers = {
        node.name
        for node in _tree().body
        if isinstance(node, ast.FunctionDef) and node.name.endswith("_command")
    }
    assert handlers == FROZEN_HANDLERS


def test_every_other_command_is_registered_from_its_own_cli_module() -> None:
    """Each ``add_…_command`` called in ``cli.py`` is imported from a ``*_cli`` module."""
    tree = _tree()
    imported = {
        alias.name: node.module or ""
        for node in tree.body
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    registrations = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id.startswith("add_")
    }
    assert registrations
    assert all(imported.get(name, "").endswith("_cli") for name in registrations)


def test_the_size_decision_still_states_this_boundary() -> None:
    """The recorded responsibility names the boundary these checks hold."""
    rows = json.loads((ROOT / "module-size-decisions.json").read_text(encoding="utf-8"))["files"]
    row = next(row for row in rows if row["path"] == "src/rigor_foundry/cli.py")
    assert "own *_cli module" in row["dependency_boundary"]
