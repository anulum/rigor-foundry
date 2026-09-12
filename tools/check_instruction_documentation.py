# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — instruction cohort native documentation gate
"""Require native documentation on every declaration in the instruction cohort."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PATHS = (
    "src/rigor_foundry/instruction_scope.py",
    "src/rigor_foundry/instruction_resolution.py",
    "src/rigor_foundry/instruction_dispatch.py",
    "tests/test_instruction_scope.py",
    "tests/test_instruction_resolution.py",
    "tests/test_instruction_dispatch.py",
    "tools/check_instruction_documentation.py",
    "tests/test_check_instruction_documentation.py",
)


def undocumented_definitions(paths: tuple[Path, ...]) -> tuple[str, ...]:
    """Read exact files and report missing module, class and function docstrings.

    Private, nested and test definitions are not exempt. Syntax and read errors
    propagate and fail the caller. Presence is mechanical evidence only; review
    still determines whether documentation meaningfully describes the contract.
    """
    missing: list[str] = []
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(
                node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
            ) and not ast.get_docstring(node):
                missing.append(f"{path}:{getattr(node, 'lineno', 1)}")
    return tuple(missing)


def main(root: Path = ROOT) -> int:
    """Check the fixed maintained cohort, including this gate and its tests."""
    missing = undocumented_definitions(tuple(root / path for path in PATHS))
    for finding in missing:
        print(f"Missing native documentation: {finding}")
    return int(bool(missing))


if __name__ == "__main__":
    raise SystemExit(main())
