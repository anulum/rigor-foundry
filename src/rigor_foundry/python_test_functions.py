# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — shared Python test-function ownership
"""Locate pytest-style functions without entering nested execution scopes."""

from __future__ import annotations

import ast


def collect_test_functions(
    tree: ast.Module,
) -> tuple[ast.FunctionDef | ast.AsyncFunctionDef, ...]:
    """Return top-level and ``Test*`` class-owned Python test functions.

    Parameters
    ----------
    tree:
        Parsed Python module from one repository test owner.

    Returns
    -------
    tuple[ast.FunctionDef | ast.AsyncFunctionDef, ...]
        Source-ordered functions whose names start with ``test_``. Nested
        functions and methods below non-test classes remain outside this
        deliberately structural pytest contract.
    """
    functions: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith(
            "test_"
        ):
            functions.append(node)
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            functions.extend(
                member
                for member in node.body
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
                and member.name.startswith("test_")
            )
    return tuple(functions)
