# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — YAML dump references in workflow test modules
"""Find every YAML dump reference in a test module, for the workflow writer guard.

It lives outside the workflow test modules that it scans, so the guard's own spelling of
the dump names is never counted as a use.
"""

from __future__ import annotations

import ast

_DUMP_NAMES = frozenset({"dump", "dump_all", "safe_dump", "safe_dump_all"})


def yaml_dump_references(source: str, file_name: str) -> list[tuple[str, str]]:
    """Return every YAML dump reference in one test module and its enclosing function.

    Any attribute, name or string constant spelled like a dump function counts, whatever
    the receiver, alias or lookup, and so does any ``from yaml import``. Only ``json.dump``
    on a name bound to ``json`` is not a YAML dump.

    Parameters
    ----------
    source : str
        Complete module text.
    file_name : str
        Module file name, carried into each finding.

    Returns
    -------
    list[tuple[str, str]]
        One ``(file_name, enclosing function or "<module>")`` pair per reference.
    """
    tree = ast.parse(source)
    owners: dict[ast.AST, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.walk(node):
                owners.setdefault(child, node.name)
    uses: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            found = node.attr in _DUMP_NAMES and not (
                node.attr == "dump"
                and isinstance(node.value, ast.Name)
                and node.value.id == "json"
            )
        elif isinstance(node, ast.Name):
            found = node.id in _DUMP_NAMES
        elif isinstance(node, ast.Constant):
            found = isinstance(node.value, str) and node.value in _DUMP_NAMES
        elif isinstance(node, ast.ImportFrom):
            found = node.module == "yaml"
        else:
            found = False
        if found:
            uses.append((file_name, owners.get(node, "<module>")))
    return uses
