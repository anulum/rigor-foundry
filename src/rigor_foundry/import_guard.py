# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Python import-syntax guard
"""Enforce explicit static-prefix and reserved dynamic-import syntax policies."""

from __future__ import annotations

import ast
from typing import Final, Literal, cast

DynamicImportPolicy = Literal["allow", "forbid-syntax"]
_DYNAMIC_MODULES: Final = frozenset({"builtins", "importlib"})
_DYNAMIC_NAMES: Final = frozenset({"__import__", "import_module"})
_CODE_CALLS: Final = frozenset({"compile", "eval", "exec"})
_RESERVED_NAMES: Final = _DYNAMIC_NAMES | _CODE_CALLS


def _constant_string(node: ast.AST) -> str | None:
    """Fold a bounded constant string expression without executing code."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _constant_string(node.left)
        right = _constant_string(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _symbol_name(node: ast.AST) -> str | None:
    """Return one loaded name or attribute spelling."""
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
        return node.id
    if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
        return node.attr
    return None


def _static_import_matches(
    node: ast.Import | ast.ImportFrom,
    prefixes: tuple[str, ...],
) -> set[str]:
    """Return forbidden prefixes matched by one static import."""
    if isinstance(node, ast.Import):
        imported = tuple(alias.name for alias in node.names)
        return {prefix for prefix in prefixes if any(name.startswith(prefix) for name in imported)}
    if node.level:
        raise ValueError(f"relative import cannot be resolved at line {node.lineno}")
    module = cast(str, node.module)
    matches: set[str] = set()
    for prefix in prefixes:
        package, separator, member_prefix = prefix.rpartition(".")
        if module.startswith(prefix) or (
            separator
            and module == package
            and any(alias.name.startswith(member_prefix) for alias in node.names)
        ):
            matches.add(prefix)
    return matches


def _dynamic_import_module(node: ast.Import | ast.ImportFrom) -> str | None:
    """Return a reserved dynamic-import module spelling, if imported."""
    if isinstance(node, ast.Import):
        return next(
            (
                alias.name
                for alias in node.names
                if alias.name.partition(".")[0] in _DYNAMIC_MODULES
            ),
            None,
        )
    if node.module is not None and node.module.partition(".")[0] in _DYNAMIC_MODULES:
        return node.module
    return None


def _reflective_name(node: ast.Call) -> str | None:
    """Return a reserved name selected through ``getattr`` syntax."""
    if _symbol_name(node.func) != "getattr":
        return None
    candidates = list(node.args[1:2])
    candidates.extend(keyword.value for keyword in node.keywords if keyword.arg == "name")
    if len(candidates) != 1:
        return None
    value = _constant_string(candidates[0])
    return value if value in _RESERVED_NAMES else None


def forbidden_imports(
    text: str,
    prefixes: tuple[str, ...],
    dynamic_import_policy: DynamicImportPolicy,
) -> tuple[tuple[str, int], ...]:
    """Return reserved import syntax evidence and exact source lines.

    ``forbid-syntax`` is intentionally lexical: shadowed or unreachable reserved
    spellings still violate the selected high-assurance policy. It is not a
    runtime reachability or sandbox proof.
    """
    if dynamic_import_policy not in {"allow", "forbid-syntax"}:
        raise ValueError("unsupported dynamic import policy")
    tree = ast.parse(text)
    matches: set[tuple[str, int]] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            matches.update(
                (f"static-prefix:{prefix}", node.lineno)
                for prefix in _static_import_matches(node, prefixes)
            )
            if dynamic_import_policy == "forbid-syntax" and (
                module := _dynamic_import_module(node)
            ):
                matches.add((f"reserved-module:{module}", node.lineno))
        if dynamic_import_policy != "forbid-syntax":
            continue
        if isinstance(node, (ast.Name, ast.Attribute)):
            if (name := _symbol_name(node)) in _RESERVED_NAMES:
                matches.add((f"reserved-name:{name}", node.lineno))
        elif isinstance(node, ast.Call):
            if name := _reflective_name(node):
                matches.add((f"reserved-reflection:{name}", node.lineno))
        elif (
            isinstance(node, ast.Subscript)
            and (name := _constant_string(node.slice)) in _RESERVED_NAMES
        ):
            matches.add((f"reserved-subscript:{name}", node.lineno))
    return tuple(sorted(matches, key=lambda item: (item[1], item[0])))
