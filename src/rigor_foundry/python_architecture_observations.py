# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Python architecture source observations
"""Reuse bounded facts from successfully parsed Python sources."""

from __future__ import annotations

import ast
import hashlib
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import PurePosixPath
from threading import Lock

from .git_inventory import TrackedFile

# Bound retained input independently of the much larger live text limit.
_MAX_RETAINED_OBSERVATIONS = 4096
_MAX_RETAINED_TEXT_CHARACTERS = 2048


@dataclass(frozen=True)
class PythonDefinition:
    """Bounded metadata for one top-level Python function definition."""

    name: str
    line: int
    end_line: int
    body_digest: str | None


@dataclass(frozen=True)
class PythonArchitectureObservation:
    """Describe one parsed source without deciding any repository relation."""

    imports: tuple[str, ...]
    wildcard_imports: tuple[tuple[int, str], ...]
    broad_import_lines: tuple[int, ...]
    definitions: tuple[PythonDefinition, ...]
    has_top_level_imports: bool


_observations: OrderedDict[tuple[TrackedFile, str, str], PythonArchitectureObservation] = (
    OrderedDict()
)
_observation_lock = Lock()


def _relative_import_name(module: str, node: ast.ImportFrom, is_package: bool) -> str:
    """Resolve one relative import against its owning module."""
    if node.level == 0:
        return node.module or ""
    base = module.split(".")
    if not is_package:
        base = base[:-1]
    climb = node.level - 1
    if climb > len(base):
        return ""
    prefix = base[: len(base) - climb]
    if node.module:
        prefix.extend(node.module.split("."))
    return ".".join(prefix)


def _handler_is_broad(handler: ast.ExceptHandler) -> bool:
    """Identify handlers catching every ordinary import failure."""
    if handler.type is None:
        return True
    if isinstance(handler.type, ast.Name):
        return handler.type.id in {"Exception", "BaseException"}
    if isinstance(handler.type, ast.Tuple):
        return any(
            isinstance(item, ast.Name) and item.id in {"Exception", "BaseException"}
            for item in handler.type.elts
        )
    return False


def _has_broad_import_handler(node: ast.Try) -> bool:
    """Check an actual guarded import and its exception handlers."""
    return any(_handler_is_broad(item) for item in node.handlers) and any(
        isinstance(child, (ast.Import, ast.ImportFrom))
        for statement in node.body
        for child in ast.walk(statement)
    )


def _definition_digest(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """Hash the normalised body of a non-trivial definition."""
    statement_count = sum(1 for child in ast.walk(node) if isinstance(child, ast.stmt))
    if statement_count < 6:
        return None
    payload = ast.dump(ast.Module(body=node.body, type_ignores=[]), include_attributes=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _collect_architecture(
    tree: ast.Module, path: str, module: str
) -> PythonArchitectureObservation:
    """Collect file-local facts from a parsed tree."""
    is_package = PurePosixPath(path).name == "__init__.py"
    imports: set[str] = set()
    wildcard_imports: list[tuple[int, str]] = []
    guarded_lines: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = _relative_import_name(module, node, is_package)
            if base:
                imports.add(base)
                imports.update(f"{base}.{alias.name}" for alias in node.names if alias.name != "*")
            if any(alias.name == "*" for alias in node.names):
                wildcard_imports.append((node.lineno, f"from {node.module or '.'} import *"))
        elif isinstance(node, ast.Try) and _has_broad_import_handler(node):
            guarded_lines.append(node.lineno)
    return PythonArchitectureObservation(
        imports=tuple(sorted(imports)),
        wildcard_imports=tuple(sorted(wildcard_imports)),
        broad_import_lines=tuple(sorted(guarded_lines)),
        definitions=tuple(
            PythonDefinition(
                node.name, node.lineno, node.end_lineno or node.lineno, _definition_digest(node)
            )
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ),
        has_top_level_imports=any(
            isinstance(node, (ast.Import, ast.ImportFrom)) for node in tree.body
        ),
    )


def _retained_architecture(
    tree: ast.Module, file: TrackedFile, module: str, policy_digest: str
) -> PythonArchitectureObservation:
    """Reuse the AST-derived facts for an exact successful parse."""
    # The cache key includes TrackedFile's path, mode, blob identities, byte
    # digest and exact text. Interpreter and installed source share its lifetime.
    key = (file, module, policy_digest)
    with _observation_lock:
        observation = _observations.get(key)
        if observation is not None:
            _observations.move_to_end(key)
            return observation
    observation = _collect_architecture(tree, file.path, module)
    with _observation_lock:
        _observations[key] = observation
        _observations.move_to_end(key)
        if len(_observations) > _MAX_RETAINED_OBSERVATIONS:
            _observations.popitem(last=False)
    return observation


def observe_python_architecture(
    file: TrackedFile, module: str, policy_digest: str
) -> PythonArchitectureObservation | None:
    """Observe Python facts from a live tracked file.

    Parameters
    ----------
    file
        Exact current tracked file, with worktree content already verified.
    module
        Current module name derived from its path and the resolved policy.
    policy_digest
        Identity of the complete policy governing this observation.

    Returns
    -------
    PythonArchitectureObservation or None
        File-local imports, definition metadata and boundary facts. Non-text
        or syntactically invalid Python supplies no parsed observation.
    """
    text = file.text
    if text is None:
        return None
    # Always parse with the caller's current warning handling. The same input
    # can emit a warning or raise SyntaxError under different filters.
    try:
        tree = ast.parse(text, filename=file.path)
    except SyntaxError:
        return None
    if len(text) > _MAX_RETAINED_TEXT_CHARACTERS:
        return _collect_architecture(tree, file.path, module)
    return _retained_architecture(tree, file, module, policy_digest)
