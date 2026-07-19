# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — scientific and numerical correctness candidate scanner
"""Collect bounded floating-point and stochastic-test review signals."""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from typing import Literal

from .candidate_anchor import TrackedBlobAnchor
from .git_inventory import GitInventory, TrackedFile
from .language_capabilities import is_test_path
from .models import AuditPolicy, Candidate
from .python_test_functions import collect_test_functions

_RANDOM_DRAWS = frozenset(
    {
        "choice",
        "choices",
        "gauss",
        "getrandbits",
        "randbytes",
        "randint",
        "random",
        "randrange",
        "sample",
        "shuffle",
        "uniform",
    }
)
_NUMPY_DRAWS = frozenset(
    {
        "choice",
        "normal",
        "poisson",
        "rand",
        "randint",
        "randn",
        "random",
        "random_sample",
        "shuffle",
        "standard_normal",
        "uniform",
    }
)
_Framework = Literal["random", "numpy"]
_Kind = Literal["draw", "seed", "constructor"]


@dataclass(frozen=True)
class _Aliases:
    """Import-bound local names for supported stochastic APIs."""

    random_modules: frozenset[str]
    numpy_modules: frozenset[str]
    numpy_random_modules: frozenset[str]
    random_draws: frozenset[str]
    numpy_draws: frozenset[str]
    random_seeders: frozenset[str]
    numpy_seeders: frozenset[str]
    random_constructors: frozenset[str]
    numpy_constructors: frozenset[str]


def _line_evidence(item: TrackedFile, line: int, occurrences: int) -> str:
    """Return bounded content identities for one candidate line."""
    lines = (item.text or "").splitlines()
    content = lines[line - 1] if 0 < line <= len(lines) else ""
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return f"file_sha256={item.content_digest}; line_sha256={digest}; occurrences={occurrences}"


def _aliases(tree: ast.Module, function: ast.FunctionDef | ast.AsyncFunctionDef) -> _Aliases:
    """Resolve explicit module-level and function-local stochastic imports."""
    imports = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
    imports.extend(
        node for node in ast.walk(function) if isinstance(node, (ast.Import, ast.ImportFrom))
    )
    sets: list[set[str]] = [set() for _ in range(9)]
    rm, nm, nrm, rd, numpy_draw_aliases, rs, ns, rc, nc = sets
    for node in imports:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "random":
                    rm.add(alias.asname or "random")
                elif alias.name == "numpy":
                    nm.add(alias.asname or "numpy")
                elif alias.name == "numpy.random":
                    (nrm if alias.asname else nm).add(alias.asname or "numpy")
        elif node.module == "random":
            for alias in node.names:
                local = alias.asname or alias.name
                if alias.name in _RANDOM_DRAWS:
                    rd.add(local)
                elif alias.name == "seed":
                    rs.add(local)
                elif alias.name == "Random":
                    rc.add(local)
        elif node.module == "numpy":
            for alias in node.names:
                if alias.name == "random":
                    nrm.add(alias.asname or alias.name)
        elif node.module == "numpy.random":
            for alias in node.names:
                local = alias.asname or alias.name
                if alias.name in _NUMPY_DRAWS:
                    numpy_draw_aliases.add(local)
                elif alias.name == "seed":
                    ns.add(local)
                elif alias.name == "default_rng":
                    nc.add(local)
    return _Aliases(*(frozenset(values) for values in sets))


def _parts(node: ast.expr) -> tuple[str, ...]:
    """Return a simple dotted name."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    return tuple(reversed((*parts, node.id))) if isinstance(node, ast.Name) else ()


def _binding(call: ast.Call, aliases: _Aliases) -> tuple[_Framework, _Kind] | None:
    """Return the imported stochastic API bound to one call."""
    if isinstance(call.func, ast.Name):
        name = call.func.id
        groups: tuple[tuple[frozenset[str], _Framework, _Kind], ...] = (
            (aliases.random_draws, "random", "draw"),
            (aliases.numpy_draws, "numpy", "draw"),
            (aliases.random_seeders, "random", "seed"),
            (aliases.numpy_seeders, "numpy", "seed"),
            (aliases.random_constructors, "random", "constructor"),
            (aliases.numpy_constructors, "numpy", "constructor"),
        )
        for names, framework, kind in groups:
            if name in names:
                return framework, kind
        return None
    parts = _parts(call.func)
    if len(parts) == 2:
        root, name = parts
        if root in aliases.random_modules:
            return (
                ("random", "draw")
                if name in _RANDOM_DRAWS
                else ("random", "seed")
                if name == "seed"
                else ("random", "constructor")
                if name == "Random"
                else None
            )
        if root in aliases.numpy_random_modules:
            return (
                ("numpy", "draw")
                if name in _NUMPY_DRAWS
                else ("numpy", "seed")
                if name == "seed"
                else ("numpy", "constructor")
                if name == "default_rng"
                else None
            )
    if len(parts) == 3 and parts[0] in aliases.numpy_modules and parts[1] == "random":
        name = parts[2]
        return (
            ("numpy", "draw")
            if name in _NUMPY_DRAWS
            else ("numpy", "seed")
            if name == "seed"
            else ("numpy", "constructor")
            if name == "default_rng"
            else None
        )
    return None


def _explicit_seed(call: ast.Call) -> bool:
    """Return whether the call's actual seed parameter is present and non-None."""
    values = list(call.args[:1])
    if not values:
        values.extend(
            keyword.value for keyword in call.keywords if keyword.arg in {"a", "seed", "x"}
        )
    if not values:
        return False
    value = values[0]
    return not (isinstance(value, ast.Constant) and value.value is None)


def _unseeded_lines(
    tree: ast.Module, function: ast.FunctionDef | ast.AsyncFunctionDef
) -> tuple[int, ...]:
    aliases = _aliases(tree, function)
    calls = sorted(
        (node for node in ast.walk(function) if isinstance(node, ast.Call)),
        key=lambda node: (node.lineno, node.col_offset),
    )
    seeded: set[_Framework] = set()
    findings: set[int] = set()
    for call in calls:
        binding = _binding(call, aliases)
        if binding is None:
            continue
        framework, kind = binding
        if kind == "seed" and _explicit_seed(call):
            seeded.add(framework)
        elif (kind == "constructor" and not _explicit_seed(call)) or (
            kind == "draw" and framework not in seeded
        ):
            findings.add(call.lineno)
    return tuple(sorted(findings))


def _float_literal(node: ast.expr) -> bool:
    return (isinstance(node, ast.Constant) and isinstance(node.value, float)) or (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, (ast.UAdd, ast.USub))
        and isinstance(node.operand, ast.Constant)
        and isinstance(node.operand.value, float)
    )


def _approximation(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Call)
        and bool(parts := _parts(node.func))
        and parts[-1] in {"approx", "isclose"}
    )


def _exact_float_lines(function: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[int, ...]:
    lines: set[int] = set()
    for node in ast.walk(function):
        if not isinstance(node, ast.Compare):
            continue
        operands = (node.left, *node.comparators)
        if any(
            isinstance(op, (ast.Eq, ast.NotEq))
            and (_float_literal(left) or _float_literal(right))
            and not (_approximation(left) or _approximation(right))
            for left, op, right in zip(operands[:-1], node.ops, operands[1:], strict=True)
        ):
            lines.add(node.lineno)
    return tuple(sorted(lines))


def _file_candidates(item: TrackedFile, policy: AuditPolicy) -> tuple[Candidate, ...]:
    if (
        item.text is None
        or not item.path.endswith(".py")
        or not is_test_path(item.path, policy.test_roots)
    ):
        return ()
    try:
        tree = ast.parse(item.text, filename=item.path)
    except SyntaxError:
        return ()
    findings: list[tuple[int, str, str, int, str, str]] = []
    for function in collect_test_functions(tree):
        exact = _exact_float_lines(function)
        if exact:
            findings.append(
                (
                    exact[0],
                    "SN001-exact-float-equality-in-test",
                    function.name,
                    len(exact),
                    "A test compares a direct floating-point literal with exact equality, which can hide representation or tolerance assumptions.",
                    "Use a justified absolute/relative tolerance or prove exact binary identity is intended.",
                )
            )
        unseeded = _unseeded_lines(tree, function)
        if unseeded:
            findings.append(
                (
                    unseeded[0],
                    "SN002-unseeded-stochastic-test",
                    function.name,
                    len(unseeded),
                    "A supported stochastic API is used before deterministic local seeding, so repeated test outcomes may consume different samples.",
                    "Seed before the first draw or construct the local generator with a seed, then verify deterministic replay.",
                )
            )
    return tuple(
        Candidate.build(
            category="scientific",
            rule_id=rule_id,
            anchor=TrackedBlobAnchor.build(item, line_start=line),
            symbol=symbol,
            evidence=_line_evidence(item, line, count),
            confidence="high",
            rationale=rationale,
            verification=verification,
        )
        for line, rule_id, symbol, count, rationale, verification in sorted(findings)
    )


def scan_scientific(inventory: GitInventory, policy: AuditPolicy) -> tuple[Candidate, ...]:
    """Return bounded scientific/numerical correctness review candidates."""
    return tuple(
        candidate for item in inventory.files for candidate in _file_candidates(item, policy)
    )
