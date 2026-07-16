# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — cross-language responsibility-size scanner
"""Collect large-file responsibility and registry-drift candidates."""

from __future__ import annotations

import ast
import json
import re
from collections import Counter
from pathlib import PurePosixPath
from typing import cast

from .candidate_anchor import RepositoryTreeAnchor, TrackedBlobAnchor
from .git_inventory import GitInventory, TrackedFile
from .models import AuditPolicy, Candidate

_CODE_EXTENSIONS = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".go",
        ".h",
        ".hpp",
        ".jl",
        ".js",
        ".jsx",
        ".lean",
        ".mojo",
        ".py",
        ".pyi",
        ".rs",
        ".sh",
        ".sv",
        ".ts",
        ".tsx",
        ".v",
    }
)

_DEFINITION_PATTERNS = (
    re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)"),
    re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)"),
    re.compile(r"^\s*(?:export\s+)?(?:class|interface|type)\s+([A-Za-z_$][A-Za-z0-9_$]*)"),
    re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)"),
    re.compile(r"^\s*function\s+([A-Za-z_][A-Za-z0-9_!]*)"),
    re.compile(r"^\s*(?:def|theorem|lemma|structure|inductive)\s+([A-Za-z_][A-Za-z0-9_']*)"),
    re.compile(r"^\s*(?:class|struct|enum)\s+([A-Za-z_][A-Za-z0-9_]*)"),
)

_IMPORT_PATTERN = re.compile(
    r"^\s*(?:from\s+([^\s]+)\s+import|import\s+([^\s;]+)|use\s+([^;]+)|"
    r"require\s*\(([^)]+)\)|using\s+([^\s;]+))"
)

_COMMON_TOKENS = frozenset(
    {
        "get",
        "set",
        "is",
        "has",
        "to",
        "from",
        "build",
        "create",
        "make",
        "run",
        "load",
        "write",
        "read",
        "validate",
        "check",
        "test",
        "main",
        "new",
        "default",
    }
)


def _physical_lines(text: str) -> int:
    """Return physical line count with the repository module-size convention."""
    if not text:
        return 0
    encoded = text.encode("utf-8")
    return encoded.count(b"\n") + int(not encoded.endswith(b"\n"))


def _is_test_path(path: str, policy: AuditPolicy) -> bool:
    """Return whether a path belongs to the configured test surface."""
    pure = PurePosixPath(path)
    name = pure.name.lower()
    return (
        any(root in pure.parts for root in policy.test_roots)
        or name.startswith("test_")
        or name.endswith("_test.py")
        or ".test." in name
        or ".spec." in name
    )


def _split_symbol(symbol: str) -> tuple[str, ...]:
    """Split one identifier into lower-case responsibility tokens."""
    camel = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", symbol)
    return tuple(
        token.lower()
        for token in re.split(r"[^A-Za-z0-9]+", camel)
        if len(token) > 2 and token.lower() not in _COMMON_TOKENS
    )


def _python_metrics(text: str) -> tuple[tuple[str, ...], int]:
    """Return top-level Python symbols and distinct import count."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return (), 0
    symbols = tuple(
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    )
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
    return symbols, len(imports)


def _text_metrics(text: str) -> tuple[tuple[str, ...], int]:
    """Return approximate cross-language symbols and import count."""
    symbols: list[str] = []
    imports: set[str] = set()
    for line in text.splitlines():
        for expression in _DEFINITION_PATTERNS:
            match = expression.match(line)
            if match is not None:
                symbols.append(match.group(1))
                break
        import_match = _IMPORT_PATTERN.match(line)
        if import_match is not None:
            imports.add(next(group for group in import_match.groups() if group is not None))
    return tuple(symbols), len(imports)


def _responsibility_metrics(item: TrackedFile) -> tuple[int, int, tuple[str, ...]]:
    """Return definition count, import fan-out, and dominant symbol tokens."""
    if item.text is None:
        return 0, 0, ()
    if item.path.endswith((".py", ".pyi")):
        symbols, imports = _python_metrics(item.text)
    else:
        symbols, imports = _text_metrics(item.text)
    token_counts = Counter(token for symbol in symbols for token in _split_symbol(symbol))
    dominant = tuple(token for token, _count in token_counts.most_common(8))
    return len(symbols), imports, dominant


def _large_file_candidates(
    inventory: GitInventory,
    policy: AuditPolicy,
) -> tuple[Candidate, ...]:
    """Return one responsibility-review candidate per configured large file."""
    candidates: list[Candidate] = []
    for item in inventory.files:
        if item.text is None or PurePosixPath(item.path).suffix.lower() not in _CODE_EXTENSIONS:
            continue
        is_test = _is_test_path(item.path, policy)
        threshold = policy.test_line_threshold if is_test else policy.source_line_threshold
        lines = _physical_lines(item.text)
        if lines <= threshold:
            continue
        definitions, imports, tokens = _responsibility_metrics(item)
        evidence = (
            f"lines={lines}; threshold={threshold}; definitions={definitions}; "
            f"import_fanout={imports}; symbol_families={','.join(tokens) or 'none'}"
        )
        candidates.append(
            Candidate.build(
                category="godfile",
                rule_id="GF001-large-responsibility-owner",
                anchor=TrackedBlobAnchor.build(
                    item,
                    line_start=1,
                    line_end=max(1, _physical_lines(item.text)),
                ),
                symbol="test" if is_test else "source",
                evidence=evidence,
                confidence="medium",
                rationale=(
                    "The file exceeds the configured review threshold; line count opens a "
                    "responsibility audit but is not itself a GodFile verdict."
                ),
                verification=(
                    "Read the full file, classify each top-level responsibility and direct dependency, "
                    "trace every public consumer and test owner, then record one cohesive responsibility "
                    "with a reopen trigger or split mixed ownership behind stable contracts."
                ),
            )
        )
    return tuple(candidates)


def _registry_rows(value: object) -> tuple[dict[str, object], ...]:
    """Return module-size registry rows or reject the document."""
    if not isinstance(value, dict):
        raise ValueError("registry root must be an object")
    data = cast(dict[str, object], value)
    raw_rows = data.get("files")
    if not isinstance(raw_rows, list):
        raise ValueError("registry files must be an array")
    rows: list[dict[str, object]] = []
    for raw in raw_rows:
        if not isinstance(raw, dict) or not all(isinstance(key, str) for key in raw):
            raise ValueError("registry row must be an object with string keys")
        rows.append(cast(dict[str, object], raw))
    return tuple(rows)


def _registry_candidates(
    inventory: GitInventory,
    policy: AuditPolicy,
) -> tuple[Candidate, ...]:
    """Return stale or incomplete module-size registry candidates."""
    by_path = {item.path: item for item in inventory.files}
    candidates: list[Candidate] = []
    required = ("path", "lines", "responsibility", "dependency_boundary", "reassess_when")
    for registry_path in policy.module_size_registries:
        registry = by_path.get(registry_path)
        if registry is None or registry.text is None:
            candidates.append(
                Candidate.build(
                    category="godfile",
                    rule_id="GF002-missing-size-registry",
                    anchor=RepositoryTreeAnchor.build(
                        inventory,
                        path=registry_path,
                    ),
                    symbol="",
                    evidence="configured registry is missing or not UTF-8 text",
                    confidence="high",
                    rationale="Configured GodFile responsibility evidence cannot be loaded.",
                    verification="Restore the tracked registry and rerun its native strict audit.",
                )
            )
            continue
        try:
            rows = _registry_rows(json.loads(registry.text))
        except (ValueError, json.JSONDecodeError) as exc:
            candidates.append(
                Candidate.build(
                    category="godfile",
                    rule_id="GF003-invalid-size-registry",
                    anchor=TrackedBlobAnchor.build(
                        registry,
                        line_start=1,
                        line_end=max(1, _physical_lines(registry.text)),
                    ),
                    symbol="",
                    evidence=str(exc),
                    confidence="high",
                    rationale="Configured GodFile responsibility evidence is malformed.",
                    verification="Run the repository-native module-size registry parser and repair it.",
                )
            )
            continue
        for index, row in enumerate(rows):
            missing = tuple(
                field
                for field in required
                if field not in row or not isinstance(row[field], (str, int)) or row[field] == ""
            )
            path_value = row.get("path")
            recorded_lines = row.get("lines")
            if missing:
                candidates.append(
                    Candidate.build(
                        category="godfile",
                        rule_id="GF004-incomplete-size-decision",
                        anchor=TrackedBlobAnchor.build(
                            registry,
                            line_start=1,
                            line_end=max(1, _physical_lines(registry.text)),
                        ),
                        symbol=str(path_value or f"row-{index}"),
                        evidence=f"missing_or_invalid={','.join(missing)}",
                        confidence="high",
                        rationale="A large-file decision lacks required responsibility evidence.",
                        verification=(
                            "Read the complete owner and record current responsibility, direct "
                            "dependency boundary, exact line count, disposition, and reopen trigger."
                        ),
                    )
                )
                continue
            if (
                not isinstance(path_value, str)
                or isinstance(recorded_lines, bool)
                or not isinstance(recorded_lines, int)
            ):
                continue
            owner = by_path.get(path_value)
            if owner is None or owner.text is None:
                evidence = f"registered path unavailable; recorded_lines={recorded_lines}"
            else:
                current_lines = _physical_lines(owner.text)
                if current_lines == recorded_lines:
                    continue
                evidence = f"recorded_lines={recorded_lines}; current_lines={current_lines}"
            candidates.append(
                Candidate.build(
                    category="godfile",
                    rule_id="GF005-size-decision-drift",
                    anchor=(
                        RepositoryTreeAnchor.build(inventory, path=path_value)
                        if owner is None
                        else TrackedBlobAnchor.build(
                            owner,
                            line_start=1,
                            line_end=max(
                                1,
                                _physical_lines(owner.text) if owner.text is not None else 1,
                            ),
                        )
                    ),
                    symbol=registry_path,
                    evidence=evidence,
                    confidence="high",
                    rationale="A reviewed large-file decision no longer matches the tracked tree.",
                    verification=(
                        "Re-read the complete file, re-evaluate its responsibility/dependencies and "
                        "reopen trigger, then update the registry only after that review."
                    ),
                )
            )
    return tuple(candidates)


def scan_godfiles(
    inventory: GitInventory,
    policy: AuditPolicy,
) -> tuple[Candidate, ...]:
    """Return cross-language size and responsibility-evidence candidates.

    Parameters
    ----------
    inventory:
        Exact Git-tracked repository inventory.
    policy:
        Repository-local thresholds and registry paths.

    Returns
    -------
    tuple[Candidate, ...]
        Large-owner and stale-registry signals requiring full-file review.

    """
    return (*_large_file_candidates(inventory, policy), *_registry_candidates(inventory, policy))
