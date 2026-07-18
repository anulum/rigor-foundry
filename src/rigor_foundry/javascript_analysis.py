# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native JavaScript/TypeScript analysis
"""Collect native JavaScript and TypeScript signals from a tree-sitter AST."""

from __future__ import annotations

import hashlib
from pathlib import PurePosixPath
from typing import Any

from .candidate_anchor import TrackedBlobAnchor
from .git_inventory import GitInventory, TrackedFile
from .models import AuditPolicy, Candidate

_DYNAMIC_EXEC_RULE = "AS006-js-dynamic-code-execution"
_DYNAMIC_EXEC_RATIONALE = (
    "eval and the Function constructor execute a string as code, turning any tainted "
    "argument into arbitrary execution."
)
_DYNAMIC_EXEC_VERIFICATION = (
    "Replace the dynamic evaluation with an explicit parser, a lookup table, or a typed "
    "dispatch; if evaluation is unavoidable, prove the source is a trusted literal."
)


def _import_grammars() -> tuple[Any, Any, Any]:
    """Import the optional tree-sitter runtime and grammars.

    Isolated so the availability path is testable; a missing optional extra is
    surfaced as an ``ImportError`` that the caller degrades gracefully.
    """
    import tree_sitter
    import tree_sitter_javascript
    import tree_sitter_typescript

    return tree_sitter, tree_sitter_javascript, tree_sitter_typescript


def _load_parsers() -> dict[str, Any] | None:
    """Return a per-suffix parser map, or ``None`` when the extra is absent."""
    try:
        tree_sitter, javascript, typescript = _import_grammars()
    except ImportError:
        return None
    js_language = tree_sitter.Language(javascript.language())
    ts_language = tree_sitter.Language(typescript.language_typescript())
    tsx_language = tree_sitter.Language(typescript.language_tsx())
    return {
        ".js": tree_sitter.Parser(js_language),
        ".jsx": tree_sitter.Parser(js_language),
        ".ts": tree_sitter.Parser(ts_language),
        ".tsx": tree_sitter.Parser(tsx_language),
    }


def _line_evidence(item: TrackedFile, line: int) -> str:
    """Return content-addressed evidence without copying repository source."""
    lines = (item.text or "").splitlines()
    content = lines[line - 1] if 0 < line <= len(lines) else ""
    line_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return f"file_sha256={item.content_digest}; line_sha256={line_digest}"


def _dynamic_execution_findings(root: Any) -> list[tuple[int, str]]:
    """Return (line, symbol) for each eval call or Function constructor in a tree."""
    findings: list[tuple[int, str]] = []
    stack: list[Any] = [root]
    while stack:
        node = stack.pop()
        if node.type == "call_expression":
            target = node.child_by_field_name("function")
            if target is not None and target.type == "identifier" and target.text == b"eval":
                findings.append((node.start_point[0] + 1, "eval"))
        elif node.type == "new_expression":
            target = node.child_by_field_name("constructor")
            if target is not None and target.type == "identifier" and target.text == b"Function":
                findings.append((node.start_point[0] + 1, "new Function"))
        stack.extend(node.children)
    return findings


def scan_javascript(
    inventory: GitInventory,
    policy: AuditPolicy,
) -> tuple[Candidate, ...]:
    """Return native JavaScript/TypeScript candidates from tracked source.

    Parameters
    ----------
    inventory:
        Read-only tracked-content inventory of the repository.
    policy:
        Repository audit policy (accepted for signature parity; every tracked
        JavaScript and TypeScript file is in scope).

    Returns
    -------
    tuple[Candidate, ...]
        Deterministic, anchored candidates. Empty when the optional ``javascript``
        extra (tree-sitter) is not installed.
    """
    del policy
    parsers = _load_parsers()
    if parsers is None:
        return ()
    candidates: list[Candidate] = []
    for item in inventory.files:
        parser = parsers.get(PurePosixPath(item.path).suffix.lower())
        if parser is None or item.text is None:
            continue
        tree = parser.parse(item.text.encode("utf-8"))
        for line, symbol in sorted(_dynamic_execution_findings(tree.root_node)):
            candidates.append(
                Candidate.build(
                    category="application-security",
                    rule_id=_DYNAMIC_EXEC_RULE,
                    anchor=TrackedBlobAnchor.build(item, line_start=line),
                    symbol=symbol,
                    evidence=_line_evidence(item, line),
                    confidence="high",
                    rationale=_DYNAMIC_EXEC_RATIONALE,
                    verification=_DYNAMIC_EXEC_VERIFICATION,
                )
            )
    return tuple(candidates)
