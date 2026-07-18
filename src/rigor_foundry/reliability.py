# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — reliability candidate scanner
"""Collect bounded static reliability signals from tracked Python."""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass

from .candidate_anchor import TrackedBlobAnchor
from .git_inventory import GitInventory, TrackedFile
from .models import AuditPolicy, Candidate, Confidence

_MUTABLE_BUILTINS: frozenset[str] = frozenset({"list", "dict", "set"})


@dataclass(frozen=True)
class _Signal:
    """One classified reliability signal for a line."""

    rule_id: str
    confidence: Confidence
    rationale: str
    verification: str


_BARE_EXCEPT = _Signal(
    rule_id="RL001-bare-except",
    confidence="high",
    rationale=(
        "A bare except catches every exception, including SystemExit and "
        "KeyboardInterrupt, so it hides real failures and blocks interruption."
    ),
    verification=(
        "Catch the specific exception types the block can actually handle, or re-raise after "
        "recording context; never swallow BaseException silently."
    ),
)
_MUTABLE_DEFAULT = _Signal(
    rule_id="RL002-mutable-default-argument",
    confidence="high",
    rationale=(
        "A mutable default argument is created once and shared across every call, so state "
        "leaks between invocations."
    ),
    verification=(
        "Default the parameter to None and create the list, dict, or set inside the function "
        "body, or confirm the shared instance is genuinely intended."
    ),
)


def _line_evidence(item: TrackedFile, line: int) -> str:
    """Return content-addressed evidence without copying repository source."""
    lines = (item.text or "").splitlines()
    content = lines[line - 1] if 0 < line <= len(lines) else ""
    line_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return f"file_sha256={item.content_digest}; line_sha256={line_digest}"


def _is_mutable_default(node: ast.expr) -> bool:
    """Return whether a default expression constructs a fresh mutable container."""
    if isinstance(node, (ast.List, ast.Dict, ast.Set)):
        return True
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in _MUTABLE_BUILTINS
        and not node.args
        and not node.keywords
    )


def _mutable_default_lines(tree: ast.Module) -> list[int]:
    """Return the lines of mutable default arguments in every function definition."""
    lines: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        defaults = [
            *node.args.defaults,
            *(item for item in node.args.kw_defaults if item is not None),
        ]
        lines.extend(default.lineno for default in defaults if _is_mutable_default(default))
    return lines


def _bare_except_lines(tree: ast.Module) -> list[int]:
    """Return the lines of every bare ``except:`` handler."""
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.ExceptHandler) and node.type is None
    ]


def _file_candidates(item: TrackedFile) -> tuple[Candidate, ...]:
    """Collect reliability candidates from one tracked Python file."""
    if item.text is None or not item.path.endswith(".py"):
        return ()
    try:
        tree = ast.parse(item.text, filename=item.path)
    except SyntaxError:
        return ()
    findings: list[tuple[int, _Signal, str]] = []
    findings.extend((line, _BARE_EXCEPT, "except") for line in _bare_except_lines(tree))
    findings.extend((line, _MUTABLE_DEFAULT, "default") for line in _mutable_default_lines(tree))
    return tuple(
        Candidate.build(
            category="reliability",
            rule_id=signal.rule_id,
            anchor=TrackedBlobAnchor.build(item, line_start=line),
            symbol=symbol,
            evidence=_line_evidence(item, line),
            confidence=signal.confidence,
            rationale=signal.rationale,
            verification=signal.verification,
        )
        for line, signal, symbol in sorted(findings, key=lambda finding: (finding[0], finding[2]))
    )


def scan_reliability(
    inventory: GitInventory,
    policy: AuditPolicy,
) -> tuple[Candidate, ...]:
    """Return bounded reliability candidates for the tracked Python surface.

    Parameters
    ----------
    inventory:
        Read-only tracked-content inventory of the repository.
    policy:
        Repository audit policy (accepted for signature parity; every tracked
        Python file is in scope).

    Returns
    -------
    tuple[Candidate, ...]
        Deterministic, anchored, needs-evidence candidates.
    """
    del policy
    candidates: list[Candidate] = []
    for item in inventory.files:
        candidates.extend(_file_candidates(item))
    return tuple(candidates)
