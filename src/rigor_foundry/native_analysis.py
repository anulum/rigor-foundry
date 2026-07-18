# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native tree-sitter analysis
"""Collect native JavaScript, TypeScript, Go, Rust, and C/C++ signals from tree-sitter ASTs."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from .candidate_anchor import TrackedBlobAnchor
from .git_inventory import GitInventory, TrackedFile
from .models import AuditPolicy, Candidate, Confidence

_Matcher = Callable[[Any], "tuple[_NativeRule, str] | None"]


@dataclass(frozen=True)
class _NativeRule:
    """One application-security rule emitted by a native AST matcher."""

    rule_id: str
    confidence: Confidence
    rationale: str
    verification: str


_JS_DYNAMIC = _NativeRule(
    rule_id="AS006-js-dynamic-code-execution",
    confidence="high",
    rationale=(
        "eval and the Function constructor execute a string as code, turning any tainted "
        "argument into arbitrary execution."
    ),
    verification=(
        "Replace the dynamic evaluation with an explicit parser, a lookup table, or a typed "
        "dispatch; if evaluation is unavoidable, prove the source is a trusted literal."
    ),
)
_GO_COMMAND = _NativeRule(
    rule_id="AS007-go-command-execution",
    confidence="high",
    rationale=(
        "os/exec runs an external command, so a tainted argument can execute an unintended "
        "program or, with a shell, inject further commands."
    ),
    verification=(
        "Prove every argument is a trusted constant or validated allow-list value, pass an "
        "explicit argument vector, and never build the command from unsanitised input."
    ),
)
_RUST_UNSAFE = _NativeRule(
    rule_id="AS008-rust-unsafe-block",
    confidence="medium",
    rationale=(
        "An unsafe block suspends the compiler's memory-safety guarantees, so a mistake inside "
        "it can cause undefined behaviour that safe Rust would have prevented."
    ),
    verification=(
        "Confirm the block is minimal, documents the invariants it upholds, and cannot be "
        "replaced by a safe abstraction; record why each unsafe operation is sound."
    ),
)
_C_UNSAFE_LIBC = _NativeRule(
    rule_id="AS009-c-unsafe-libc",
    confidence="high",
    rationale=(
        "gets, the unbounded str/sprintf family, and system/popen are classic buffer-overflow "
        "and command-injection surfaces when their input is not strictly bounded and trusted."
    ),
    verification=(
        "Replace the call with a length-bounded equivalent (fgets, snprintf, strncpy with an "
        "explicit size) or an argument-vector exec, and prove the input is trusted and bounded."
    ),
)
_UNSAFE_C_FUNCTIONS: frozenset[bytes] = frozenset(
    {b"gets", b"strcpy", b"strcat", b"sprintf", b"vsprintf", b"system", b"popen"}
)


def _match_javascript(node: Any) -> tuple[_NativeRule, str] | None:
    """Match a JavaScript/TypeScript eval call or Function constructor."""
    if node.type == "call_expression":
        target = node.child_by_field_name("function")
        if target is not None and target.type == "identifier" and target.text == b"eval":
            return _JS_DYNAMIC, "eval"
    elif node.type == "new_expression":
        target = node.child_by_field_name("constructor")
        if target is not None and target.type == "identifier" and target.text == b"Function":
            return _JS_DYNAMIC, "new Function"
    return None


def _match_go(node: Any) -> tuple[_NativeRule, str] | None:
    """Match a Go os/exec command construction."""
    if node.type != "call_expression":
        return None
    function = node.child_by_field_name("function")
    if function is None or function.type != "selector_expression":
        return None
    operand = function.child_by_field_name("operand")
    field = function.child_by_field_name("field")
    if operand is None or field is None:
        return None
    if (
        operand.type == "identifier"
        and operand.text == b"exec"
        and field.text
        in (
            b"Command",
            b"CommandContext",
        )
    ):
        return _GO_COMMAND, f"exec.{field.text.decode('utf-8')}"
    return None


def _match_rust(node: Any) -> tuple[_NativeRule, str] | None:
    """Match a Rust unsafe block."""
    if node.type == "unsafe_block":
        return _RUST_UNSAFE, "unsafe"
    return None


def _match_c(node: Any) -> tuple[_NativeRule, str] | None:
    """Match a C or C++ call to an unbounded or command-executing libc function."""
    if node.type != "call_expression":
        return None
    function = node.child_by_field_name("function")
    if (
        function is None
        or function.type != "identifier"
        or function.text not in _UNSAFE_C_FUNCTIONS
    ):
        return None
    return _C_UNSAFE_LIBC, function.text.decode("utf-8")


def _import_grammars() -> tuple[Any, ...]:
    """Import the optional tree-sitter runtime and every native grammar.

    Isolated so the availability path is testable; a missing optional extra is
    surfaced as an ``ImportError`` that the caller degrades gracefully.
    """
    import tree_sitter
    import tree_sitter_c
    import tree_sitter_cpp
    import tree_sitter_go
    import tree_sitter_javascript
    import tree_sitter_rust
    import tree_sitter_typescript

    return (
        tree_sitter,
        tree_sitter_javascript,
        tree_sitter_typescript,
        tree_sitter_go,
        tree_sitter_rust,
        tree_sitter_c,
        tree_sitter_cpp,
    )


def _load_routes() -> dict[str, tuple[Any, _Matcher]] | None:
    """Return a per-suffix (parser, matcher) map, or ``None`` when the extra is absent."""
    try:
        tree_sitter, javascript, typescript, go, rust, c, cpp = _import_grammars()
    except ImportError:
        return None
    js_parser = tree_sitter.Parser(tree_sitter.Language(javascript.language()))
    ts_parser = tree_sitter.Parser(tree_sitter.Language(typescript.language_typescript()))
    tsx_parser = tree_sitter.Parser(tree_sitter.Language(typescript.language_tsx()))
    go_parser = tree_sitter.Parser(tree_sitter.Language(go.language()))
    rust_parser = tree_sitter.Parser(tree_sitter.Language(rust.language()))
    c_parser = tree_sitter.Parser(tree_sitter.Language(c.language()))
    cpp_parser = tree_sitter.Parser(tree_sitter.Language(cpp.language()))
    return {
        ".js": (js_parser, _match_javascript),
        ".jsx": (js_parser, _match_javascript),
        ".ts": (ts_parser, _match_javascript),
        ".tsx": (tsx_parser, _match_javascript),
        ".go": (go_parser, _match_go),
        ".rs": (rust_parser, _match_rust),
        ".c": (c_parser, _match_c),
        ".h": (c_parser, _match_c),
        ".cc": (cpp_parser, _match_c),
        ".cpp": (cpp_parser, _match_c),
        ".hpp": (cpp_parser, _match_c),
    }


def _line_evidence(item: TrackedFile, line: int) -> str:
    """Return content-addressed evidence without copying repository source."""
    lines = (item.text or "").splitlines()
    content = lines[line - 1] if 0 < line <= len(lines) else ""
    line_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return f"file_sha256={item.content_digest}; line_sha256={line_digest}"


def _findings(root: Any, matcher: _Matcher) -> list[tuple[int, str, _NativeRule]]:
    """Return (line, symbol, rule) for every node the matcher accepts."""
    results: list[tuple[int, str, _NativeRule]] = []
    stack: list[Any] = [root]
    while stack:
        node = stack.pop()
        matched = matcher(node)
        if matched is not None:
            rule, symbol = matched
            results.append((node.start_point[0] + 1, symbol, rule))
        stack.extend(node.children)
    return results


def scan_native(
    inventory: GitInventory,
    policy: AuditPolicy,
) -> tuple[Candidate, ...]:
    """Return native JavaScript, TypeScript, Go, Rust, and C/C++ candidates.

    Parameters
    ----------
    inventory:
        Read-only tracked-content inventory of the repository.
    policy:
        Repository audit policy (accepted for signature parity; every tracked file
        in a supported language is in scope).

    Returns
    -------
    tuple[Candidate, ...]
        Deterministic, anchored candidates. Empty when the optional ``native``
        extra (tree-sitter and the grammars) is not installed.
    """
    del policy
    routes = _load_routes()
    if routes is None:
        return ()
    candidates: list[Candidate] = []
    for item in inventory.files:
        route = routes.get(PurePosixPath(item.path).suffix.lower())
        if route is None or item.text is None:
            continue
        parser, matcher = route
        tree = parser.parse(item.text.encode("utf-8"))
        for line, symbol, rule in sorted(
            _findings(tree.root_node, matcher), key=lambda finding: (finding[0], finding[1])
        ):
            candidates.append(
                Candidate.build(
                    category="application-security",
                    rule_id=rule.rule_id,
                    anchor=TrackedBlobAnchor.build(item, line_start=line),
                    symbol=symbol,
                    evidence=_line_evidence(item, line),
                    confidence=rule.confidence,
                    rationale=rule.rationale,
                    verification=rule.verification,
                )
            )
    return tuple(candidates)
