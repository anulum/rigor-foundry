# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — operations and observability candidate scanner
"""Collect bounded library-output and credential-logging review signals."""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import PurePosixPath

from .candidate_anchor import TrackedBlobAnchor
from .git_inventory import GitInventory, TrackedFile
from .language_capabilities import is_test_path, repository_path_under_roots
from .models import AuditPolicy, Candidate, Confidence
from .python_output import bound_target_names, print_lines

_SCRIPT_ROOTS = frozenset({"bin", "scripts", "tools"})
_CLI_STEMS = frozenset({"__main__", "cli"})
_LOG_METHODS = frozenset({"critical", "debug", "error", "exception", "info", "log", "warning"})
_SENSITIVE = re.compile(
    r"(?:^|_)(?:passwords?|passwd|secrets?|credentials?|api_?keys?|access_?keys?"
    r"|secret_?keys?|private_?keys?|auth_?tokens?|access_?tokens?|api_?tokens?)(?:_|$)"
)
_DESCRIPTOR = re.compile(
    r"_(?:name|type|id|field|label|header|url|path|file|env|var|pattern|regex|prefix"
    r"|suffix|len|length|size|hash|digest|kind|format|scheme|count|list|set|map|dict)s?$"
)


def _line_evidence(item: TrackedFile, line: int) -> str:
    """Return exact file/line content identities without source text."""
    lines = (item.text or "").splitlines()
    content = lines[line - 1] if 0 < line <= len(lines) else ""
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return f"file_sha256={item.content_digest}; line_sha256={digest}"


def _normalise(name: str) -> str:
    """Return a snake-cased, lower-case identifier."""
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def _sensitive_name(name: str) -> bool:
    """Return whether an identifier names credential material, not metadata."""
    normalised = _normalise(name)
    return _DESCRIPTOR.search(normalised) is None and _SENSITIVE.search(normalised) is not None


def _production_python(item: TrackedFile, policy: AuditPolicy) -> bool:
    """Return whether one tracked file is in bounded Python library scope."""
    pure = PurePosixPath(item.path)
    return (
        item.text is not None
        and pure.suffix.lower() == ".py"
        and repository_path_under_roots(item.path, policy.source_roots)
        and not is_test_path(item.path, policy.test_roots)
        and pure.parts[0].casefold() not in _SCRIPT_ROOTS
        and pure.stem.casefold() not in _CLI_STEMS
        and not pure.stem.casefold().endswith("_cli")
    )


def _logging_bindings(
    tree: ast.Module,
) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """Return logging-module aliases and logger instances."""
    modules: set[str] = set()
    factories: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(
                alias.asname or "logging" for alias in node.names if alias.name == "logging"
            )
        elif isinstance(node, ast.ImportFrom) and node.module == "logging":
            factories.update(
                alias.asname or alias.name for alias in node.names if alias.name == "getLogger"
            )
    loggers: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or not isinstance(
            node.value, ast.Call
        ):
            continue
        function = node.value.func
        factory = isinstance(function, ast.Name) and function.id in factories
        module_factory = (
            isinstance(function, ast.Attribute)
            and isinstance(function.value, ast.Name)
            and function.value.id in modules
            and function.attr == "getLogger"
        )
        if not (factory or module_factory):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            loggers.update(bound_target_names(target))
    return frozenset(modules), frozenset(factories), frozenset(loggers)


def _credential_argument(call: ast.Call) -> bool:
    """Return whether a log argument directly contains a credential-named expression."""
    expressions = [*call.args, *(keyword.value for keyword in call.keywords)]
    return any(
        _sensitive_name(node.id if isinstance(node, ast.Name) else node.attr)
        for expression in expressions
        for node in ast.walk(expression)
        if isinstance(node, (ast.Name, ast.Attribute))
    )


def _log_lines(tree: ast.Module) -> tuple[tuple[int, str], ...]:
    """Return import-bound logging calls that carry credential-named expressions."""
    modules, factories, loggers = _logging_bindings(tree)
    findings: set[tuple[int, str]] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        receiver = node.func.value
        bound = isinstance(receiver, ast.Name) and receiver.id in modules | loggers
        chained_module = (
            isinstance(receiver, ast.Call)
            and isinstance(receiver.func, ast.Attribute)
            and isinstance(receiver.func.value, ast.Name)
            and receiver.func.value.id in modules
            and receiver.func.attr == "getLogger"
        )
        chained_factory = (
            isinstance(receiver, ast.Call)
            and isinstance(receiver.func, ast.Name)
            and receiver.func.id in factories
        )
        if (
            (bound or chained_module or chained_factory)
            and node.func.attr in _LOG_METHODS
            and _credential_argument(node)
        ):
            findings.add((node.lineno, node.func.attr))
    return tuple(sorted(findings))


def _file_candidates(item: TrackedFile, policy: AuditPolicy) -> tuple[Candidate, ...]:
    """Collect operations candidates from one bounded production Python owner."""
    if not _production_python(item, policy):
        return ()
    try:
        tree = ast.parse(item.text or "", filename=item.path)
    except SyntaxError:
        return ()
    findings: list[tuple[int, str, str, Confidence, str, str]] = []
    findings.extend(
        (
            line,
            "OP001-print-in-library-code",
            "print",
            "medium",
            "Library code writes directly to process output, bypassing caller-controlled observability and output routing.",
            "Replace incidental output with a returned value or structured logger, or prove the module is an intentional command boundary.",
        )
        for line in print_lines(tree)
    )
    findings.extend(
        (
            line,
            "OP002-credential-in-log-call",
            method,
            "high",
            "A credential-named expression is passed to an import-bound logging call and may disclose sensitive material.",
            "Remove or redact the credential value before logging and verify captured logs contain only non-sensitive identifiers or digests.",
        )
        for line, method in _log_lines(tree)
    )
    return tuple(
        Candidate.build(
            category="operations",
            rule_id=rule_id,
            anchor=TrackedBlobAnchor.build(item, line_start=line),
            symbol=symbol,
            evidence=_line_evidence(item, line),
            confidence=confidence,
            rationale=rationale,
            verification=verification,
        )
        for line, rule_id, symbol, confidence, rationale, verification in sorted(findings)
    )


def scan_operations(inventory: GitInventory, policy: AuditPolicy) -> tuple[Candidate, ...]:
    """Return bounded operations and observability review candidates."""
    return tuple(
        candidate for item in inventory.files for candidate in _file_candidates(item, policy)
    )
