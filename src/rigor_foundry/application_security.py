# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — application-security candidate scanner
"""Collect bounded static application-security signals from tracked Python."""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass

from .candidate_anchor import TrackedBlobAnchor
from .git_inventory import GitInventory, TrackedFile
from .models import AuditPolicy, Candidate, Confidence


@dataclass(frozen=True)
class _Signal:
    """One classified application-security signal for a call node."""

    rule_id: str
    confidence: Confidence
    rationale: str
    verification: str


_DYNAMIC_EXEC = _Signal(
    rule_id="AS001-dynamic-code-execution",
    confidence="high",
    rationale="eval and exec run arbitrary code and turn any tainted argument into execution.",
    verification=(
        "Trace the argument to a trusted literal or a validated allow-list; otherwise replace the "
        "call with an explicit parser, dispatch table, or sandboxed evaluator."
    ),
)
_SHELL_EXEC = _Signal(
    rule_id="AS002-shell-command-execution",
    confidence="high",
    rationale="A shell command surface lets a tainted argument inject additional commands.",
    verification=(
        "Pass an argument vector without a shell (shell=False, or subprocess with a list), or prove "
        "every interpolated value is a trusted constant."
    ),
)
_UNSAFE_DESERIALIZE = _Signal(
    rule_id="AS003-unsafe-deserialization",
    confidence="high",
    rationale="pickle and the default yaml.load reconstruct arbitrary objects from their input.",
    verification=(
        "Deserialize only trusted local data, or switch to a bounded safe format (yaml.safe_load, "
        "JSON, or a schema-validated parser) for any externally sourced bytes."
    ),
)
_WEAK_HASH = _Signal(
    rule_id="AS004-weak-hash-primitive",
    confidence="low",
    rationale="md5 and sha1 are not collision resistant and must not back a security decision.",
    verification=(
        "Confirm the digest is a non-security checksum; otherwise move to SHA-256 or a keyed MAC and "
        "record why the primitive is acceptable."
    ),
)
_INSECURE_TEMP = _Signal(
    rule_id="AS005-insecure-temporary-file",
    confidence="high",
    rationale="tempfile.mktemp returns a name with a race between the check and the later open.",
    verification=(
        "Use tempfile.mkstemp or NamedTemporaryFile, which create the file atomically with a bound "
        "descriptor."
    ),
)
_DISABLED_TLS = _Signal(
    rule_id="AS012-disabled-tls-verification",
    confidence="high",
    rationale=(
        "verify=False disables certificate verification, so a network attacker can present any "
        "certificate and read or alter the traffic."
    ),
    verification=(
        "Restore verification (verify=True or a trusted CA bundle); if a self-signed host is truly "
        "required, pin its certificate instead of disabling verification."
    ),
)
_INSECURE_SSL = _Signal(
    rule_id="AS013-insecure-ssl-context",
    confidence="high",
    rationale=(
        "ssl._create_unverified_context returns a context that accepts any certificate, so the peer "
        "is never authenticated."
    ),
    verification=(
        "Use ssl.create_default_context, or a context with an explicit trusted CA, so the peer "
        "certificate is verified."
    ),
)


def _line_evidence(item: TrackedFile, line: int) -> str:
    """Return content-addressed evidence without copying repository source."""
    lines = (item.text or "").splitlines()
    content = lines[line - 1] if 0 < line <= len(lines) else ""
    line_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return f"file_sha256={item.content_digest}; line_sha256={line_digest}"


def _call_target(node: ast.expr) -> str:
    """Return a readable dotted name for a call target expression."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_call_target(node.value)}.{node.attr}"
    return "<expr>"


def _has_shell_true(node: ast.Call) -> bool:
    """Return whether the call passes a literal ``shell=True`` keyword."""
    return any(
        keyword.arg == "shell"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is True
        for keyword in node.keywords
    )


def _has_verify_false(node: ast.Call) -> bool:
    """Return whether the call passes a literal ``verify=False`` keyword."""
    return any(
        keyword.arg == "verify"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is False
        for keyword in node.keywords
    )


def _is_attribute(node: ast.expr, module: str, attributes: frozenset[str]) -> bool:
    """Return whether ``node`` is ``module.<attr>`` for one accepted attribute."""
    return (
        isinstance(node, ast.Attribute)
        and node.attr in attributes
        and isinstance(node.value, ast.Name)
        and node.value.id == module
    )


def _classify(node: ast.Call) -> _Signal | None:
    """Return the application-security signal for one call node, if any."""
    func = node.func
    if isinstance(func, ast.Name) and func.id in {"eval", "exec"}:
        return _DYNAMIC_EXEC
    if _has_shell_true(node) or _is_attribute(func, "os", frozenset({"system", "popen"})):
        return _SHELL_EXEC
    if _is_attribute(func, "pickle", frozenset({"load", "loads"})):
        return _UNSAFE_DESERIALIZE
    if _is_attribute(func, "yaml", frozenset({"load"})) and _is_unbounded_yaml(node):
        return _UNSAFE_DESERIALIZE
    if _is_attribute(func, "hashlib", frozenset({"md5", "sha1"})):
        return _WEAK_HASH
    if _is_attribute(func, "tempfile", frozenset({"mktemp"})):
        return _INSECURE_TEMP
    if _has_verify_false(node):
        return _DISABLED_TLS
    if _is_attribute(func, "ssl", frozenset({"_create_unverified_context"})):
        return _INSECURE_SSL
    return None


def _is_unbounded_yaml(node: ast.Call) -> bool:
    """Return whether a ``yaml.load`` call omits an explicit loader."""
    has_loader_keyword = any(keyword.arg == "Loader" for keyword in node.keywords)
    return len(node.args) < 2 and not has_loader_keyword


def _file_candidates(item: TrackedFile) -> tuple[Candidate, ...]:
    """Collect application-security candidates from one tracked Python file."""
    if item.text is None or not item.path.endswith(".py"):
        return ()
    try:
        tree = ast.parse(item.text, filename=item.path)
    except SyntaxError:
        return ()
    findings: list[tuple[int, _Signal, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        signal = _classify(node)
        if signal is not None:
            findings.append((node.lineno, signal, _call_target(node.func)))
    return tuple(
        Candidate.build(
            category="application-security",
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


def scan_application_security(
    inventory: GitInventory,
    policy: AuditPolicy,
) -> tuple[Candidate, ...]:
    """Return bounded application-security candidates for the tracked Python surface.

    Parameters
    ----------
    inventory:
        Read-only tracked-content inventory of the repository.
    policy:
        Repository audit policy (accepted for signature parity; every tracked
        Python file is in scope because security defects are not test-only).

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
