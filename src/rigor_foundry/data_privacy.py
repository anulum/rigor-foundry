# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — data-and-privacy candidate scanner
"""Collect bounded static data-and-privacy signals from tracked Python."""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass

from .candidate_anchor import TrackedBlobAnchor
from .git_inventory import GitInventory, TrackedFile
from .models import AuditPolicy, Candidate, Confidence

# A credential-bearing identifier component, bounded so 'secretary' is not 'secret'.
_SENSITIVE = re.compile(
    r"(?:^|_)(?:passwords?|passwd|secrets?|credentials?|api_?keys?|access_?keys?"
    r"|secret_?keys?|private_?keys?|auth_?tokens?|access_?tokens?|api_?tokens?)(?:_|$)"
)
# Identifier suffixes that name the concept rather than hold the secret value.
_DESCRIPTOR = re.compile(
    r"_(?:name|type|id|field|label|header|url|path|file|env|var|pattern|regex|prefix"
    r"|suffix|len|length|size|hash|digest|column|param|kind|format|scheme|policy|error"
    r"|message|msg|doc|default|example|placeholder|expiry|ttl|count|list|set|map|dict)s?$"
)
# A PEM private-key block embedded in source is an unambiguous key disclosure.
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
# Obvious non-secret stand-ins that a reviewer should not have to triage.
_PLACEHOLDERS: frozenset[str] = frozenset(
    {
        "",
        "changeme",
        "change-me",
        "password",
        "passwd",
        "secret",
        "none",
        "null",
        "example",
        "redacted",
        "placeholder",
        "todo",
        "fixme",
        "dummy",
        "fake",
        "test",
        "sample",
    }
)


@dataclass(frozen=True)
class _Signal:
    """One classified data-and-privacy signal for a line."""

    rule_id: str
    confidence: Confidence
    symbol: str
    rationale: str
    verification: str


_HARDCODED_CREDENTIAL = _Signal(
    rule_id="DP001-hardcoded-credential",
    confidence="medium",
    symbol="assignment",
    rationale=(
        "A credential-named variable is assigned a string literal, so a secret is "
        "embedded in tracked source where it cannot be rotated and is exposed to "
        "everyone with repository read access."
    ),
    verification=(
        "Load the value from an environment variable or secret manager at runtime and "
        "remove the literal, or confirm it is a non-secret placeholder or fixture."
    ),
)
_EMBEDDED_PRIVATE_KEY = _Signal(
    rule_id="DP002-embedded-private-key",
    confidence="high",
    symbol="private-key",
    rationale=(
        "A PEM private-key block is embedded in tracked source, disclosing key "
        "material to everyone with repository read access."
    ),
    verification=(
        "Remove the key from source, rotate it, and load it at runtime from a secret "
        "store or an out-of-tree file that is never committed."
    ),
)


def _line_evidence(item: TrackedFile, line: int) -> str:
    """Return content-addressed evidence without copying repository source."""
    lines = (item.text or "").splitlines()
    content = lines[line - 1] if 0 < line <= len(lines) else ""
    line_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return f"file_sha256={item.content_digest}; line_sha256={line_digest}"


def _normalise(name: str) -> str:
    """Return a snake-cased, lower-case identifier so camelCase is comparable."""
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def _is_credential_name(name: str) -> bool:
    """Return whether an assignment target names a credential rather than metadata."""
    normalised = _normalise(name)
    if _DESCRIPTOR.search(normalised):
        return False
    return _SENSITIVE.search(normalised) is not None


def _is_secret_literal(value: str) -> bool:
    """Return whether a string literal looks like a real secret, not a placeholder."""
    stripped = value.strip()
    if stripped.lower() in _PLACEHOLDERS:
        return False
    return not (stripped[:1] in {"$", "<", "{"} or "${" in stripped or "{{" in stripped)


def _assignment_targets(node: ast.AST) -> list[ast.expr]:
    """Return the assignment targets of an assignment statement."""
    if isinstance(node, ast.Assign):
        return list(node.targets)
    if isinstance(node, ast.AnnAssign):
        return [node.target]
    return []


def _string_value(node: ast.expr | None) -> str | None:
    """Return the string value of a constant expression, if it is a string."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _hardcoded_credentials(tree: ast.Module) -> list[int]:
    """Return the lines of credential-named assignments of a secret string literal."""
    lines: list[int] = []
    for node in ast.walk(tree):
        value = _string_value(getattr(node, "value", None))
        if value is None or not _is_secret_literal(value):
            continue
        for target in _assignment_targets(node):
            if isinstance(target, ast.Name) and _is_credential_name(target.id):
                lines.append(node.lineno)
                break
    return lines


def _embedded_private_keys(tree: ast.Module) -> list[int]:
    """Return the lines of string literals that embed a PEM private-key block."""
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and _PRIVATE_KEY.search(node.value)
    ]


def _file_candidates(item: TrackedFile) -> tuple[Candidate, ...]:
    """Collect data-and-privacy candidates from one tracked Python file."""
    if item.text is None or not item.path.endswith(".py"):
        return ()
    try:
        tree = ast.parse(item.text, filename=item.path)
    except SyntaxError:
        return ()
    findings: list[tuple[int, _Signal]] = []
    findings.extend((line, _HARDCODED_CREDENTIAL) for line in _hardcoded_credentials(tree))
    findings.extend((line, _EMBEDDED_PRIVATE_KEY) for line in _embedded_private_keys(tree))
    return tuple(
        Candidate.build(
            category="data-privacy",
            rule_id=signal.rule_id,
            anchor=TrackedBlobAnchor.build(item, line_start=line),
            symbol=signal.symbol,
            evidence=_line_evidence(item, line),
            confidence=signal.confidence,
            rationale=signal.rationale,
            verification=signal.verification,
        )
        for line, signal in sorted(findings, key=lambda finding: (finding[0], finding[1].rule_id))
    )


def scan_data_privacy(
    inventory: GitInventory,
    policy: AuditPolicy,
) -> tuple[Candidate, ...]:
    """Return bounded data-and-privacy candidates for the tracked Python surface.

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
