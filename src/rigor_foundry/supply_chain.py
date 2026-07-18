# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — supply-chain candidate scanner
"""Collect bounded static supply-chain signals from tracked requirement files."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from .candidate_anchor import TrackedBlobAnchor
from .git_inventory import GitInventory, TrackedFile
from .models import AuditPolicy, Candidate, Confidence

_REQUIREMENT_SUFFIXES: frozenset[str] = frozenset({".txt", ".in"})
# A pinned requirement names a distribution and an exact '==' or '===' version.
_PINNED_REQUIREMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?\s*===?")
# A direct VCS checkout or URL reference bypasses the index and hash pinning.
_VCS_URL_REQUIREMENT = re.compile(
    r"(?:git|hg|svn|bzr)\+[a-z0-9]+://"  # direct VCS checkout install
    r"|\s@\s*https?://"  # PEP 508 direct URL reference (name @ url)
)


@dataclass(frozen=True)
class _Signal:
    """One classified supply-chain signal for a requirement line."""

    rule_id: str
    confidence: Confidence
    symbol: str
    rationale: str
    verification: str


_UNHASHED_PIN = _Signal(
    rule_id="SC001-unhashed-pinned-requirement",
    confidence="high",
    symbol="pinned-requirement",
    rationale=(
        "A hash-pinned lock file records integrity digests for every dependency, but "
        "this pinned requirement carries none, so its artefact is installed without "
        "verification against tampering or index substitution."
    ),
    verification=(
        "Recompile the lock with hashes (for example `pip-compile --generate-hashes`) "
        "so every pinned requirement carries a `--hash=` digest, or justify why this "
        "dependency is exempt."
    ),
)
_VCS_URL = _Signal(
    rule_id="SC002-vcs-url-requirement",
    confidence="high",
    symbol="vcs-url-requirement",
    rationale=(
        "A dependency installed directly from a VCS checkout or a URL bypasses the "
        "package index and hash pinning, so the resolved artefact is mutable and "
        "unverified."
    ),
    verification=(
        "Pin the dependency to an immutable released version from the index with a "
        "recorded hash, or vendor and audit the exact revision if a direct source is "
        "genuinely required."
    ),
)


def _line_evidence(item: TrackedFile, line: int) -> str:
    """Return content-addressed evidence without copying repository source."""
    lines = (item.text or "").splitlines()
    content = lines[line - 1] if 0 < line <= len(lines) else ""
    line_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return f"file_sha256={item.content_digest}; line_sha256={line_digest}"


def _is_requirements_file(path: str) -> bool:
    """Return whether a tracked path is a Python requirement specification file."""
    pure = PurePosixPath(path)
    if pure.suffix not in _REQUIREMENT_SUFFIXES:
        return False
    return pure.name.startswith("requirements") or "requirements" in pure.parent.parts


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Join backslash-continued physical lines, keeping each block's first line."""
    results: list[tuple[int, str]] = []
    start: int | None = None
    buffer = ""
    for lineno, line in enumerate(text.splitlines(), start=1):
        if start is None:
            start = lineno
        if line.endswith("\\"):
            buffer += line[:-1]
            continue
        results.append((start, buffer + line))
        start = None
        buffer = ""
    if start is not None:
        results.append((start, buffer))
    return results


def _file_candidates(item: TrackedFile) -> tuple[Candidate, ...]:
    """Collect supply-chain candidates from one tracked requirement file."""
    if item.text is None or not _is_requirements_file(item.path):
        return ()
    logical = _logical_lines(item.text)
    hash_mode = any("--hash=" in text for _, text in logical)
    findings: list[tuple[int, _Signal]] = []
    for lineno, text in logical:
        stripped = text.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if hash_mode and "--hash=" not in text and _PINNED_REQUIREMENT.match(stripped):
            findings.append((lineno, _UNHASHED_PIN))
        if _VCS_URL_REQUIREMENT.search(text):
            findings.append((lineno, _VCS_URL))
    return tuple(
        Candidate.build(
            category="supply-chain",
            rule_id=signal.rule_id,
            anchor=TrackedBlobAnchor.build(item, line_start=lineno),
            symbol=signal.symbol,
            evidence=_line_evidence(item, lineno),
            confidence=signal.confidence,
            rationale=signal.rationale,
            verification=signal.verification,
        )
        for lineno, signal in sorted(
            findings, key=lambda finding: (finding[0], finding[1].rule_id)
        )
    )


def scan_supply_chain(
    inventory: GitInventory,
    policy: AuditPolicy,
) -> tuple[Candidate, ...]:
    """Return bounded supply-chain candidates for tracked requirement files.

    Parameters
    ----------
    inventory:
        Read-only tracked-content inventory of the repository.
    policy:
        Repository audit policy (accepted for signature parity; every tracked
        requirement file is in scope).

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
