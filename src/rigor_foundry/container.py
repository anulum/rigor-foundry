# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — container-image hardening candidate scanner
"""Collect bounded static container-image hardening signals from Dockerfiles."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from .candidate_anchor import TrackedBlobAnchor
from .git_inventory import GitInventory, TrackedFile
from .models import AuditPolicy, Candidate, Confidence

# A reproducible base image is pinned by an immutable content digest.
_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}\b")
# Users that leave the container running with full root authority.
_ROOT_USERS: frozenset[str] = frozenset({"root", "0"})


@dataclass(frozen=True)
class _Signal:
    """One classified container-hardening signal for a Dockerfile line."""

    rule_id: str
    confidence: Confidence
    symbol: str
    rationale: str
    verification: str


_UNPINNED_BASE = _Signal(
    rule_id="DK001-unpinned-base-image",
    confidence="high",
    symbol="base-image",
    rationale=(
        "A base image referenced only by tag is mutable, so the resolved image can "
        "change under the same Dockerfile and is never verified against a known digest."
    ),
    verification=(
        "Pin the base image to an immutable `@sha256:` digest (for example "
        "`python:3.12-slim@sha256:...`), or justify why a moving tag is required."
    ),
)
_ROOT_RUNTIME = _Signal(
    rule_id="DK002-root-runtime-user",
    confidence="high",
    symbol="runtime-user",
    rationale=(
        "The final image stage sets no non-root USER, so the container runs as root "
        "and a process escape keeps full root authority inside the namespace."
    ),
    verification=(
        "Add a `USER` directive selecting an unprivileged account (and create it if "
        "needed) as the last identity in the runtime stage, or justify the root run."
    ),
)


def _line_evidence(item: TrackedFile, line: int) -> str:
    """Return content-addressed evidence without copying repository source."""
    lines = (item.text or "").splitlines()
    content = lines[line - 1] if 0 < line <= len(lines) else ""
    line_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    return f"file_sha256={item.content_digest}; line_sha256={line_digest}"


def _is_dockerfile(path: str) -> bool:
    """Return whether a tracked path is a Docker or OCI build recipe."""
    name = PurePosixPath(path).name.lower()
    return (
        name in {"dockerfile", "containerfile"}
        or name.startswith("dockerfile.")
        or name.endswith((".dockerfile", ".containerfile"))
    )


def _instructions(text: str) -> list[tuple[int, str]]:
    """Join backslash-continued lines into instructions, dropping comments and blanks."""
    results: list[tuple[int, str]] = []
    start: int | None = None
    buffer = ""
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if buffer == "" and (not line or line.startswith("#")):
            continue
        if start is None:
            start = lineno
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        results.append((start, (buffer + line).strip()))
        start = None
        buffer = ""
    if start is not None:
        results.append((start, buffer.strip()))
    return results


def _directive(instruction: str) -> str:
    """Return the upper-case directive keyword of one instruction."""
    return instruction.split(maxsplit=1)[0].upper()


def _parse_from(instruction: str) -> tuple[str, str | None]:
    """Return the image reference and optional stage name of a FROM instruction."""
    operands = [token for token in instruction.split()[1:] if not token.startswith("--")]
    image = operands[0] if operands else ""
    stage = None
    if len(operands) >= 3 and operands[1].upper() == "AS":
        stage = operands[2].lower()
    return image, stage


def _runtime_user(instruction: str) -> str:
    """Return the lower-case account of a USER instruction, without any group."""
    operands = instruction.split()
    account = operands[1] if len(operands) >= 2 else ""
    return account.split(":", 1)[0].lower()


def _file_candidates(item: TrackedFile) -> tuple[Candidate, ...]:
    """Collect container-hardening candidates from one tracked Dockerfile."""
    if item.text is None or not _is_dockerfile(item.path):
        return ()
    instructions = _instructions(item.text)
    from_lines = [
        (lineno, *_parse_from(text)) for lineno, text in instructions if _directive(text) == "FROM"
    ]
    stage_names = {stage for _, _, stage in from_lines if stage is not None}
    findings: list[tuple[int, _Signal]] = []
    for lineno, image, _stage in from_lines:
        base = image.split("@", 1)[0].split(":", 1)[0].lower()
        if base == "scratch" or base in stage_names:
            continue
        if not _DIGEST.search(image):
            findings.append((lineno, _UNPINNED_BASE))
    if from_lines:
        runtime_line = from_lines[-1][0]
        effective_user: str | None = None
        for lineno, text in instructions:
            if lineno >= runtime_line and _directive(text) == "USER":
                effective_user = _runtime_user(text)
        if effective_user is None or effective_user in _ROOT_USERS:
            findings.append((runtime_line, _ROOT_RUNTIME))
    return tuple(
        Candidate.build(
            category="container",
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


def scan_container(
    inventory: GitInventory,
    policy: AuditPolicy,
) -> tuple[Candidate, ...]:
    """Return bounded container-image hardening candidates for tracked Dockerfiles.

    Parameters
    ----------
    inventory:
        Read-only tracked-content inventory of the repository.
    policy:
        Repository audit policy (accepted for signature parity; every tracked
        Dockerfile is in scope).

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
