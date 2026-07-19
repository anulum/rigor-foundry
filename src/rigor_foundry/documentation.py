# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — documentation, claims, and IP candidate scanner
"""Collect bounded licence-header and package-version documentation signals."""

from __future__ import annotations

import hashlib
import re
import tomllib
from dataclasses import dataclass
from pathlib import PurePosixPath

from .audit_primitives import require_mapping, require_string
from .candidate_anchor import TrackedBlobAnchor
from .git_inventory import GitInventory, TrackedFile
from .language_capabilities import repository_path_under_roots, suffixes_with
from .models import AuditPolicy, Candidate

_SPDX_MARKER = "SPDX-License-" + "Identifier:"
_HEADER_LINE_LIMIT = 5
_COMMENT_PREFIXES = ("#", "//", "/*", "*", "--", "/-")
_SOURCE_SUFFIXES = suffixes_with("responsibility")
_DOCUMENT_SUFFIXES = frozenset({".md", ".rst"})
_HISTORICAL_DOCUMENTS = frozenset({"changelog", "changes", "history", "release-notes", "releases"})
_DISTRIBUTION_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\Z")
_VERSION_PATTERN = r"[0-9](?:[A-Za-z0-9.!+_-]*[A-Za-z0-9])?"


@dataclass(frozen=True)
class _ProjectIdentity:
    """Static distribution identity read from root ``pyproject.toml``."""

    name: str
    version: str


def _line_evidence(item: TrackedFile, line: int, **identities: str) -> str:
    """Return bounded content identities for one exact tracked line."""
    lines = (item.text or "").splitlines()
    content = lines[line - 1] if lines else ""
    fields = {
        "file_sha256": item.content_digest,
        "line_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        **{
            f"{name}_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest()
            for name, value in identities.items()
        },
    }
    return "; ".join(f"{name}={value}" for name, value in sorted(fields.items()))


def _has_spdx_header(text: str) -> bool:
    """Return whether the bounded leading header declares an SPDX licence."""
    return any(
        stripped.startswith(_COMMENT_PREFIXES) and _SPDX_MARKER in stripped
        for line in text.splitlines()[:_HEADER_LINE_LIMIT]
        if (stripped := line.lstrip())
    )


def _source_candidate(item: TrackedFile, policy: AuditPolicy) -> Candidate | None:
    """Return a missing-header candidate for one in-scope source file."""
    if (
        item.text is None
        or PurePosixPath(item.path).suffix.lower() not in _SOURCE_SUFFIXES
        or not repository_path_under_roots(item.path, policy.source_roots)
        or _has_spdx_header(item.text)
    ):
        return None
    return Candidate.build(
        category="documentation",
        rule_id="DC001-missing-license-header",
        anchor=TrackedBlobAnchor.build(item, line_start=1),
        symbol="spdx-license-header",
        evidence=_line_evidence(item, 1),
        confidence="high",
        rationale=(
            "A tracked source owner has no SPDX licence identifier in its leading header, "
            "so automated licence inventory cannot establish its declared licence."
        ),
        verification=(
            "Confirm the file's intended licence with the repository owner, then add the exact "
            "SPDX-License-Identifier header or record why the source is separately licensed."
        ),
    )


def _project_identity(inventory: GitInventory) -> _ProjectIdentity | None:
    """Return a static PEP 621 name/version pair when it is unambiguous."""
    matches = tuple(
        item for item in inventory.files if item.path == "pyproject.toml" and item.text is not None
    )
    if len(matches) != 1:
        return None
    try:
        parsed: object = tomllib.loads(matches[0].text or "")
        document = require_mapping(parsed, "pyproject")
        project = require_mapping(document.get("project"), "pyproject.project")
        name = require_string(project.get("name"), "pyproject.project.name")
        version = require_string(project.get("version"), "pyproject.project.version")
    except ValueError:
        return None
    if _DISTRIBUTION_NAME.fullmatch(name) is None:
        return None
    return _ProjectIdentity(name=name, version=version)


def _documentation_path(path: str) -> bool:
    """Return whether a public README or documentation page can state package versions."""
    pure = PurePosixPath(path)
    suffix = pure.suffix.lower()
    if suffix not in _DOCUMENT_SUFFIXES or pure.stem.casefold() in _HISTORICAL_DOCUMENTS:
        return False
    if len(pure.parts) == 1:
        return pure.name.casefold().startswith("readme")
    return pure.parts[0] == "docs" and pure.parts[:2] != ("docs", "internal")


def _version_pattern(distribution_name: str) -> re.Pattern[str]:
    """Compile a separator-normalised explicit distribution-version pattern."""
    components = tuple(
        re.escape(component) for component in re.split(r"[-_.]+", distribution_name) if component
    )
    name = r"[-_.]".join(components)
    return re.compile(
        rf"(?<![A-Za-z0-9]){name}(?:\[[^\]\n]+\])?"
        rf"(?:\s*==\s*|\s+v|\s+version\s+)(?P<version>{_VERSION_PATTERN})"
        r"(?![A-Za-z0-9])",
        re.IGNORECASE,
    )


def _documentation_candidates(
    item: TrackedFile,
    identity: _ProjectIdentity,
) -> tuple[Candidate, ...]:
    """Return stale explicit package-version statements from one public document."""
    if item.text is None or not _documentation_path(item.path):
        return ()
    pattern = _version_pattern(identity.name)
    stale_lines = tuple(
        lineno
        for lineno, line in enumerate(item.text.splitlines(), start=1)
        if any(match.group("version") != identity.version for match in pattern.finditer(line))
    )
    return tuple(
        Candidate.build(
            category="documentation",
            rule_id="DC002-doc-version-drift",
            anchor=TrackedBlobAnchor.build(item, line_start=line),
            symbol="documented-package-version",
            evidence=_line_evidence(
                item,
                line,
                expected_version=identity.version,
                package_name=identity.name,
            ),
            confidence="high",
            rationale=(
                "A public README or documentation page names an explicit package version that "
                "differs from the repository's static PEP 621 project version."
            ),
            verification=(
                "Compare the statement with pyproject.toml [project].version, update current "
                "installation or compatibility guidance, or move genuinely historical text to "
                "a changelog or release-note surface."
            ),
        )
        for line in stale_lines
    )


def scan_documentation(
    inventory: GitInventory,
    policy: AuditPolicy,
) -> tuple[Candidate, ...]:
    """Return bounded documentation, claims, and IP candidates.

    Parameters
    ----------
    inventory:
        Read-only tracked-content inventory of the repository.
    policy:
        Repository policy defining exact production source roots.

    Returns
    -------
    tuple[Candidate, ...]
        Deterministic, anchored, needs-evidence candidates.
    """
    identity = _project_identity(inventory)
    candidates = tuple(
        candidate
        for item in inventory.files
        if (candidate := _source_candidate(item, policy)) is not None
    )
    if identity is None:
        return candidates
    return candidates + tuple(
        candidate
        for item in inventory.files
        for candidate in _documentation_candidates(item, identity)
    )
