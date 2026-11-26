# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — lockfile integrity rules over a repository
"""Classify every tracked lockfile of a repository, and raise its findings as candidates.

Each tracked file with a lockfile name yields one result: classified entry by entry, or
refused with a named reason and no entries. npm lockfiles are classified; the other kinds
are refused as ``unsupported-file-kind`` until their own rules exist, so an unread file
never looks clean. Each finding of an entry the lockfile itself records becomes one
supply-chain candidate at the entry's line; a bundled entry repeats its ancestor's
findings in the report, but not as candidates. A refused file becomes one candidate.
"""

from __future__ import annotations

import hashlib
import os
import posixpath
from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from .candidate_anchor import RepositoryTreeAnchor, TrackedBlobAnchor
from .git_inventory import GitInventory, TrackedFile
from .lockfile_kinds import is_lockfile_path, lockfile_kind
from .lockfile_model import EntryFinding, LockfileKind, LockfileRefusal, LockfileResult
from .lockfile_npm import classify_npm_lockfile
from .lockfile_npmrc import (
    DEFAULT_NPM_REGISTRY,
    UNKNOWN_NPM_REGISTRY,
    NpmRegistryDeclaration,
    read_npmrc,
)
from .models import Candidate, Confidence
from .rule_guidance import RuleGuidance

REFUSED_RULE_ID: Final = "SC003-lockfile-refused"
FINDING_RULE_IDS: Final[Mapping[EntryFinding, str]] = MappingProxyType(
    {
        "missing-digest": "SC004-lockfile-missing-digest",
        "weak-digest": "SC005-lockfile-weak-digest",
        "malformed-digest": "SC006-lockfile-malformed-digest",
        "floating-ref": "SC007-lockfile-floating-ref",
        "origin-mismatch": "SC008-lockfile-origin-mismatch",
        "origin-unknown": "SC009-lockfile-origin-unknown",
        "path-escape": "SC010-lockfile-path-escape",
        "unknown-form": "SC012-lockfile-unknown-form",
    }
)
_MEDIUM_CONFIDENCE: Final[frozenset[EntryFinding]] = frozenset({"origin-unknown", "unknown-form"})
_NPMRC: Final = ".npmrc"

# Fixed rule guidance, the single source for the candidates below and the rule catalogue.
RULE_GUIDANCE: Final[Mapping[str, RuleGuidance]] = MappingProxyType(
    {
        REFUSED_RULE_ID: RuleGuidance(
            rationale=(
                "A tracked lockfile could not be classified, so none of its entries has an "
                "integrity verdict; an unread lockfile is never evidence that its "
                "dependencies are pinned."
            ),
            verification=(
                "Read the refusal reason in the candidate evidence. Regenerate the lockfile "
                "with a supported tool version, remove the conflicting or hostile content, or "
                "record why this lockfile kind is outside the review."
            ),
        ),
        "SC004-lockfile-missing-digest": RuleGuidance(
            rationale=(
                "The locked artifact records no integrity digest, so the installer cannot "
                "detect a substituted or tampered download."
            ),
            verification=(
                "Regenerate the lockfile so the entry records a SHA-256 or stronger digest, "
                "and confirm that the digest matches the artifact the registry serves."
            ),
        ),
        "SC005-lockfile-weak-digest": RuleGuidance(
            rationale=(
                "The locked artifact is protected only by SHA-1 or MD5, whose collision "
                "resistance no longer pins content against a capable adversary."
            ),
            verification=(
                "Regenerate the lockfile with a current tool so the entry records SHA-512, "
                "SHA-384 or SHA-256, and confirm the new digest against the registry."
            ),
        ),
        "SC006-lockfile-malformed-digest": RuleGuidance(
            rationale=(
                "A listed digest does not decode: its algorithm, encoding or length is wrong. "
                "A malformed digest beside a valid one is never ignored, because tools "
                "differ in which one they check."
            ),
            verification=(
                "Inspect the entry's digest text, find how it was produced, and regenerate "
                "the entry from the registry rather than editing the digest by hand."
            ),
        ),
        "SC007-lockfile-floating-ref": RuleGuidance(
            rationale=(
                "The VCS source names a branch, a tag or an abbreviated commit, so the code "
                "it installs can change without the lockfile changing."
            ),
            verification=(
                "Pin the dependency to a full commit id, or to a released version from the "
                "registry with an accepted digest, and regenerate the lockfile."
            ),
        ),
        "SC008-lockfile-origin-mismatch": RuleGuidance(
            rationale=(
                "The artifact resolves from a host that is not the registry the repository "
                "declares, which can mean dependency confusion or an unreviewed mirror."
            ),
            verification=(
                "Confirm that the host is an intended source, then declare it in the "
                "repository's registry configuration, or regenerate the entry from the "
                "declared registry."
            ),
        ),
        "SC009-lockfile-origin-unknown": RuleGuidance(
            rationale=(
                "The repository's registry declaration cannot be read with certainty, so the "
                "artifact's origin cannot be compared; an unknown origin is never a pass."
            ),
            verification=(
                "Track the registry configuration in the repository without environment "
                "interpolation or a replaced placeholder host, then rescan."
            ),
        ),
        "SC010-lockfile-path-escape": RuleGuidance(
            rationale=(
                "A local dependency path resolves outside the repository root, so its "
                "content is neither versioned nor reviewed with the repository."
            ),
            verification=(
                "Move the dependency inside the repository, or replace it with a pinned "
                "registry or VCS source."
            ),
        ),
        "SC012-lockfile-unknown-form": RuleGuidance(
            rationale=(
                "The entry uses a form these rules do not know, so it has no integrity "
                "verdict; an unknown form is reported rather than skipped."
            ),
            verification=(
                "Identify how the entry is resolved and fetched, and confirm its integrity by "
                "other means, or regenerate the lockfile with a supported tool."
            ),
        ),
    }
)


def _sha256(text: str) -> str:
    """Return the SHA-256 of a string, so evidence never copies repository text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def npm_registry_declaration(inventory: GitInventory, lock_path: str) -> NpmRegistryDeclaration:
    """Return the registry the repository declares for one npm lockfile.

    The ``.npmrc`` beside the lockfile is read first, then the one at the repository root.
    An ``.npmrc`` that is present but untracked, or tracked but unreadable, makes the
    declaration unknown. With no ``.npmrc`` at either place, npm's default registry applies.

    Parameters
    ----------
    inventory : GitInventory
        The tracked repository content.
    lock_path : str
        The lockfile's repository-relative POSIX path.

    Returns
    -------
    NpmRegistryDeclaration
        The declaration.
    """
    tracked = {item.path: item for item in inventory.files}
    directory = posixpath.dirname(lock_path)
    for place in dict.fromkeys((directory, "")):
        path = posixpath.join(place, _NPMRC)
        item = tracked.get(path)
        if item is not None:
            return UNKNOWN_NPM_REGISTRY if item.text is None else read_npmrc(item.text)
        if os.path.lexists(inventory.root / path):
            return UNKNOWN_NPM_REGISTRY
    return DEFAULT_NPM_REGISTRY


def _refused(
    item: TrackedFile, kind: LockfileKind | None, reason: LockfileRefusal
) -> LockfileResult:
    """Return the result of a whole file refused for one named reason."""
    return LockfileResult(item.path, item.content_digest, kind, None, reason.reason, ())


def _assess(inventory: GitInventory, item: TrackedFile) -> LockfileResult:
    """Classify one tracked lockfile, or refuse it by name."""
    text = item.text
    if text is None:
        named = (
            None if posixpath.basename(item.path) == "yarn.lock" else lockfile_kind(item.path, "")
        )
        return _refused(item, named, LockfileRefusal("unreadable"))
    try:
        kind = lockfile_kind(item.path, text)
    except LockfileRefusal as refusal:
        return _refused(item, None, refusal)
    if kind != "npm":
        return _refused(item, kind, LockfileRefusal("unsupported-file-kind"))
    registry = npm_registry_declaration(inventory, item.path)
    try:
        version, entries = classify_npm_lockfile(text, posixpath.dirname(item.path), registry)
    except LockfileRefusal as refusal:
        return _refused(item, kind, refusal)
    return LockfileResult(item.path, item.content_digest, kind, version, None, entries)


def assess_lockfiles(inventory: GitInventory) -> tuple[LockfileResult, ...]:
    """Return one result for every tracked lockfile, ordered by path.

    Parameters
    ----------
    inventory : GitInventory
        The tracked repository content.

    Returns
    -------
    tuple[LockfileResult, ...]
        Classified or refused results.
    """
    items = sorted(
        (item for item in inventory.files if is_lockfile_path(item.path)),
        key=lambda item: item.path,
    )
    return tuple(_assess(inventory, item) for item in items)


def _candidate(
    rule_id: str,
    anchor: TrackedBlobAnchor | RepositoryTreeAnchor,
    symbol: str,
    evidence: str,
    confidence: Confidence,
) -> Candidate:
    """Build one supply-chain candidate with its rule's fixed guidance."""
    guidance = RULE_GUIDANCE[rule_id]
    return Candidate.build(
        category="supply-chain",
        rule_id=rule_id,
        anchor=anchor,
        symbol=symbol,
        evidence=evidence,
        confidence=confidence,
        rationale=guidance.rationale,
        verification=guidance.verification,
    )


def lockfile_candidates(
    inventory: GitInventory, results: tuple[LockfileResult, ...]
) -> tuple[Candidate, ...]:
    """Return the candidates of the lockfile results.

    Parameters
    ----------
    inventory : GitInventory
        The tracked repository content the results were read from.
    results : tuple[LockfileResult, ...]
        The results of ``assess_lockfiles``.

    Returns
    -------
    tuple[Candidate, ...]
        One candidate per refused file, and one per finding of each entry the lockfile
        records itself, in result and entry order.
    """
    items = {item.path: item for item in inventory.files}
    candidates: list[Candidate] = []
    for result in results:
        item = items[result.path]
        if result.refusal_reason is not None:
            anchor: TrackedBlobAnchor | RepositoryTreeAnchor = (
                TrackedBlobAnchor.build(item, line_start=1)
                if item.text
                else RepositoryTreeAnchor.build(inventory, path=item.path)
            )
            evidence = (
                f"file_sha256={result.file_sha256}; kind={result.kind or 'unknown'}; "
                f"reason={result.refusal_reason}"
            )
            candidates.append(_candidate(REFUSED_RULE_ID, anchor, "lockfile", evidence, "high"))
            continue
        for entry in result.entries:
            if entry.inherited_from is not None:
                continue
            for finding in entry.findings:
                evidence = (
                    f"file_sha256={result.file_sha256}; key_sha256={_sha256(entry.key)}; "
                    f"class={entry.entry_class}; finding={finding}"
                )
                confidence: Confidence = "medium" if finding in _MEDIUM_CONFIDENCE else "high"
                candidates.append(
                    _candidate(
                        FINDING_RULE_IDS[finding],
                        TrackedBlobAnchor.build(item, line_start=entry.line),
                        "lockfile-entry",
                        evidence,
                        confidence,
                    )
                )
    return tuple(candidates)


def scan_lockfile_integrity(inventory: GitInventory) -> tuple[Candidate, ...]:
    """Return the lockfile integrity candidates of one repository scan.

    Parameters
    ----------
    inventory : GitInventory
        The tracked repository content.

    Returns
    -------
    tuple[Candidate, ...]
        Deterministic, anchored, needs-evidence candidates.
    """
    return lockfile_candidates(inventory, assess_lockfiles(inventory))
