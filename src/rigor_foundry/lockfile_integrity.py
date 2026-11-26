# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — lockfile integrity rules over a repository
"""Classify every tracked lockfile of a repository, and raise its findings as candidates.

Each tracked file with a lockfile name yields one result: classified entry by entry, or
refused with a named reason and no entries. Every kind the detector recognises is classified:
npm, Yarn 1, Yarn 2+, pnpm, Cargo, Go, Poetry and Pipenv lockfiles, so an unread file never
looks clean. Each finding of an entry the lockfile itself
records becomes one supply-chain candidate at the entry's line; a bundled entry repeats its
ancestor's findings in the report, but not as candidates. A refused file becomes one candidate.
"""

from __future__ import annotations

import hashlib
import os
import posixpath
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Final, Literal

from .candidate_anchor import RepositoryTreeAnchor, TrackedBlobAnchor
from .git_inventory import GitInventory, TrackedFile
from .lockfile_cargo import classify_cargo_lockfile
from .lockfile_go import classify_go_lockfile
from .lockfile_gomod import parse_go_mod
from .lockfile_kinds import PNPM_LOCK, is_lockfile_path, lockfile_kind
from .lockfile_model import EntryFinding, LockfileKind, LockfileRefusal, LockfileResult
from .lockfile_npm import classify_npm_lockfile
from .lockfile_npmrc import (
    DEFAULT_NPM_REGISTRY,
    UNKNOWN_NPM_REGISTRY,
    NpmRegistryDeclaration,
    npmrc_registry_hosts,
    read_npmrc,
)
from .lockfile_pipenv import PIPFILE_SPEC, classify_pipenv_lockfile
from .lockfile_pnpm import classify_pnpm_lockfile
from .lockfile_pnpm_config import PnpmWorkspace, read_pnpm_workspace
from .lockfile_poetry import classify_poetry_lockfile
from .lockfile_poetry_sources import read_poetry_declaration
from .lockfile_yarn1 import classify_yarn1_lockfile
from .lockfile_yarn_berry import classify_yarn_berry_lockfile
from .lockfile_yarnrc import (
    YarnRegistryDeclaration,
    yarn_registry_declaration,
    yarnrc_registry_hosts,
)
from .lockfile_yarnrc_yml import (
    UNKNOWN_BERRY_REGISTRY,
    WEAKENING_CHECKSUM_BEHAVIORS,
    BerryRegistryDeclaration,
    YarnrcYml,
    read_yarnrc_yml,
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
_YARNRC: Final = ".yarnrc"
_YARNRC_YML: Final = ".yarnrc.yml"
_PNPM_WORKSPACE: Final = "pnpm-workspace.yaml"
_GO_MOD: Final = "go.mod"
_PYPROJECT: Final = "pyproject.toml"
# The last kind the dispatch reaches; adding a kind to ``LockfileKind`` breaks its type check.
_LastKind = Literal["pipenv"]

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


def _config_text(inventory: GitInventory, lock_path: str, name: str) -> tuple[bool, str | None]:
    """Find one configuration file beside the lockfile, then at the root.

    Returns whether it was read with certainty, and its text; ``(True, None)`` when there is
    none at either place. A file that is present but untracked, or tracked but not text, is
    uncertain.
    """
    tracked = {item.path: item for item in inventory.files}
    for place in dict.fromkeys((posixpath.dirname(lock_path), "")):
        path = posixpath.join(place, name)
        item = tracked.get(path)
        if item is not None:
            return item.text is not None, item.text
        if os.path.lexists(inventory.root / path):
            return False, None
    return True, None


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
    certain, text = _config_text(inventory, lock_path, _NPMRC)
    if not certain:
        return UNKNOWN_NPM_REGISTRY
    return DEFAULT_NPM_REGISTRY if text is None else read_npmrc(text)


def _merged_hosts(
    inventory: GitInventory,
    lock_path: str,
    name: str,
    reader: Callable[[str], dict[str, str] | None],
) -> dict[str, str] | None:
    """Merge one configuration file's registry hosts from the root down to the lockfile.

    Every tracked file of that name on the path from the repository root to the lockfile's
    directory is read, and the nearer file wins per key, as Yarn 1 merges them. An untracked or
    unreadable file at any level, or an uncertain line in any of them, gives ``None``.
    """
    tracked = {item.path: item for item in inventory.files}
    directory = posixpath.dirname(lock_path)
    parts = directory.split("/") if directory else []
    merged: dict[str, str] = {}
    for depth in range(len(parts) + 1):
        path = posixpath.join(*parts[:depth], name) if depth else name
        item = tracked.get(path)
        if item is None:
            if os.path.lexists(inventory.root / path):
                return None
            continue
        hosts = None if item.text is None else reader(item.text)
        if hosts is None:
            return None
        merged.update(hosts)
    return merged


def yarn1_registry_declaration(inventory: GitInventory, lock_path: str) -> YarnRegistryDeclaration:
    """Return the registry the repository declares for one Yarn 1 lockfile.

    Yarn 1 merges every ``.npmrc``, and every ``.yarnrc``, from the root down to the directory it
    runs in, the nearer file winning per key. So both names are read at every level from the
    repository root to the lockfile's directory and merged that way, with the same certainty
    rules as for npm at each level. ``.yarnrc.yml`` is Yarn 2+ and is not read.

    Parameters
    ----------
    inventory : GitInventory
        The tracked repository content.
    lock_path : str
        The lockfile's repository-relative POSIX path.

    Returns
    -------
    YarnRegistryDeclaration
        The declaration.
    """
    return yarn_registry_declaration(
        _merged_hosts(inventory, lock_path, _NPMRC, npmrc_registry_hosts),
        _merged_hosts(inventory, lock_path, _YARNRC, yarnrc_registry_hosts),
    )


def _levels(lock_path: str) -> list[str]:
    """Return the configuration paths from the repository root down to the lockfile's directory."""
    directory = posixpath.dirname(lock_path)
    parts = directory.split("/") if directory else []
    return [posixpath.join(*parts[:depth]) if depth else "" for depth in range(len(parts) + 1)]


def berry_registry_declaration(
    inventory: GitInventory, lock_path: str
) -> BerryRegistryDeclaration:
    """Return the registry the repository declares for one Yarn 2+ lockfile.

    Every tracked ``.yarnrc.yml`` from the root down to the lockfile's directory is merged, the
    nearer winning per key and ``npmScopes`` per scope. An untracked or unreadable file at any
    level, or an uncertain value in any file, makes the declaration unknown.

    Parameters
    ----------
    inventory : GitInventory
        The tracked repository content.
    lock_path : str
        The lockfile's repository-relative POSIX path.

    Returns
    -------
    BerryRegistryDeclaration
        The declaration.
    """
    tracked = {item.path: item for item in inventory.files}
    merged = YarnrcYml()
    for place in _levels(lock_path):
        path = posixpath.join(place, _YARNRC_YML)
        item = tracked.get(path)
        if item is None:
            if os.path.lexists(inventory.root / path):
                return UNKNOWN_BERRY_REGISTRY
            continue
        config = None if item.text is None else read_yarnrc_yml(item.text)
        if config is None:
            return UNKNOWN_BERRY_REGISTRY
        merged = merged.merged_under(config)
    return BerryRegistryDeclaration(known=True, config=merged)


def _beside(inventory: GitInventory, lock_path: str, name: str) -> tuple[bool, str | None]:
    """Find one configuration file beside the lockfile only, as pnpm reads its workspace root.

    Returns whether it was read with certainty, and its text; ``(True, None)`` when there is
    none. A file that is present but untracked, or tracked but not text, is uncertain.
    """
    path = posixpath.join(posixpath.dirname(lock_path), name)
    for item in inventory.files:
        if item.path == path:
            return item.text is not None, item.text
    return not os.path.lexists(inventory.root / path), None


def pnpm_configuration(
    inventory: GitInventory, lock_path: str
) -> tuple[Mapping[str, str] | None, PnpmWorkspace | None]:
    """Return what the ``.npmrc`` and ``pnpm-workspace.yaml`` beside a pnpm lockfile declare.

    Parameters
    ----------
    inventory : GitInventory
        The tracked repository content.
    lock_path : str
        The lockfile's repository-relative POSIX path.

    Returns
    -------
    tuple[Mapping[str, str] | None, PnpmWorkspace | None]
        The ``.npmrc`` registry hosts and the workspace declaration; each ``None`` when its file
        cannot be read with certainty, and empty when there is no file.
    """
    certain, npmrc = _beside(inventory, lock_path, _NPMRC)
    hosts = None if not certain else {} if npmrc is None else npmrc_registry_hosts(npmrc)
    certain, workspace_text = _beside(inventory, lock_path, _PNPM_WORKSPACE)
    workspace = (
        None
        if not certain
        else PnpmWorkspace()
        if workspace_text is None
        else read_pnpm_workspace(workspace_text)
    )
    return hosts, workspace


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
    lock_dir = posixpath.dirname(item.path)
    try:
        if kind == "npm":
            npm = npm_registry_declaration(inventory, item.path)
            version, entries = classify_npm_lockfile(text, lock_dir, npm)
        elif kind == "yarn-v1":
            yarn = yarn1_registry_declaration(inventory, item.path)
            version, entries = classify_yarn1_lockfile(text, lock_dir, yarn)
        elif kind == "pnpm":
            if posixpath.basename(item.path) != PNPM_LOCK:
                raise LockfileRefusal("unsupported-version")
            hosts, workspace = pnpm_configuration(inventory, item.path)
            version, entries = classify_pnpm_lockfile(text, lock_dir, hosts, workspace)
        elif kind == "cargo":
            cargo = classify_cargo_lockfile(text)
            return LockfileResult(
                item.path,
                item.content_digest,
                kind,
                cargo.version,
                None,
                cargo.entries,
                unused_patches=cargo.unused_patches,
            )
        elif kind == "go":
            certain, go_mod = _beside(inventory, item.path, _GO_MOD)
            if not certain:
                raise LockfileRefusal("unreadable")
            if go_mod is None:
                raise LockfileRefusal("unparseable")
            go = classify_go_lockfile(text, parse_go_mod(go_mod), lock_dir)
            return LockfileResult(
                item.path,
                item.content_digest,
                kind,
                "go.sum",
                None,
                go.entries,
                dropped_lines=go.dropped_lines,
            )
        elif kind == "poetry":
            # An uncertain pyproject.toml has no text, so it reads as no declaration.
            _, pyproject = _beside(inventory, item.path, _PYPROJECT)
            declaration = read_poetry_declaration(pyproject)
            poetry = classify_poetry_lockfile(text, lock_dir, declaration)
            return LockfileResult(
                item.path,
                item.content_digest,
                kind,
                poetry.version,
                None,
                poetry.entries,
                manifest_hash=poetry.content_hash,
            )
        elif kind == "yarn-berry":
            berry = berry_registry_declaration(inventory, item.path)
            version, entries = classify_yarn_berry_lockfile(text, lock_dir, berry)
            behavior = berry.config.checksum_behavior
            if behavior in WEAKENING_CHECKSUM_BEHAVIORS:
                return LockfileResult(
                    item.path, item.content_digest, kind, version, None, entries, behavior
                )
        else:
            last: _LastKind = kind
            pipenv = classify_pipenv_lockfile(text, lock_dir)
            return LockfileResult(
                item.path,
                item.content_digest,
                last,
                str(PIPFILE_SPEC),
                None,
                pipenv.entries,
                manifest_hash=pipenv.meta_hash,
            )
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
                    f"class={entry.entry_class}; finding={finding}; origin={entry.origin or 'none'}"
                )
                required_at = dict(entry.notes).get("required_at")
                if required_at is not None:
                    evidence += f"; required_at={required_at}"
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
