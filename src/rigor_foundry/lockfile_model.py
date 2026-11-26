# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — lockfile integrity classification model
"""Hold one lockfile's classified entries, or its refusal, under integrity semantics v1.

Every locked entry gets exactly one class and zero or more findings. A pinned class needs a
successful pin; a recognised form that fails its pin is ``unpinned`` and names the failure;
an unknown form is ``unclassified``. A refused file names its reason and has no entries.
The model enforces these rules when a result is built, so no parser can emit a result that
breaks them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from .lockfile_digests import DIGEST_BYTES, DigestAlgorithm

LockfileKind = Literal["npm", "yarn-v1", "yarn-berry", "pnpm", "cargo", "go", "poetry", "pipenv"]
EntryClass = Literal[
    "artifact-pinned", "commit-pinned", "local", "unpinned", "unclassified", "graph-only"
]
EntryForm = Literal["artifact", "vcs", "path"]
EntryFinding = Literal[
    "missing-digest",
    "weak-digest",
    "malformed-digest",
    "floating-ref",
    "origin-mismatch",
    "origin-unknown",
    "path-escape",
    "manifest-drift",
    "unknown-form",
]
RefusalReason = Literal[
    "unparseable",
    "missing-version",
    "unsupported-version",
    "conflicting-entries",
    "unreadable",
    "ambiguous-yarn-lock",
    "unsupported-file-kind",
    "unsupported-lock-version",
]
DigestScope = Literal["artifact", "cache-archive", "uncompressed-tar", "parent-artifact"]
CommitHashAlgorithm = Literal["sha1", "sha256"]

ENTRY_CLASSES: Final[tuple[EntryClass, ...]] = (
    "artifact-pinned",
    "commit-pinned",
    "local",
    "unpinned",
    "unclassified",
    "graph-only",
)
ENTRY_FINDINGS: Final[tuple[EntryFinding, ...]] = (
    "missing-digest",
    "weak-digest",
    "malformed-digest",
    "floating-ref",
    "origin-mismatch",
    "origin-unknown",
    "path-escape",
    "manifest-drift",
    "unknown-form",
)
REFUSAL_REASONS: Final[tuple[RefusalReason, ...]] = (
    "unparseable",
    "missing-version",
    "unsupported-version",
    "conflicting-entries",
    "unreadable",
    "ambiguous-yarn-lock",
    "unsupported-file-kind",
    "unsupported-lock-version",
)
# The findings that mean an entry's pin failed; an unpinned entry carries at least one.
PIN_FAILURES: Final[frozenset[EntryFinding]] = frozenset(
    {"missing-digest", "weak-digest", "malformed-digest", "floating-ref", "path-escape"}
)
_PINNED_CLASSES: Final[frozenset[EntryClass]] = frozenset(
    {"artifact-pinned", "commit-pinned", "local"}
)
_HEX: Final = frozenset("0123456789abcdef")


class LockfileRefusal(Exception):
    """Refuse a whole lockfile, so that it yields no entry results.

    Parameters
    ----------
    reason : RefusalReason
        The named reason the file is refused.
    """

    def __init__(self, reason: RefusalReason) -> None:
        super().__init__(reason)
        self.reason: RefusalReason = reason


def _require(condition: bool, message: str) -> None:
    """Raise ``ValueError`` with the message when a model rule does not hold."""
    if not condition:
        raise ValueError(message)


@dataclass(frozen=True)
class LockedEntry:
    """One locked entry, its class, and its findings.

    Parameters
    ----------
    key : str
        The entry's key in its lockfile, such as ``node_modules/left-pad``.
    line : int
        The 1-based line where the entry starts in the tracked lockfile.
    entry_class : EntryClass
        Exactly one class.
    findings : tuple[EntryFinding, ...]
        The findings, unique and in the fixed order of ``ENTRY_FINDINGS``.
    form : EntryForm | None
        The recognised form of an ``unpinned`` entry; ``None`` for every other class.
    digest_algorithms : tuple[DigestAlgorithm, ...]
        The algorithm of each digest that decoded, in lockfile order.
    digest_scope : DigestScope | None
        What the digests cover, when the entry has any.
    commit_hash_algorithm : CommitHashAlgorithm | None
        The object-id algorithm of a ``commit-pinned`` entry; ``None`` otherwise.
    origin : str | None
        The host or source the entry resolves from, when it has one.
    inherited_from : str | None
        The key of the bundling ancestor whose artifact carries this entry.
    archive_commit : str | None
        The full commit a hosted archive URL names, recorded as evidence. The archive's bytes
        are not verified against it, so it never makes the entry ``commit-pinned``.
    notes : tuple[tuple[str, str], ...]
        Further named evidence a lockfile kind records, ordered by name: an alias, a digest
        problem with the keys involved, or a patch source.
    """

    key: str
    line: int
    entry_class: EntryClass
    findings: tuple[EntryFinding, ...] = ()
    form: EntryForm | None = None
    digest_algorithms: tuple[DigestAlgorithm, ...] = ()
    digest_scope: DigestScope | None = None
    commit_hash_algorithm: CommitHashAlgorithm | None = None
    origin: str | None = None
    inherited_from: str | None = None
    archive_commit: str | None = None
    notes: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        """Refuse an entry that breaks a rule of integrity semantics v1."""
        _require(bool(self.key), "an entry needs a key")
        _require(self.line >= 1, "an entry line is 1-based")
        _require(self.entry_class in ENTRY_CLASSES, "an entry needs a known class")
        _require(
            all(finding in ENTRY_FINDINGS for finding in self.findings)
            and list(self.findings) == sorted(set(self.findings), key=ENTRY_FINDINGS.index),
            "findings must be known, unique and in their fixed order",
        )
        _require(
            all(algorithm in DIGEST_BYTES for algorithm in self.digest_algorithms),
            "digest algorithms must be known",
        )
        failures = PIN_FAILURES.intersection(self.findings)
        unpinned = self.entry_class == "unpinned"
        _require(unpinned == (self.form is not None), "only an unpinned entry records its form")
        _require(not unpinned or bool(failures), "an unpinned entry names its pin failure")
        _require(
            self.entry_class not in _PINNED_CLASSES or not failures,
            "a pinned entry carries no pin failure",
        )
        _require(
            (self.entry_class == "unclassified") == ("unknown-form" in self.findings),
            "exactly the unclassified entries carry unknown-form",
        )
        _require(
            (self.entry_class == "commit-pinned" or self.archive_commit is not None)
            == (self.commit_hash_algorithm is not None),
            "exactly the commit-pinned and archive entries record their commit hash algorithm",
        )
        _require(
            self.archive_commit is None
            or (self.entry_class == "artifact-pinned" or self.form == "artifact"),
            "only an artifact records the commit its archive names",
        )
        _require(
            self.entry_class != "artifact-pinned"
            or (bool(self.digest_algorithms) and self.digest_scope is not None),
            "an artifact-pinned entry records its digests and their scope",
        )
        _require(
            (self.inherited_from is not None) == (self.digest_scope == "parent-artifact"),
            "exactly the entries carried by a parent artifact name that parent",
        )
        names = [name for name, _ in self.notes]
        _require(
            names == sorted(set(names)) and all(name and value for name, value in self.notes),
            "notes are named, unique, non-empty and ordered by name",
        )

    def to_dict(self) -> dict[str, object]:
        """Return the entry as a report object with every field present."""
        return {
            "key": self.key,
            "line": self.line,
            "class": self.entry_class,
            "form": self.form,
            "findings": list(self.findings),
            "digest_algorithms": list(self.digest_algorithms),
            "digest_scope": self.digest_scope,
            "commit_hash_algorithm": self.commit_hash_algorithm,
            "origin": self.origin,
            "inherited_from": self.inherited_from,
            "archive_commit": self.archive_commit,
            "notes": dict(self.notes),
        }


@dataclass(frozen=True)
class LockfileResult:
    """One tracked lockfile, classified entry by entry, or refused as a whole.

    Parameters
    ----------
    path : str
        The repository-relative POSIX path.
    file_sha256 : str
        The SHA-256 of the tracked file bytes.
    kind : LockfileKind | None
        The detected kind; ``None`` only when detection itself refused the file.
    format_version : str | None
        The version marker the file declares, when it was read.
    refusal_reason : RefusalReason | None
        Why the whole file is refused; ``None`` for a classified file.
    entries : tuple[LockedEntry, ...]
        The entries, ordered by line, then key; empty for a refused file.
    checksum_behavior : str | None
        A Yarn ``checksumBehavior`` that weakens verification, ``ignore`` or ``update``, when the
        repository's tracked configuration sets it; ``None`` otherwise.
    """

    path: str
    file_sha256: str
    kind: LockfileKind | None
    format_version: str | None
    refusal_reason: RefusalReason | None
    entries: tuple[LockedEntry, ...]
    checksum_behavior: str | None = None

    def __post_init__(self) -> None:
        """Refuse a result that breaks the file-level rules."""
        _require(bool(self.path), "a result needs its path")
        _require(
            len(self.file_sha256) == 64 and set(self.file_sha256) <= _HEX,
            "a result binds the lowercase SHA-256 of its file",
        )
        _require(
            self.refusal_reason is None or self.refusal_reason in REFUSAL_REASONS,
            "a refusal names a known reason",
        )
        _require(
            self.refusal_reason is None or not self.entries,
            "a refused file has no entry results",
        )
        _require(
            self.kind is not None or self.refusal_reason is not None,
            "only a refused file may lack a kind",
        )
        _require(
            self.refusal_reason is not None or self.format_version is not None,
            "a classified file records its format version",
        )
        order = [(entry.line, entry.key) for entry in self.entries]
        _require(order == sorted(order), "entries are ordered by line, then key")
        keys = [entry.key for entry in self.entries]
        _require(len(keys) == len(set(keys)), "entry keys are unique within a file")

    @property
    def status(self) -> Literal["classified", "refused"]:
        """Return whether the file was classified or refused."""
        return "refused" if self.refusal_reason is not None else "classified"

    def to_dict(self) -> dict[str, object]:
        """Return the file as a report object with every field present."""
        return {
            "path": self.path,
            "file_sha256": self.file_sha256,
            "kind": self.kind,
            "format_version": self.format_version,
            "status": self.status,
            "refusal_reason": self.refusal_reason,
            "entries": [entry.to_dict() for entry in self.entries],
            "checksum_behavior": self.checksum_behavior,
        }
