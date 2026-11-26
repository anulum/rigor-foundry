# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Go lockfile classification
"""Classify every module version of a ``go.sum``, read together with the ``go.mod`` beside it.

``go.sum`` has no format version; Go 1.16.15, 1.17.13, 1.22.2 and 1.27.4 wrote the same bytes for
the fixtures here. It is read as Go's ``readGoSum`` reads it (``modfetch/fetch.go`` at go1.27.4):
lines split at each line feed, fields split on the characters ``unicode.IsSpace`` accepts (so
CRLF reads the same), blank lines skipped, any other line needing exactly three fields, and
lines carrying the empty-``go.mod`` hash skipped as an old Go bug, which this rule counts.

Each ``module version`` is one entry. Its ``h1:`` line pins the module's file tree
(``dirhash.Hash1``, a SHA-256) and its ``/go.mod`` line pins only its ``go.mod``, a graph digest.
With both, it is pinned; with only ``/go.mod``, it is in the graph only, unless ``go.mod`` requires
that version, when it is missing its digest, as is a required version with ``h1:`` alone. A
version ``go.mod`` requires with no ``go.sum`` line stands at line 1, noted with the requirement's
``go.mod`` line. A local ``replace`` is local, a module ``replace`` takes its target's class, and
an excluded version is classified as written, with a note. The origin is the import path's host,
which ``GOPROXY`` does not change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, Literal

from .lockfile_digests import DigestReading, missing_digest, read_base64_digest
from .lockfile_forms import artifact_entry, path_escapes
from .lockfile_gomod import GoModule
from .lockfile_model import LockedEntry, LockfileRefusal

# ``emptyGoModHash`` in ``src/cmd/go/internal/modfetch/fetch.go`` at go1.27.4: the hash of a
# one-file tree holding an empty go.mod, which an old Go wrote for non-modules; Go drops it.
EMPTY_GO_MOD_HASH: Final = "h1:G7mAYYxgmS0lVkHyy2hEOLQCFB0DlQFTMLWggykrydY="
_GO_MOD_SUFFIX: Final = "/go.mod"
_H1: Final = "h1:"
# The characters ``unicode.IsSpace`` accepts, which ``strings.Fields`` splits on: the Latin-1 set,
# then Unicode's White_Space property above it.
_GO_SPACE: Final = re.compile(
    "[\t\n\v\f\r \x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+"
)

LineKind = Literal["zip", "mod"]
Module = tuple[str, str]


@dataclass(frozen=True)
class GoLockfile:
    """One classified ``go.sum``.

    Parameters
    ----------
    entries : tuple[LockedEntry, ...]
        The entries, ordered by line, then key.
    dropped_lines : int
        How many lines carrying the empty-``go.mod`` hash were skipped.
    """

    entries: tuple[LockedEntry, ...]
    dropped_lines: int


@dataclass
class _Sums:
    """The hashes ``go.sum`` lists for one module version, and the line the entry stands at.

    The line is the first ``h1:`` line, else the first line of the module version.
    """

    line: int
    zip: str | None = None
    mod: str | None = None


def _reading(value: str) -> DigestReading:
    """Read an ``h1:`` hash: lower-case ``h1:`` and standard base64 of 32 bytes, or malformed."""
    if not value.startswith(_H1):
        return DigestReading(algorithms=(), malformed_tokens=1)
    return read_base64_digest("sha256", value.removeprefix(_H1))


def _read_sums(text: str) -> tuple[dict[Module, _Sums], int]:
    """Read every module version's hashes, refusing a malformed line or two different hashes."""
    sums: dict[Module, _Sums] = {}
    dropped = 0
    for number, line in enumerate(text.split("\n"), start=1):
        fields = [field for field in _GO_SPACE.split(line) if field]
        if not fields:
            continue
        if len(fields) != 3:
            raise LockfileRefusal("unparseable")
        path, version, value = fields
        if value == EMPTY_GO_MOD_HASH:
            dropped += 1
            continue
        kind: LineKind = "mod" if version.endswith(_GO_MOD_SUFFIX) else "zip"
        module = (path, version.removesuffix(_GO_MOD_SUFFIX))
        found = sums.setdefault(module, _Sums(number))
        recorded = found.zip if kind == "zip" else found.mod
        if recorded is not None and recorded != value:
            raise LockfileRefusal("conflicting-entries")
        if kind == "zip":
            if found.zip is None:
                found.line = number
            found.zip = value
        else:
            found.mod = value
    return sums, dropped


def _origin(path: str) -> str:
    """Return the import path's host, its first element."""
    return path.split("/", 1)[0]


def _classify(
    key: str,
    line: int,
    origin: str,
    sums: _Sums | None,
    required: bool,
    notes: tuple[tuple[str, str], ...],
) -> LockedEntry:
    """Classify one module version by the ``go.sum`` lines it has."""
    if sums is None or (required and (sums.zip is None or sums.mod is None)):
        reading = missing_digest() if sums is None or sums.zip is None else _reading(sums.zip)
        return artifact_entry(
            key, line, reading, origin, {"missing-digest"}, digest_scope="module-tree", notes=notes
        )
    if sums.zip is None:
        notes = tuple(sorted((*notes, ("go_mod_digest", "present"))))
        return LockedEntry(key, line, "graph-only", origin=origin, notes=notes)
    return artifact_entry(
        key, line, _reading(sums.zip), origin, set(), digest_scope="module-tree", notes=notes
    )


def _notes(module: GoModule, path: str, version: str) -> tuple[tuple[str, str], ...]:
    """Return the ``exclude`` note of one module version, if ``go.mod`` excludes it."""
    excluded = module.exclusion(path, version)
    return () if excluded is None else (("excluded_at", f"go.mod:{excluded.line}"),)


def classify_go_lockfile(text: str, module: GoModule, lock_dir: str) -> GoLockfile:
    """Classify every module version of one ``go.sum``.

    Parameters
    ----------
    text : str
        The ``go.sum`` text.
    module : GoModule
        The ``go.mod`` beside it.
    lock_dir : str
        The repository-relative POSIX directory holding both; ``""`` for the root.

    Returns
    -------
    GoLockfile
        The entries and the count of dropped lines.

    Raises
    ------
    LockfileRefusal
        ``unparseable`` or ``conflicting-entries``, with no entry results.
    """
    sums, dropped = _read_sums(text)
    required = {(item.path, item.version): item for item in module.requirements}
    entries: dict[str, LockedEntry] = {}
    for (path, version), found in sums.items():
        key = f"{path} {version}"
        notes = _notes(module, path, version)
        entries[key] = _classify(
            key, found.line, _origin(path), found, (path, version) in required, notes
        )
    for (path, version), requirement in required.items():
        key = f"{path} {version}"
        replacement = module.replacement(path, version)
        if key in entries and replacement is None:
            continue
        at = ("required_at", f"go.mod:{requirement.line}")
        line = sums[(path, version)].line if (path, version) in sums else 1
        if replacement is not None and replacement.local:
            local_notes = (("replaced_by", replacement.target), at)
            entries[key] = (
                LockedEntry(
                    key,
                    line,
                    "unpinned",
                    ("path-escape",),
                    form="path",
                    origin="local",
                    notes=local_notes,
                )
                if path_escapes(lock_dir, replacement.target)
                else LockedEntry(key, line, "local", origin="local", notes=local_notes)
            )
            continue
        target = (path, version)
        notes = (at, *_notes(module, path, version))
        if replacement is not None and replacement.target_version is not None:
            target = (replacement.target, replacement.target_version)
            notes = (*notes, ("replaced_by", f"{target[0]} {target[1]}"))
        entries[key] = _classify(
            key, line, _origin(target[0]), sums.get(target), True, tuple(sorted(notes))
        )
    ordered = sorted(entries.values(), key=lambda entry: (entry.line, entry.key))
    return GoLockfile(tuple(ordered), dropped)
