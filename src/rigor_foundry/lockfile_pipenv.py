# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Pipenv lockfile classification
"""Classify every entry of a ``Pipfile.lock``, ``pipfile-spec`` 6.

Pipenv 2020.11.15 to 2026.12.1 all write ``pipfile-spec`` 6, as a strict JSON object whose
``_meta`` records the hash of the Pipfile, the sources and the Python requirement, and whose
every other key is a category of entries: ``default``, ``develop``, and from Pipenv 2022.10
categories the Pipfile names. Each entry is keyed ``<category>/<name>`` at its own key's line.

An exact ``version`` (``==``) pins through its ``hashes``, from the source its ``index`` names in
``_meta.sources``; pip accepts a file when any listed hash of any algorithm matches, so a weak
hash anywhere in the list weakens the entry. A remote ``file`` pins through its hashes too; a
local ``file`` or a ``path`` is local; a ``git`` entry is pinned by a full-commit ``ref``. Any
other form, ``===``, prefix matches such as ``==1.*`` and ranges included, is unknown.
``_meta.hash`` is a manifest hash, recorded and not compared.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, cast
from urllib.parse import urlsplit

from .lockfile_digests import missing_digest
from .lockfile_forms import artifact_entry, listed_hashes, local_entry, unknown_entry, vcs_entry
from .lockfile_json import json_key_lines, load_lockfile_json
from .lockfile_model import EntryFinding, LockedEntry, LockfileRefusal
from .lockfile_npmrc import url_host

PIPFILE_SPEC: Final = 6
_META: Final = "_meta"
# One ``==`` specifier of an exact version: no prefix match, no second specifier, no marker.
_EXACT: Final = re.compile(r"==[^=*,;\s]+")
_SCHEME: Final = re.compile(r"[A-Za-z][A-Za-z0-9+.-]+://")
_REMOTE_SCHEMES: Final = frozenset({"http", "https"})
_OTHER_VCS: Final = ("hg", "svn", "bzr")


@dataclass(frozen=True)
class PipenvLockfile:
    """One classified ``Pipfile.lock``.

    Parameters
    ----------
    entries : tuple[LockedEntry, ...]
        The entries, ordered by line.
    meta_hash : str | None
        ``_meta.hash.sha256``, the hash of the Pipfile the lock was made from; a drift signal only.
    """

    entries: tuple[LockedEntry, ...]
    meta_hash: str | None


@dataclass(frozen=True)
class _Source:
    """One source ``_meta.sources`` records."""

    url: str
    verify_ssl: bool


def _object(value: object) -> dict[str, object]:
    """Return a JSON object, refusing anything else."""
    if not isinstance(value, dict):
        raise LockfileRefusal("unparseable")
    return value


def _text(owner: dict[str, object], field: str) -> str | None:
    """Return a string field, absent as ``None``, refusing another type."""
    value = owner.get(field)
    if value is not None and not isinstance(value, str):
        raise LockfileRefusal("unparseable")
    return value


def _meta(document: dict[str, object]) -> dict[str, object]:
    """Return ``_meta``, refusing a missing marker or a ``pipfile-spec`` but the integer 6."""
    if _META not in document:
        raise LockfileRefusal("missing-version")
    meta = _object(document[_META])
    spec = meta.get("pipfile-spec")
    if spec is None:
        raise LockfileRefusal("missing-version")
    if type(spec) is not int or spec != PIPFILE_SPEC:
        raise LockfileRefusal("unsupported-version")
    return meta


def _sources(meta: dict[str, object]) -> dict[str, _Source]:
    """Return the recorded sources by name, refusing an unwritten shape or a repeated name."""
    raw = meta.get("sources", [])
    if not isinstance(raw, list):
        raise LockfileRefusal("unparseable")
    sources = {}
    for item in raw:
        source = _object(item)
        name, url, verify = source.get("name"), source.get("url"), source.get("verify_ssl", True)
        if not isinstance(name, str) or not isinstance(url, str) or not isinstance(verify, bool):
            raise LockfileRefusal("unparseable")
        if name in sources:
            raise LockfileRefusal("conflicting-entries")
        sources[name] = _Source(url, verify)
    return sources


def _meta_hash(meta: dict[str, object]) -> str | None:
    """Return ``_meta.hash.sha256``, absent as ``None``."""
    raw = meta.get("hash")
    return None if raw is None else _text(_object(raw), "sha256")


def _hashes(entry: dict[str, object]) -> list[str]:
    """Return an entry's listed hashes, refusing anything but a list of strings."""
    raw = entry.get("hashes", [])
    if not isinstance(raw, list) or not all(isinstance(value, str) for value in raw):
        raise LockfileRefusal("unparseable")
    return cast(list[str], raw)


def _origin(
    entry: dict[str, object], sources: dict[str, _Source]
) -> tuple[str | None, frozenset[EntryFinding], tuple[tuple[str, str], ...]]:
    """Return a version entry's origin host, origin finding and source note."""
    index = _text(entry, "index")
    if index is None and len(sources) != 1:
        return None, frozenset({"origin-unknown"}), ()
    source = next(iter(sources.values())) if index is None else sources.get(index)
    if source is None:
        return None, frozenset({"origin-mismatch"}), ()
    notes = () if source.verify_ssl else (("verify_ssl", "false"),)
    return url_host(source.url), frozenset(), notes


def _classify(
    key: str, line: int, entry: dict[str, object], sources: dict[str, _Source], lock_dir: str
) -> LockedEntry:
    """Classify one entry by its form."""
    hashes = _hashes(entry)
    editable = (("editable", "true"),) if entry.get("editable") is True else ()
    if "git" in entry:
        url = _text(entry, "git") or ""
        subdirectory = _text(entry, "subdirectory")
        notes = () if subdirectory is None else (("subdirectory", subdirectory),)
        return vcs_entry(
            key, line, f"{url}#{_text(entry, 'ref') or ''}", missing_digest(), notes=notes
        )
    if any(field in entry for field in _OTHER_VCS):
        return unknown_entry(key, line)
    file = _text(entry, "file")
    if file is not None:
        scheme = _SCHEME.match(file)
        if scheme is None:
            notes = (*editable, ("file_hash", " ".join(hashes))) if hashes else editable
            return local_entry(key, line, lock_dir, file, notes=notes)
        if urlsplit(file).scheme not in _REMOTE_SCHEMES:
            return unknown_entry(key, line)
        listed = listed_hashes(hashes)
        return artifact_entry(
            key, line, listed.reading, url_host(file), set(listed.findings), notes=listed.notes
        )
    path = _text(entry, "path")
    if path is not None:
        return local_entry(key, line, lock_dir, path, notes=editable)
    version = _text(entry, "version")
    if version is None or _EXACT.fullmatch(version) is None:
        return unknown_entry(key, line)
    listed = listed_hashes(hashes)
    origin, finding, source_notes = _origin(entry, sources)
    return artifact_entry(
        key,
        line,
        listed.reading,
        origin,
        {*listed.findings, *finding},
        # unrecognised_algorithm sorts before verify_ssl, so the notes stay in name order.
        notes=(*listed.notes, *source_notes),
    )


def classify_pipenv_lockfile(text: str, lock_dir: str) -> PipenvLockfile:
    """Classify every entry of one ``Pipfile.lock``.

    Parameters
    ----------
    text : str
        The lockfile text.
    lock_dir : str
        The repository-relative POSIX directory holding it; ``""`` for the root.

    Returns
    -------
    PipenvLockfile
        The entries ordered by line, and the recorded Pipfile hash.

    Raises
    ------
    LockfileRefusal
        ``unparseable``, ``conflicting-entries``, ``missing-version`` or ``unsupported-version``,
        with no entry results.
    """
    document = load_lockfile_json(text)
    meta = _meta(document)
    sources = _sources(meta)
    lines = json_key_lines(text)
    entries = []
    for category, raw in document.items():
        if category == _META:
            continue
        for name, entry in _object(raw).items():
            key = f"{category}/{name}"
            entries.append(
                _classify(key, lines[(category, name)], _object(entry), sources, lock_dir)
            )
    # JSON keys appear in the text in document order, so the entries are already in line order.
    return PipenvLockfile(tuple(entries), _meta_hash(meta))
