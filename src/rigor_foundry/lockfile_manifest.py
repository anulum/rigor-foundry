# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Poetry and Pipenv manifest-hash comparison
"""Compare the manifest hash a ``poetry.lock`` or ``Pipfile.lock`` records with its manifest.

Each form mirrors a released tool's own hash, read at its tag:

* **Poetry F1** (2.3.0 and later, ``packages/locker.py``): ``json.dumps(..., sort_keys=True)`` of
  ``[project]``'s ``requires-python``, ``dependencies`` and ``optional-dependencies``, a non-empty
  ``[dependency-groups]``, and ``[tool.poetry]``'s ``dependencies``, ``source``, ``extras``,
  ``dev-dependencies`` and ``group``; the four legacy keys appear as ``null`` only when neither
  ``[project]`` nor the groups add content, and with neither the ``[tool.poetry]`` part stands at
  the top level. **F2** (2.0 to 2.2) is F1 without the groups, and **F3** (1.x) is the
  ``[tool.poetry]`` part alone.
* **Pipenv plette** (2022.12.19 to 2025.x, and 2020.11.15 over ``default`` and ``develop``):
  compact ``json.dumps(..., sort_keys=True)`` of ``_meta.sources`` and ``_meta.requires``,
  ``default``, ``develop`` and every other category, with PyPI inserted as the source when
  ``[[source]]`` is absent; **canonical** (2026.12.1) is the same with every package name in its
  PEP 503 form. Neither expands an environment variable in a source URL.

A Poetry lockfile names its writer on line 1. The accepted forms are the union of the writer's
own verdict and that of Poetry 2.5.2, which recomputes without the groups for a writer before
2.3.0, compared as PEP 440 orders versions, pre-releases included. A writer newer than 2.5.2 is
judged by F1 alone, and a mismatch is uncertain rather than drift, since a later Poetry may hash
differently. ``Pipfile.lock`` names no writer, so either Pipenv form is accepted. A lockfile
without its hash is drift, as both tools treat it.
"""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from dataclasses import dataclass
from typing import Final, Literal

from .lockfile_json import json_key_lines

ManifestState = Literal[
    "fresh", "drift", "manifest-missing", "manifest-uncertain", "manifest-unparseable"
]
MANIFEST_STATES: Final[tuple[ManifestState, ...]] = (
    "fresh",
    "drift",
    "manifest-missing",
    "manifest-uncertain",
    "manifest-unparseable",
)
UNTRACKED_MANIFEST: Final = "manifest-untracked-or-not-text"
NEWER_WRITER: Final = "writer-newer-than-mirrored"
NEWEST_MIRRORED_POETRY: Final = (2, 5, 2)
_GROUPS_HASHED_FROM: Final = (2, 3, 0)
_PROJECT_TABLE_FROM: Final = (2, 0, 0)
_LEGACY_KEYS: Final = ("dependencies", "source", "extras", "dev-dependencies")
_RELEVANT_KEYS: Final = (*_LEGACY_KEYS, "group")
_PROJECT_KEYS: Final = ("requires-python", "dependencies", "optional-dependencies")
_PIPFILE_SECTIONS: Final = frozenset(
    {"source", "packages", "dev-packages", "requires", "scripts", "pipfile", "pipenv"}
)
_DEFAULT_SOURCE: Final = ({"name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": True},)
_WRITER: Final = re.compile(r"Poetry ([^ ]+)")
_CONTENT_HASH_LINE: Final = re.compile(r"^content-hash\s*=", re.MULTILINE)
_NAME_SEPARATORS: Final = re.compile(r"[-_.]+")
_PEP440: Final = re.compile(
    r"v?(?:(?P<epoch>[0-9]+)!)?(?P<release>[0-9]+(?:\.[0-9]+)*)"
    r"(?:[-_.]?(?P<pre>a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?"
    r"(?:(?P<implicit>-[0-9]+)|[-_.]?(?P<post>post|rev|r)[-_.]?[0-9]*)?"
    r"(?:[-_.]?(?P<dev>dev)[-_.]?[0-9]*)?"
    r"(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class TrackedManifest:
    """The manifest beside a lockfile, as the tracked repository content holds it.

    Attributes
    ----------
    path : str
        The repository-relative POSIX path where the manifest belongs.
    certain : bool
        Whether its presence and text are known: ``False`` for a file present but untracked, or
        tracked but not text.
    text : str | None
        The tracked text; ``None`` when there is none or it is uncertain.
    sha256 : str | None
        The SHA-256 of the tracked bytes; ``None`` when there is no tracked text.
    """

    path: str
    certain: bool
    text: str | None
    sha256: str | None


@dataclass(frozen=True)
class ManifestCheck:
    """The comparison of one lockfile's manifest hash with its manifest.

    Attributes
    ----------
    manifest_path : str
        The manifest compared, or expected, beside the lockfile.
    manifest_sha256 : str | None
        The SHA-256 of the tracked manifest, when one was read.
    state : ManifestState
        ``fresh``, ``drift``, or why no comparison was made.
    reason : str | None
        Why the state is uncertain; ``None`` for every other state.
    recorded : str | None
        The hash the lockfile records; ``None`` when it records none.
    hash_line : int
        The lockfile line that records the hash, or 1 when there is none.
    writer : str | None
        The Poetry release line 1 names, as written; ``None`` for Pipenv or an unnamed writer.
    accepted : tuple[str, ...]
        The forms that would have been accepted.
    """

    manifest_path: str
    manifest_sha256: str | None
    state: ManifestState
    reason: str | None
    recorded: str | None
    hash_line: int
    writer: str | None
    accepted: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Return the check as a report object with every field present."""
        return {
            "manifest_path": self.manifest_path,
            "manifest_sha256": self.manifest_sha256,
            "state": self.state,
            "reason": self.reason,
            "recorded": self.recorded,
            "hash_line": self.hash_line,
            "writer": self.writer,
            "accepted": list(self.accepted),
        }


def compare_to_release(version: str, release: tuple[int, ...]) -> int | None:
    """Order a PEP 440 version against a final release, as Poetry's ``Version`` orders them.

    Parameters
    ----------
    version : str
        The version text.
    release : tuple[int, ...]
        A final release with no pre, post, dev or local part.

    Returns
    -------
    int | None
        -1, 0 or 1 as the version is before, equal to or after the release; ``None`` when the
        text is not a PEP 440 version.
    """
    match = _PEP440.fullmatch(version.strip())
    if match is None:
        return None
    if int(match["epoch"] or 0) > 0:
        return 1
    parts = tuple(int(part) for part in match["release"].split("."))
    width = max(len(parts), len(release))
    padded = parts + (0,) * (width - len(parts))
    target = release + (0,) * (width - len(release))
    if padded != target:
        return -1 if padded < target else 1
    post = match["post"] or match["implicit"]
    if match["pre"] or (match["dev"] and not post):
        return -1
    return 1 if post or match["local"] else 0


def _table(parent: dict[str, object], key: str) -> dict[str, object]:
    """Return a TOML table, absent as empty, refusing a value of another type."""
    value = parent.get(key, {})
    if not isinstance(value, dict):
        raise ValueError(key)
    return value


def _sha256_json(value: object, *, compact: bool) -> str:
    """Return the SHA-256 of the key-sorted JSON a tool hashes; a non-JSON value raises."""
    separators = (",", ":") if compact else None
    text = json.dumps(value, sort_keys=True, separators=separators)
    return hashlib.sha256(text.encode()).hexdigest()


def _poetry_forms(document: dict[str, object]) -> dict[str, str]:
    """Return the F1, F2 and F3 hashes of a parsed ``pyproject.toml``."""
    tool = _table(_table(document, "tool"), "poetry")
    project = _table(document, "project")
    legacy = {key: tool.get(key) for key in _RELEVANT_KEYS if key in _LEGACY_KEYS or key in tool}
    forms = {"F3": _sha256_json(legacy, compact=False)}
    for name, groups in (("F1", _table(document, "dependency-groups")), ("F2", {})):
        chosen = {key: project[key] for key in _PROJECT_KEYS if project.get(key) is not None}
        poetry = {
            key: tool.get(key)
            for key in _RELEVANT_KEYS
            if tool.get(key) is not None or (key in _LEGACY_KEYS and not (chosen or groups))
        }
        content: dict[str, object] = {}
        if chosen:
            content["project"] = chosen
        if groups:
            content["dependency-groups"] = groups
        forms[name] = _sha256_json(
            {**content, "tool": {"poetry": poetry}} if content else poetry, compact=False
        )
    return forms


def _canonical(section: dict[str, object]) -> dict[str, object]:
    """Return a package table with every name in its PEP 503 form."""
    return {_NAME_SEPARATORS.sub("-", name).lower(): value for name, value in section.items()}


def _pipenv_forms(document: dict[str, object]) -> dict[str, str]:
    """Return the plette and canonical hashes of a parsed ``Pipfile``."""
    sources = document.get("source", list(_DEFAULT_SOURCE))
    if not isinstance(sources, list):
        raise ValueError("source")
    categories = {
        name: _table(document, name)
        for name in document
        if name not in _PIPFILE_SECTIONS and name not in ("default", "develop")
    }
    forms = {}
    for name, rename in (("plette", False), ("canonical", True)):
        sections = {
            "default": _table(document, "packages"),
            "develop": _table(document, "dev-packages"),
            **categories,
        }
        data: dict[str, object] = {
            "_meta": {"sources": sources, "requires": _table(document, "requires")},
            **{key: _canonical(value) if rename else value for key, value in sections.items()},
        }
        forms[name] = _sha256_json(data, compact=True)
    return forms


def _not_compared(
    manifest: TrackedManifest, recorded: str | None, line: int, writer: str | None
) -> ManifestCheck | None:
    """Return the check when the manifest cannot be compared, or ``None`` when it can."""
    if not manifest.certain:
        state: ManifestState = "manifest-uncertain"
        reason: str | None = UNTRACKED_MANIFEST
    elif manifest.text is None:
        state, reason = "manifest-missing", None
    else:
        return None
    return ManifestCheck(manifest.path, None, state, reason, recorded, line, writer, ())


def _poetry_accepted(writer: str | None) -> tuple[tuple[str, ...], bool]:
    """Return the forms a Poetry writer is judged by, and whether it is newer than mirrored."""
    if writer is None or compare_to_release(writer, NEWEST_MIRRORED_POETRY) is None:
        return ("F1", "F2", "F3"), False
    if compare_to_release(writer, NEWEST_MIRRORED_POETRY) == 1:
        return ("F1",), True
    if compare_to_release(writer, _GROUPS_HASHED_FROM) != -1:
        return ("F1",), False
    if compare_to_release(writer, _PROJECT_TABLE_FROM) != -1:
        return ("F1", "F2"), False
    return ("F1", "F2", "F3"), False


def _decide(
    manifest: TrackedManifest,
    recorded: str | None,
    line: int,
    writer: str | None,
    accepted: tuple[str, ...],
    forms: dict[str, str] | None,
    *,
    newer: bool = False,
) -> ManifestCheck:
    """Return fresh, drift, or uncertain for a manifest that was read."""
    if forms is None:
        state: ManifestState = "manifest-unparseable"
        reason = None
    elif recorded is not None and any(forms[name] == recorded for name in accepted):
        state, reason = "fresh", None
    elif newer and recorded is not None:
        state, reason = "manifest-uncertain", NEWER_WRITER
    else:
        state, reason = "drift", None
    return ManifestCheck(
        manifest.path, manifest.sha256, state, reason, recorded, line, writer, accepted
    )


def _parsed(text: str) -> dict[str, object] | None:
    """Return a parsed TOML document, or ``None`` when it does not parse."""
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return None


def poetry_manifest_check(
    lock_text: str, recorded: str | None, manifest: TrackedManifest
) -> ManifestCheck:
    """Compare a ``poetry.lock``'s ``content-hash`` with the ``pyproject.toml`` beside it.

    Parameters
    ----------
    lock_text : str
        The lockfile text, whose line 1 names its writer.
    recorded : str | None
        The ``content-hash`` the lockfile records.
    manifest : TrackedManifest
        The ``pyproject.toml`` beside it.

    Returns
    -------
    ManifestCheck
        The comparison.
    """
    found = _WRITER.search(lock_text.split("\n", 1)[0])
    writer = None if found is None else found.group(1)
    hash_at = _CONTENT_HASH_LINE.search(lock_text)
    line = 1 if hash_at is None else lock_text.count("\n", 0, hash_at.start()) + 1
    skipped = _not_compared(manifest, recorded, line, writer)
    if skipped is not None:
        return skipped
    accepted, newer = _poetry_accepted(writer)
    document = _parsed(manifest.text or "")
    try:
        forms = None if document is None else _poetry_forms(document)
    except (TypeError, ValueError):
        forms = None
    return _decide(manifest, recorded, line, writer, accepted, forms, newer=newer)


def pipenv_manifest_check(
    lock_text: str, recorded: str | None, manifest: TrackedManifest
) -> ManifestCheck:
    """Compare a ``Pipfile.lock``'s ``_meta.hash`` with the ``Pipfile`` beside it.

    Parameters
    ----------
    lock_text : str
        The lockfile text, already accepted by the JSON reader.
    recorded : str | None
        The ``_meta.hash.sha256`` the lockfile records.
    manifest : TrackedManifest
        The ``Pipfile`` beside it.

    Returns
    -------
    ManifestCheck
        The comparison.
    """
    line = json_key_lines(lock_text).get(("_meta", "hash"), 1)
    skipped = _not_compared(manifest, recorded, line, None)
    if skipped is not None:
        return skipped
    document = _parsed(manifest.text or "")
    try:
        forms = None if document is None else _pipenv_forms(document)
    except (TypeError, ValueError):
        forms = None
    return _decide(manifest, recorded, line, None, ("plette", "canonical"), forms)
