# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Poetry lockfile classification
"""Classify every package of a ``poetry.lock``, lock-version 2.0 or 2.1.

Poetry 1.3 to 1.8 write lock-version 2.0 and Poetry 2 writes 2.1; both list each package's files
and hashes in its own ``files``. Lock-version 1.x keeps the hashes in ``[metadata.files]`` keyed by
name alone, so it is refused as ``unsupported-lock-version``, and a 2.x file that still carries
``[metadata.files]`` mixes the two as ``conflicting-entries``. Any other lock-version is
``unsupported-version``.

Poetry verifies an archive at install by its file name against ``files``, and verifies nothing
when ``files`` is empty. Every listed file must carry an accepted hash (sha256, sha384 or
sha512): a weak one (sha1 or md5) on any file gives ``weak-digest`` even beside accepted ones,
because the file Poetry picks depends on the platform; this departs from the general rule that
one accepted digest suffices. An algorithm outside that table is ``malformed-digest``, noted
``unrecognised_algorithm``.

The source decides the class: none is PyPI; ``legacy`` is an index named by ``reference``; ``url``
is a direct archive; ``file`` and ``directory`` are local paths read from the lockfile's
directory; ``git`` is pinned by its ``resolved_reference``; any other type is unknown. The
``content-hash`` is a manifest hash, recorded and not compared.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from .lockfile_digests import missing_digest
from .lockfile_forms import artifact_entry, listed_hashes, local_entry, unknown_entry, vcs_entry
from .lockfile_model import EntryFinding, LockedEntry, LockfileRefusal
from .lockfile_npmrc import url_host
from .lockfile_poetry_sources import PoetryDeclaration
from .lockfile_toml import entry_keys, header_lines, load_document, table, tables, text_field

SUPPORTED_POETRY_LOCK_VERSIONS: Final = frozenset({"2.0", "2.1"})
PYPI_HOST: Final = "pypi.org"
_VERSION: Final = re.compile(r"(\d+)\.(\d+)")


@dataclass(frozen=True)
class PoetryLockfile:
    """One classified ``poetry.lock``.

    Parameters
    ----------
    version : str
        The ``lock-version``: ``2.0`` or ``2.1``.
    entries : tuple[LockedEntry, ...]
        The entries, ordered by line.
    content_hash : str | None
        The ``content-hash`` of the manifest the lock was made from; a drift signal only.
    """

    version: str
    entries: tuple[LockedEntry, ...]
    content_hash: str | None


def _version(metadata: dict[str, object]) -> str:
    """Return the lock-version, refusing a missing, old, unknown or mixed one."""
    raw = metadata.get("lock-version")
    if raw is None:
        raise LockfileRefusal("missing-version")
    if not isinstance(raw, str):
        raise LockfileRefusal("unsupported-version")
    parsed = _VERSION.fullmatch(raw)
    if parsed is not None and int(parsed.group(1)) < 2:
        raise LockfileRefusal("unsupported-lock-version")
    if raw not in SUPPORTED_POETRY_LOCK_VERSIONS:
        raise LockfileRefusal("unsupported-version")
    if "files" in metadata:
        raise LockfileRefusal("conflicting-entries")
    return raw


def _hashes(package: dict[str, object]) -> list[str]:
    """Return a package's listed hashes, refusing a package without ``files`` or a bad shape."""
    if "files" not in package:
        raise LockfileRefusal("unparseable")
    hashes = []
    for item in tables(package["files"]):
        if text_field(item, "file") is None:
            raise LockfileRefusal("unparseable")
        value = text_field(item, "hash")
        if value is None:
            raise LockfileRefusal("unparseable")
        hashes.append(value)
    return hashes


def _origin_finding(
    declaration: PoetryDeclaration | None, verdict: bool | None
) -> frozenset[EntryFinding]:
    """Return the origin finding: unknown with nothing to judge by, else a mismatch or none."""
    if declaration is None or verdict is None:
        return frozenset({"origin-unknown"})
    return frozenset({"origin-mismatch"}) if verdict else frozenset()


def _classify(
    key: str,
    line: int,
    package: dict[str, object],
    version: str,
    lock_dir: str,
    declaration: PoetryDeclaration | None,
) -> LockedEntry:
    """Classify one package by its source type."""
    hashes = _hashes(package)
    raw_source = package.get("source")
    if raw_source is None:
        digests = listed_hashes(hashes)
        deactivated = None if declaration is None else declaration.pypi_deactivated(version)
        return artifact_entry(
            key,
            line,
            digests.reading,
            PYPI_HOST,
            {*digests.findings, *_origin_finding(declaration, deactivated)},
            notes=digests.notes,
        )
    source = table(raw_source)
    kind, url = text_field(source, "type"), text_field(source, "url")
    if kind == "legacy":
        digests = listed_hashes(hashes)
        mismatch = (
            None
            if declaration is None
            else not declaration.matches(text_field(source, "reference"), url)
        )
        return artifact_entry(
            key,
            line,
            digests.reading,
            None if url is None else url_host(url),
            {*digests.findings, *_origin_finding(declaration, mismatch)},
            notes=digests.notes,
        )
    if kind == "url" and url is not None:
        digests = listed_hashes(hashes)
        return artifact_entry(
            key, line, digests.reading, url_host(url), set(digests.findings), notes=digests.notes
        )
    if kind == "file" and url is not None:
        file_notes = (("file_hash", " ".join(hashes)),) if hashes else ()
        return local_entry(key, line, lock_dir, url, notes=file_notes)
    if kind == "directory" and url is not None:
        develop = package.get("develop")
        return local_entry(
            key, line, lock_dir, url, notes=(("develop", "true"),) if develop is True else ()
        )
    if kind == "git" and url is not None:
        git_notes = tuple(
            (name, value)
            for name, field in (("git_reference", "reference"), ("subdirectory", "subdirectory"))
            if (value := text_field(source, field)) is not None
        )
        commit = text_field(source, "resolved_reference") or ""
        return vcs_entry(key, line, f"{url}#{commit}", missing_digest(), notes=git_notes)
    return unknown_entry(key, line)


def classify_poetry_lockfile(
    text: str, lock_dir: str, declaration: PoetryDeclaration | None
) -> PoetryLockfile:
    """Classify every package of one ``poetry.lock``.

    Parameters
    ----------
    text : str
        The lockfile text.
    lock_dir : str
        The repository-relative POSIX directory holding it; ``""`` for the root.
    declaration : PoetryDeclaration | None
        The sources the ``pyproject.toml`` beside it declares, or ``None`` when it cannot be read.

    Returns
    -------
    PoetryLockfile
        The lock-version, the entries ordered by line, and the content hash.

    Raises
    ------
    LockfileRefusal
        ``unparseable``, ``missing-version``, ``unsupported-version``,
        ``unsupported-lock-version`` or ``conflicting-entries``, with no entry results.
    """
    document = load_document(text)
    metadata = table(document.get("metadata", {}))
    version = _version(metadata)
    packages = tables(document.get("package", []))
    lines = header_lines(text, packages)
    sources = [
        None if "source" not in package else text_field(table(package["source"]), "url")
        for package in packages
    ]
    keys = entry_keys(packages, sources)
    entries = tuple(
        _classify(key, line, package, version, lock_dir, declaration)
        for key, line, package in zip(keys, lines, packages, strict=True)
    )
    return PoetryLockfile(version, entries, text_field(metadata, "content-hash"))
