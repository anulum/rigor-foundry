# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Yarn 1 lockfile classification
"""Classify every entry of a Yarn 1 ``yarn.lock``.

A ``file:`` or ``link:`` specifier is a local source. A ``resolved`` Git URL with ``#<commit>``
is cloned through Git and pinned by a full commit. A ``codeload.github.com`` archive of a commit
is a plain tarball that neither Git nor Yarn verifies: without a digest it is ``unpinned`` with
``missing-digest``, and the commit it names is recorded as ``archive_commit``. Its host is
recorded, not compared, like every VCS host. Any other URL is a registry artifact, pinned by an
accepted ``integrity`` digest; the SHA-1 hex after its ``#`` is a weak digest of its own. Its
host is compared with the registry the repository declares for Yarn 1. The entry key lists the
entry's specifiers, unquoted, separated by ``, ``.
"""

from __future__ import annotations

from typing import Final
from urllib.parse import urlsplit

from .lockfile_digests import (
    DigestReading,
    combine_readings,
    missing_digest,
    read_hex_digest,
    read_sri,
)
from .lockfile_forms import (
    FULL_COMMIT,
    artifact_entry,
    is_vcs,
    local_entry,
    unknown_entry,
    vcs_entry,
)
from .lockfile_model import EntryFinding, LockedEntry
from .lockfile_npmrc import url_host
from .lockfile_yarn1_syntax import Yarn1Entry, parse_yarn1
from .lockfile_yarnrc import YarnRegistryDeclaration

CODELOAD_HOST: Final = "codeload.github.com"
_LOCAL_PROTOCOLS: Final = ("file:", "link:")


def _name_and_range(specifier: str) -> tuple[str, str]:
    """Split a specifier into its package name and the range or source after ``@``."""
    at = specifier.find("@", 1 if specifier.startswith("@") else 0)
    if at <= 0:
        return specifier, ""
    return specifier[:at], specifier[at + 1 :]


def _digest(entry: Yarn1Entry, fragment: str) -> DigestReading:
    """Read an entry's ``integrity`` and the SHA-1 hex its URL fragment carries, if any."""
    readings: list[DigestReading] = []
    if "integrity" in entry.fields:
        readings.append(read_sri(entry.fields["integrity"]))
    if fragment:
        readings.append(read_hex_digest("sha1", fragment))
    return combine_readings(readings) if readings else missing_digest()


def _codeload_ref(resolved: str) -> str | None:
    """Return the reference a codeload archive URL names, or ``None`` for another shape."""
    parts = urlsplit(resolved).path.split("/")
    if len(parts) != 5 or parts[0] or parts[3] != "tar.gz" or not all(parts[1:]):
        return None
    return parts[4]


def _classify(entry: Yarn1Entry, lock_dir: str, registry: YarnRegistryDeclaration) -> LockedEntry:
    """Classify one entry."""
    key = ", ".join(entry.specifiers)
    name, _ = _name_and_range(entry.specifiers[0])
    for specifier in entry.specifiers:
        _, source = _name_and_range(specifier)
        if source.startswith(_LOCAL_PROTOCOLS):
            return local_entry(key, entry.line, lock_dir, source.split(":", 1)[1])
    resolved = entry.fields.get("resolved")
    if resolved is None:
        return unknown_entry(key, entry.line)
    if is_vcs(resolved):
        reading = (
            read_sri(entry.fields["integrity"])
            if "integrity" in entry.fields
            else missing_digest()
        )
        return vcs_entry(key, entry.line, resolved, reading)
    if resolved.startswith("file:"):
        return local_entry(key, entry.line, lock_dir, resolved.removeprefix("file:"))
    host = url_host(resolved)
    if host is None or not entry.fields.get("version"):
        return unknown_entry(key, entry.line)
    location, _, fragment = resolved.partition("#")
    ref = _codeload_ref(location) if host == CODELOAD_HOST else None
    if ref is not None:
        full = FULL_COMMIT.fullmatch(ref) is not None
        extra: set[EntryFinding] = set() if full else {"floating-ref"}
        reading = _digest(entry, "")
        return artifact_entry(
            key, entry.line, reading, host, extra, archive_commit=ref if full else None
        )
    finding = registry.origin_finding(name, host)
    origin_findings: set[EntryFinding] = set() if finding is None else {finding}
    return artifact_entry(key, entry.line, _digest(entry, fragment), host, origin_findings)


def classify_yarn1_lockfile(
    text: str, lock_dir: str, registry: YarnRegistryDeclaration
) -> tuple[str, tuple[LockedEntry, ...]]:
    """Classify every entry of one Yarn 1 lockfile.

    Parameters
    ----------
    text : str
        The lockfile text.
    lock_dir : str
        The repository-relative POSIX directory holding the lockfile; ``""`` for the root.
    registry : YarnRegistryDeclaration
        The registries the repository declares for Yarn 1.

    Returns
    -------
    tuple[str, tuple[LockedEntry, ...]]
        The format version ``"1"``, and the entries ordered by line.

    Raises
    ------
    LockfileRefusal
        ``unparseable`` or ``conflicting-entries``, with no entry results.
    """
    entries = tuple(_classify(entry, lock_dir, registry) for entry in parse_yarn1(text))
    return "1", tuple(sorted(entries, key=lambda entry: (entry.line, entry.key)))
