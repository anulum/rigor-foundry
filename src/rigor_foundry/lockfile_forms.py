# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — the locked-entry forms every lockfile kind shares
"""Classify the locked-entry forms that every lockfile kind shares.

A local source is pinned by a path inside the repository; a VCS source by a full commit and no
malformed digest; a remote artifact by an exact version and an accepted, well-formed digest. A
form that fails its pin is ``unpinned`` and names the failure; a form these rules do not know is
``unclassified``. Each lockfile kind reads its own syntax and hands the forms it finds here.
"""

from __future__ import annotations

import posixpath
import re
from typing import Final
from urllib.parse import urlsplit

from .lockfile_digests import DigestReading
from .lockfile_model import (
    ENTRY_FINDINGS,
    PIN_FAILURES,
    CommitHashAlgorithm,
    DigestScope,
    EntryFinding,
    LockedEntry,
)

VCS_URL_PREFIXES: Final = ("git+ssh://", "git+https://", "git+http://", "git+file://", "git://")
HOSTED_SHORTCUTS: Final[dict[str, str]] = {
    "github:": "github.com",
    "gitlab:": "gitlab.com",
    "bitbucket:": "bitbucket.org",
    "gist:": "gist.github.com",
}
FULL_COMMIT: Final = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_WINDOWS_DRIVE: Final = re.compile(r"[A-Za-z]:")


def ordered(findings: set[EntryFinding]) -> tuple[EntryFinding, ...]:
    """Return findings in their fixed order.

    Parameters
    ----------
    findings : set[EntryFinding]
        The findings of one entry.

    Returns
    -------
    tuple[EntryFinding, ...]
        The findings in the order of ``ENTRY_FINDINGS``.
    """
    return tuple(finding for finding in ENTRY_FINDINGS if finding in findings)


def commit_hash_algorithm(commit: str) -> CommitHashAlgorithm:
    """Return the object-id algorithm of a full commit id.

    Parameters
    ----------
    commit : str
        A full commit id that ``FULL_COMMIT`` accepts.

    Returns
    -------
    CommitHashAlgorithm
        ``sha1`` for 40 hex digits, ``sha256`` for 64.
    """
    return "sha1" if len(commit) == 40 else "sha256"


def path_escapes(lock_dir: str, path: str) -> bool:
    """Return whether a lockfile-relative path leaves the repository root.

    Parameters
    ----------
    lock_dir : str
        The repository-relative POSIX directory holding the lockfile.
    path : str
        The path as the lockfile writes it.

    Returns
    -------
    bool
        Whether it is absolute, uses a Windows drive or a backslash, or climbs out.
    """
    if path.startswith("/") or "\\" in path or _WINDOWS_DRIVE.match(path):
        return True
    joined = posixpath.normpath(posixpath.join(lock_dir, path))
    return joined == ".." or joined.startswith("../")


def local_entry(key: str, line: int, lock_dir: str, path: str) -> LockedEntry:
    """Classify a local path source, which is unpinned when it leaves the repository.

    Parameters
    ----------
    key : str
        The entry key.
    line : int
        The entry's line.
    lock_dir : str
        The directory holding the lockfile.
    path : str
        The local path the entry names.

    Returns
    -------
    LockedEntry
        ``local``, or ``unpinned`` with ``path-escape``.
    """
    if path_escapes(lock_dir, path):
        return LockedEntry(key, line, "unpinned", ("path-escape",), form="path")
    return LockedEntry(key, line, "local")


def unknown_entry(key: str, line: int) -> LockedEntry:
    """Classify a form these rules do not know.

    Parameters
    ----------
    key : str
        The entry key.
    line : int
        The entry's line.

    Returns
    -------
    LockedEntry
        ``unclassified`` with ``unknown-form``.
    """
    return LockedEntry(key, line, "unclassified", ("unknown-form",))


def is_vcs(spec: str) -> bool:
    """Return whether a source specification names a VCS checkout.

    Parameters
    ----------
    spec : str
        The specification or URL.

    Returns
    -------
    bool
        Whether it is a ``git+…`` or ``git://`` URL or a hosted shortcut.
    """
    return spec.startswith((*VCS_URL_PREFIXES, *HOSTED_SHORTCUTS))


def vcs_host(spec: str) -> str | None:
    """Return the host a VCS specification fetches from, when it names one.

    Parameters
    ----------
    spec : str
        A specification that ``is_vcs`` accepts.

    Returns
    -------
    str | None
        The host; ``None`` for a ``git+file://`` source.
    """
    for prefix, host in HOSTED_SHORTCUTS.items():
        if spec.startswith(prefix):
            return host
    if spec.startswith("git+file://"):
        return None
    return urlsplit(spec.removeprefix("git+")).hostname


def vcs_entry(
    key: str,
    line: int,
    spec: str,
    reading: DigestReading,
    digest_scope: DigestScope = "artifact",
    notes: tuple[tuple[str, str], ...] = (),
    extra_findings: frozenset[EntryFinding] = frozenset(),
) -> LockedEntry:
    """Classify a VCS source: pinned by a full commit, no malformed digest and no other finding.

    Parameters
    ----------
    key : str
        The entry key.
    line : int
        The entry's line.
    spec : str
        The VCS specification, with the commit after ``#``.
    reading : DigestReading
        The entry's digests, if it records any.
    digest_scope : DigestScope
        What those digests cover, such as Yarn's ``cache-archive``.
    notes : tuple[tuple[str, str], ...]
        Further evidence to record, ordered by name.
    extra_findings : frozenset[EntryFinding]
        Findings beside the commit and digest ones, such as a patch's ``path-escape``.

    Returns
    -------
    LockedEntry
        ``commit-pinned``, or ``unpinned`` with ``floating-ref``, ``malformed-digest`` or the
        extra findings.
    """
    host = vcs_host(spec)
    commit = spec.partition("#")[2]
    scope: DigestScope | None = digest_scope if reading.algorithms else None
    full = FULL_COMMIT.fullmatch(commit) is not None
    if full and not reading.malformed_tokens and not extra_findings:
        return LockedEntry(
            key,
            line,
            "commit-pinned",
            digest_algorithms=reading.algorithms,
            digest_scope=scope,
            commit_hash_algorithm=commit_hash_algorithm(commit),
            origin=host,
            notes=notes,
        )
    failures: set[EntryFinding] = set(extra_findings)
    if not full:
        failures.add("floating-ref")
    if reading.malformed_tokens:
        failures.add("malformed-digest")
    return LockedEntry(
        key,
        line,
        "unpinned",
        ordered(failures),
        form="vcs",
        digest_algorithms=reading.algorithms,
        digest_scope=scope,
        origin=host,
        notes=notes,
    )


def artifact_entry(
    key: str,
    line: int,
    reading: DigestReading,
    origin: str | None,
    extra_findings: set[EntryFinding],
    archive_commit: str | None = None,
    digest_scope: DigestScope = "artifact",
    notes: tuple[tuple[str, str], ...] = (),
) -> LockedEntry:
    """Classify a remote artifact with an exact version, by its digests.

    Parameters
    ----------
    key : str
        The entry key.
    line : int
        The entry's line.
    reading : DigestReading
        The entry's digests.
    origin : str | None
        The host the artifact resolves from.
    extra_findings : set[EntryFinding]
        Findings beside the digest ones: an origin finding, or ``floating-ref`` for an archive
        of a moving reference.
    archive_commit : str | None
        The full commit a hosted archive names, recorded as evidence.
    digest_scope : DigestScope
        What the digests cover.
    notes : tuple[tuple[str, str], ...]
        Further evidence to record, ordered by name.

    Returns
    -------
    LockedEntry
        ``artifact-pinned`` when the digests pin it and nothing floats; otherwise ``unpinned``
        with its form ``artifact``.
    """
    findings: set[EntryFinding] = {*reading.findings, *extra_findings}
    algorithm = commit_hash_algorithm(archive_commit) if archive_commit is not None else None
    scope: DigestScope | None = digest_scope if reading.algorithms else None
    if reading.pins_artifact and not PIN_FAILURES.intersection(findings):
        return LockedEntry(
            key,
            line,
            "artifact-pinned",
            ordered(findings),
            digest_algorithms=reading.algorithms,
            digest_scope=digest_scope,
            commit_hash_algorithm=algorithm,
            origin=origin,
            archive_commit=archive_commit,
            notes=notes,
        )
    return LockedEntry(
        key,
        line,
        "unpinned",
        ordered(findings),
        form="artifact",
        digest_algorithms=reading.algorithms,
        digest_scope=scope,
        commit_hash_algorithm=algorithm,
        origin=origin,
        archive_commit=archive_commit,
        notes=notes,
    )
