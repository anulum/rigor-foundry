# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — classify one pnpm package resolution
"""Classify one pnpm ``packages`` entry by its ``resolution``, as pnpm 8.15.9 to 11.29.0 read it.

- **No ``type`` and no ``tarball``:** a registry package, fetched from the registry declared for
  its scope and pinned by its ``integrity``.
- **A ``tarball`` URL:** a relative one is resolved against that registry, as
  ``new URL(tarball, registry)`` does, and an absolute one names its own host, compared with the
  registry and recorded as ``tarball_url_dependency``. A ``file:`` tarball is local, its path read
  from the lockfile's directory.
- **A git host's archive** (``codeload.github.com``, ``bitbucket.org`` or ``gitlab.com`` in the
  path shapes pnpm 11 recognises): pnpm exempts it from integrity because its URL names a commit,
  but nothing verifies those bytes against the commit, so it is an artifact pinned only by its
  ``integrity``, with ``archive_commit``; another reference floats.
- **``type: git``:** a clone, pinned by a full commit; ``path`` is recorded.
- **``type: directory``:** local, its path read from the lockfile's directory.
- Any other ``type`` (``binary``, ``variations``, ``custom:…``) has no fixture yet and is unknown.
"""

from __future__ import annotations

import re
from typing import Final
from urllib.parse import parse_qs, urljoin, urlsplit

from .lockfile_digests import DigestReading, missing_digest, read_sri
from .lockfile_forms import artifact_entry, ordered, path_escapes, unknown_entry, vcs_entry
from .lockfile_model import EntryFinding, LockedEntry
from .lockfile_npmrc import url_host
from .lockfile_pnpm_config import PnpmRegistryDeclaration
from .workflow_yaml import WorkflowValue

Notes = tuple[tuple[str, str], ...]
_GIT_COMMIT: Final = re.compile(r"[0-9a-fA-F]{40}")


def _sorted_notes(notes: Notes, *extra: tuple[str, str]) -> Notes:
    """Return notes with more added, ordered by name."""
    return tuple(sorted((*notes, *extra)))


def _segments(url: str) -> list[str]:
    """Return a URL path's non-empty segments."""
    return [segment for segment in urlsplit(url).path.split("/") if segment]


def _gitlab_reference(url: str, segments: list[str]) -> str | None:
    """Return the reference of a GitLab archive URL, or ``None`` when it is not one."""
    if (
        len(segments) == 6
        and segments[:3] == ["api", "v4", "projects"]
        and segments[4:] == ["repository", "archive.tar.gz"]
    ):
        return parse_qs(urlsplit(url).query).get("ref", [""])[0]
    for index in range(2, len(segments) - 1):
        if segments[index] == "-" and segments[index + 1] == "archive":
            if len(segments) == index + 4 and segments[index + 3].endswith(".tar.gz"):
                return segments[index + 2]
            return None
    return None


def git_hosted_reference(url: str) -> str | None:
    """Return the reference a git host's archive URL names, or ``None`` when it is not one.

    Parameters
    ----------
    url : str
        A tarball URL.

    Returns
    -------
    str | None
        The reference, which is a commit only when pnpm would treat the archive as immutable.
    """
    parts = urlsplit(url)
    if parts.scheme != "https":
        return None
    host = (parts.hostname or "").lower()
    segments = _segments(url)
    if host == "codeload.github.com" and len(segments) == 4 and segments[2] == "tar.gz":
        return segments[3]
    if host == "bitbucket.org" and len(segments) == 4 and segments[2] == "get":
        name = segments[3]
        return name.removesuffix(".tar.gz") if name.endswith(".tar.gz") else None
    if host == "gitlab.com":
        return _gitlab_reference(url, segments)
    return None


def _integrity(resolution: dict[str, WorkflowValue]) -> DigestReading:
    """Read a resolution's ``integrity``, missing or malformed as written."""
    value = resolution.get("integrity")
    if value is None:
        return missing_digest()
    if value.kind != "scalar":
        return DigestReading(algorithms=(), malformed_tokens=1)
    return read_sri(value.text)


def _local(
    key: str,
    line: int,
    lock_dir: str,
    path: str,
    reading: DigestReading,
    extra: frozenset[EntryFinding],
) -> LockedEntry:
    """Classify a local folder or tarball, recording a tarball's integrity."""
    findings = set(extra)
    if path_escapes(lock_dir, path):
        findings.add("path-escape")
    if findings:
        return LockedEntry(key, line, "unpinned", ordered(findings), form="path")
    algorithms = reading.algorithms
    return LockedEntry(
        key,
        line,
        "local",
        digest_algorithms=algorithms,
        digest_scope="artifact" if algorithms else None,
    )


def _archive(
    key: str,
    line: int,
    url: str,
    reference: str,
    reading: DigestReading,
    notes: Notes,
    extra: frozenset[EntryFinding],
) -> LockedEntry:
    """Classify a git host's archive: an artifact pinned only by its integrity."""
    commit = reference.lower() if _GIT_COMMIT.fullmatch(reference) else None
    findings = set(extra) if commit is not None else {*extra, "floating-ref"}
    return artifact_entry(
        key, line, reading, url_host(url), findings, archive_commit=commit, notes=notes
    )


def _tarball(
    key: str,
    line: int,
    name: str,
    tarball: str,
    reading: DigestReading,
    registry: PnpmRegistryDeclaration,
    notes: Notes,
    extra: frozenset[EntryFinding],
) -> LockedEntry:
    """Classify a remote tarball, relative to the registry or absolute."""
    if "\\" in tarball:
        return unknown_entry(key, line)
    absolute = bool(urlsplit(tarball).scheme)
    declared = registry.registry_origin(name)[0]
    if not absolute and declared is None:
        return artifact_entry(key, line, reading, None, {*extra, "origin-unknown"}, notes=notes)
    url = tarball if absolute else urljoin(f"https://{declared}/", tarball)
    host = url_host(url)
    if host is None:
        return unknown_entry(key, line)
    reference = git_hosted_reference(url)
    if reference is not None:
        return _archive(key, line, url, reference, reading, notes, extra)
    if absolute:
        notes = _sorted_notes(notes, ("tarball_url_dependency", "true"))
    origin = registry.origin_finding(name, host)
    findings = set(extra) if origin is None else {*extra, origin}
    return artifact_entry(key, line, reading, host, findings, notes=notes)


def _git(
    key: str,
    line: int,
    resolution: dict[str, WorkflowValue],
    notes: Notes,
    extra: frozenset[EntryFinding],
) -> LockedEntry:
    """Classify a Git clone by its repository and commit."""
    repo = resolution.get("repo")
    commit = resolution.get("commit")
    if repo is None or commit is None or repo.kind != "scalar" or commit.kind != "scalar":
        return unknown_entry(key, line)
    subdirectory = resolution.get("path")
    if subdirectory is not None:
        if subdirectory.kind != "scalar":
            return unknown_entry(key, line)
        notes = _sorted_notes(notes, ("git_path", subdirectory.text))
    spec = repo.text if repo.text.startswith(("git+", "git://")) else "git+" + repo.text
    return vcs_entry(
        key, line, f"{spec}#{commit.text}", missing_digest(), notes=notes, extra_findings=extra
    )


def classify_resolution(
    key: str,
    line: int,
    name: str,
    resolution: WorkflowValue | None,
    lock_dir: str,
    registry: PnpmRegistryDeclaration,
    notes: Notes = (),
    extra: frozenset[EntryFinding] = frozenset(),
) -> LockedEntry:
    """Classify one package entry by its resolution.

    Parameters
    ----------
    key : str
        The entry key.
    line : int
        The entry's line.
    name : str
        The package name, which picks its scope's registry.
    resolution : WorkflowValue | None
        The entry's ``resolution`` field.
    lock_dir : str
        The repository-relative POSIX directory holding the lockfile; ``""`` for the root.
    registry : PnpmRegistryDeclaration
        The registries pnpm would use.
    notes : tuple[tuple[str, str], ...]
        Evidence already gathered for the entry, such as its patch, ordered by name.
    extra : frozenset[EntryFinding]
        Findings already made for the entry, such as its patch file's ``path-escape``.

    Returns
    -------
    LockedEntry
        The classified entry.
    """
    if resolution is None or resolution.kind != "mapping":
        return unknown_entry(key, line)
    fields = resolution.mapping()
    kind = fields.get("type")
    reading = _integrity(fields)
    if kind is None:
        tarball = fields.get("tarball")
        if tarball is None:
            origin, finding = registry.registry_origin(name)
            findings = set(extra) if finding is None else {*extra, finding}
            return artifact_entry(key, line, reading, origin, findings, notes=notes)
        if tarball.kind != "scalar":
            return unknown_entry(key, line)
        if tarball.text.startswith("file:"):
            path = tarball.text.removeprefix("file:")
            return _local(key, line, lock_dir, path, reading, extra)
        return _tarball(key, line, name, tarball.text, reading, registry, notes, extra)
    if kind.kind != "scalar":
        return unknown_entry(key, line)
    if kind.text == "git":
        return _git(key, line, fields, notes, extra)
    directory = fields.get("directory")
    if kind.text == "directory" and directory is not None and directory.kind == "scalar":
        return _local(key, line, lock_dir, directory.text, missing_digest(), extra)
    return unknown_entry(key, line)
