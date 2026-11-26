# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Yarn 2+ lockfile classification
"""Classify every entry of a Yarn 2 or later ``yarn.lock``.

The file is YAML with a ``__metadata`` mapping, read without anchors, aliases or tags and with a
duplicate key refused. Only ``__metadata.version`` values a real Yarn release has written into a
fixture here are read: 6 (Yarn 3) and 10 (Yarn 4). Each other key is an entry listing its
descriptors, written as Yarn writes it: plain when it is a plain YAML string and JSON otherwise, on
the line before its fields, or, when longer than 1024 characters, after ``? `` with the ``:`` alone
on the next line.

A checksum hashes Yarn's own cache archive (scope ``cache-archive``); Yarn 3 writes bare hex and
Yarn 4 prefixes the cache key. A checksum whose cache key differs from ``__metadata.cacheKey`` is
not verified by Yarn, so it is ``malformed-digest`` with the keys recorded. An ``npm:`` resolution
comes from the declared registry. A Git clone at a full commit is ``commit-pinned``; a GitHub
archive is an artifact pinned only by its checksum, with ``archive_commit``. ``#head=``, ``#tag=``,
``#semver=`` and short commits float. ``file:``, ``link:``, ``portal:`` and ``workspace:`` are
local; ``exec:`` and other protocols are unknown. A ``patch:`` entry is classified by its own
checksum, and records its patch source.

Paths are read as Yarn 3.8.7 and 4.19.0 read them: from a range's selector (after ``#``, else its
source), URL-decoded, and a relative path resolved from the package its ``locator`` binding names:
a workspace's directory, or a local package's folder, found the same way. A path inside a fetched
package is not a repository path, so that entry is unknown. Patch paths are split on ``&``. Yarn 3
(lockfile version 6) reads a leading ``~`` as "optional"; Yarn 4 (version 10) reads flags before
the last ``!`` and ``~/`` as the project root.
"""

from __future__ import annotations

import json
import posixpath
import re
from typing import Final
from urllib.parse import parse_qs, unquote, urlsplit

from .lockfile_digests import DigestReading, missing_digest, read_hex_digest
from .lockfile_forms import (
    FULL_COMMIT,
    artifact_entry,
    path_escapes,
    unknown_entry,
    vcs_entry,
)
from .lockfile_model import EntryFinding, LockedEntry, LockfileRefusal
from .lockfile_npmrc import url_host
from .lockfile_yarnrc_yml import BerryRegistryDeclaration
from .workflow_yaml import WorkflowFormatError, WorkflowValue, YamlLimits, parse_workflow_yaml

LOCKFILE_YAML_LIMITS: Final = YamlLimits(8 * 1024 * 1024, 2_000_000, False)
SUPPORTED_BERRY_VERSIONS: Final = frozenset({"6", "10"})
_CACHE_KEY: Final = re.compile(r"[0-9]+(?:[a-z][0-9a-z]*)?")
_LOCAL_PROTOCOLS: Final = ("file:", "link:", "portal:", "workspace:")
_GIT_PROTOCOLS: Final = ("git:", "git+", "ssh:")
_FLOATING_KEYS: Final = ("head", "tag", "semver")
_GITHUB: Final = "github.com"
_RANGE: Final = re.compile(r"([^#:]*:)?((?:(?!::)[^#])*)(?:#((?:(?!::).)*))?(?:::(.*))?")
_BAD_ESCAPE: Final = re.compile(r"%(?![0-9A-Fa-f]{2})")
_BUILTIN_PATCH: Final = re.compile(r"builtin<[^>]+>")
_PATH_PROTOCOLS: Final = ("file:", "link:", "portal:")
_MAX_PARENT_DEPTH: Final = 32
_OUTSIDE: Final = ".."
_PLAIN_KEY: Final = re.compile(
    r"(?![-?:,\][{}#&*!|>'\"%@` \t\r\n])[^\n\r\u2028\u2029]"
    r"(?:[ \t]*(?![,\][{}:# \t\r\n])[^\n\r\u2028\u2029])*"
)
_LONG_KEY: Final = 1024
_LINE_BREAK: Final = re.compile("\r\n|[\r\n\x85\u2028\u2029]")


def _name_and_reference(descriptor: str) -> tuple[str, str]:
    """Split ``name@reference`` at the ``@`` after a scoped name's own."""
    at = descriptor.find("@", 1 if descriptor.startswith("@") else 0)
    return (descriptor, "") if at <= 0 else (descriptor[:at], descriptor[at + 1 :])


def _checksum(
    entry: dict[str, WorkflowValue], cache_key: str
) -> tuple[DigestReading, tuple[tuple[str, str], ...]]:
    """Read an entry's checksum against the lockfile's cache key, with any problem recorded."""
    value = entry.get("checksum")
    if value is None:
        return missing_digest(), ()
    if value.kind != "scalar":
        return DigestReading(algorithms=(), malformed_tokens=1), ()
    prefix, separator, digest = value.text.rpartition("/")
    if separator and prefix != cache_key:
        notes = (
            ("checksum_cache_key", prefix),
            ("digest_problem", "foreign-cache-key"),
            ("lockfile_cache_key", cache_key),
        )
        return DigestReading(algorithms=(), malformed_tokens=1), notes
    return read_hex_digest("sha512", digest), ()


def _decoded(text: str) -> str | None:
    """Decode a range part as ``decodeURIComponent`` does, or ``None`` where it would throw."""
    if _BAD_ESCAPE.search(text):
        return None
    try:
        return unquote(text, errors="strict")
    except UnicodeDecodeError:
        return None


def _parse_range(reference: str) -> tuple[str | None, str, str] | None:
    """Split a range as Yarn's ``parseRange`` does.

    Returns the decoded source (``None`` without a ``#``), the decoded selector (the source when
    there is no ``#``) and the raw bindings, or ``None`` where Yarn would refuse the range.
    """
    match = _RANGE.fullmatch(reference)
    if match is None:
        return None
    written = _decoded(match.group(2))
    selector = written if match.group(3) is None else _decoded(match.group(3))
    if written is None or selector is None:
        return None
    return (None if match.group(3) is None else written), selector, match.group(4) or ""


def _within(base: str, path: str) -> str:
    """Resolve a Yarn path from a repository directory; ``..`` when it leaves the repository."""
    if path_escapes(base, path):
        return _OUTSIDE
    return posixpath.normpath(posixpath.join(base, path))


def _locator(bindings: str) -> str | None:
    """Return the one ``locator`` binding Yarn reads, or ``None`` when it is missing or repeated."""
    locators = parse_qs(bindings).get("locator", [])
    return locators[0] if len(locators) == 1 else None


def _parent_directory(lock_dir: str, locator: str | None, depth: int) -> str | None:
    """Return the repository directory a relative path is resolved from, or ``None``.

    The locator names the package that declared the path. A workspace's directory is the
    repository path its reference names; a local package's folder is found the same way, at most
    ``_MAX_PARENT_DEPTH`` levels deep. A fetched package, or no locator, gives ``None``.
    """
    if locator is None or depth >= _MAX_PARENT_DEPTH:
        return None
    _, reference = _name_and_reference(locator)
    if reference.startswith("workspace:"):
        return _within(lock_dir, reference.removeprefix("workspace:"))
    if reference.startswith(_PATH_PROTOCOLS):
        return _local_location(lock_dir, reference, depth + 1)
    return None


def _local_location(lock_dir: str, reference: str, depth: int = 0) -> str | None:
    """Return the repository path a ``file:``, ``link:`` or ``portal:`` reference names.

    ``..`` means the path leaves the repository; ``None`` means it is not a repository path or
    Yarn could not read it. As in Yarn, one ``locator`` binding is required first, and an
    absolute path is read from the disk whoever declared it.
    """
    parsed = _parse_range(reference)
    if parsed is None:
        return None
    _, path, bindings = parsed
    locator = _locator(bindings)
    if locator is None:
        return None
    if path.startswith("/"):
        return _OUTSIDE
    parent = _parent_directory(lock_dir, locator, depth)
    return None if parent is None else _within(parent, path)


def _local(
    key: str, line: int, lock_dir: str, reference: str, reading: DigestReading
) -> LockedEntry:
    """Classify a local source, recording a ``file:`` folder's checksum when it has one."""
    location = (
        _within(lock_dir, reference.removeprefix("workspace:"))
        if reference.startswith("workspace:")
        else _local_location(lock_dir, reference)
    )
    if location is None:
        return unknown_entry(key, line)
    if location == _OUTSIDE:
        return LockedEntry(key, line, "unpinned", ("path-escape",), form="path")
    algorithms = reading.algorithms
    return LockedEntry(
        key,
        line,
        "local",
        digest_algorithms=algorithms,
        digest_scope="cache-archive" if algorithms else None,
    )


def _patch_path(lock_dir: str, version: str, path: str, bindings: str) -> tuple[str, bool] | None:
    """Return one patch path without its flags and whether it leaves the repository.

    ``None`` means it is relative to a package outside the repository, or to none.
    """
    if version == "6":
        path = path.removeprefix("~")
    else:
        path = path[path.rfind("!") + 1 :]
    if _BUILTIN_PATCH.fullmatch(path):
        return path, False
    if version != "6" and path.startswith("~/"):
        return path, _within(lock_dir, path[2:]) == _OUTSIDE
    if path.startswith("/"):
        return path, True
    parent = _parent_directory(lock_dir, _locator(bindings), 0)
    return None if parent is None else (path, _within(parent, path) == _OUTSIDE)


def _patch(
    key: str,
    line: int,
    lock_dir: str,
    version: str,
    reference: str,
    reading: DigestReading,
    notes: tuple[tuple[str, str], ...],
) -> LockedEntry:
    """Classify a patched package by its own checksum, recording its patch sources."""
    parsed = _parse_range(reference)
    if parsed is None or parsed[0] is None or not parsed[1]:
        return unknown_entry(key, line)
    _, selector, bindings = parsed
    sources: list[str] = []
    escape: set[EntryFinding] = set()
    for path in selector.split("&"):
        read = _patch_path(lock_dir, version, path, bindings)
        if read is None:
            return unknown_entry(key, line)
        sources.append(read[0])
        if read[1]:
            escape.add("path-escape")
    patch_notes = tuple(sorted((*notes, ("patch_source", "&".join(sources)))))
    return artifact_entry(
        key, line, reading, None, escape, digest_scope="cache-archive", notes=patch_notes
    )


def _git(
    key: str, line: int, reference: str, reading: DigestReading, notes: tuple[tuple[str, str], ...]
) -> LockedEntry:
    """Classify a ``#commit=`` reference: a clone pins by commit, a GitHub archive by checksum."""
    location, _, fragment = reference.partition("#")
    parameters = parse_qs(fragment, keep_blank_values=True)
    commit = parameters.get("commit", [""])[0]
    full = FULL_COMMIT.fullmatch(commit) is not None and not any(
        name in parameters for name in _FLOATING_KEYS
    )
    if urlsplit(location).hostname == _GITHUB and location.startswith("https:"):
        extra: set[EntryFinding] = set() if full else {"floating-ref"}
        return artifact_entry(
            key,
            line,
            reading,
            _GITHUB,
            extra,
            archive_commit=commit if full else None,
            digest_scope="cache-archive",
            notes=notes,
        )
    spec = location + "#" + (commit if full else fragment)
    return vcs_entry(key, line, spec, reading, digest_scope="cache-archive", notes=notes)


def _classify(
    key: str,
    descriptors: tuple[str, ...],
    line: int,
    entry: dict[str, WorkflowValue],
    lock_dir: str,
    metadata: tuple[str, str],
    registry: BerryRegistryDeclaration,
) -> LockedEntry:
    """Classify one entry by its resolution, given the lockfile's version and cache key."""
    version, cache_key = metadata
    resolution = entry.get("resolution")
    if resolution is None or resolution.kind != "scalar":
        return unknown_entry(key, line)
    name, reference = _name_and_reference(resolution.text)
    reading, notes = _checksum(entry, cache_key)
    aliases = sorted({_name_and_reference(d)[0] for d in descriptors} - {name})
    if aliases:
        notes = tuple(sorted((*notes, ("alias", ", ".join(aliases)))))
    if reference.startswith(_LOCAL_PROTOCOLS):
        return _local(key, line, lock_dir, reference, reading)
    if reference.startswith("npm:"):
        locked = entry.get("version")
        if locked is None or locked.kind != "scalar" or not locked.text:
            return unknown_entry(key, line)
        origin, finding = registry.registry_origin(name)
        extra: set[EntryFinding] = set() if finding is None else {finding}
        return artifact_entry(
            key, line, reading, origin, extra, digest_scope="cache-archive", notes=notes
        )
    if reference.startswith("patch:"):
        return _patch(key, line, lock_dir, version, reference, reading, notes)
    if "#" in reference and reference.startswith((*_GIT_PROTOCOLS, "https:", "http:")):
        return _git(key, line, reference, reading, notes)
    host = url_host(reference)
    if host is None:
        return unknown_entry(key, line)
    finding = registry.origin_finding(name, host)
    origin_findings: set[EntryFinding] = set() if finding is None else {finding}
    return artifact_entry(
        key, line, reading, host, origin_findings, digest_scope="cache-archive", notes=notes
    )


def _key_line(lines: list[str], key: str, field_line: int) -> int:
    """Return the line an entry's key is on, refusing any layout Yarn does not write.

    Parameters
    ----------
    lines : list[str]
        The lockfile's lines, split at YAML line breaks.
    key : str
        The entry's key as parsed.
    field_line : int
        The 1-based line of the entry's first field.

    Returns
    -------
    int
        The 1-based line of the key, or of its ``? `` for a long key.

    Raises
    ------
    LockfileRefusal
        ``unparseable`` when the key is not written where and as Yarn writes it.
    """
    written = key if _PLAIN_KEY.fullmatch(key) else json.dumps(key, ensure_ascii=False)
    if len(written) > _LONG_KEY:
        layout, line = [f"? {written}", ":"], field_line - 2
    else:
        layout, line = [f"{written}:"], field_line - 1
    if line < 1 or lines[line - 1 : field_line - 1] != layout:
        raise LockfileRefusal("unparseable")
    return line


def _metadata(root: dict[str, WorkflowValue]) -> tuple[str, str]:
    """Return the supported ``__metadata`` version and cache key, or refuse the file."""
    metadata = root.get("__metadata")
    if metadata is None or metadata.kind != "mapping":
        raise LockfileRefusal("unparseable")
    fields = metadata.mapping()
    version = fields.get("version")
    if version is None:
        raise LockfileRefusal("missing-version")
    if version.kind != "scalar" or version.text not in SUPPORTED_BERRY_VERSIONS:
        raise LockfileRefusal("unsupported-version")
    cache_key = fields.get("cacheKey")
    if cache_key is None or cache_key.kind != "scalar" or not _CACHE_KEY.fullmatch(cache_key.text):
        raise LockfileRefusal("unparseable")
    return version.text, cache_key.text


def classify_yarn_berry_lockfile(
    text: str, lock_dir: str, registry: BerryRegistryDeclaration
) -> tuple[str, tuple[LockedEntry, ...]]:
    """Classify every entry of one Yarn 2+ lockfile.

    Parameters
    ----------
    text : str
        The lockfile text.
    lock_dir : str
        The repository-relative POSIX directory holding the lockfile; ``""`` for the root.
    registry : BerryRegistryDeclaration
        The registries the repository declares for Yarn 2+.

    Returns
    -------
    tuple[str, tuple[LockedEntry, ...]]
        ``__metadata.version``, and the entries ordered by line.

    Raises
    ------
    LockfileRefusal
        ``unparseable``, ``conflicting-entries``, ``missing-version`` or ``unsupported-version``,
        with no entry results.
    """
    try:
        document = parse_workflow_yaml(text, LOCKFILE_YAML_LIMITS)
    except WorkflowFormatError:
        raise LockfileRefusal("unparseable") from None
    if document.kind != "mapping":
        raise LockfileRefusal("unparseable")
    root = document.mapping()
    metadata = _metadata(root)
    lines = _LINE_BREAK.split(text)
    seen: set[str] = set()
    entries: list[LockedEntry] = []
    for key, value in document.pairs:
        if key == "__metadata":
            continue
        if value.kind != "mapping":
            raise LockfileRefusal("unparseable")
        line = _key_line(lines, key, value.line)
        descriptors = tuple(key.split(", "))
        if seen.intersection(descriptors) or len(set(descriptors)) != len(descriptors):
            raise LockfileRefusal("conflicting-entries")
        seen.update(descriptors)
        entries.append(
            _classify(key, descriptors, line, value.mapping(), lock_dir, metadata, registry)
        )
    return metadata[0], tuple(sorted(entries, key=lambda entry: (entry.line, entry.key)))
