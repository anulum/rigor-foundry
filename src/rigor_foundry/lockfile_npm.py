# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — npm lockfile classification
"""Classify every entry of an npm ``package-lock.json`` or ``npm-shrinkwrap.json``.

``lockfileVersion`` 2 and 3 are read from ``packages``; version 1 from its nested
``dependencies`` tree, whose entries are keyed here by their equivalent ``node_modules`` path.
A version 2 file also keeps that legacy tree for npm 6, and an ``integrity`` or ``resolved``
it records differently from ``packages`` refuses the file as conflicting.

A registry artifact is pinned by an exact version and an accepted, well-formed ``integrity``
digest; a VCS source by a full commit; a local source by a path inside the repository. A
bundled entry arrives inside its nearest non-bundled ancestor's artifact and takes that
ancestor's class. A registry artifact's host is compared with the declared registry, and an
entry with no ``resolved`` URL but an exact version comes from that registry. A VCS host is
recorded but not compared, because the commit is its pin.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Final, cast
from urllib.parse import urlsplit

from .lockfile_digests import DigestReading, missing_digest, read_sri
from .lockfile_json import KeyPath, json_key_lines, load_lockfile_json
from .lockfile_model import (
    ENTRY_FINDINGS,
    DigestScope,
    EntryFinding,
    LockedEntry,
    LockfileRefusal,
)
from .lockfile_npmrc import NpmRegistryDeclaration, url_host

SUPPORTED_LOCKFILE_VERSIONS: Final = (1, 2, 3)
_NODE_MODULES: Final = "node_modules/"
_NESTED: Final = "/node_modules/"
_VCS_URL_PREFIXES: Final = ("git+ssh://", "git+https://", "git+http://", "git+file://", "git://")
_HOSTED_SHORTCUTS: Final[dict[str, str]] = {
    "github:": "github.com",
    "gitlab:": "gitlab.com",
    "bitbucket:": "bitbucket.org",
    "gist:": "gist.github.com",
}
_FULL_COMMIT: Final = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_EXACT_VERSION: Final = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
_WINDOWS_DRIVE: Final = re.compile(r"[A-Za-z]:")
_MALFORMED_DIGEST: Final = DigestReading(algorithms=(), malformed_tokens=1)


@dataclass(frozen=True)
class _Node:
    """One locked package before classification."""

    key: str
    name: str
    line: int
    fields: dict[str, object]
    bundled: bool
    parent: str | None


def _mapping(value: object) -> dict[str, object]:
    """Return a JSON object, refusing any other value as unparseable."""
    if not isinstance(value, dict):
        raise LockfileRefusal("unparseable")
    return cast(dict[str, object], value)


def _ordered(findings: set[EntryFinding]) -> tuple[EntryFinding, ...]:
    """Return findings in their fixed order."""
    return tuple(finding for finding in ENTRY_FINDINGS if finding in findings)


def _is_package_key(key: str) -> bool:
    """Return whether a ``packages`` key is an installed package rather than a local path."""
    return key.startswith(_NODE_MODULES) or _NESTED in key


def _path_escapes(lock_dir: str, path: str) -> bool:
    """Return whether a lockfile-relative path leaves the repository root."""
    if path.startswith("/") or "\\" in path or _WINDOWS_DRIVE.match(path):
        return True
    joined = posixpath.normpath(posixpath.join(lock_dir, path))
    return joined == ".." or joined.startswith("../")


def _local(node: _Node, lock_dir: str, path: str) -> LockedEntry:
    """Classify a local path source, which is unpinned when it leaves the repository."""
    if _path_escapes(lock_dir, path):
        return LockedEntry(node.key, node.line, "unpinned", ("path-escape",), form="path")
    return LockedEntry(node.key, node.line, "local")


def _unknown(node: _Node) -> LockedEntry:
    """Classify a form these rules do not know."""
    return LockedEntry(node.key, node.line, "unclassified", ("unknown-form",))


def _digest(fields: dict[str, object]) -> DigestReading:
    """Read an entry's ``integrity``: absent is missing, a non-string is malformed."""
    if "integrity" not in fields:
        return missing_digest()
    integrity = fields["integrity"]
    return read_sri(integrity) if isinstance(integrity, str) else _MALFORMED_DIGEST


def _vcs_host(spec: str) -> str | None:
    """Return the host a VCS specification fetches from, when it names one."""
    for prefix, host in _HOSTED_SHORTCUTS.items():
        if spec.startswith(prefix):
            return host
    if spec.startswith("git+file://"):
        return None
    return urlsplit(spec.removeprefix("git+")).hostname


def _vcs(node: _Node, spec: str) -> LockedEntry:
    """Classify a VCS source: pinned by a full commit and no malformed digest."""
    host = _vcs_host(spec)
    commit = spec.partition("#")[2]
    reading = _digest(node.fields)
    scope: DigestScope | None = "artifact" if reading.algorithms else None
    full = _FULL_COMMIT.fullmatch(commit) is not None
    if full and not reading.malformed_tokens:
        return LockedEntry(
            node.key,
            node.line,
            "commit-pinned",
            digest_algorithms=reading.algorithms,
            digest_scope=scope,
            commit_hash_algorithm="sha1" if len(commit) == 40 else "sha256",
            origin=host,
        )
    failures: set[EntryFinding] = set()
    if not full:
        failures.add("floating-ref")
    if reading.malformed_tokens:
        failures.add("malformed-digest")
    return LockedEntry(
        node.key,
        node.line,
        "unpinned",
        _ordered(failures),
        form="vcs",
        digest_algorithms=reading.algorithms,
        digest_scope=scope,
        origin=host,
    )


def _artifact(node: _Node, origin: str | None, origin_finding: EntryFinding | None) -> LockedEntry:
    """Classify a remote artifact: pinned by an exact version and an accepted, well-formed digest."""
    version = node.fields.get("version")
    if not isinstance(version, str) or not version:
        return _unknown(node)
    reading = _digest(node.fields)
    findings: set[EntryFinding] = set(reading.findings)
    if origin_finding is not None:
        findings.add(origin_finding)
    if reading.pins_artifact:
        return LockedEntry(
            node.key,
            node.line,
            "artifact-pinned",
            _ordered(findings),
            digest_algorithms=reading.algorithms,
            digest_scope="artifact",
            origin=origin,
        )
    return LockedEntry(
        node.key,
        node.line,
        "unpinned",
        _ordered(findings),
        form="artifact",
        digest_algorithms=reading.algorithms,
        digest_scope="artifact" if reading.algorithms else None,
        origin=origin,
    )


def _registry_artifact(node: _Node, registry: NpmRegistryDeclaration) -> LockedEntry:
    """Classify an exact version with no URL, which comes from the declared registry."""
    if not registry.known:
        return _artifact(node, None, "origin-unknown")
    scope = node.name.split("/", 1)[0] if node.name.startswith("@") else ""
    return _artifact(node, registry.scoped_hosts.get(scope, registry.registry_host), None)


def _classify(node: _Node, lock_dir: str, registry: NpmRegistryDeclaration) -> LockedEntry:
    """Classify one non-bundled entry."""
    fields = node.fields
    if not _is_package_key(node.key):
        return _local(node, lock_dir, node.key)
    resolved = fields.get("resolved")
    if fields.get("link") is True:
        return _local(node, lock_dir, resolved) if isinstance(resolved, str) else _unknown(node)
    spec = fields.get("version") if resolved is None else resolved
    if not isinstance(spec, str):
        return _unknown(node)
    if spec.startswith("file:"):
        return _local(node, lock_dir, spec.removeprefix("file:"))
    if spec.startswith((*_VCS_URL_PREFIXES, *_HOSTED_SHORTCUTS)):
        return _vcs(node, spec)
    host = url_host(spec)
    if host is not None:
        return _artifact(node, host, registry.origin_finding(node.name, host))
    if resolved is None and _EXACT_VERSION.fullmatch(spec):
        return _registry_artifact(node, registry)
    return _unknown(node)


def _inherit(node: _Node, ancestor: LockedEntry) -> LockedEntry:
    """Give a bundled entry its ancestor's class, carried by the ancestor's artifact."""
    return LockedEntry(
        node.key,
        node.line,
        ancestor.entry_class,
        ancestor.findings,
        form=ancestor.form,
        digest_algorithms=ancestor.digest_algorithms,
        digest_scope="parent-artifact",
        commit_hash_algorithm=ancestor.commit_hash_algorithm,
        origin=ancestor.origin,
        inherited_from=ancestor.key,
    )


def _packages_nodes(packages: dict[str, object], lines: dict[KeyPath, int]) -> Iterator[_Node]:
    """Yield the nodes of a version 2 or 3 ``packages`` map, skipping the root project."""
    for key, value in packages.items():
        if key == "":
            continue
        fields = _mapping(value)
        yield _Node(
            key=key,
            name=key.rsplit(_NODE_MODULES, 1)[-1],
            line=lines[("packages", key)],
            fields=fields,
            bundled=fields.get("inBundle") is True,
            parent=key.rsplit(_NESTED, 1)[0] if _NESTED in key else None,
        )


def _walk_tree(
    dependencies: dict[str, object],
) -> Iterator[tuple[KeyPath, str, str, str | None, dict[str, object]]]:
    """Walk a version 1 ``dependencies`` tree without recursion.

    Yields the JSON key path, the ``node_modules`` key, the name, the parent key and the
    fields of every entry.
    """
    pending: list[tuple[dict[str, object], KeyPath, str | None]] = [
        (dependencies, ("dependencies",), None)
    ]
    while pending:
        level, json_path, parent = pending.pop()
        for name, value in level.items():
            fields = _mapping(value)
            key = f"{parent}/{_NODE_MODULES}{name}" if parent else f"{_NODE_MODULES}{name}"
            here = (*json_path, name)
            yield here, key, name, parent, fields
            if "dependencies" in fields:
                pending.append((_mapping(fields["dependencies"]), (*here, "dependencies"), key))


def _tree_nodes(dependencies: dict[str, object], lines: dict[KeyPath, int]) -> Iterator[_Node]:
    """Yield the nodes of a version 1 ``dependencies`` tree."""
    for json_path, key, name, parent, fields in _walk_tree(dependencies):
        yield _Node(
            key=key,
            name=name,
            line=lines[json_path],
            fields=fields,
            bundled=fields.get("bundled") is True,
            parent=parent,
        )


def _legacy_conflicts(packages: dict[str, object], dependencies: dict[str, object]) -> bool:
    """Return whether a version 2 legacy tree records an ``integrity`` or URL differently."""
    for _, key, _, _, fields in _walk_tree(dependencies):
        current = packages.get(key)
        if not isinstance(current, dict):
            continue
        for field_name in ("integrity", "resolved"):
            if (
                field_name in fields
                and field_name in current
                and fields[field_name] != current[field_name]
            ):
                return True
    return False


def classify_npm_lockfile(
    text: str, lock_dir: str, registry: NpmRegistryDeclaration
) -> tuple[str, tuple[LockedEntry, ...]]:
    """Classify every entry of one npm lockfile.

    Parameters
    ----------
    text : str
        The lockfile text.
    lock_dir : str
        The repository-relative POSIX directory holding the lockfile; ``""`` for the root.
    registry : NpmRegistryDeclaration
        The registries the repository declares.

    Returns
    -------
    tuple[str, tuple[LockedEntry, ...]]
        The declared ``lockfileVersion``, and the entries ordered by line, then key.

    Raises
    ------
    LockfileRefusal
        ``unparseable``, ``conflicting-entries``, ``missing-version`` or
        ``unsupported-version``, with no entry results.
    """
    document = load_lockfile_json(text)
    if "lockfileVersion" not in document:
        raise LockfileRefusal("missing-version")
    version = document["lockfileVersion"]
    if isinstance(version, bool) or version not in SUPPORTED_LOCKFILE_VERSIONS:
        raise LockfileRefusal("unsupported-version")
    lines = json_key_lines(text)
    if version == 1:
        nodes = list(_tree_nodes(_mapping(document.get("dependencies", {})), lines))
    else:
        if "packages" not in document:
            raise LockfileRefusal("unparseable")
        packages = _mapping(document["packages"])
        nodes = list(_packages_nodes(packages, lines))
        legacy = document.get("dependencies")
        if version == 2 and legacy is not None and _legacy_conflicts(packages, _mapping(legacy)):
            raise LockfileRefusal("conflicting-entries")
    by_key = {node.key: node for node in nodes}
    classified = {
        node.key: _classify(node, lock_dir, registry) for node in nodes if not node.bundled
    }
    for node in nodes:
        if not node.bundled:
            continue
        ancestor = node.parent
        while ancestor is not None and ancestor in by_key and by_key[ancestor].bundled:
            ancestor = by_key[ancestor].parent
        source = classified.get(ancestor) if ancestor is not None else None
        classified[node.key] = _inherit(node, source) if source is not None else _unknown(node)
    entries = sorted(classified.values(), key=lambda entry: (entry.line, entry.key))
    return str(version), tuple(entries)
