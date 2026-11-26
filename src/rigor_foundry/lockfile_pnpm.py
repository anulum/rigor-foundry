# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — pnpm lockfile classification
"""Classify every entry of a ``pnpm-lock.yaml``.

Only the versions a real pnpm release wrote into a fixture here are read: ``6.0`` (pnpm 8.15.9)
and ``9.0`` (pnpm 9.15.9 to 12.23.0). The file is YAML read without anchors, aliases or tags and
with duplicate keys refused. pnpm 11 and later may write two documents, an env document (the
configuration dependencies and the pinned package manager) and the main lockfile, split as
pnpm's ``extractMainDocument`` splits them; each is read, and the env document's entries are keyed
``env › <key>``. An env document with no main document has no fixture and is unsupported.

Each ``packages`` key is an entry, written as js-yaml writes keys: plain or quoted on the line
before its fields, or after ``? `` with the ``:`` alone on the next line when longer than 1024
characters. In ``9.0``, ``snapshots`` add peer and patch suffixes to packages and must each name
one. Each importer's ``link:`` dependency (``workspace:`` included) is a local entry keyed
``<importer> › <name>``, its path resolved from the importer's directory; a ``6.0`` lockfile of a
single project writes its dependencies at the top level, as importer ``.``; pnpm 8 writes one form
or the other, so a ``6.0`` file with both is unparseable.

A patched package carries ``(patch_hash=…)`` in its ``6.0`` key or its ``9.0`` snapshot. The
patch is named by ``patchedDependencies``: with its path (pnpm 8 to 10) or by hash only (pnpm 11),
when its path comes from the tracked ``pnpm-workspace.yaml``; with no path the entry is unknown.
"""

from __future__ import annotations

import json
import posixpath
import re
from collections.abc import Mapping
from typing import Final

from .lockfile_forms import path_escapes, unknown_entry
from .lockfile_model import EntryFinding, LockedEntry, LockfileRefusal
from .lockfile_pnpm_config import (
    PnpmRegistryDeclaration,
    PnpmWorkspace,
    pnpm_registry_declaration,
)
from .lockfile_pnpm_resolution import classify_resolution
from .workflow_yaml import WorkflowFormatError, WorkflowValue, YamlLimits, parse_workflow_yaml

LOCKFILE_YAML_LIMITS: Final = YamlLimits(8 * 1024 * 1024, 2_000_000, False)
SUPPORTED_PNPM_VERSIONS: Final = frozenset({"6.0", "9.0"})
DOCUMENT_START: Final = "---\n"
DOCUMENT_SEPARATOR: Final = "\n---\n"
ENV_PREFIX: Final = "env › "
_DEPENDENCY_GROUPS: Final = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "configDependencies",
    "packageManagerDependencies",
)
_PATCH_HASH: Final = "(patch_hash="
_LONG_KEY: Final = 1024
_LINE_BREAK: Final = re.compile("\r\n|[\r\n\x85  ]")

Notes = tuple[tuple[str, str], ...]


def split_documents(text: str) -> tuple[tuple[str, int, str], ...]:
    """Split a lockfile into its documents, as pnpm 11's ``extractMainDocument`` does.

    Parameters
    ----------
    text : str
        The lockfile text.

    Returns
    -------
    tuple[tuple[str, int, str], ...]
        Each document's text, the number of lines before it, and its entries' key prefix.

    Raises
    ------
    LockfileRefusal
        ``unsupported-version`` for an env document with no main document.
    """
    text = text.replace("\r\n", "\n")
    if not text.startswith(DOCUMENT_START):
        return ((text, 0, ""),)
    separator = text.find(DOCUMENT_SEPARATOR, len(DOCUMENT_START))
    if separator == -1:
        raise LockfileRefusal("unsupported-version")
    main = separator + len(DOCUMENT_SEPARATOR)
    return (
        (text[len(DOCUMENT_START) : separator], 1, ENV_PREFIX),
        (text[main:], text.count("\n", 0, main), ""),
    )


def dep_path_base(key: str) -> tuple[str, str | None]:
    """Split a dependency path's peer and patch suffix off, as pnpm's ``indexOfDepPathSuffix``.

    Parameters
    ----------
    key : str
        A ``packages`` or ``snapshots`` key.

    Returns
    -------
    tuple[str, str | None]
        The key without its suffix, and the patch hash the suffix names, if any.
    """
    if not key.endswith(")"):
        return key, None
    depth = 1
    for index in range(len(key) - 2, -1, -1):
        character = key[index]
        if character == "(":
            depth -= 1
        elif character == ")":
            depth += 1
        elif depth == 0:
            suffix = key[index + 1 :]
            patch = None
            if suffix.startswith(_PATCH_HASH):
                patch = suffix[len(_PATCH_HASH) : suffix.index(")")]
            return key[: index + 1], patch
    return key, None


def _unquoted(written: str) -> str | None:
    """Return a key as js-yaml writes it, unquoted; ``None`` for an escape JSON does not read.

    The parser has already accepted the key, so its quoting is well formed; whatever this returns
    is compared with the parsed key, and any difference refuses the file.
    """
    if written.startswith("'"):
        return written[1:-1].replace("''", "'")
    if written.startswith('"'):
        try:
            value: str = json.loads(written)
        except ValueError:
            return None
        return value
    return written


def _key_line(lines: list[str], key: str, field_line: int) -> int:
    """Return the line an entry's key is on, refusing any layout js-yaml does not write.

    A plain or quoted key longer than 1024 characters never parses, so only the explicit form
    needs the length check.
    """
    simple = lines[field_line - 2].strip() if field_line >= 2 else ""
    if simple.endswith(":") and simple != ":" and _unquoted(simple.removesuffix(":")) == key:
        return field_line - 1
    explicit = lines[field_line - 3].strip() if field_line >= 3 else ""
    if simple == ":" and explicit.startswith("? "):
        written = explicit.removeprefix("? ")
        if len(written) > _LONG_KEY and _unquoted(written) == key:
            return field_line - 2
    raise LockfileRefusal("unparseable")


def _parse(document: str) -> dict[str, WorkflowValue]:
    """Parse one document into its top-level mapping, or refuse it."""
    try:
        root = parse_workflow_yaml(document, LOCKFILE_YAML_LIMITS)
    except WorkflowFormatError:
        raise LockfileRefusal("unparseable") from None
    if root.kind != "mapping":
        raise LockfileRefusal("unparseable")
    return root.mapping()


def _version(root: dict[str, WorkflowValue]) -> str:
    """Return a supported ``lockfileVersion``, or refuse the file."""
    version = root.get("lockfileVersion")
    if version is None:
        raise LockfileRefusal("missing-version")
    if version.kind != "scalar" or version.text not in SUPPORTED_PNPM_VERSIONS:
        raise LockfileRefusal("unsupported-version")
    return version.text


def _section(root: dict[str, WorkflowValue], name: str) -> tuple[tuple[str, WorkflowValue], ...]:
    """Return a top-level mapping's pairs, empty when absent; anything else is unparseable."""
    value = root.get(name)
    if value is None:
        return ()
    if value.kind != "mapping":
        raise LockfileRefusal("unparseable")
    return value.pairs


def _name(version: str, base: str, fields: dict[str, WorkflowValue]) -> str:
    """Return a package's name from its key, or from its ``name`` field for a 6.0 non-registry key."""
    if version == "6.0":
        if not base.startswith("/"):
            field = fields.get("name")
            return field.text if field is not None and field.kind == "scalar" else base
        base = base[1:]
    at = base.find("@", 1)
    return base if at <= 0 else base[:at]


class _Patches:
    """The patches ``patchedDependencies`` declares, found by the hash a package carries."""

    def __init__(
        self, root: dict[str, WorkflowValue], workspace: PnpmWorkspace | None, lock_dir: str
    ) -> None:
        """Index the declared patches by hash."""
        self.lock_dir = lock_dir
        self.by_hash: dict[str, tuple[str, str | None]] = {}
        for patch_key, value in _section(root, "patchedDependencies"):
            path: str | None = None
            if value.kind == "scalar":
                digest = value.text
                if workspace is not None:
                    path = workspace.patches.get(patch_key)
            else:
                fields = value.mapping() if value.kind == "mapping" else {}
                digest_value, path_value = fields.get("hash"), fields.get("path")
                if digest_value is None or digest_value.kind != "scalar":
                    raise LockfileRefusal("unparseable")
                digest = digest_value.text
                if path_value is not None and path_value.kind == "scalar":
                    path = path_value.text
            self.by_hash[digest] = (patch_key, path)

    def evidence(self, digest: str | None) -> tuple[Notes, frozenset[EntryFinding]] | None:
        """Return a patched package's notes and findings; ``None`` when no path can be found."""
        if digest is None:
            return (), frozenset()
        declared = self.by_hash.get(digest)
        if declared is None:
            raise LockfileRefusal("unparseable")
        _, path = declared
        if path is None:
            return None
        escape: frozenset[EntryFinding] = (
            frozenset({"path-escape"}) if path_escapes(self.lock_dir, path) else frozenset()
        )
        return (("patch_hash", digest), ("patch_source", path)), escape


def _snapshot_patches(
    root: dict[str, WorkflowValue], packages: Mapping[str, WorkflowValue]
) -> dict[str, str]:
    """Check every snapshot names a package, and return each patched package's hash."""
    patched: dict[str, str] = {}
    for key, _ in _section(root, "snapshots"):
        base, digest = dep_path_base(key)
        if base not in packages:
            raise LockfileRefusal("unparseable")
        if digest is not None:
            patched[base] = digest
    return patched


def _links(
    root: dict[str, WorkflowValue],
    version: str,
    lines: list[str],
    offset: int,
    prefix: str,
    lock_dir: str,
) -> list[LockedEntry]:
    """Return a local entry for every importer's ``link:`` dependency."""
    projects: list[tuple[str, dict[str, WorkflowValue]]] = []
    if version == "6.0":
        top_level = any(group in root for group in _DEPENDENCY_GROUPS)
        if top_level and "importers" in root:
            raise LockfileRefusal("unparseable")
        if top_level:
            projects.append((".", root))
    for importer, project in _section(root, "importers"):
        if project.kind != "mapping":
            raise LockfileRefusal("unparseable")
        projects.append((importer, project.mapping()))
    entries: list[LockedEntry] = []
    for importer, groups in projects:
        for group in _DEPENDENCY_GROUPS:
            for name, dependency in _section(groups, group):
                locked = (
                    dependency.mapping().get("version") if dependency.kind == "mapping" else None
                )
                if locked is None or locked.kind != "scalar":
                    raise LockfileRefusal("unparseable")
                if not locked.text.startswith("link:"):
                    continue
                key = f"{prefix}{importer} › {name}"
                line = _key_line(lines, name, dependency.line) + offset
                path = locked.text.removeprefix("link:")
                base = posixpath.normpath(posixpath.join(lock_dir, importer))
                if path_escapes(lock_dir, importer) or path_escapes(base, path):
                    entries.append(
                        LockedEntry(key, line, "unpinned", ("path-escape",), form="path")
                    )
                else:
                    entries.append(LockedEntry(key, line, "local"))
    return entries


def _document_entries(
    document: str,
    offset: int,
    prefix: str,
    lock_dir: str,
    npmrc_hosts: Mapping[str, str] | None,
    workspace: PnpmWorkspace | None,
) -> tuple[str, list[LockedEntry]]:
    """Return one document's version and entries."""
    root = _parse(document)
    version = _version(root)
    if prefix and version != "9.0":
        raise LockfileRefusal("unsupported-version")
    registry: PnpmRegistryDeclaration = pnpm_registry_declaration(version, npmrc_hosts, workspace)
    lines = _LINE_BREAK.split(document)
    packages = dict(_section(root, "packages"))
    patched = _snapshot_patches(root, packages) if version == "9.0" else {}
    patches = _Patches(root, workspace, lock_dir)
    entries = _links(root, version, lines, offset, prefix, lock_dir)
    for key, value in _section(root, "packages"):
        if value.kind != "mapping":
            raise LockfileRefusal("unparseable")
        line = _key_line(lines, key, value.line) + offset
        fields = value.mapping()
        base, digest = dep_path_base(key)
        evidence = patches.evidence(patched.get(key, digest))
        if evidence is None:
            entries.append(unknown_entry(prefix + key, line))
            continue
        notes, extra = evidence
        name = _name(version, base, fields)
        entries.append(
            classify_resolution(
                prefix + key,
                line,
                name,
                fields.get("resolution"),
                lock_dir,
                registry,
                notes,
                extra,
            )
        )
    return version, entries


def classify_pnpm_lockfile(
    text: str,
    lock_dir: str,
    npmrc_hosts: Mapping[str, str] | None,
    workspace: PnpmWorkspace | None,
) -> tuple[str, tuple[LockedEntry, ...]]:
    """Classify every entry of one pnpm lockfile.

    Parameters
    ----------
    text : str
        The lockfile text.
    lock_dir : str
        The repository-relative POSIX directory holding the lockfile; ``""`` for the root.
    npmrc_hosts : Mapping[str, str] | None
        The registry hosts the tracked ``.npmrc`` beside the lockfile declares, ``""`` for the
        default; ``None`` when it cannot be read with certainty.
    workspace : PnpmWorkspace | None
        The tracked ``pnpm-workspace.yaml`` beside the lockfile, read for ``9.0`` registries and
        pnpm 11's hash-only patches; ``None`` when it cannot be read with certainty.

    Returns
    -------
    tuple[str, tuple[LockedEntry, ...]]
        The main document's ``lockfileVersion``, and the entries ordered by line.

    Raises
    ------
    LockfileRefusal
        ``unparseable``, ``missing-version`` or ``unsupported-version``, with no entry results.
    """
    version = ""
    entries: list[LockedEntry] = []
    for document, offset, prefix in split_documents(text):
        version, found = _document_entries(
            document, offset, prefix, lock_dir, npmrc_hosts, workspace
        )
        entries.extend(found)
    return version, tuple(sorted(entries, key=lambda entry: (entry.line, entry.key)))
