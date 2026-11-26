# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Cargo lockfile classification
"""Classify every entry of a ``Cargo.lock``.

Only the formats a real Cargo release wrote into a fixture here are read: v1 (Cargo 1.40.0), v2
(1.47.0), ``version = 3`` (1.75.0) and ``version = 4`` (1.83.0 and 1.100.0). The version is a
TOML integer, as Cargo's ``Option<u32>`` reads it; a float such as ``3.0`` is refused. v1 and v2
carry no ``version``: v1 lists its checksums in ``[metadata]`` as
``"checksum <name> <version> (<source>)"``, and v2 lists them on each package. A file whose
``[metadata]`` holds checksum keys but which is otherwise v2 or later is one Cargo treats as a bad
merge, dropping every checksum, so it is refused as ``conflicting-entries``.

Each ``[[package]]`` is an entry, at the line of its header, which Cargo writes with ``name`` and
``version`` on the two lines after it. A registry package (``registry+`` or ``sparse+``) is an
artifact pinned by the 64-hex sha256 Cargo verifies on download; its origin is the index the
lockfile names, ``crates.io`` for crates.io's two source IDs, and any other index is noted as an
alternate registry. A Git package is pinned by the full commit after ``#``, whatever its query
asks for, and the query is noted. A package with no source is local; its path is only in
``Cargo.toml``, so it is noted as unverified. A package that names a ``replace`` is in the graph
only: its replacement is fetched instead, and is classified as its own entry.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlsplit

from .lockfile_digests import DigestReading, missing_digest, read_hex_digest
from .lockfile_forms import artifact_entry, unknown_entry, vcs_entry
from .lockfile_model import LockedEntry, LockfileRefusal
from .lockfile_npmrc import url_host
from .lockfile_toml import entry_keys, header_lines, load_document, table, tables, text_field

CRATES_IO: Final = "crates.io"
CRATES_IO_SOURCES: Final = frozenset(
    {"registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/"}
)
SUPPORTED_CARGO_VERSIONS: Final = frozenset({3, 4})
_CHECKSUM_KEY: Final = "checksum "
_NO_CHECKSUM: Final = "<none>"
_PACKAGE_ID: Final = re.compile(r"(\S+) (\S+)(?: \((.+)\))?")


@dataclass(frozen=True)
class CargoLockfile:
    """One classified ``Cargo.lock``.

    Parameters
    ----------
    version : str
        The format: ``1`` to ``4``.
    entries : tuple[LockedEntry, ...]
        The entries, ordered by line.
    unused_patches : int
        How many ``[[patch.unused]]`` entries the file lists; they are not installed.
    """

    version: str
    entries: tuple[LockedEntry, ...]
    unused_patches: int


def _unfragmented(source: str) -> str:
    """Return a source ID without its precise ``#`` fragment, as Cargo's package IDs write it."""
    return source.partition("#")[0]


def _version(document: dict[str, object], packages: list[dict[str, object]]) -> str:
    """Return the format version, refusing an unsupported one or a bad merge."""
    metadata = table(document.get("metadata", {}))
    listed = any(key.startswith(_CHECKSUM_KEY) for key in metadata)
    raw = document.get("version")
    if raw is not None and (type(raw) is not int or raw not in SUPPORTED_CARGO_VERSIONS):
        raise LockfileRefusal("unsupported-version")
    inline = any("checksum" in package for package in packages)
    if listed and (raw is not None or inline):
        raise LockfileRefusal("conflicting-entries")
    if raw is not None:
        return str(raw)
    return "1" if listed else "2"


def _reading(value: object) -> DigestReading:
    """Read a checksum: missing, ``<none>``, or a sha256 that must be 64 lowercase hex."""
    if value is None or value == _NO_CHECKSUM:
        return missing_digest()
    if not isinstance(value, str):
        return DigestReading(algorithms=(), malformed_tokens=1)
    return read_hex_digest("sha256", value)


def _registry(key: str, line: int, source: str, reading: DigestReading) -> LockedEntry:
    """Classify a registry package: pinned by its checksum, its origin the index it names."""
    notes: tuple[tuple[str, str], ...] = ()
    origin: str | None = CRATES_IO
    if source not in CRATES_IO_SOURCES:
        origin = url_host(source.partition("+")[2])
        notes = (("alternate_registry", "true"),)
    if origin is None:
        return unknown_entry(key, line)
    return artifact_entry(key, line, reading, origin, set(), notes=notes)


def _git(key: str, line: int, source: str, reading: DigestReading) -> LockedEntry:
    """Classify a Git package by the precise commit after ``#``, noting what its query follows."""
    reference = urlsplit(source.partition("#")[0]).query or "default-branch"
    return vcs_entry(key, line, source, reading, notes=(("git_reference", reference),))


def _replaced_target(replace: str, packages: list[dict[str, object]]) -> None:
    """Require that a ``replace`` ID names a package in the file that is itself fetched.

    Cargo writes a replacement as a Git or path package with no ``replace`` of its own. A target that
    carries one (a package replacing itself, a cycle or a chain) would leave every link in the graph
    only and hide an unpinned package, so it refuses the file.
    """
    match = _PACKAGE_ID.fullmatch(replace)
    if match is not None:
        name, version, source = match.groups()
        for package in packages:
            recorded = package.get("source")
            if (package["name"], package["version"]) == (name, version) and (
                source == (None if recorded is None else _unfragmented(str(recorded)))
            ):
                if "replace" in package:
                    break
                return
    raise LockfileRefusal("unparseable")


def _classify(
    key: str,
    line: int,
    package: dict[str, object],
    checksum: object,
    packages: list[dict[str, object]],
) -> LockedEntry:
    """Classify one package."""
    replace = text_field(package, "replace")
    if replace is not None:
        _replaced_target(replace, packages)
        return LockedEntry(key, line, "graph-only", notes=(("replaced_by", replace),))
    source = text_field(package, "source")
    if source is None:
        return LockedEntry(key, line, "local", notes=(("path_unverified", "manifest"),))
    reading = _reading(checksum)
    if source.startswith(("registry+", "sparse+")):
        return _registry(key, line, source, reading)
    if source.startswith("git+"):
        return _git(key, line, source, reading)
    return unknown_entry(key, line)


def classify_cargo_lockfile(text: str) -> CargoLockfile:
    """Classify every entry of one ``Cargo.lock``.

    Parameters
    ----------
    text : str
        The lockfile text.

    Returns
    -------
    CargoLockfile
        The format version, the entries ordered by line, and the count of unused patches.

    Raises
    ------
    LockfileRefusal
        ``unparseable``, ``conflicting-entries`` or ``unsupported-version``, with no entry results.
    """
    document = load_document(text)
    packages = tables(document.get("package", []))
    version = _version(document, packages)
    lines = header_lines(text, packages)
    keys = entry_keys(packages, [text_field(package, "source") for package in packages])
    metadata = table(document.get("metadata", {}))
    entries = []
    for key, line, package in zip(keys, lines, packages, strict=True):
        source = text_field(package, "source")
        checksum = (
            package.get("checksum")
            if version != "1" or source is None
            else metadata.get(
                f"{_CHECKSUM_KEY}{package['name']} {package['version']} ({_unfragmented(source)})"
            )
        )
        entries.append(_classify(key, line, package, checksum, packages))
    unused = tables(table(document.get("patch", {})).get("unused", []))
    return CargoLockfile(version, tuple(entries), len(unused))
