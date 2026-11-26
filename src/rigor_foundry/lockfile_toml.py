# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — the TOML package array shared by Cargo and Poetry lockfiles
"""Read the ``[[package]]`` array that ``Cargo.lock`` and ``poetry.lock`` both write.

Both tools write each package as a ``[[package]]`` header followed by its ``name`` and ``version``
lines, so an entry stands at its header's line. Anything that is not the expected TOML shape
refuses the file as ``unparseable``.
"""

from __future__ import annotations

import tomllib
from collections import Counter
from typing import Final

from .lockfile_model import LockfileRefusal

_HEADER: Final = "[[package]]"


def load_document(text: str) -> dict[str, object]:
    """Parse a TOML lockfile.

    Parameters
    ----------
    text : str
        The lockfile text.

    Returns
    -------
    dict[str, object]
        The document.

    Raises
    ------
    LockfileRefusal
        ``unparseable`` when the text is not TOML.
    """
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        raise LockfileRefusal("unparseable") from None


def table(value: object) -> dict[str, object]:
    """Return a TOML table, refusing anything else.

    Parameters
    ----------
    value : object
        The value read.

    Returns
    -------
    dict[str, object]
        The table.

    Raises
    ------
    LockfileRefusal
        ``unparseable`` when the value is not a table.
    """
    if not isinstance(value, dict):
        raise LockfileRefusal("unparseable")
    return value


def tables(value: object) -> list[dict[str, object]]:
    """Return an array of TOML tables, refusing anything else.

    Parameters
    ----------
    value : object
        The value read.

    Returns
    -------
    list[dict[str, object]]
        The tables, in file order.

    Raises
    ------
    LockfileRefusal
        ``unparseable`` when the value is not an array of tables.
    """
    if not isinstance(value, list):
        raise LockfileRefusal("unparseable")
    return [table(item) for item in value]


def text_field(owner: dict[str, object], field: str) -> str | None:
    """Return a string field, absent as ``None``, refusing another type.

    Parameters
    ----------
    owner : dict[str, object]
        The table holding the field.
    field : str
        The field's name.

    Returns
    -------
    str | None
        The string, or ``None`` when the field is absent.

    Raises
    ------
    LockfileRefusal
        ``unparseable`` when the field holds anything but a string.
    """
    value = owner.get(field)
    if value is not None and not isinstance(value, str):
        raise LockfileRefusal("unparseable")
    return value


def header_lines(text: str, packages: list[dict[str, object]]) -> list[int]:
    """Return each package's header line, requiring the tools' own layout.

    Parameters
    ----------
    text : str
        The lockfile text.
    packages : list[dict[str, object]]
        The parsed ``package`` array.

    Returns
    -------
    list[int]
        Each package's 1-based header line, in file order.

    Raises
    ------
    LockfileRefusal
        ``unparseable`` unless every header is followed by its ``name`` and ``version`` lines as
        quoted strings, so a missing or non-string name or version refuses the file here.
    """
    lines = text.splitlines()
    headers = [index + 1 for index, line in enumerate(lines) if line == _HEADER]
    if len(headers) != len(packages):
        raise LockfileRefusal("unparseable")
    for line, package in zip(headers, packages, strict=True):
        written = lines[line : line + 2]
        expected = [f'name = "{package.get("name")}"', f'version = "{package.get("version")}"']
        if written != expected:
            raise LockfileRefusal("unparseable")
    return headers


def entry_keys(packages: list[dict[str, object]], sources: list[str | None]) -> list[str]:
    """Return each package's key, with its source when its name and version are shared.

    Parameters
    ----------
    packages : list[dict[str, object]]
        The parsed ``package`` array, whose names and versions ``header_lines`` checked.
    sources : list[str | None]
        Each package's source, as the tool records it, or ``None``.

    Returns
    -------
    list[str]
        ``<name> <version>``, plus `` (<source>)`` for a shared name and version.

    Raises
    ------
    LockfileRefusal
        ``conflicting-entries`` when two packages still share a key.
    """
    shared = Counter((package["name"], package["version"]) for package in packages)
    keys = []
    for package, source in zip(packages, sources, strict=True):
        key = f"{package['name']} {package['version']}"
        if shared[(package["name"], package["version"])] > 1 and source is not None:
            key += f" ({source})"
        keys.append(key)
    if len(set(keys)) != len(keys):
        raise LockfileRefusal("conflicting-entries")
    return keys
