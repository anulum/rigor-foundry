# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — the strict reader of Yarn 1 lockfile syntax
"""Read exactly the syntax Yarn 1 writes in ``yarn.lock``, and refuse anything else.

The file opens with comment lines that include ``# yarn lockfile v1``. Each entry is a key line
at column 0 listing one or more specifiers separated by ``, `` and ending ``:``, followed by
fields indented two spaces (``key value`` or ``key:``) and the members of a ``key:`` block
indented four. Quoted keys and values use JSON string escapes; bare ones hold no space, quote or
colon, since Yarn quotes any value that does. Entries are separated by blank lines. A file whose line endings are all CRLF reads as LF;
mixed endings, a byte-order mark, a tab, another indentation, a comment after the first entry or
a line of any other shape is ``unparseable``. A field repeated in one entry or block, or a
specifier named by two entries, is ``conflicting-entries``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Final, cast

from .lockfile_model import LockfileRefusal

YARN1_HEADER: Final = "# yarn lockfile v1"
_STRING: Final = r'"(?:[^"\\]|\\.)*"'
_SPECIFIER: Final = re.compile(rf'({_STRING}|[^\s",:]+)(, |$)')
_FIELD: Final = re.compile(rf'({_STRING}|[^\s":]+)(?: ({_STRING}|[^\s":]+)|(:))')


@dataclass(frozen=True)
class Yarn1Entry:
    """One ``yarn.lock`` entry as written.

    Parameters
    ----------
    specifiers : tuple[str, ...]
        The unquoted specifiers of the key line, in order.
    line : int
        The 1-based line of the key line.
    fields : dict[str, str]
        The scalar fields indented two spaces, unquoted.
    blocks : tuple[str, ...]
        The names of the ``key:`` blocks, in order.
    """

    specifiers: tuple[str, ...]
    line: int
    fields: dict[str, str]
    blocks: tuple[str, ...]


def _unquote(token: str) -> str:
    """Return a token's text, decoding a quoted JSON string."""
    if not token.startswith('"'):
        return token
    try:
        return cast(str, json.loads(token))
    except ValueError:
        raise LockfileRefusal("unparseable") from None


def _normalised(text: str) -> str:
    """Return the text with all-CRLF endings read as LF, refusing mixed endings.

    A byte-order mark needs no check of its own: it hides the header comment, so the file is
    refused as unparseable when the header is looked for.
    """
    if "\r" not in text:
        return text
    if text.count("\r") != text.count("\r\n") or text.count("\n") != text.count("\r\n"):
        raise LockfileRefusal("unparseable")
    return text.replace("\r\n", "\n")


def _specifiers(content: str) -> tuple[str, ...]:
    """Return the unquoted specifiers of one key line's content, without its colon."""
    found: list[str] = []
    position = 0
    while position < len(content):
        match = _SPECIFIER.match(content, position)
        if match is None or (match.group(2) == "" and match.end() != len(content)):
            raise LockfileRefusal("unparseable")
        found.append(_unquote(match.group(1)))
        position = match.end()
    if not found or content.endswith(", "):
        raise LockfileRefusal("unparseable")
    return tuple(found)


def _field(content: str) -> tuple[str, str | None]:
    """Return one field line's name and value; the value is ``None`` for a block opener."""
    match = _FIELD.fullmatch(content)
    if match is None:
        raise LockfileRefusal("unparseable")
    name = _unquote(match.group(1))
    if match.group(3):
        return name, None
    return name, _unquote(match.group(2))


def _indent(line: str) -> tuple[int, str]:
    """Return a line's space indentation and content, refusing a tab."""
    content = line.lstrip(" ")
    if "\t" in line:
        raise LockfileRefusal("unparseable")
    return len(line) - len(content), content


def parse_yarn1(text: str) -> tuple[Yarn1Entry, ...]:
    """Return every entry of one Yarn 1 lockfile.

    Parameters
    ----------
    text : str
        The lockfile text.

    Returns
    -------
    tuple[Yarn1Entry, ...]
        The entries in file order.

    Raises
    ------
    LockfileRefusal
        ``unparseable`` or ``conflicting-entries``, with no entry results.
    """
    lines = _normalised(text).split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    index = 0
    header: list[str] = []
    while index < len(lines) and (not lines[index] or lines[index].startswith("#")):
        header.append(lines[index])
        index += 1
    if YARN1_HEADER not in header:
        raise LockfileRefusal("unparseable")
    entries: list[Yarn1Entry] = []
    seen: set[str] = set()
    current: tuple[tuple[str, ...], int, dict[str, str], list[str]] | None = None
    block: set[str] | None = None
    for number, line in enumerate(lines[index:], start=index + 1):
        if not line:
            block = None
            continue
        indent, content = _indent(line)
        if indent == 0:
            if content.startswith("#") or not content.endswith(":"):
                raise LockfileRefusal("unparseable")
            if current is not None:
                entries.append(Yarn1Entry(current[0], current[1], current[2], tuple(current[3])))
            specifiers = _specifiers(content[:-1])
            if seen.intersection(specifiers) or len(set(specifiers)) != len(specifiers):
                raise LockfileRefusal("conflicting-entries")
            seen.update(specifiers)
            current, block = (specifiers, number, {}, []), None
        elif indent == 2 and current is not None:
            name, value = _field(content)
            if name in current[2] or name in current[3]:
                raise LockfileRefusal("conflicting-entries")
            if value is None:
                current[3].append(name)
                block = set()
            else:
                current[2][name] = value
                block = None
        elif indent == 4 and block is not None:
            name, value = _field(content)
            if value is None or name in block:
                raise LockfileRefusal("unparseable" if value is None else "conflicting-entries")
            block.add(name)
        else:
            raise LockfileRefusal("unparseable")
    if current is not None:
        entries.append(Yarn1Entry(current[0], current[1], current[2], tuple(current[3])))
    return tuple(entries)
