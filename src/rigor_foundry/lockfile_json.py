# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — strict JSON lockfile reading
"""Read a JSON lockfile strictly, and index the line of every object key.

A JSON lockfile is one object. A repeated key is a conflict, never resolved by keeping the
last value; a non-finite number, trailing text or nesting past the interpreter's recursion
limit is unparseable. Each refusal names its reason and suppresses the parser's traceback.
The key index lets a finding point at the line where its entry starts.
"""

from __future__ import annotations

import bisect
import json
import math
import re
from typing import Final, cast

from .lockfile_model import LockfileRefusal

KeyPath = tuple[str, ...]

_LEXEME: Final = re.compile(r'"(?:[^"\\]|\\.)*"|[{}\[\]:,]|[^\s{}\[\]:,"]+')


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Build one JSON object, refusing a key that appears twice."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise LockfileRefusal("conflicting-entries")
        result[key] = value
    return result


def _finite_float(text: str) -> float:
    """Return a finite JSON number, refusing one that overflows to infinity."""
    value = float(text)
    if not math.isfinite(value):
        raise LockfileRefusal("unparseable")
    return value


def _no_constant(text: str) -> object:
    """Refuse the non-standard ``NaN``, ``Infinity`` and ``-Infinity`` constants."""
    del text
    raise LockfileRefusal("unparseable")


def load_lockfile_json(text: str) -> dict[str, object]:
    """Return the one JSON object a lockfile holds.

    Parameters
    ----------
    text : str
        The lockfile text.

    Returns
    -------
    dict[str, object]
        The top-level object.

    Raises
    ------
    LockfileRefusal
        ``conflicting-entries`` for a repeated key; ``unparseable`` for anything that is
        not one strict JSON object, including nesting past the recursion limit.
    """
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_finite_float,
            parse_constant=_no_constant,
        )
    except (ValueError, RecursionError):
        raise LockfileRefusal("unparseable") from None
    if not isinstance(value, dict):
        raise LockfileRefusal("unparseable")
    return cast(dict[str, object], value)


class _Frame:
    """One open container while the key index walks the document."""

    __slots__ = ("expect_key", "last_key", "path")

    def __init__(self, path: KeyPath | None) -> None:
        self.path = path
        self.expect_key = path is not None
        self.last_key = ""


def json_key_lines(text: str) -> dict[KeyPath, int]:
    """Return the 1-based line of every object key reachable through object keys alone.

    Parameters
    ----------
    text : str
        A document that ``load_lockfile_json`` has already accepted.

    Returns
    -------
    dict[KeyPath, int]
        The line of each key, by its full path of keys. Keys inside arrays are not indexed.
    """
    newlines = [match.start() for match in re.finditer("\n", text)]
    lines: dict[KeyPath, int] = {}
    stack: list[_Frame] = []
    for match in _LEXEME.finditer(text):
        lexeme = match.group()
        frame = stack[-1] if stack else None
        if lexeme in ("{", "["):
            if frame is None:
                path: KeyPath | None = ()
            elif frame.path is not None and lexeme == "{" and not frame.expect_key:
                path = (*frame.path, frame.last_key)
            else:
                path = None
            stack.append(_Frame(path if lexeme == "{" else None))
        elif lexeme in ("}", "]"):
            stack.pop()
        elif lexeme == ",":
            if frame is not None and frame.path is not None:
                frame.expect_key = True
        elif frame is not None and frame.path is not None and frame.expect_key:
            key = cast(str, json.loads(lexeme))
            frame.last_key = key
            frame.expect_key = False
            lines[(*frame.path, key)] = bisect.bisect_left(newlines, match.start()) + 1
    return lines
