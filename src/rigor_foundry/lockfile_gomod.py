# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — the part of go.mod the go.sum rules read
"""Read the requirements, replacements and exclusions of a ``go.mod``.

The grammar is Go's own (``golang.org/x/mod/modfile`` ``read.go`` and ``rule.go``, vendored in
go1.27.4). Tokens are separated by spaces, tabs and carriage returns; ``//`` starts a comment;
``(``, ``)``, ``[``, ``]``, ``{``, ``}`` and ``,`` are tokens of their own; any other printable,
non-space character belongs to a word. A statement is one line, or a directive followed by ``(``
at the end of its line, which opens a block of argument lines closed by a line holding ``)``.

The subset read here refuses, as ``unparseable``: ``/*`` comments, a character Go's lexer
refuses, a back-quoted string or an unquoted word holding a quote (Go refuses both as module
paths), a double-quoted string with a backslash escape (Go accepts some; this reader does not
decode them), an unknown directive, a line ending in ``(`` that is not a directive Go accepts as
a block followed by ``(`` alone (Go's "unknown block type"), an unterminated block, and a
``require``, ``exclude`` or ``replace`` line whose arguments Go would refuse. Of the other
directives Go knows, ``module``, ``go``, ``toolchain``, ``godebug``, ``retract``, ``tool``
and ``ignore``, nothing is read. Versions are kept as written: a version Go would refuse, or
rewrite under ``-mod=mod``, simply has no ``go.sum`` line and so no pin.

A replacement target that ``modfile.IsDirectoryPath`` calls a directory (``.`` or ``..``, either of
them followed by a slash or a backslash, a leading slash or backslash, or a drive letter) is local
and must carry no version, and on Linux holds no backslash; any other target must name a version.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from .lockfile_model import LockfileRefusal

_READ: Final = frozenset({"require", "replace", "exclude"})
_IGNORED: Final = frozenset({"module", "go", "toolchain", "godebug", "retract", "tool", "ignore"})
# The directives Go accepts as blocks (``parseToFile`` in ``rule.go``).
_BLOCKS: Final = frozenset(
    {"module", "godebug", "require", "exclude", "replace", "retract", "tool", "ignore"}
)
_SEPARATORS: Final = " \t\r"
_PUNCTUATION: Final = "()[]{},"
_QUOTES: Final = "\"'`"
_DIRECTORY_PREFIXES: Final = ("./", ".\\", "../", "..\\", "/", "\\")
_DRIVE: Final = re.compile(r"[A-Za-z]:")


@dataclass(frozen=True)
class GoRequirement:
    """One required module version.

    Parameters
    ----------
    path : str
        The module path.
    version : str
        The required version.
    line : int
        The ``go.mod`` line that requires it.
    """

    path: str
    version: str
    line: int


@dataclass(frozen=True)
class GoReplacement:
    """One ``replace`` directive.

    Parameters
    ----------
    path : str
        The replaced module path.
    version : str | None
        The replaced version, or ``None`` for every version.
    target : str
        The replacement module path, or the local directory.
    target_version : str | None
        The replacement version; ``None`` for a local directory.
    line : int
        The ``go.mod`` line of the directive.
    """

    path: str
    version: str | None
    target: str
    target_version: str | None
    line: int

    @property
    def local(self) -> bool:
        """Return whether the replacement is a local directory."""
        return self.target_version is None


@dataclass(frozen=True)
class GoModule:
    """What one ``go.mod`` says about the module versions its ``go.sum`` should pin.

    Parameters
    ----------
    requirements : tuple[GoRequirement, ...]
        The ``require`` directives, in file order.
    replacements : tuple[GoReplacement, ...]
        The ``replace`` directives, in file order.
    exclusions : tuple[GoRequirement, ...]
        The ``exclude`` directives, in file order.
    """

    requirements: tuple[GoRequirement, ...]
    replacements: tuple[GoReplacement, ...]
    exclusions: tuple[GoRequirement, ...]

    def replacement(self, path: str, version: str) -> GoReplacement | None:
        """Return the replacement Go applies to one module version, if any.

        Parameters
        ----------
        path : str
            The module path.
        version : str
            The version.

        Returns
        -------
        GoReplacement | None
            The replacement naming that exact version, else one naming no version, else ``None``,
            as Go's ``modload`` looks them up.
        """
        exact = [r for r in self.replacements if r.path == path and r.version == version]
        general = [r for r in self.replacements if r.path == path and r.version is None]
        matches = exact or general
        return matches[0] if matches else None

    def exclusion(self, path: str, version: str) -> GoRequirement | None:
        """Return the ``exclude`` directive naming one module version, if any.

        Parameters
        ----------
        path : str
            The module path.
        version : str
            The version.

        Returns
        -------
        GoRequirement | None
            The directive, or ``None``.
        """
        return next(
            (item for item in self.exclusions if (item.path, item.version) == (path, version)),
            None,
        )


def _tokens(line: str) -> list[str]:
    """Split one line into Go's tokens, as written, with its ``//`` comment removed.

    A double-quoted string stays quoted, so that ``"=>"`` or ``")"`` is never read as the arrow
    or the end of a block, as in Go; ``_unquote`` reads it where Go calls ``parseString``.
    """
    tokens: list[str] = []
    index = 0
    while index < len(line):
        character = line[index]
        if character in _SEPARATORS:
            index += 1
        elif line.startswith("//", index):
            break
        elif character in _PUNCTUATION:
            tokens.append(character)
            index += 1
        elif character == '"':
            end = line.find('"', index + 1)
            if end < 0 or "\\" in line[index:end]:
                raise LockfileRefusal("unparseable")
            tokens.append(line[index : end + 1])
            index = end + 1
        else:
            end = index
            while end < len(line) and _word_character(line[end]):
                if line.startswith(("//", "/*"), end):
                    break
                end += 1
            word = line[index:end]
            if not word or set(word) & set(_QUOTES):
                raise LockfileRefusal("unparseable")
            tokens.append(word)
            index = end
    return tokens


def _word_character(character: str) -> bool:
    """Return whether Go's lexer reads one character as part of a word (``isIdent``)."""
    return character.isprintable() and character != " " and character not in _PUNCTUATION


def _unquote(token: str) -> str:
    """Return a path or version as Go's ``parseString`` reads it."""
    return token[1:-1] if token.startswith('"') else token


def _is_directory_path(target: str) -> bool:
    """Return whether Go reads a replacement target as a directory (``IsDirectoryPath``)."""
    return (
        target in (".", "..")
        or target.startswith(_DIRECTORY_PREFIXES)
        or _DRIVE.match(target) is not None
    )


def _replacement(arguments: list[str], line: int) -> GoReplacement:
    """Read one replacement as Go's ``parseReplace`` does, refusing a form it refuses."""
    arrow = 1 if arguments[1:2] == ["=>"] else 2
    if not arrow + 2 <= len(arguments) <= arrow + 3 or arguments[arrow] != "=>":
        raise LockfileRefusal("unparseable")
    target = _unquote(arguments[arrow + 1])
    local = _is_directory_path(target)
    if local != (len(arguments) == arrow + 2) or (local and "\\" in target):
        raise LockfileRefusal("unparseable")
    return GoReplacement(
        _unquote(arguments[0]),
        _unquote(arguments[1]) if arrow == 2 else None,
        target,
        None if local else _unquote(arguments[arrow + 2]),
        line,
    )


@dataclass
class _Found:
    """The directives read so far."""

    requirements: list[GoRequirement]
    replacements: list[GoReplacement]
    exclusions: list[GoRequirement]


def _directive(verb: str, arguments: list[str], line: int, found: _Found) -> None:
    """Record one directive line, refusing a directive Go does not know or a malformed one."""
    if verb in _IGNORED:
        return
    if verb not in _READ or set(arguments) & set(_PUNCTUATION):
        raise LockfileRefusal("unparseable")
    if verb == "replace":
        found.replacements.append(_replacement(arguments, line))
        return
    if len(arguments) != 2:
        raise LockfileRefusal("unparseable")
    target = found.requirements if verb == "require" else found.exclusions
    target.append(GoRequirement(_unquote(arguments[0]), _unquote(arguments[1]), line))


def parse_go_mod(text: str) -> GoModule:
    """Read one ``go.mod``.

    Parameters
    ----------
    text : str
        The file text.

    Returns
    -------
    GoModule
        Its requirements, replacements and exclusions.

    Raises
    ------
    LockfileRefusal
        ``unparseable`` for anything outside the grammar subset, and ``conflicting-entries`` for
        two different replacements of one module version, which Go refuses as conflicting.
    """
    found = _Found([], [], [])
    block: str | None = None
    for number, raw in enumerate(text.split("\n"), start=1):
        tokens = _tokens(raw)
        if not tokens:
            continue
        if block is not None:
            if tokens[0] == ")":
                if len(tokens) > 1:
                    raise LockfileRefusal("unparseable")
                block = None
            else:
                _directive(block, tokens, number, found)
            continue
        if tokens[-1] == "(" or tokens[1:] == ["(", ")"]:
            if tokens[1:] not in (["("], ["(", ")"]) or tokens[0] not in _BLOCKS:
                raise LockfileRefusal("unparseable")
            block = tokens[0] if len(tokens) == 2 else None
            continue
        _directive(tokens[0], tokens[1:], number, found)
    if block is not None:
        raise LockfileRefusal("unparseable")
    targets: dict[tuple[str, str | None], tuple[str, str | None]] = {}
    for item in found.replacements:
        target = targets.setdefault((item.path, item.version), (item.target, item.target_version))
        if target != (item.target, item.target_version):
            raise LockfileRefusal("conflicting-entries")
    return GoModule(tuple(found.requirements), tuple(found.replacements), tuple(found.exclusions))
