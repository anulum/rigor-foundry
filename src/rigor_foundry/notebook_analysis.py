# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — bounded Jupyter notebook analysis
"""Inspect tracked Python notebook cells without executing a Jupyter kernel."""

from __future__ import annotations

import ast
import hashlib
import json
from bisect import bisect_left
from dataclasses import dataclass, replace
from pathlib import PurePosixPath
from typing import NoReturn, cast

from .application_security import scan_application_security
from .candidate_anchor import TrackedBlobAnchor
from .data_privacy import scan_data_privacy
from .git_inventory import GitInventory, TrackedFile
from .models import AuditPolicy, Candidate
from .operations import scan_operations
from .performance import scan_performance
from .reliability import scan_reliability
from .scientific import scan_scientific
from .test_authenticity import _infer_packages, _python_candidates

NOTEBOOK_SUFFIXES = frozenset({".ipynb"})
MAX_NOTEBOOK_CELLS = 1_024
MAX_JSON_DEPTH = 64

_JsonPath = tuple[str | int, ...]


@dataclass(frozen=True)
class _StringToken:
    """One decoded JSON string and its exact physical notebook line span."""

    value: str
    line_start: int
    line_end: int


@dataclass(frozen=True)
class _SourceChunk:
    """One notebook source fragment bound to its JSON token."""

    text: str
    token: _StringToken


@dataclass(frozen=True)
class _CellSource:
    """One Python code cell with physical notebook spans for each source line."""

    index: int
    text: str
    line_spans: tuple[tuple[int, int], ...]


class _NotebookFormatError(ValueError):
    """A bounded notebook format or analysis failure."""

    def __init__(self, reason: str, line: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.line = line


def _reject_constant(value: str) -> object:
    """Reject non-standard JSON constants such as NaN and Infinity."""
    raise ValueError(f"unsupported JSON constant: {value}")


class _JsonCursor:
    """Strict JSON parser that retains value-string locations by JSON path."""

    def __init__(self, text: str) -> None:
        self._text = text
        self._position = 0
        self._newlines = tuple(index for index, character in enumerate(text) if character == "\n")
        self._decoder = json.JSONDecoder(parse_constant=_reject_constant)
        self.tokens: dict[_JsonPath, _StringToken] = {}

    def parse(self) -> object:
        """Parse exactly one JSON value and reject trailing content."""
        value = self._value((), 0)
        self._whitespace()
        if self._position != len(self._text):
            self._fail("trailing-json-content")
        return value

    def _value(self, path: _JsonPath, depth: int) -> object:
        self._whitespace()
        if depth > MAX_JSON_DEPTH:
            self._fail("json-depth-limit")
        if self._position >= len(self._text):
            self._fail("unexpected-json-end")
        character = self._text[self._position]
        if character == '"':
            value, token = self._string()
            self.tokens[path] = token
            return value
        if character == "{":
            return self._object(path, depth)
        if character == "[":
            return self._array(path, depth)
        try:
            decoded, end = cast(
                tuple[object, int],
                self._decoder.raw_decode(self._text, self._position),
            )
        except (json.JSONDecodeError, ValueError) as exc:
            raise _NotebookFormatError("invalid-json", self._line(self._position)) from exc
        self._position = end
        return decoded

    def _object(self, path: _JsonPath, depth: int) -> dict[str, object]:
        self._position += 1
        result: dict[str, object] = {}
        self._whitespace()
        if self._consume("}"):
            return result
        while True:
            self._whitespace()
            if self._position >= len(self._text) or self._text[self._position] != '"':
                self._fail("invalid-json-object-key")
            key, _token = self._string()
            if key in result:
                self._fail("duplicate-json-key")
            self._whitespace()
            self._expect(":")
            result[key] = self._value((*path, key), depth + 1)
            self._whitespace()
            if self._consume("}"):
                return result
            self._expect(",")

    def _array(self, path: _JsonPath, depth: int) -> list[object]:
        self._position += 1
        result: list[object] = []
        self._whitespace()
        if self._consume("]"):
            return result
        while True:
            result.append(self._value((*path, len(result)), depth + 1))
            self._whitespace()
            if self._consume("]"):
                return result
            self._expect(",")

    def _string(self) -> tuple[str, _StringToken]:
        start = self._position
        try:
            decoded, end = cast(
                tuple[object, int],
                self._decoder.raw_decode(self._text, self._position),
            )
        except (json.JSONDecodeError, ValueError) as exc:
            raise _NotebookFormatError("invalid-json-string", self._line(start)) from exc
        value = cast(str, decoded)
        self._position = end
        return value, _StringToken(
            value=value,
            line_start=self._line(start),
            line_end=self._line(max(start, end - 1)),
        )

    def _expect(self, character: str) -> None:
        self._whitespace()
        if not self._consume(character):
            self._fail("invalid-json-delimiter")

    def _consume(self, character: str) -> bool:
        if self._text.startswith(character, self._position):
            self._position += len(character)
            return True
        return False

    def _whitespace(self) -> None:
        while self._position < len(self._text) and self._text[self._position] in " \t\r\n":
            self._position += 1

    def _line(self, position: int) -> int:
        return bisect_left(self._newlines, max(0, min(position, len(self._text)))) + 1

    def _fail(self, reason: str) -> NoReturn:
        raise _NotebookFormatError(reason, self._line(self._position))


def _mapping(value: object, reason: str, line: int = 1) -> dict[str, object]:
    """Return one string-keyed mapping or raise a bounded notebook error."""
    if not isinstance(value, dict):
        raise _NotebookFormatError(reason, line)
    return cast(dict[str, object], value)


def _sequence(value: object, reason: str, line: int = 1) -> list[object]:
    """Return one JSON array or raise a bounded notebook error."""
    if not isinstance(value, list):
        raise _NotebookFormatError(reason, line)
    return cast(list[object], value)


def _token_line(tokens: dict[_JsonPath, _StringToken], path: _JsonPath) -> int:
    """Return a recorded string-token line or the notebook root line."""
    token = tokens.get(path)
    return token.line_start if token is not None else 1


def _notebook_language(
    document: dict[str, object],
    tokens: dict[_JsonPath, _StringToken],
) -> None:
    """Require one unambiguous Python notebook language declaration."""
    metadata = _mapping(document.get("metadata"), "invalid-notebook-metadata")
    declarations: list[tuple[str, int]] = []
    for key in ("language_info", "kernelspec"):
        section_value = metadata.get(key)
        if section_value is None:
            continue
        section = _mapping(
            section_value,
            "invalid-notebook-language-metadata",
            _token_line(tokens, ("metadata", key)),
        )
        name = section.get("name" if key == "language_info" else "language")
        if name is None:
            continue
        line = _token_line(
            tokens,
            ("metadata", key, "name" if key == "language_info" else "language"),
        )
        if not isinstance(name, str) or not name.strip():
            raise _NotebookFormatError("invalid-notebook-language", line)
        declarations.append((name.strip().casefold(), line))
    if not declarations:
        raise _NotebookFormatError("missing-notebook-language", 1)
    names = {name for name, _line in declarations}
    if len(names) != 1:
        raise _NotebookFormatError("conflicting-notebook-language", declarations[0][1])
    if names.pop() not in {"python", "python3"}:
        raise _NotebookFormatError("unsupported-notebook-language", declarations[0][1])


def _source_chunks(
    value: object,
    tokens: dict[_JsonPath, _StringToken],
    path: _JsonPath,
) -> tuple[_SourceChunk, ...]:
    """Return validated notebook source strings with their JSON token locations."""
    if isinstance(value, str):
        token = tokens[path]
        return (_SourceChunk(value, token),)
    values = _sequence(value, "invalid-code-cell-source", _token_line(tokens, path))
    chunks: list[_SourceChunk] = []
    for index, item in enumerate(values):
        if not isinstance(item, str):
            raise _NotebookFormatError(
                "invalid-code-cell-source",
                1,
            )
        token = tokens[(*path, index)]
        chunks.append(_SourceChunk(item, token))
    return tuple(chunks)


def _logical_line_spans(chunks: tuple[_SourceChunk, ...]) -> tuple[tuple[int, int], ...]:
    """Map concatenated source lines to the exact JSON token lines that supplied them."""
    source = "".join(chunk.text for chunk in chunks)
    if not source:
        return ()
    intervals: list[tuple[int, int, _StringToken]] = []
    offset = 0
    for chunk in chunks:
        end = offset + len(chunk.text)
        intervals.append((offset, end, chunk.token))
        offset = end
    spans: list[tuple[int, int]] = []
    for offset, end in _python_line_ranges(source):
        tokens = [token for start, stop, token in intervals if stop > offset and start < end]
        spans.append(
            (
                min(token.line_start for token in tokens),
                max(token.line_end for token in tokens),
            )
        )
    return tuple(spans)


def _python_line_ranges(source: str) -> tuple[tuple[int, int], ...]:
    """Return source ranges using only newline forms recognised by Python."""
    ranges: list[tuple[int, int]] = []
    start = 0
    index = 0
    while index < len(source):
        character = source[index]
        if character not in "\r\n":
            index += 1
            continue
        end = index + 1
        if character == "\r" and end < len(source) and source[end] == "\n":
            end += 1
        ranges.append((start, end))
        start = end
        index = end
    if start < len(source):
        ranges.append((start, len(source)))
    return tuple(ranges)


def _code_cells(
    document: dict[str, object],
    tokens: dict[_JsonPath, _StringToken],
) -> tuple[_CellSource, ...]:
    """Validate notebook schema 4 and return its bounded Python code cells."""
    nbformat = document.get("nbformat")
    if isinstance(nbformat, bool) or not isinstance(nbformat, int) or nbformat != 4:
        raise _NotebookFormatError("unsupported-notebook-schema", 1)
    _notebook_language(document, tokens)
    cells = _sequence(document.get("cells"), "invalid-notebook-cells")
    if len(cells) > MAX_NOTEBOOK_CELLS:
        raise _NotebookFormatError("notebook-cell-limit", 1)
    sources: list[_CellSource] = []
    for index, value in enumerate(cells):
        cell = _mapping(value, "invalid-notebook-cell")
        cell_type = cell.get("cell_type")
        cell_line = _token_line(tokens, ("cells", index, "cell_type"))
        if not isinstance(cell_type, str):
            raise _NotebookFormatError("invalid-notebook-cell-type", cell_line)
        if cell_type != "code":
            continue
        path: _JsonPath = ("cells", index, "source")
        chunks = _source_chunks(cell.get("source"), tokens, path)
        source = "".join(chunk.text for chunk in chunks)
        sources.append(
            _CellSource(
                index=index,
                text=source,
                line_spans=_logical_line_spans(chunks),
            )
        )
    return tuple(sources)


def _virtual_item(item: TrackedFile, cell: _CellSource) -> TrackedFile:
    """Project one cell as a Python owner while retaining the notebook blob identity."""
    pure = PurePosixPath(item.path)
    owner = pure.with_suffix("") / f"__cell_{cell.index:04d}.py"
    return replace(item, path=owner.as_posix(), text=cell.text, content_kind="text")


def _cell_candidates(
    inventory: GitInventory,
    policy: AuditPolicy,
    item: TrackedFile,
    cell: _CellSource,
) -> tuple[Candidate, ...]:
    """Run only applicable existing Python-AST scanners over one code cell."""
    virtual = _virtual_item(item, cell)
    projected = replace(inventory, files=(virtual,))
    candidates = [
        *scan_application_security(projected, policy),
        *scan_reliability(projected, policy),
        *scan_data_privacy(projected, policy),
        *scan_scientific(projected, policy),
        *scan_operations(projected, policy),
        *scan_performance(projected, policy),
        *_python_candidates(virtual, policy, _infer_packages(inventory, policy)),
    ]
    return tuple(_reanchor(item, cell, candidate) for candidate in candidates)


def _reanchor(item: TrackedFile, cell: _CellSource, candidate: Candidate) -> Candidate:
    """Translate one virtual Python line span back to the exact notebook blob span."""
    start = candidate.anchor.line_start
    end = candidate.anchor.line_end
    mapped = cell.line_spans[start - 1 : end]
    line_start = min(span[0] for span in mapped)
    line_end = max(span[1] for span in mapped)
    return Candidate.build(
        category=candidate.category,
        rule_id=candidate.rule_id,
        anchor=TrackedBlobAnchor.build(item, line_start=line_start, line_end=line_end),
        symbol=candidate.symbol,
        evidence=(
            f"file_sha256={item.content_digest}; "
            f"notebook_span_sha256={_span_digest(item, line_start, line_end)}; "
            f"cell_index={cell.index}; source_line_start={start}; source_line_end={end}"
        ),
        confidence=candidate.confidence,
        rationale=candidate.rationale,
        verification=candidate.verification,
    )


def _span_digest(item: TrackedFile, line_start: int, line_end: int) -> str:
    """Return the SHA-256 of the exact physical notebook lines in one anchor."""
    lines = (item.text or "").splitlines(keepends=True)
    payload = "".join(lines[line_start - 1 : line_end]).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _bounded_line(item: TrackedFile, line: int) -> int:
    """Clamp a parser location to the addressable notebook blob line range."""
    count = max(1, len((item.text or "").splitlines()))
    return max(1, min(line, count))


def _issue_candidate(item: TrackedFile, error: _NotebookFormatError) -> Candidate:
    """Represent incomplete notebook analysis as a fail-closed governance candidate."""
    line = _bounded_line(item, error.line)
    return Candidate.build(
        category="governance",
        rule_id="GV005-unscanned-jupyter-notebook",
        anchor=TrackedBlobAnchor.build(item, line_start=line),
        symbol=error.reason,
        evidence=(
            f"file_sha256={item.content_digest}; "
            f"notebook_line_sha256={_span_digest(item, line, line)}; reason={error.reason}"
        ),
        confidence="high",
        rationale=(
            "A tracked Jupyter notebook could not be completely projected into the bounded "
            "Python-AST analysis surface."
        ),
        verification=(
            "Open the exact tracked blob, validate nbformat 4 and an unambiguous Python language "
            "declaration, repair malformed or unsupported cells, and rerun the read-only scan."
        ),
    )


def scan_notebooks(
    inventory: GitInventory,
    policy: AuditPolicy,
) -> tuple[Candidate, ...]:
    """Return anchored candidates from tracked Python Jupyter notebooks.

    The scanner reads only the bounded UTF-8 text already captured by the Git
    inventory. It never imports Jupyter, starts a kernel, evaluates a cell, or
    writes into the audited checkout.
    """
    candidates: list[Candidate] = []
    for item in inventory.files:
        if PurePosixPath(item.path).suffix.lower() not in NOTEBOOK_SUFFIXES:
            continue
        if item.text is None:
            continue
        parser = _JsonCursor(item.text)
        try:
            document = _mapping(parser.parse(), "invalid-notebook-root")
            cells = _code_cells(document, parser.tokens)
        except _NotebookFormatError as exc:
            candidates.append(_issue_candidate(item, exc))
            continue
        for cell in cells:
            if not cell.text:
                continue
            try:
                ast.parse(cell.text, filename=f"{item.path}#cell-{cell.index}")
            except (SyntaxError, UnicodeError) as exc:
                source_line = (
                    exc.lineno if isinstance(exc, SyntaxError) and exc.lineno is not None else 1
                )
                mapped_line = (
                    cell.line_spans[source_line - 1][0]
                    if 0 < source_line <= len(cell.line_spans)
                    else 1
                )
                candidates.append(
                    _issue_candidate(
                        item,
                        _NotebookFormatError("unparseable-python-cell", mapped_line),
                    )
                )
                continue
            candidates.extend(_cell_candidates(inventory, policy, item, cell))
    return tuple(candidates)
