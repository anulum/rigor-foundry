# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — bounded GitHub Actions YAML representation
"""Read YAML events into immutable source-located values without construction."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, cast

from yaml import SafeLoader
from yaml.error import Mark, MarkedYAMLError, YAMLError
from yaml.events import (
    AliasEvent,
    DocumentStartEvent,
    Event,
    MappingEndEvent,
    MappingStartEvent,
    ScalarEvent,
    SequenceEndEvent,
    SequenceStartEvent,
    StreamEndEvent,
)

MAX_WORKFLOW_BYTES = 1_048_576
MAX_WORKFLOW_EVENTS = 8_192
MAX_WORKFLOW_DEPTH = 32
MAX_WORKFLOW_ALIASES = 128
_TAGS = frozenset(
    f"tag:yaml.org,2002:{name}" for name in ("str", "null", "bool", "int", "float", "seq", "map")
)


class WorkflowFormatError(ValueError):
    """Report a fixed reason and physical line without retaining source text."""

    def __init__(self, reason: str, line: int = 1) -> None:
        """Store a source-free diagnostic for an incomplete YAML analysis."""
        super().__init__(reason)
        self.reason = reason
        self.line = line


@dataclass(frozen=True)
class WorkflowValue:
    """One scalar, sequence or mapping with its original inclusive line span."""

    kind: Literal["scalar", "sequence", "mapping"]
    line: int
    end_line: int
    text: str = ""
    items: tuple[WorkflowValue, ...] = ()
    pairs: tuple[tuple[str, WorkflowValue], ...] = ()

    def mapping(self) -> dict[str, WorkflowValue]:
        """Return mapping entries or refuse a structurally different value."""
        if self.kind != "mapping":
            raise WorkflowFormatError("expected-mapping", self.line)
        return dict(self.pairs)

    def sequence(self) -> tuple[WorkflowValue, ...]:
        """Return sequence entries or refuse a structurally different value."""
        if self.kind != "sequence":
            raise WorkflowFormatError("expected-sequence", self.line)
        return self.items

    def scalar(self) -> str:
        """Return literal scalar text without YAML 1.1 boolean coercion."""
        if self.kind != "scalar":
            raise WorkflowFormatError("expected-scalar", self.line)
        return self.text


def _line(event: Event, *, end: bool = False) -> int:
    """Return an inclusive source line from a native parser event mark."""
    # SafeLoader's native events always carry the pure-Python source Mark.
    mark = cast(Mark, event.end_mark if end else event.start_mark)
    return max(1, mark.line + (0 if end and mark.column == 0 else 1))


class _EventReader:
    """Consume a bounded single YAML document with backward acyclic aliases."""

    def __init__(self, text: str) -> None:
        """Open a parser only; never call a YAML object constructor."""
        self.loader = SafeLoader(text)
        self.events = 0
        self.aliases = 0
        self.anchors: dict[str, WorkflowValue] = {}
        self.anchor_names: set[str] = set()

    def event(self) -> Event:
        """Read one event and enforce the allocation budget before building nodes."""
        # PyYAML's parser stubs omit the documented Event return annotation.
        read_event = cast(Callable[[], Event], self.loader.get_event)
        event = read_event()
        self.events += 1
        if self.events > MAX_WORKFLOW_EVENTS:
            raise WorkflowFormatError("yaml-event-limit", _line(event))
        return event

    def value(self, event: Event, depth: int = 0) -> WorkflowValue:
        """Build one typed value while checking depth, tags, keys and aliases."""
        if depth > MAX_WORKFLOW_DEPTH:
            raise WorkflowFormatError("yaml-depth-limit", _line(event))
        if isinstance(event, AliasEvent):
            self.aliases += 1
            if self.aliases > MAX_WORKFLOW_ALIASES:
                raise WorkflowFormatError("yaml-alias-limit", _line(event))
            if event.anchor not in self.anchors:
                raise WorkflowFormatError("unresolved-or-cyclic-alias", _line(event))
            return self.anchors[event.anchor]
        if not isinstance(event, (ScalarEvent, MappingStartEvent, SequenceStartEvent)):
            raise WorkflowFormatError("expected-yaml-value", _line(event))
        if event.tag is not None and event.tag not in _TAGS:
            raise WorkflowFormatError("unsupported-yaml-tag", _line(event))
        if event.anchor is not None:
            if event.anchor in self.anchor_names:
                raise WorkflowFormatError("duplicate-yaml-anchor", _line(event))
            self.anchor_names.add(event.anchor)
        if event.tag is not None:
            expected = (
                {"tag:yaml.org,2002:seq"}
                if isinstance(event, SequenceStartEvent)
                else {"tag:yaml.org,2002:map"}
                if isinstance(event, MappingStartEvent)
                else _TAGS.difference({"tag:yaml.org,2002:seq", "tag:yaml.org,2002:map"})
            )
            if event.tag not in expected:
                raise WorkflowFormatError("yaml-tag-shape-mismatch", _line(event))
        line = _line(event)
        if isinstance(event, ScalarEvent):
            result = WorkflowValue("scalar", line, _line(event, end=True), text=event.value)
        elif isinstance(event, SequenceStartEvent):
            items: list[WorkflowValue] = []
            child = self.event()
            while not isinstance(child, SequenceEndEvent):
                items.append(self.value(child, depth + 1))
                child = self.event()
            result = WorkflowValue("sequence", line, _line(child, end=True), items=tuple(items))
        else:
            pairs: dict[str, WorkflowValue] = {}
            child = self.event()
            while not isinstance(child, MappingEndEvent):
                key = self.value(child, depth + 1)
                name = key.scalar()
                if name == "<<":
                    raise WorkflowFormatError("unsupported-yaml-merge", key.line)
                if name in pairs:
                    raise WorkflowFormatError("duplicate-yaml-key", key.line)
                pairs[name] = self.value(self.event(), depth + 1)
                child = self.event()
            result = WorkflowValue(
                "mapping", line, _line(child, end=True), pairs=tuple(pairs.items())
            )
        if event.anchor is not None:
            self.anchors[event.anchor] = result
        return result

    def document(self) -> WorkflowValue:
        """Require one complete document and dispose the parser on every outcome."""
        try:
            self.event()  # Native parser's mandatory StreamStartEvent.
            if not isinstance(self.event(), DocumentStartEvent):
                raise WorkflowFormatError("missing-yaml-document")
            result = self.value(self.event())
            self.event()  # Native parser's mandatory DocumentEndEvent.
            if not isinstance(self.event(), StreamEndEvent):
                raise WorkflowFormatError("multiple-yaml-documents")
            return result
        finally:
            self.loader.dispose()


def parse_workflow_yaml(text: str) -> WorkflowValue:
    """Parse one bounded YAML document without constructing or executing objects.

    Literal keys, including on, and scalar contents retain their spelling.
    Aliases refer to completed immutable values at their definition locations.
    Merge keys, custom tags, cycles and duplicate keys refuse explicitly.
    """
    if len(text.encode("utf-8")) > MAX_WORKFLOW_BYTES:
        raise WorkflowFormatError("yaml-byte-limit")
    try:
        return _EventReader(text).document()
    except MarkedYAMLError as exc:
        line = 1 if exc.problem_mark is None else exc.problem_mark.line + 1
        raise WorkflowFormatError("invalid-yaml", line) from None
    except YAMLError:
        raise WorkflowFormatError("invalid-yaml") from None
