# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — exact policy source byte spans
"""Verify policy statement coordinates against complete retained source bytes."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from .audit_primitives import (
    canonical_digest,
    require_exact_fields,
    require_integer,
    require_mapping,
)
from .model_primitives import require_digest, require_identifier
from .policy_read_budget import PolicyReadBudget1
from .policy_source_reads import read_policy_source_payloads

SOURCE_SPAN_SCHEMA_VERSION = "1.0"

_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "span_id",
        "source_id",
        "start_byte",
        "end_byte",
        "byte_digest",
        "span_digest",
    }
)


@dataclass(frozen=True)
class SourceSpan1:
    """Half-open original-byte coordinates with separate content and record hashes."""

    span_id: str
    source_id: str
    start_byte: int
    end_byte: int
    byte_digest: str
    span_digest: str

    schema_version: ClassVar[str] = SOURCE_SPAN_SCHEMA_VERSION
    object_kind: ClassVar[str] = "source-span"

    def __post_init__(self) -> None:
        """Validate direct records without claiming their retained bytes were read."""
        body = self._body()
        if require_digest(self.span_digest, "source span digest") != canonical_digest(body):
            raise ValueError("source span digest differs")

    def _body(self) -> dict[str, object]:
        """Validate structural coordinates before computing the record identity."""
        start = require_integer(self.start_byte, "source span start")
        end = require_integer(self.end_byte, "source span end", minimum=1)
        if start >= end:
            raise ValueError("source span must be nonempty and forward")
        return {
            "schema_version": SOURCE_SPAN_SCHEMA_VERSION,
            "object_kind": "source-span",
            "span_id": require_identifier(self.span_id, "source span identity"),
            "source_id": require_identifier(self.source_id, "source identity"),
            "start_byte": start,
            "end_byte": end,
            "byte_digest": require_digest(self.byte_digest, "source span byte digest"),
        }

    @classmethod
    def build(
        cls,
        *,
        span_id: str,
        source_id: str,
        start_byte: int,
        end_byte: int,
        payload: bytes,
    ) -> SourceSpan1:
        """Bind one nonempty span of actual original bytes without text normalization."""
        start = require_integer(start_byte, "source span start")
        end = require_integer(end_byte, "source span end", minimum=1)
        if not isinstance(payload, bytes) or not start < end <= len(payload):
            raise ValueError("source span is outside the retained bytes")
        byte_digest = hashlib.sha256(payload[start:end]).hexdigest()
        body: dict[str, object] = {
            "schema_version": SOURCE_SPAN_SCHEMA_VERSION,
            "object_kind": "source-span",
            "span_id": require_identifier(span_id, "source span identity"),
            "source_id": require_identifier(source_id, "source identity"),
            "start_byte": start,
            "end_byte": end,
            "byte_digest": byte_digest,
        }
        return cls(
            span_id,
            source_id,
            start,
            end,
            byte_digest,
            canonical_digest(body),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize only the closed record after checking its integrity."""
        body = self._body()
        digest = require_digest(self.span_digest, "source span digest")
        if digest != canonical_digest(body):
            raise ValueError("source span digest differs")
        return {**body, "span_digest": digest}

    @classmethod
    def from_dict(cls, value: object) -> SourceSpan1:
        """Parse structural identity; use verify to check the actual source bytes."""
        data = require_mapping(value, "source span")
        require_exact_fields(data, _FIELDS, "source span")
        if (
            data["schema_version"] != SOURCE_SPAN_SCHEMA_VERSION
            or data["object_kind"] != "source-span"
        ):
            raise ValueError("unsupported source span")
        return cls(
            require_identifier(data["span_id"], "source span identity"),
            require_identifier(data["source_id"], "source identity"),
            require_integer(data["start_byte"], "source span start"),
            require_integer(data["end_byte"], "source span end", minimum=1),
            require_digest(data["byte_digest"], "source span byte digest"),
            require_digest(data["span_digest"], "source span digest"),
        )

    def verify(self, payload: bytes) -> None:
        """Revalidate this record and compare its raw byte digest and bounds."""
        checked = SourceSpan1.from_dict(self.to_dict())
        if not isinstance(payload, bytes) or checked.end_byte > len(payload):
            raise ValueError("source span is outside the retained bytes")
        actual = hashlib.sha256(payload[checked.start_byte : checked.end_byte]).hexdigest()
        if actual != checked.byte_digest:
            raise ValueError("source span byte digest differs")


def verify_policy_source_spans(
    paths: Mapping[str, Path],
    spans: tuple[SourceSpan1, ...],
    *,
    budget: PolicyReadBudget1,
) -> tuple[SourceSpan1, ...]:
    """Check all supplied source spans through real bounded retained-file reads.

    Parameters
    ----------
    paths : Mapping[str, Path]
        Complete supplied source-ID/path mapping for this verification.
    spans : tuple[SourceSpan1, ...]
        Unique span identities in the caller's declared source/selection order.
    budget : PolicyReadBudget1
        Explicit byte, source-count and reference-count ceilings.

    Returns
    -------
    tuple[SourceSpan1, ...]
        Structurally and byte-verified records, retaining the supplied order.

    Raises
    ------
    ValueError
        A record is malformed, duplicated, over budget or not bound to its bytes.
    OSError
        A retained file cannot be read.
    StableReadError
        Retained-file custody or stability checks fail.

    Notes
    -----
    Byte verification does not establish corpus completeness, semantic acceptance,
    issuer authority, current host selection or permission to perform effects.
    """
    if type(budget) is not PolicyReadBudget1:
        raise ValueError("policy read budget is required")
    checked_budget = PolicyReadBudget1.from_dict(budget.to_dict())
    if not isinstance(spans, tuple) or len(spans) > checked_budget.max_references:
        raise ValueError("policy source spans exceed the reference budget")
    checked: list[SourceSpan1] = []
    identities: set[str] = set()
    for span in spans:
        if type(span) is not SourceSpan1:
            raise ValueError("policy source span record is required")
        item = SourceSpan1.from_dict(span.to_dict())
        if item.span_id in identities or item.source_id not in paths:
            raise ValueError("policy source span identity is duplicated or unresolved")
        identities.add(item.span_id)
        checked.append(item)
    payloads = read_policy_source_payloads(paths, budget=checked_budget)
    for item in checked:
        item.verify(payloads[item.source_id])
    return tuple(checked)
