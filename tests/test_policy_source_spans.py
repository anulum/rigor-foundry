# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — policy source byte span tests
"""Check source spans through real retained files and the public byte verifier."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_spans import SourceSpan1, verify_policy_source_spans


def budget(**changes: int) -> PolicyReadBudget1:
    """Supply every parser allocation ceiling explicitly."""
    limits = {
        "max_document_bytes": 1024,
        "max_source_bytes": 64,
        "max_total_source_bytes": 128,
        "max_sources": 2,
        "max_rules": 8,
        "max_references": 2,
        "max_depth": 4,
    }
    return PolicyReadBudget1.build(**{**limits, **changes})


def test_actual_utf8_crlf_and_half_open_bytes_are_preserved(tmp_path: Path) -> None:
    """Offsets address original bytes rather than code points or normalized lines."""
    payload = "Pravidlá\r\nžijú\n".encode()
    path = tmp_path / "source"
    path.write_bytes(payload)
    start = payload.index("ž".encode())
    item = SourceSpan1.build(
        span_id="statement",
        source_id="broadcast",
        start_byte=start,
        end_byte=len(payload) - 1,
        payload=payload,
    )
    assert item.byte_digest == hashlib.sha256("žijú".encode()).hexdigest()
    assert SourceSpan1.from_dict(item.to_dict()) == item
    assert verify_policy_source_spans({"broadcast": path}, (item,), budget=budget()) == (item,)
    item.verify(payload)
    with pytest.raises(ValueError, match="byte digest"):
        item.verify(payload.replace(b"\r\n", b"\n") + b"x")


@pytest.mark.parametrize(("start", "end"), [(-1, 1), (0, 0), (1, 1), (2, 1), (0, 4)])
def test_build_refuses_invalid_or_out_of_source_coordinates(start: int, end: int) -> None:
    """No empty, reversed, negative or out-of-range statement is emitted."""
    with pytest.raises(ValueError):
        SourceSpan1.build(
            span_id="s",
            source_id="source",
            start_byte=start,
            end_byte=end,
            payload=b"abc",
        )


def test_rehashed_structural_record_still_requires_actual_bytes(tmp_path: Path) -> None:
    """A recomputed record digest cannot authenticate a wrong statement digest."""
    path = tmp_path / "source"
    path.write_bytes(b"abc")
    item = SourceSpan1.build(
        span_id="s",
        source_id="source",
        start_byte=0,
        end_byte=3,
        payload=b"abc",
    )
    data = item.to_dict()
    data.pop("span_digest")
    data["byte_digest"] = "0" * 64
    altered = SourceSpan1.from_dict({**data, "span_digest": canonical_digest(data)})
    with pytest.raises(ValueError, match="byte digest"):
        verify_policy_source_spans({"source": path}, (altered,), budget=budget())
    path.write_bytes(b"ab")
    with pytest.raises(ValueError, match="outside"):
        verify_policy_source_spans({"source": path}, (item,), budget=budget())


def test_declared_selection_order_and_source_reference_budget(tmp_path: Path) -> None:
    """The verifier retains selection order and refuses duplicate or unresolved IDs."""
    path = tmp_path / "source"
    path.write_bytes(b"ab")
    first = SourceSpan1.build(
        span_id="z", source_id="source", start_byte=0, end_byte=1, payload=b"ab"
    )
    second = SourceSpan1.build(
        span_id="a", source_id="source", start_byte=1, end_byte=2, payload=b"ab"
    )
    paths = {"source": path}
    assert verify_policy_source_spans(paths, (first, second), budget=budget()) == (first, second)
    with pytest.raises(ValueError, match="reference budget"):
        verify_policy_source_spans(paths, (first, second), budget=budget(max_references=1))
    with pytest.raises(ValueError, match="duplicated or unresolved"):
        verify_policy_source_spans(paths, (first, first), budget=budget())
    with pytest.raises(ValueError, match="duplicated or unresolved"):
        verify_policy_source_spans({}, (first,), budget=budget())


@pytest.mark.parametrize("field", ["schema_version", "object_kind"])
def test_closed_header_refuses_unknown_version_or_kind(field: str) -> None:
    """A source span cannot reinterpret an unrelated record."""
    item = SourceSpan1.build(
        span_id="s", source_id="source", start_byte=0, end_byte=1, payload=b"a"
    )
    data = item.to_dict()
    data[field] = "other"
    with pytest.raises(ValueError, match="unsupported"):
        SourceSpan1.from_dict(data)


def test_missing_extra_and_forged_direct_records_refuse() -> None:
    """All public record routes retain exact field and digest checks."""
    item = SourceSpan1.build(
        span_id="s", source_id="source", start_byte=0, end_byte=1, payload=b"a"
    )
    data = item.to_dict()
    for invalid in [
        None,
        {**data, "extra": 0},
        {k: v for k, v in data.items() if k != "source_id"},
    ]:
        with pytest.raises(ValueError):
            SourceSpan1.from_dict(invalid)
    with pytest.raises(ValueError, match="digest"):
        replace(item, span_digest="0" * 64)
    with pytest.raises(ValueError, match="forward"):
        replace(item, start_byte=1)
    object.__setattr__(item, "span_digest", "0" * 64)
    with pytest.raises(ValueError, match="digest"):
        item.to_dict()
    with pytest.raises(ValueError, match="digest"):
        item.verify(b"a")


def test_public_verifier_rejects_wrong_runtime_record_types(tmp_path: Path) -> None:
    """Unparsed objects cannot reach the source reader as accepted span records."""
    with pytest.raises(ValueError, match="budget is required"):
        verify_policy_source_spans({}, (), budget=cast(PolicyReadBudget1, {}))
    with pytest.raises(ValueError, match="span record is required"):
        verify_policy_source_spans(
            {"source": tmp_path / "absent"},
            (cast(SourceSpan1, {}),),
            budget=budget(),
        )
