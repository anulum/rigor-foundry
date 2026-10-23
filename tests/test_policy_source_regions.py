# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — policy source partition tests
"""Exercise complete source accounting against real retained and repository files."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_regions import (
    RegionDisposition,
    SourceRegion1,
    verify_policy_source_regions,
)


def budget(**changes: int) -> PolicyReadBudget1:
    """Specify all ceilings for an actual partition verification."""
    limits = {
        "max_document_bytes": 1024,
        "max_source_bytes": 64,
        "max_total_source_bytes": 128,
        "max_sources": 2,
        "max_rules": 8,
        "max_references": 16,
        "max_depth": 4,
    }
    return PolicyReadBudget1.build(**{**limits, **changes})


def region(
    payload: bytes,
    start: int,
    end: int,
    *,
    source: str = "source",
    disposition: RegionDisposition = "context",
    rules: tuple[str, ...] = (),
    decisions: tuple[str, ...] = (),
) -> SourceRegion1:
    """Bind a complete declared interval to the original fixture bytes."""
    return SourceRegion1.build(
        source_id=source,
        start_byte=start,
        end_byte=end,
        payload=payload,
        disposition=disposition,
        rule_ids=rules,
        decision_ids=decisions,
        reason_code="declared",
    )


def test_partition_of_actual_repository_operating_contract() -> None:
    """The byte reader covers the repository's real operating-contract statement."""
    path = Path(__file__).resolve().parents[1] / "README.md"
    payload = path.read_bytes()
    statement = b"- Missing evidence is explicit; it never resolves to pass."
    start = payload.index(statement)
    end = start + len(statement)
    regions = (
        region(payload, 0, start),
        region(payload, start, end, disposition="normative", rules=("missing-evidence",)),
        region(payload, end, len(payload)),
    )
    limits = budget(max_source_bytes=len(payload), max_total_source_bytes=len(payload))
    assert verify_policy_source_regions({"source": path}, regions, budget=limits) == regions
    assert SourceRegion1.from_dict(regions[1].to_dict()) == regions[1]


def test_multiple_source_partition_and_empty_source(tmp_path: Path) -> None:
    """Original UTF8/CRLF and zero-byte source membership are both retained."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    payload = "ž\r\n".encode()
    a.write_bytes(payload)
    b.write_bytes(b"")
    rows = (region(payload, 0, len(payload), source="a"),)
    assert verify_policy_source_regions({"a": a, "b": b}, rows, budget=budget()) == rows
    assert verify_policy_source_regions({}, (), budget=budget()) == ()


@pytest.mark.parametrize("disposition", ["context", "nonnormative", "protected", "unresolved"])
def test_partition_integrity_does_not_promote_disposition(
    tmp_path: Path,
    disposition: RegionDisposition,
) -> None:
    """Unresolved/protected declarations remain exact data after byte verification."""
    path = tmp_path / "source"
    path.write_bytes(b"abc")
    row = region(b"abc", 0, 3, disposition=disposition, decisions=("decision",))
    actual = verify_policy_source_regions({"source": path}, (row,), budget=budget())
    assert actual[0].disposition == disposition
    assert actual[0].decision_ids == ("decision",)


@pytest.mark.parametrize(
    "coordinates",
    [
        ((1, 3),),
        ((0, 1), (2, 3)),
        ((0, 2), (1, 3)),
        ((0, 2),),
    ],
)
def test_partition_gaps_overlap_and_unaccounted_tail_refuse(
    tmp_path: Path,
    coordinates: tuple[tuple[int, int], ...],
) -> None:
    """All original bytes need exactly one declared region."""
    path = tmp_path / "source"
    path.write_bytes(b"abc")
    rows = tuple(region(b"abc", start, end) for start, end in coordinates)
    with pytest.raises(ValueError, match="partition"):
        verify_policy_source_regions({"source": path}, rows, budget=budget())


def test_unrepresented_source_changed_bytes_and_changed_length_refuse(tmp_path: Path) -> None:
    """Matching interval metadata cannot hide an omitted or changed retained object."""
    path = tmp_path / "source"
    path.write_bytes(b"abc")
    row = region(b"abc", 0, 3)
    with pytest.raises(ValueError, match="omits"):
        verify_policy_source_regions({"source": path}, (), budget=budget())
    path.write_bytes(b"abd")
    with pytest.raises(ValueError, match="byte digest"):
        verify_policy_source_regions({"source": path}, (row,), budget=budget())
    path.write_bytes(b"ab")
    with pytest.raises(ValueError, match="bound"):
        verify_policy_source_regions({"source": path}, (row,), budget=budget())


def test_source_and_coordinate_order_is_verified_without_sorting(tmp_path: Path) -> None:
    """Reordered or duplicated rows are rejected before file reads."""
    first = region(b"ab", 0, 1)
    last = region(b"ab", 1, 2)
    for rows in [(last, first), (first, first)]:
        with pytest.raises(ValueError, match="order"):
            verify_policy_source_regions({"source": tmp_path / "absent"}, rows, budget=budget())
    with pytest.raises(ValueError, match="unresolved source"):
        verify_policy_source_regions({}, (first,), budget=budget())


def test_all_relation_and_region_count_budgets_apply_before_io(tmp_path: Path) -> None:
    """A small byte source cannot bypass limits with dense relation arrays."""
    path = tmp_path / "absent"
    row = region(b"a", 0, 1, disposition="normative", rules=("a", "b"), decisions=("d",))
    with pytest.raises(ValueError, match="relations exceed"):
        verify_policy_source_regions({"source": path}, (row,), budget=budget(max_references=3))
    with pytest.raises(ValueError, match="relations exceed"):
        verify_policy_source_regions({"source": path}, (row,), budget=budget(max_rules=1))
    with pytest.raises(ValueError, match="reference budget"):
        verify_policy_source_regions({"source": path}, (row, row), budget=budget(max_references=1))


@pytest.mark.parametrize(("start", "end"), [(-1, 1), (0, 0), (1, 1), (2, 1), (0, 4)])
def test_invalid_region_bounds_refuse_at_construction(start: int, end: int) -> None:
    """No empty, negative, reversed or outside interval is emitted."""
    with pytest.raises(ValueError):
        region(b"abc", start, end)


def test_direct_construction_rejects_invalid_meaning_and_mutable_relations() -> None:
    """Normative mapping, supported disposition and ordered immutable IDs are required."""
    row = region(b"a", 0, 1)
    with pytest.raises(ValueError, match="requires rule"):
        replace(row, disposition="normative")
    with pytest.raises(ValueError, match="unsupported"):
        replace(row, disposition=cast(RegionDisposition, "unknown"))
    with pytest.raises(ValueError, match="immutable"):
        replace(row, rule_ids=cast(tuple[str, ...], []))
    for relations in [("b", "a"), ("a", "a")]:
        with pytest.raises(ValueError, match="sorted and unique"):
            region(b"a", 0, 1, rules=relations)
    with pytest.raises(ValueError, match="forward"):
        replace(row, start_byte=1)


@pytest.mark.parametrize("field", ["schema_version", "object_kind"])
def test_wrong_header_cannot_be_rehashed_into_a_region(field: str) -> None:
    """Version and kind remain closed before any source byte is opened."""
    data = region(b"a", 0, 1).to_dict()
    data[field] = "other"
    with pytest.raises(ValueError, match="unsupported"):
        SourceRegion1.from_dict(data)


def test_closed_fields_and_rehashed_unknown_disposition_refuse() -> None:
    """Unknown fields, missing fields and unsupported classifications never normalize."""
    data = region(b"a", 0, 1).to_dict()
    for invalid in [
        None,
        {**data, "extra": True},
        {key: value for key, value in data.items() if key != "reason_code"},
        {**data, "disposition": "unknown"},
    ]:
        with pytest.raises(ValueError):
            SourceRegion1.from_dict(invalid)
    body = {key: value for key, value in data.items() if key != "region_digest"}
    body["rule_ids"] = ["z", "a"]
    with pytest.raises(ValueError, match="sorted and unique"):
        SourceRegion1.from_dict({**body, "region_digest": canonical_digest(body)})


def test_forged_record_and_wrong_runtime_types_cannot_cross_verifier(tmp_path: Path) -> None:
    """The public boundary revalidates direct Python instances before performing IO."""
    row = region(b"a", 0, 1)
    with pytest.raises(ValueError, match="digest"):
        replace(row, region_digest="0" * 64)
    object.__setattr__(row, "region_digest", "0" * 64)
    with pytest.raises(ValueError, match="digest"):
        verify_policy_source_regions({"source": tmp_path / "absent"}, (row,), budget=budget())
    with pytest.raises(ValueError, match="budget is required"):
        verify_policy_source_regions({}, (), budget=cast(PolicyReadBudget1, {}))
    with pytest.raises(ValueError, match="region record is required"):
        verify_policy_source_regions({}, (cast(SourceRegion1, {}),), budget=budget())
