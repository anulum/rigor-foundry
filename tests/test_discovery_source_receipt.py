# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — original discovery receipt tests
"""Exercise original validator receipts without replacing source or digest meanings."""

from __future__ import annotations

from dataclasses import asdict, replace
from pathlib import Path
from typing import cast

import pytest
from discovery_source_support import limits, snapshot
from test_context_owner_implementation import implementation_budget

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.discovery_source_receipt import DiscoverySourceReceipt1
from rigor_foundry.discovery_source_schema import DiscoveryLimits
from rigor_foundry.discovery_source_validation import validate_discovery_sources
from rigor_foundry.policy_read_budget import PolicyReadBudget1


def receipt(root: Path) -> dict[str, object]:
    """Run the unchanged public validator over complete real discovery files."""
    snapshot(root)
    return validate_discovery_sources(root, "manifest.json", limits=limits(root))


def test_actual_original_receipt_round_trips_and_remains_integrity_only(tmp_path: Path) -> None:
    """Every original field, unused source and limit survives with its original digest."""
    original = receipt(tmp_path)
    files = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    parsed = DiscoverySourceReceipt1.from_dict(original, budget=implementation_budget())
    assert parsed.to_dict() == original
    assert asdict(parsed.limits) == original["limits"]
    assert parsed.unused_source_ids == ("source2",)
    assert parsed.candidate_count == parsed.span_count == 2
    assert parsed.to_dict()["promotable"] is False
    assert parsed.to_dict()["assertion_class"] == "declared-snapshot-integrity-only"
    assert parsed.to_dict()["receipt_digest"] == original["receipt_digest"]
    assert "object_kind" not in parsed.to_dict()
    assert (
        DiscoverySourceReceipt1.from_dict(
            original, budget=implementation_budget(max_references=34, max_depth=3)
        )
        == parsed
    )
    assert validate_discovery_sources(tmp_path, "manifest.json", limits=parsed.limits) == original
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == files
    (tmp_path / "source0.txt").write_bytes(b"changed actual source")
    with pytest.raises(ValueError):
        validate_discovery_sources(tmp_path, "manifest.json", limits=parsed.limits)
    assert parsed.to_dict() == original


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "1.0"),
        ("status", "accepted"),
        ("assertion_class", "semantic-acceptance"),
        ("promotable", True),
        ("promotable", 0),
        ("manifest_sha256", "invalid"),
        ("sources", []),
        ("sources", {}),
        ("sources", [{"source_id": "source", "sha256": "a" * 64, "loader": "caller"}]),
        ("sources", [{"source_id": "bad identity", "sha256": "a" * 64}]),
        ("sources", [{"source_id": "source", "sha256": "bad"}]),
        ("shards", []),
        ("candidate_count", True),
        ("candidate_count", 0),
        ("candidate_count", 1),
        ("candidate_count", 3),
        ("span_count", 1),
        ("span_count", 3),
        ("unused_source_ids", ()),
        ("unused_source_ids", ["unknown"]),
        ("unused_source_ids", ["source0", "source1", "source2"]),
        ("unused_source_ids", ["source2", "source2"]),
        ("limits", {}),
        ("receipt_digest", "f" * 64),
    ],
)
def test_closed_original_wire_refuses_rehashed_forgery(
    tmp_path: Path, field: str, value: object
) -> None:
    """A new hash cannot grant acceptance, change original counts or enroll fields."""
    data = receipt(tmp_path)
    data[field] = value
    if field != "receipt_digest":
        data.pop("receipt_digest")
        data["receipt_digest"] = canonical_digest(data)
    with pytest.raises(ValueError):
        DiscoverySourceReceipt1.from_dict(data, budget=implementation_budget())


def test_collection_order_closure_and_original_limits_refuse(tmp_path: Path) -> None:
    """Preserve canonical order and original limits without silently truncating rows."""
    original = receipt(tmp_path)
    for field in ("sources", "shards"):
        rows = cast(list[dict[str, object]], original[field])
        for altered in (rows[::-1], [*rows, rows[0]]):
            with pytest.raises(ValueError):
                DiscoverySourceReceipt1.from_dict(
                    {**original, field: altered}, budget=implementation_budget()
                )
    for name in ("sources", "shards", "candidates", "spans", "file_bytes"):
        changed = {
            **cast(dict[str, object], original["limits"]),
            name: 0 if name == "file_bytes" else 1,
        }
        with pytest.raises(ValueError):
            DiscoverySourceReceipt1.from_dict(
                {**original, "limits": changed}, budget=implementation_budget()
            )
    for malformed in ({**original, "object_kind": "discovery-source-receipt"}, None):
        with pytest.raises(ValueError):
            DiscoverySourceReceipt1.from_dict(malformed, budget=implementation_budget())


def test_explicit_parser_limits_do_not_rewrite_original_limits(tmp_path: Path) -> None:
    """Allocation refusals occur even for a receipt with an otherwise valid original hash."""
    original = receipt(tmp_path)
    for changes in (
        {"max_sources": 2},
        {"max_references": 2},
        {"max_references": 33},
        {"max_depth": 2},
    ):
        with pytest.raises(ValueError):
            DiscoverySourceReceipt1.from_dict(original, budget=implementation_budget(**changes))
    with pytest.raises(ValueError, match="budget is required"):
        DiscoverySourceReceipt1.from_dict(original, budget=cast(PolicyReadBudget1, {}))


def test_direct_instances_require_immutable_valid_original_children(tmp_path: Path) -> None:
    """Direct construction rejects mutable/oversized rows and inconsistent original identity."""
    actual = DiscoverySourceReceipt1.from_dict(receipt(tmp_path), budget=implementation_budget())
    mutations: tuple[dict[str, object], ...] = (
        {"sources": []},
        {"sources": ()},
        {"sources": (("source0",),)},
        {"sources": (["source0", "a" * 64],)},
        {"sources": actual.sources[::-1]},
        {"limits": {}},
        {"unused_source_ids": []},
        {"unused_source_ids": ("source2",) * 65536},
        {"unused_source_ids": ("source1", "source0")},
        {"receipt_digest": "0" * 64},
    )
    for changed in mutations:
        with pytest.raises(ValueError):
            DiscoverySourceReceipt1(
                **{**asdict(actual), **changed, "limits": changed.get("limits", actual.limits)}
            )
    with pytest.raises(ValueError):
        replace(actual, limits=DiscoveryLimits(**{**asdict(actual.limits), "sources": 1}))
