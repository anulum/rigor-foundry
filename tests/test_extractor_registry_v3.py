# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — closed extractor registry3 tests
"""Exercise the actual bounded producer, file reader and closed registry parser."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_policy_model_inputs import budget

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.extractor_registry_v2 import ExtractorRegistryV2
from rigor_foundry.extractor_registry_v3 import ExtractorRegistryV3
from rigor_foundry.policy_source_reads import read_policy_document


def rehash_registry(wire: dict[str, object]) -> None:
    """Recompute only the owning preimage, preserving the changed public wire."""
    wire["registry_digest"] = canonical_digest(
        {key: value for key, value in wire.items() if key != "registry_digest"}
    )


def test_registry_roundtrips_complete_nonempty_body_through_real_file(tmp_path: Path) -> None:
    """Both common headers and the exact two descriptor contracts own the digest."""
    registry = ExtractorRegistryV3.build(budget=budget(references=2))
    wire = registry.to_dict(budget=budget())
    assert set(wire) == {"schema_version", "object_kind", "extractors", "registry_digest"}
    assert wire["schema_version"] == "3.0" and wire["object_kind"] == "extractor-registry"
    descriptors = cast(list[dict[str, object]], wire["extractors"])
    assert [row["id"] for row in descriptors] == [
        "builtin.extract.atomic-replace.v3",
        "builtin.extract.native-profile-audit.v3",
    ]
    assert all(set(row) == {"id", "input_contract", "output_contract"} for row in descriptors)
    path = tmp_path / "extractors.json"
    path.write_text(json.dumps(wire), encoding="utf-8")
    assert (
        ExtractorRegistryV3.from_dict(read_policy_document(path, budget=budget()), budget=budget())
        == registry
    )
    digest = wire.pop("registry_digest")
    assert digest == canonical_digest(wire)
    assert canonical_digest({k: v for k, v in wire.items() if k != "schema_version"}) != digest
    assert canonical_digest({k: v for k, v in wire.items() if k != "object_kind"}) != digest


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "2.0"),
        ("schema_version", "3.1"),
        ("schema_version", 3),
        ("object_kind", "effect-operations"),
        ("schema", "rigor.extractor-registry.v3"),
        ("extractors", []),
        ("extractors", {}),
        ("extractors", True),
    ],
)
def test_recomputed_registry_hash_cannot_admit_wrong_headers_or_cohort(
    field: str, value: object
) -> None:
    """Unknown, old-style, mixed or mismatched metadata never acquires an accepted identity."""
    wire = ExtractorRegistryV3.build(budget=budget()).to_dict(budget=budget())
    wire[field] = value
    rehash_registry(wire)
    with pytest.raises(ValueError):
        ExtractorRegistryV3.from_dict(wire, budget=budget())


@pytest.mark.parametrize("field", ["id", "input_contract", "output_contract", "module"])
def test_changed_inline_contract_is_rejected_even_with_recomputed_digest(field: str) -> None:
    """A metadata edit cannot register another implementation or weaker contract."""
    wire = ExtractorRegistryV3.build(budget=budget()).to_dict(budget=budget())
    cast(list[dict[str, object]], wire["extractors"])[0][field] = "unreviewed"
    rehash_registry(wire)
    with pytest.raises(ValueError, match="unreviewed descriptor"):
        ExtractorRegistryV3.from_dict(wire, budget=budget())


def test_registry_missing_fields_order_duplicates_and_wrong_preimages_refuse() -> None:
    """The parser closes every field and keeps descriptor order, count and digest preimage exact."""
    registry = ExtractorRegistryV3.build(budget=budget())
    wire = registry.to_dict(budget=budget())
    for field in tuple(wire):
        changed = {key: value for key, value in wire.items() if key != field}
        with pytest.raises(ValueError):
            ExtractorRegistryV3.from_dict(changed, budget=budget())
    descriptors = cast(list[dict[str, object]], wire["extractors"])
    for changed_rows in (descriptors[::-1], descriptors[:1], descriptors + descriptors):
        changed = {**wire, "extractors": changed_rows}
        rehash_registry(changed)
        with pytest.raises(ValueError, match="unreviewed descriptor"):
            ExtractorRegistryV3.from_dict(changed, budget=budget())
    for digest in (
        "0" * 64,
        canonical_digest(wire),
        canonical_digest({"schema": "rigor.extractor-registry.v3", "extractors": descriptors}),
        canonical_digest({"extractors": descriptors}),
    ):
        with pytest.raises(ValueError, match="digest differs"):
            ExtractorRegistryV3.from_dict({**wire, "registry_digest": digest}, budget=budget())
    with pytest.raises(ValueError, match="digest differs"):
        replace(registry, registry_digest="0" * 64).to_dict(budget=budget())


def test_registry_complete_byte_depth_reference_limits_and_fresh_maps() -> None:
    """Bounds include the final digest and nested contracts; returned mappings share no state."""
    registry = ExtractorRegistryV3.build(budget=budget())
    wire = registry.to_dict(budget=budget())
    size = len(json.dumps(wire, ensure_ascii=False, separators=(",", ":")).encode())
    assert ExtractorRegistryV3.build(budget=budget(size=size, references=2)) == registry
    for limits in (budget(size=size - 1), budget(depth=2), budget(references=1)):
        with pytest.raises(ValueError):
            registry.to_dict(budget=limits)
        with pytest.raises(ValueError):
            ExtractorRegistryV3.from_dict(wire, budget=limits)
    cast(list[dict[str, object]], wire["extractors"])[0]["input_contract"] = "changed"
    assert registry.to_dict(budget=budget()) != wire
    for malformed in ({"registry_digest": False}, {"registry_digest": "not-a-digest"}):
        with pytest.raises(ValueError):
            ExtractorRegistryV3.from_dict(
                {**registry.to_dict(budget=budget()), **malformed}, budget=budget()
            )


def test_legacy_registry_bytes_and_duplicate_keys_keep_separate_parsers(tmp_path: Path) -> None:
    """Old bytes roundtrip unchanged; new bytes refuse there and duplicate JSON never normalizes."""
    original = ExtractorRegistryV2.first_atomic_candidate()
    assert ExtractorRegistryV2.from_bytes(original.body_bytes) == original
    wire = ExtractorRegistryV3.build(budget=budget()).to_dict(budget=budget())
    with pytest.raises(ValueError):
        ExtractorRegistryV2.from_bytes(
            json.dumps(wire, sort_keys=True, separators=(",", ":")).encode()
        )
    with pytest.raises(ValueError):
        ExtractorRegistryV3.from_dict(json.loads(original.body_bytes), budget=budget())
    path = tmp_path / "duplicate.json"
    path.write_text(
        json.dumps(wire)[:-1] + ', "object_kind":"extractor-registry"}', encoding="utf-8"
    )
    with pytest.raises(ValueError, match="duplicate"):
        read_policy_document(path, budget=budget())


def test_inline_missing_fields_interim_schema_only_and_cross_catalogue_hash_refuse() -> None:
    """Neither a descriptor omission nor another actual owner's hash is this registry identity."""
    from test_effect_operations_v3 import catalogue

    for field in ("id", "input_contract", "output_contract"):
        wire = ExtractorRegistryV3.build(budget=budget()).to_dict(budget=budget())
        del cast(list[dict[str, object]], wire["extractors"])[1][field]
        rehash_registry(wire)
        with pytest.raises(ValueError):
            ExtractorRegistryV3.from_dict(wire, budget=budget())
    wire = ExtractorRegistryV3.build(budget=budget()).to_dict(budget=budget())
    wire["registry_digest"] = catalogue().operations_digest
    with pytest.raises(ValueError):
        ExtractorRegistryV3.from_dict(wire, budget=budget())
    del wire["schema_version"]
    del wire["object_kind"]
    wire["schema"] = "rigor.extractor-registry.v3"
    rehash_registry(wire)
    with pytest.raises(ValueError):
        ExtractorRegistryV3.from_dict(wire, budget=budget())
