# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — candidate effect catalogue3 tests
"""Verify complete fixed operation metadata against actual original dependency owners."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_policy_model_inputs import budget

from rigor_foundry.adapter_operations_v2 import AdapterOperationsV2
from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.effect_operations_v3 import EffectOperationsV3
from rigor_foundry.effect_target_table_v2 import EffectTargetTableV2
from rigor_foundry.effect_vocabulary_v2 import EffectVocabularyV2
from rigor_foundry.extractor_registry_v2 import ExtractorRegistryV2
from rigor_foundry.extractor_registry_v3 import ExtractorRegistryV3
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_reads import read_policy_document


def catalogue() -> EffectOperationsV3:
    """Construct the actual complete new catalogue with unchanged original vocabulary/table."""
    return EffectOperationsV3.build(
        vocabulary=EffectVocabularyV2.build(),
        target_table=EffectTargetTableV2.build(),
        extractors=ExtractorRegistryV3.build(budget=budget()),
        budget=budget(),
    )


def parse_catalogue(
    wire: object, *, limits: PolicyReadBudget1 | None = None
) -> EffectOperationsV3:
    """Supply independently constructed actual dependency objects at the public parse boundary."""
    return EffectOperationsV3.from_dict(
        wire,
        vocabulary=EffectVocabularyV2.build(),
        target_table=EffectTargetTableV2.build(),
        extractors=ExtractorRegistryV3.build(budget=budget()),
        budget=budget() if limits is None else limits,
    )


def rehash_catalogue(wire: dict[str, object]) -> None:
    """Rehash the complete changed wire without quietly repairing any descriptor."""
    wire["operations_digest"] = canonical_digest(
        {key: value for key, value in wire.items() if key != "operations_digest"}
    )


def test_operation_catalogue_roundtrips_through_real_bounded_file(tmp_path: Path) -> None:
    """All seven exact fields and three actual dependency digests bind the complete body."""
    value = catalogue()
    wire = value.to_dict(budget=budget())
    assert len(wire) == 7
    assert wire["schema_version"] == "3.0" and wire["object_kind"] == "effect-operations"
    assert wire["vocabulary_digest"] == value.vocabulary.vocabulary_digest
    assert wire["target_table_digest"] == (
        "4340dcb96fabda56535afcba2ec0b9b8160e8e0c98a9cbdde6b2aecf1d3d2c76"
    )
    assert wire["extractor_registry_digest"] == value.extractors.registry_digest
    path = tmp_path / "operations.json"
    path.write_text(json.dumps(wire), encoding="utf-8")
    assert parse_catalogue(read_policy_document(path, budget=budget())) == value
    digest = wire.pop("operations_digest")
    assert digest == canonical_digest(wire)
    for omitted in ("schema_version", "object_kind"):
        assert canonical_digest({k: v for k, v in wire.items() if k != omitted}) != digest


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "2.0"),
        ("schema_version", "3.1"),
        ("schema_version", 3),
        ("object_kind", "extractor-registry"),
        ("schema", "rigor.adapter-operations.v3"),
        ("vocabulary_digest", "0" * 64),
        ("target_table_digest", "0" * 64),
        ("extractor_registry_digest", "0" * 64),
        ("operations", []),
        ("operations", {}),
        ("operations", True),
    ],
)
def test_rehashing_cannot_change_headers_dependencies_or_operation_set(
    field: str, value: object
) -> None:
    """A new digest supplies no supported body or selected original dependency."""
    wire = catalogue().to_dict(budget=budget())
    wire[field] = value
    rehash_catalogue(wire)
    with pytest.raises(ValueError):
        parse_catalogue(wire)


@pytest.mark.parametrize(
    "field,value",
    [
        ("operation_id", "arbitrary-command"),
        ("handler_id", "user-supplied.handler"),
        ("invocation_contract_digest", "0" * 64),
        ("cancellation_contract_digest", "0" * 64),
        ("atomicity", "atomic"),
        ("partial_states", []),
        ("parts", []),
        ("command", ["/bin/sh"]),
    ],
)
def test_native_descriptor_edits_refuse_with_recomputed_digest(field: str, value: object) -> None:
    """The native operation cannot silently drop lifecycle obligations or install commands."""
    wire = catalogue().to_dict(budget=budget())
    cast(list[dict[str, object]], wire["operations"])[1][field] = value
    rehash_catalogue(wire)
    with pytest.raises(ValueError, match="complete closed candidate"):
        parse_catalogue(wire)


@pytest.mark.parametrize(
    "field,value",
    [
        ("index", False),
        ("index", 0.0),
        ("stage", "audit"),
        ("effect_class", "read"),
        ("target_kind", "service-endpoint"),
        ("target_extractor_id", "unreviewed"),
        ("route_extractor_id", "unreviewed"),
        ("byte_count_extractor_id", None),
        ("variant_extractor_id", None),
        ("executable", "/bin/sh"),
    ],
)
def test_inline_part_changes_cannot_launder_bool_float_aliases_or_unknown_fields(
    field: str, value: object
) -> None:
    """Canonical body comparison distinguishes real integer indices from Python-equal aliases."""
    wire = catalogue().to_dict(budget=budget())
    operations = cast(list[dict[str, object]], wire["operations"])
    cast(list[dict[str, object]], operations[0]["parts"])[0][field] = value
    rehash_catalogue(wire)
    with pytest.raises(ValueError, match="complete closed candidate"):
        parse_catalogue(wire)


def test_missing_fields_order_duplicates_and_wrong_digest_preimages_refuse() -> None:
    """All fields and selected descriptor order are closed, including both digest-bound headers."""
    value = catalogue()
    wire = value.to_dict(budget=budget())
    for field in tuple(wire):
        with pytest.raises(ValueError):
            parse_catalogue({key: item for key, item in wire.items() if key != field})
    operations = cast(list[dict[str, object]], wire["operations"])
    for changed_operations in (operations[::-1], operations[:1], operations + operations):
        changed = {**wire, "operations": changed_operations}
        rehash_catalogue(changed)
        with pytest.raises(ValueError):
            parse_catalogue(changed)
    native_parts = cast(list[dict[str, object]], operations[1]["parts"])
    for changed_parts in (native_parts[::-1], native_parts[:-1], native_parts + native_parts[:1]):
        changed = value.to_dict(budget=budget())
        cast(list[dict[str, object]], changed["operations"])[1]["parts"] = changed_parts
        rehash_catalogue(changed)
        with pytest.raises(ValueError):
            parse_catalogue(changed)
    for digest in (
        "0" * 64,
        value.extractors.registry_digest,
        canonical_digest(wire),
        canonical_digest(
            {k: v for k, v in wire.items() if k not in {"schema_version", "operations_digest"}}
        ),
        canonical_digest(
            {k: v for k, v in wire.items() if k not in {"object_kind", "operations_digest"}}
        ),
    ):
        with pytest.raises(ValueError):
            parse_catalogue({**wire, "operations_digest": digest})
    with pytest.raises(ValueError, match="digest differs"):
        replace(value, operations_digest="0" * 64).to_dict(budget=budget())


def test_direct_dependency_type_and_complete_body_are_revalidated() -> None:
    """An unchanged borrowed digest cannot hide altered original bytes or a replaced owner."""
    value = catalogue()
    for changed in (
        replace(value, vocabulary=cast(EffectVocabularyV2, None)),
        replace(value, target_table=cast(EffectTargetTableV2, None)),
        replace(value, extractors=cast(ExtractorRegistryV3, None)),
        replace(value, vocabulary=replace(value.vocabulary, body_bytes=b"{}")),
        replace(value, target_table=replace(value.target_table, body_bytes=b"{}")),
        replace(value, extractors=replace(value.extractors, registry_digest="0" * 64)),
    ):
        with pytest.raises(ValueError):
            changed.to_dict(budget=budget())


def test_aggregate_reference_limit_final_bytes_depth_and_returned_map_isolation() -> None:
    """All dependency/handler/contract/part/extractor references and final wire bytes consume limits."""
    value = catalogue()
    wire = value.to_dict(budget=budget())
    size = len(json.dumps(wire, ensure_ascii=False, separators=(",", ":")).encode())
    assert parse_catalogue(wire, limits=budget(size=size, references=48)) == value
    assert value.to_dict(budget=budget(size=size, references=48)) == wire
    for limits in (budget(size=size - 1), budget(depth=2), budget(references=47)):
        with pytest.raises(ValueError):
            value.to_dict(budget=limits)
        with pytest.raises(ValueError):
            parse_catalogue(wire, limits=limits)
    cast(list[dict[str, object]], wire["operations"])[0]["handler_id"] = "modified"
    assert value.to_dict(budget=budget()) != wire


def test_v2_catalogue_bytes_remain_exact_and_new_bytes_never_enter_legacy_parser() -> None:
    """Explicit new dispatch is mandatory; neither original v2 envelope becomes a v3 alias."""
    vocabulary, table = EffectVocabularyV2.build(), EffectTargetTableV2.build()
    registry = ExtractorRegistryV2.first_atomic_candidate()
    old = AdapterOperationsV2.first_atomic_candidate(
        vocabulary=vocabulary, target_table=table, extractors=registry
    )
    assert (
        AdapterOperationsV2.from_bytes(
            old.body_bytes, vocabulary=vocabulary, target_table=table, extractors=registry
        )
        == old
    )
    with pytest.raises(ValueError):
        parse_catalogue(json.loads(old.body_bytes))
    new_bytes = json.dumps(
        catalogue().to_dict(budget=budget()), sort_keys=True, separators=(",", ":")
    ).encode()
    with pytest.raises(ValueError):
        AdapterOperationsV2.from_bytes(
            new_bytes, vocabulary=vocabulary, target_table=table, extractors=registry
        )


def test_nested_missing_fields_boolean_one_alias_and_interim_schema_only_wire_refuse() -> None:
    """Closed inline records retain every field and cannot borrow Python's True-equals-one alias."""
    for field in (
        "index",
        "stage",
        "effect_class",
        "target_kind",
        "target_extractor_id",
        "route_extractor_id",
        "byte_count_extractor_id",
        "variant_extractor_id",
    ):
        wire = catalogue().to_dict(budget=budget())
        native = cast(list[dict[str, object]], wire["operations"])[1]
        del cast(list[dict[str, object]], native["parts"])[1][field]
        rehash_catalogue(wire)
        with pytest.raises(ValueError):
            parse_catalogue(wire)
    wire = catalogue().to_dict(budget=budget())
    native = cast(list[dict[str, object]], wire["operations"])[1]
    cast(list[dict[str, object]], native["parts"])[1]["index"] = True
    rehash_catalogue(wire)
    with pytest.raises(ValueError):
        parse_catalogue(wire)
    wire = catalogue().to_dict(budget=budget())
    del wire["schema_version"]
    del wire["object_kind"]
    wire["schema"] = "rigor.adapter-operations.v3"
    rehash_catalogue(wire)
    with pytest.raises(ValueError):
        parse_catalogue(wire)
