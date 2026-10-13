# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — sealed v2 adapter operations tests
"""Keep the effect catalogue closed until handlers and extractors are reviewed."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import cast

import pytest

from rigor_foundry.adapter_operations_v2 import AdapterOperationsV2
from rigor_foundry.effect_journal_records_v2 import canonical_journal_json_v2
from rigor_foundry.effect_target_table_v2 import EffectTargetTableV2
from rigor_foundry.effect_vocabulary_v2 import EffectVocabularyV2
from rigor_foundry.extractor_registry_v2 import ExtractorRegistryV2
from rigor_foundry.models import canonical_digest


def _inputs() -> tuple[EffectVocabularyV2, EffectTargetTableV2, ExtractorRegistryV2]:
    """Supply the three exact, independently reviewed input bodies."""
    return EffectVocabularyV2.build(), EffectTargetTableV2.build(), ExtractorRegistryV2.empty()


def test_empty_operations_bind_all_three_reviewed_bodies() -> None:
    """The effect-free catalogue is canonical and digest bound to its inputs."""
    vocabulary, table, registry = _inputs()
    operations = AdapterOperationsV2.empty(
        vocabulary=vocabulary, target_table=table, extractors=registry
    )
    expected: dict[str, object] = {
        "schema": "rigor.adapter-operations.v2",
        "vocabulary_digest": vocabulary.vocabulary_digest,
        "effect_target_table_digest": table.table_digest,
        "extractor_registry_digest": registry.registry_digest,
        "operations": [],
    }
    assert operations.body_bytes == canonical_journal_json_v2(expected)
    assert operations.operations_digest == canonical_digest(expected)
    assert (
        AdapterOperationsV2.from_bytes(
            operations.body_bytes, vocabulary=vocabulary, target_table=table, extractors=registry
        )
        == operations
    )


def test_first_atomic_candidate_binds_one_closed_part_and_reviewed_inputs() -> None:
    """The first operation's exact wire is tied to the nonempty extractor body."""
    vocabulary = EffectVocabularyV2.build()
    table = EffectTargetTableV2.build()
    registry = ExtractorRegistryV2.first_atomic_candidate()
    catalogue = AdapterOperationsV2.first_atomic_candidate(
        vocabulary=vocabulary, target_table=table, extractors=registry
    )
    body = json.loads(catalogue.body_bytes)
    assert body == {
        "schema": "rigor.adapter-operations.v2",
        "vocabulary_digest": vocabulary.vocabulary_digest,
        "effect_target_table_digest": table.table_digest,
        "extractor_registry_digest": registry.registry_digest,
        "operations": [
            {
                "operation_id": "local-file-write.atomic-replace",
                "handler": {"id": "builtin.handler.atomic-file-replace.v2"},
                "parts": [
                    {
                        "index": 0,
                        "effect_class": "local-file-write",
                        "target_kind": "filesystem-path",
                        "target_extractor": {"id": "builtin.extract.path-target.v2"},
                        "route_extractor": None,
                        "byte_count_extractor": {"id": "builtin.extract.content-byte-count.v2"},
                        "variant_extractor": {
                            "id": "builtin.extract.fixed-variant-replace-or-create.v2"
                        },
                    }
                ],
                "atomicity": "atomic",
                "partial_states": [],
                "max_duration_seconds": 60,
                "cancellable": "yes",
            }
        ],
    }
    assert catalogue.operations_digest == canonical_digest(body)
    assert (
        AdapterOperationsV2.from_bytes(
            catalogue.body_bytes, vocabulary=vocabulary, target_table=table, extractors=registry
        )
        == catalogue
    )
    with pytest.raises(ValueError, match="extractor registry differs"):
        AdapterOperationsV2.first_atomic_candidate(
            vocabulary=vocabulary,
            target_table=table,
            extractors=ExtractorRegistryV2.empty(),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("atomicity", "partial-allowed"),
        ("max_duration_seconds", 3601),
        (
            "partial_states",
            [{"parts_applied": [0], "admission_rule": "release-applied-and-unstarted"}],
        ),
        ("handler", {"id": "builtin.handler.unreviewed.v2"}),
    ],
)
def test_changed_first_atomic_operation_refuses(field: str, value: object) -> None:
    """A candidate operation cannot silently change its authority or handler."""
    vocabulary = EffectVocabularyV2.build()
    table = EffectTargetTableV2.build()
    registry = ExtractorRegistryV2.first_atomic_candidate()
    catalogue = AdapterOperationsV2.first_atomic_candidate(
        vocabulary=vocabulary, target_table=table, extractors=registry
    )
    body = json.loads(catalogue.body_bytes)
    body["operations"][0][field] = value
    with pytest.raises(ValueError, match="unreviewed effect"):
        AdapterOperationsV2.from_bytes(
            canonical_journal_json_v2(body),
            vocabulary=vocabulary,
            target_table=table,
            extractors=registry,
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "rigor.adapter-operations.v3"),
        ("vocabulary_digest", "0" * 64),
        ("effect_target_table_digest", "0" * 64),
        ("extractor_registry_digest", "0" * 64),
        ("operations", [{"operation_id": "unreviewed"}]),
    ],
)
def test_changed_body_refuses(field: str, value: object) -> None:
    """Pin drift or any unreviewed operation cannot be sealed."""
    vocabulary, table, registry = _inputs()
    operations = AdapterOperationsV2.empty(
        vocabulary=vocabulary, target_table=table, extractors=registry
    )
    body = json.loads(operations.body_bytes)
    body[field] = value
    with pytest.raises(ValueError):
        AdapterOperationsV2.from_bytes(
            canonical_journal_json_v2(body),
            vocabulary=vocabulary,
            target_table=table,
            extractors=registry,
        )


def test_noncanonical_and_nonbytes_operations_refuse() -> None:
    """A caller cannot launder malformed bytes through canonical parsing."""
    vocabulary, table, registry = _inputs()
    operations = AdapterOperationsV2.empty(
        vocabulary=vocabulary, target_table=table, extractors=registry
    )
    with pytest.raises(ValueError):
        AdapterOperationsV2.from_bytes(
            operations.body_bytes + b" ",
            vocabulary=vocabulary,
            target_table=table,
            extractors=registry,
        )
    with pytest.raises(ValueError):
        AdapterOperationsV2.from_bytes(
            cast(bytes, "{}"),
            vocabulary=vocabulary,
            target_table=table,
            extractors=registry,
        )
    with pytest.raises(ValueError):
        AdapterOperationsV2.from_bytes(
            b'{"schema":"rigor.adapter-operations.v2","schema":"rigor.adapter-operations.v2"}',
            vocabulary=vocabulary,
            target_table=table,
            extractors=registry,
        )


@pytest.mark.parametrize("tampered_input", ["vocabulary", "target_table", "extractors"])
def test_tampered_input_bodies_refuse_at_build_and_parse(tampered_input: str) -> None:
    """A substituted protected body cannot borrow an original digest."""
    vocabulary, table, registry = _inputs()
    operations = AdapterOperationsV2.empty(
        vocabulary=vocabulary, target_table=table, extractors=registry
    )
    if tampered_input == "vocabulary":
        vocabulary = replace(vocabulary, body_bytes=b"{}")
    elif tampered_input == "target_table":
        table = replace(table, body_bytes=b"{}")
    else:
        registry = replace(registry, body_bytes=b"{}")
    with pytest.raises(ValueError):
        AdapterOperationsV2.empty(vocabulary=vocabulary, target_table=table, extractors=registry)
    with pytest.raises(ValueError):
        AdapterOperationsV2.from_bytes(
            operations.body_bytes,
            vocabulary=vocabulary,
            target_table=table,
            extractors=registry,
        )
