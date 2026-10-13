# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — sealed v2 adapter operations
"""Bind the closed first effect-operation catalogue to reviewed inputs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .effect_journal_records_v2 import canonical_journal_json_v2
from .effect_target_table_v2 import EffectTargetTableV2
from .effect_vocabulary_v2 import EffectVocabularyV2
from .extractor_registry_v2 import ExtractorRegistryV2
from .models import canonical_digest
from .project_registry_primitives import ProjectRegistryInvalid, project_registry_strict_json

ADAPTER_OPERATIONS_SCHEMA_V2: Final = "rigor.adapter-operations.v2"
_FIRST_ATOMIC_OPERATION: Final = {
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
            "variant_extractor": {"id": "builtin.extract.fixed-variant-replace-or-create.v2"},
        }
    ],
    "atomicity": "atomic",
    "partial_states": [],
    "max_duration_seconds": 60,
    "cancellable": "yes",
}


def _expected_body(
    vocabulary: EffectVocabularyV2,
    target_table: EffectTargetTableV2,
    extractors: ExtractorRegistryV2,
) -> dict[str, object]:
    """Select only the bootstrap or first reviewed candidate body."""
    if vocabulary != EffectVocabularyV2.build():
        raise ValueError("adapter operations vocabulary differs from reviewed body")
    if target_table != EffectTargetTableV2.build():
        raise ValueError("adapter operations target table differs from reviewed body")
    if extractors == ExtractorRegistryV2.empty():
        operations: list[object] = []
    elif extractors == ExtractorRegistryV2.first_atomic_candidate():
        operations = [_FIRST_ATOMIC_OPERATION]
    else:
        raise ValueError("adapter operations extractor registry is not reviewed")
    return {
        "schema": ADAPTER_OPERATIONS_SCHEMA_V2,
        "vocabulary_digest": vocabulary.vocabulary_digest,
        "effect_target_table_digest": target_table.table_digest,
        "extractor_registry_digest": extractors.registry_digest,
        "operations": operations,
    }


@dataclass(frozen=True)
class AdapterOperationsV2:
    """Sealed operation metadata awaiting protected selection.

    Attributes
    ----------
    body_bytes : bytes
        Canonical closed catalogue bytes, bound to vocabulary, target table and extractor digests.
    operations_digest : str
        Canonical digest of the complete catalogue body.

    Notes
    -----
    Parsing this metadata neither imports a handler nor authorizes execution.
    """

    body_bytes: bytes
    operations_digest: str

    @classmethod
    def empty(
        cls,
        *,
        vocabulary: EffectVocabularyV2,
        target_table: EffectTargetTableV2,
        extractors: ExtractorRegistryV2,
    ) -> AdapterOperationsV2:
        """Build the closed catalogue containing no effects.

        Parameters
        ----------
        vocabulary : EffectVocabularyV2
            Exact reviewed effect vocabulary.
        target_table : EffectTargetTableV2
            Exact reviewed target-kind table.
        extractors : ExtractorRegistryV2
            Exact sealed extractor registry required by the selected catalogue variant.

        Returns
        -------
        AdapterOperationsV2
            Validated empty catalogue.

        Raises
        ------
        ValueError
            A supplied dependency differs from the reviewed empty-catalogue inputs.
        """
        if extractors != ExtractorRegistryV2.empty():
            raise ValueError("adapter operations extractor registry is not reviewed")
        body = _expected_body(vocabulary, target_table, extractors)
        return cls.from_bytes(
            canonical_journal_json_v2(body),
            vocabulary=vocabulary,
            target_table=target_table,
            extractors=extractors,
        )

    @classmethod
    def first_atomic_candidate(
        cls,
        *,
        vocabulary: EffectVocabularyV2,
        target_table: EffectTargetTableV2,
        extractors: ExtractorRegistryV2,
    ) -> AdapterOperationsV2:
        """Build the fixed first-operation metadata without selecting it.

        Parameters
        ----------
        vocabulary : EffectVocabularyV2
            Exact reviewed effect vocabulary.
        target_table : EffectTargetTableV2
            Exact reviewed target-kind table.
        extractors : ExtractorRegistryV2
            Exact sealed extractor registry required by the selected catalogue variant.

        Returns
        -------
        AdapterOperationsV2
            Canonical atomic-replacement candidate catalogue.

        Raises
        ------
        ValueError
            A supplied vocabulary, table or extractor registry differs from the fixed candidate.
        """
        if extractors != ExtractorRegistryV2.first_atomic_candidate():
            raise ValueError("first atomic extractor registry differs")
        body = _expected_body(vocabulary, target_table, extractors)
        return cls.from_bytes(
            canonical_journal_json_v2(body),
            vocabulary=vocabulary,
            target_table=target_table,
            extractors=extractors,
        )

    @classmethod
    def from_bytes(
        cls,
        payload: bytes,
        *,
        vocabulary: EffectVocabularyV2,
        target_table: EffectTargetTableV2,
        extractors: ExtractorRegistryV2,
    ) -> AdapterOperationsV2:
        """Parse only an exact reviewed closed operation catalogue.

        Parameters
        ----------
        payload : bytes
            Canonical catalogue bytes; bootstrap and first-atomic forms are the only accepted bodies.
        vocabulary : EffectVocabularyV2
            Exact reviewed effect vocabulary.
        target_table : EffectTargetTableV2
            Exact reviewed target-kind table.
        extractors : ExtractorRegistryV2
            Exact sealed extractor registry required by the selected catalogue variant.

        Returns
        -------
        AdapterOperationsV2
            Validated metadata and its recomputed digest.

        Raises
        ------
        ValueError
            Input is non-bytes, malformed, noncanonical, mismatched or contains an unreviewed operation.
        """
        if not isinstance(payload, bytes):
            raise ValueError("adapter operations must be bytes")
        expected = _expected_body(vocabulary, target_table, extractors)
        try:
            body = project_registry_strict_json(payload)
            if canonical_journal_json_v2(body) != payload:
                raise ValueError("adapter operations bytes are not canonical")
        except ProjectRegistryInvalid as exc:
            raise ValueError("adapter operations are not strict JSON") from exc
        if body != expected:
            raise ValueError("adapter operations contain an unreviewed effect")
        return cls(payload, canonical_digest(expected))
