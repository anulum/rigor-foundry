# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — closed candidate effect operation catalogue
"""Bind the two fixed operation descriptors to actual closed dependency owners."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import ClassVar, cast

from .audit_primitives import canonical_digest
from .effect_operation_contracts_v3 import _operation_descriptors
from .effect_target_table_v2 import EffectTargetTableV2
from .effect_vocabulary_v2 import EffectVocabularyV2
from .extractor_registry_v3 import ExtractorRegistryV3
from .model_primitives import require_digest
from .policy_model_inputs import checked_policy_budget, policy_record_mapping, policy_wire_size
from .policy_read_budget import PolicyReadBudget1

EFFECT_OPERATIONS_V3_SCHEMA_VERSION = "3.0"
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "vocabulary_digest",
        "target_table_digest",
        "extractor_registry_digest",
        "operations",
        "operations_digest",
    }
)


@dataclass(frozen=True)
class EffectOperationsV3:
    """Candidate atomic/native metadata, separately versioned from executable consumers.

    The native descriptor retains all seven parts even when original execute
    actions deduplicate. Its handler and lifecycle contract are requirements
    for a future installed consumer, not proof that such a consumer exists.
    No plugin, import, command launch, host enrollment or effect follows.
    """

    vocabulary: EffectVocabularyV2
    target_table: EffectTargetTableV2
    extractors: ExtractorRegistryV3
    operations_digest: str

    schema_version: ClassVar[str] = EFFECT_OPERATIONS_V3_SCHEMA_VERSION
    object_kind: ClassVar[str] = "effect-operations"

    def _body(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Revalidate complete actual dependency objects and bound the fixed descriptor cohort."""
        limits = checked_policy_budget(budget)
        if type(self.vocabulary) is not EffectVocabularyV2 or (
            self.vocabulary != EffectVocabularyV2.build()
        ):
            raise ValueError("operation catalogue3 vocabulary differs from its actual owner")
        if type(self.target_table) is not EffectTargetTableV2 or (
            self.target_table != EffectTargetTableV2.build()
        ):
            raise ValueError("operation catalogue3 target table differs from its actual owner")
        if type(self.extractors) is not ExtractorRegistryV3:
            raise ValueError("operation catalogue3 requires the actual extractor registry3")
        self.extractors.to_dict(budget=limits)
        operations = _operation_descriptors()
        references = 3
        for operation in operations:
            parts = cast(list[dict[str, object]], operation["parts"])
            references += 3 + len(parts)
            references += sum(
                part[name] is not None
                for part in parts
                for name in (
                    "target_extractor_id",
                    "route_extractor_id",
                    "byte_count_extractor_id",
                    "variant_extractor_id",
                )
            )
        if references > limits.max_references:
            raise ValueError("operation catalogue3 exceeds its aggregate reference budget")
        body: dict[str, object] = {
            "schema_version": EFFECT_OPERATIONS_V3_SCHEMA_VERSION,
            "object_kind": "effect-operations",
            "vocabulary_digest": self.vocabulary.vocabulary_digest,
            "target_table_digest": self.target_table.table_digest,
            "extractor_registry_digest": self.extractors.registry_digest,
            "operations": operations,
        }
        policy_wire_size(body, budget=limits)
        return body

    @classmethod
    def build(
        cls,
        *,
        vocabulary: EffectVocabularyV2,
        target_table: EffectTargetTableV2,
        extractors: ExtractorRegistryV3,
        budget: PolicyReadBudget1,
    ) -> EffectOperationsV3:
        """Construct the complete two-operation candidate with explicit actual dependencies.

        Parameters
        ----------
        vocabulary, target_table : object
            Actual unchanged fixed v2 owners, including their complete body bytes.
        extractors : ExtractorRegistryV3
            Complete fixed new atomic/native extractor declaration.
        budget : PolicyReadBudget1
            Whole-document bytes/depth and aggregate reference allocation bound.

        Returns
        -------
        EffectOperationsV3
            Structural candidate only; no installed execution or selection proof.

        Raises
        ------
        ValueError
            A complete dependency or required allocation bound differs.
        """
        candidate = cls(vocabulary, target_table, extractors, "")
        result = replace(
            candidate, operations_digest=canonical_digest(candidate._body(budget=budget))
        )
        result.to_dict(budget=budget)
        return result

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Recheck all dependencies and emit the exact seven-field digest-bound envelope."""
        body = self._body(budget=budget)
        digest = require_digest(self.operations_digest, "operation catalogue3 digest")
        if digest != canonical_digest(body):
            raise ValueError("operation catalogue3 digest differs")
        wire = {**body, "operations_digest": digest}
        policy_wire_size(wire, budget=budget)
        return wire

    @classmethod
    def from_dict(
        cls,
        value: object,
        *,
        vocabulary: EffectVocabularyV2,
        target_table: EffectTargetTableV2,
        extractors: ExtractorRegistryV3,
        budget: PolicyReadBudget1,
    ) -> EffectOperationsV3:
        """Refuse every body outside the closed atomic/native candidate and actual dependencies.

        Parameters
        ----------
        value : object
            Strict decoded JSON; use the bounded policy reader for retained bytes.
        vocabulary, target_table, extractors : object
            Actual independently supplied complete dependency owners.
        budget : PolicyReadBudget1
            Explicit document, depth and aggregate reference bounds.

        Returns
        -------
        EffectOperationsV3
            Closed structural metadata without a selected root or execution permit.

        Raises
        ------
        ValueError
            Any header, field, descriptor, dependency, digest or bound differs.
        """
        data = policy_record_mapping(
            value,
            fields=_FIELDS,
            schema_version=EFFECT_OPERATIONS_V3_SCHEMA_VERSION,
            object_kind="effect-operations",
            budget=budget,
        )
        expected = cls.build(
            vocabulary=vocabulary, target_table=target_table, extractors=extractors, budget=budget
        )
        if canonical_digest(data) != canonical_digest(expected.to_dict(budget=budget)):
            raise ValueError("operation catalogue3 differs from the complete closed candidate")
        return expected
