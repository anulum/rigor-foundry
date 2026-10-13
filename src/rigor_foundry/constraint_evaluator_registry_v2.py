# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — fixed built-in constraint-evaluator registry
"""Bind four exact evaluator IDs to separately measured admission code."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, cast

from .effect_journal_records_v2 import canonical_journal_json_v2
from .models import canonical_digest
from .project_registry_primitives import ProjectRegistryInvalid, project_registry_strict_json

EVALUATOR_REGISTRY_SCHEMA_V2: Final = "rigor.constraint-evaluator-registry.v2"
BUILTIN_EVALUATORS_V2: Final = (
    ("builtin.precondition.v2", "precondition"),
    ("builtin.rate.v2", "rate"),
    ("builtin.route.v2", "route"),
    ("builtin.window.v2", "window"),
)


@dataclass(frozen=True)
class ConstraintEvaluatorRegistryV2:
    """Exact fixed registry; admission-code identity is pinned separately.

    Attributes
    ----------
    body_bytes : bytes
        Exact canonical mapping for four fixed evaluator identifiers.
    registry_digest : str
        Canonical content digest, independent of evaluator code releases.
    """

    body_bytes: bytes
    registry_digest: str

    @classmethod
    def build(cls) -> ConstraintEvaluatorRegistryV2:
        """Construct the four fixed IDs without loading evaluator code.

        Returns
        -------
        ConstraintEvaluatorRegistryV2
            Immutable canonical mapping and its digest.
        """
        return cls.from_bytes(
            canonical_journal_json_v2(
                {
                    "schema": EVALUATOR_REGISTRY_SCHEMA_V2,
                    "evaluators": [
                        {"id": identifier, "subject": subject}
                        for identifier, subject in BUILTIN_EVALUATORS_V2
                    ],
                }
            )
        )

    @classmethod
    def from_bytes(cls, payload: bytes) -> ConstraintEvaluatorRegistryV2:
        """Parse the exact fixed evaluator-identifier mapping.

        Parameters
        ----------
        payload : bytes
            Canonical UTF-8 JSON containing all four mappings in fixed order.

        Returns
        -------
        ConstraintEvaluatorRegistryV2
            Original bytes and their canonical digest.

        Raises
        ------
        ValueError
            Encoding, fields, order or any fixed mapping differs.
        """
        if not isinstance(payload, bytes):
            raise ValueError("evaluator registry must be bytes")
        try:
            parsed = project_registry_strict_json(payload)
            if canonical_journal_json_v2(parsed) != payload:
                raise ValueError("evaluator registry bytes are not canonical")
        except ProjectRegistryInvalid as exc:
            raise ValueError("evaluator registry is not strict JSON") from exc
        if not isinstance(parsed, dict) or set(parsed) != {"schema", "evaluators"}:
            raise ValueError("evaluator registry fields differ")
        body = cast(dict[str, object], parsed)
        expected = [
            {"id": identifier, "subject": subject} for identifier, subject in BUILTIN_EVALUATORS_V2
        ]
        if body["schema"] != EVALUATOR_REGISTRY_SCHEMA_V2 or body["evaluators"] != expected:
            raise ValueError("evaluator registry v2 content differs")
        return cls(payload, canonical_digest(body))

    def has_subject_evaluator(self, subject: str, identifier: str) -> bool:
        """Accept only the one fixed ID for a given constraint subject.

        Parameters
        ----------
        subject, identifier : str
            Exact constraint subject and evaluator identifier.

        Returns
        -------
        bool
            Whether this pair belongs to the fixed mapping.
        """
        return (identifier, subject) in BUILTIN_EVALUATORS_V2
