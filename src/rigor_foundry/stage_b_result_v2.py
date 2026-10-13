# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — v2 Stage B result wire
"""Parse one admitted Stage B part without claiming protected evaluation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Final, cast

from .audit_primitives import (
    canonical_digest,
    require_exact_fields,
    require_integer,
    require_mapping,
)
from .constraint_evaluator_registry_v2 import BUILTIN_EVALUATORS_V2
from .effect_journal_records_v2 import canonical_journal_json_v2, parse_effect_target_ref_v2
from .effect_vocabulary_v2 import EFFECT_CLASSES_V2
from .model_primitives import require_digest, require_identifier

STAGE_B_RESULT_SCHEMA_V2: Final = "rigor.stage-b-result.v2"
_FIELDS: Final = frozenset(
    {
        "schema",
        "part_index",
        "outcome",
        "effect_class",
        "target_ref",
        "admitting_clause_digests",
        "constraint_results",
        "semantics_set_digest",
        "scope_expansion_digest",
    }
)
_CONSTRAINT_FIELDS: Final = frozenset({"clause_digest", "subject", "evaluator_id", "result"})
_CONSTRAINT_SUBJECTS: Final = frozenset({"rate", "window", "route", "precondition"})


@dataclass(frozen=True)
class StageBResultV2:
    """Canonical admitted part with explicit source and target bindings.

    Attributes
    ----------
    body_bytes : bytes
        Closed canonical JSON part result, admits and successful constraints.
    result_digest : str
        Canonical content digest of the complete result body.

    Notes
    -----
    Parsing checks consistency, not actual evaluation, issuer custody or effect authority.
    Direct construction is revalidated before export.
    """

    body_bytes: bytes
    result_digest: str

    @classmethod
    def from_dict(cls, value: object) -> StageBResultV2:
        """Reject malformed, incomplete or reordered per-part result fields.

        Parameters
        ----------
        value
            Closed result mapping with exact admit outcome, target, source digests
            and sorted unique admitting/constraint clause identities.

        Returns
        -------
        StageBResultV2
            Canonical structural result; actual selected evaluation remains separate.

        Raises
        ------
        ValueError
            Fields, identifiers, target, ordering or fixed evaluator/result pairing differs.
        """
        body = require_mapping(value, "v2 Stage B result")
        require_exact_fields(body, _FIELDS, "v2 Stage B result")
        if body["schema"] != STAGE_B_RESULT_SCHEMA_V2 or body["outcome"] != "admit":
            raise ValueError("v2 Stage B result schema or outcome differs")
        require_integer(body["part_index"], "v2 Stage B part index")
        effect_class = body["effect_class"]
        if type(effect_class) is not str or effect_class not in EFFECT_CLASSES_V2:
            raise ValueError("v2 Stage B effect class differs")
        parse_effect_target_ref_v2(body["target_ref"])
        admitted = body["admitting_clause_digests"]
        if type(admitted) is not list or not admitted:
            raise ValueError("v2 Stage B requires at least one admitting clause")
        admitting_digests = [
            require_digest(item, "v2 Stage B admitting clause") for item in admitted
        ]
        if admitting_digests != sorted(set(admitting_digests)):
            raise ValueError("v2 Stage B admitting clauses must be sorted and unique")
        constraints = body["constraint_results"]
        if type(constraints) is not list:
            raise ValueError("v2 Stage B constraints must be a list")
        constraint_digests: list[str] = []
        for item in constraints:
            entry = require_mapping(item, "v2 Stage B constraint")
            require_exact_fields(entry, _CONSTRAINT_FIELDS, "v2 Stage B constraint")
            digest = require_digest(entry["clause_digest"], "v2 Stage B constraint clause")
            if type(entry["subject"]) is not str or entry["subject"] not in _CONSTRAINT_SUBJECTS:
                raise ValueError("v2 Stage B constraint subject differs")
            evaluator_id = require_identifier(entry["evaluator_id"], "v2 Stage B evaluator")
            if (evaluator_id, entry["subject"]) not in BUILTIN_EVALUATORS_V2:
                raise ValueError("v2 Stage B evaluator differs from constraint subject")
            if entry["result"] != "pass":
                raise ValueError("v2 Stage B admitted constraint must pass")
            constraint_digests.append(digest)
        if constraint_digests != sorted(set(constraint_digests)):
            raise ValueError("v2 Stage B constraints must be sorted and unique")
        if set(admitting_digests).intersection(constraint_digests):
            raise ValueError("v2 Stage B clause cannot both admit and constrain")
        require_digest(body["semantics_set_digest"], "v2 Stage B semantics set")
        require_digest(body["scope_expansion_digest"], "v2 Stage B scope expansion")
        encoded = canonical_journal_json_v2(body)
        return cls(encoded, canonical_digest(body))

    def to_dict(self) -> dict[str, object]:
        """Reparse direct instances before exporting an admitted result.

        Returns
        -------
        dict[str, object]
            Fresh result mapping after exact body-byte and digest revalidation.

        Raises
        ------
        ValueError
            Bytes, JSON, closed result fields or canonical record consistency differs.
        """
        if type(self.body_bytes) is not bytes:
            raise ValueError("v2 Stage B result bytes differ")
        body = cast(dict[str, object], json.loads(self.body_bytes))
        checked = self.from_dict(body)
        if checked != self:
            raise ValueError("v2 Stage B result differs from canonical bytes")
        return body
