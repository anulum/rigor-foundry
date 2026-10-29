# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — source-bound policy hold declarations
"""Retain bounded hold reasons and typed provenance without granting clearance."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import ClassVar, cast

from .audit_primitives import canonical_digest
from .model_primitives import require_digest, require_identifier
from .policy_model_inputs import (
    checked_policy_budget,
    policy_identifiers,
    policy_record_mapping,
    policy_reference,
    policy_wire_size,
)
from .policy_read_budget import PolicyReadBudget1
from .typed_object_reference import SUPPORTED_CONTEXT_SOURCE_FORMATS, TypedObjectRef1

POLICY_HOLD_SCHEMA_VERSION = "1.0"
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "code",
        "subject",
        "affected_rule_ids",
        "evidence",
        "hold_digest",
    }
)


@dataclass(frozen=True)
class PolicyHold1:
    """One declared policy hold with exact subject and supporting references.

    Empty affected-rule or evidence arrays remain explicit. Parsing does not
    resolve referenced targets, authenticate a hold or determine whether it is
    applicable. The selected policy owner derives the complete current holds;
    a caller cannot obtain clearance by omitting or editing these records.
    """

    code: str
    subject: TypedObjectRef1
    affected_rule_ids: tuple[str, ...]
    evidence: tuple[TypedObjectRef1, ...]
    hold_digest: str

    schema_version: ClassVar[str] = POLICY_HOLD_SCHEMA_VERSION
    object_kind: ClassVar[str] = "policy-hold"

    def _body(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Validate complete immutable inputs before serializing their owning preimage."""
        limits = checked_policy_budget(budget)
        rules = policy_identifiers(self.affected_rule_ids, budget=limits)
        if len(rules) > limits.max_rules:
            raise ValueError("policy hold exceeds the affected rule budget")
        if type(self.evidence) is not tuple:
            raise ValueError("policy hold evidence requires an immutable tuple")
        if 1 + len(rules) + len(self.evidence) > limits.max_references:
            raise ValueError("policy hold exceeds the aggregate reference budget")
        subject = policy_reference(self.subject, allowed=SUPPORTED_CONTEXT_SOURCE_FORMATS)
        evidence = tuple(
            policy_reference(item, allowed=SUPPORTED_CONTEXT_SOURCE_FORMATS)
            for item in self.evidence
        )
        identities = tuple((item.kind, item.format_version, item.object_id) for item in evidence)
        if identities != tuple(sorted(set(identities))):
            raise ValueError("policy hold evidence identities must be sorted and unique")
        body: dict[str, object] = {
            "schema_version": POLICY_HOLD_SCHEMA_VERSION,
            "object_kind": "policy-hold",
            "code": require_identifier(self.code, "policy hold reason code"),
            "subject": subject.to_dict(),
            "affected_rule_ids": list(rules),
            "evidence": [item.to_dict() for item in evidence],
        }
        policy_wire_size(body, budget=limits)
        return body

    @classmethod
    def build(
        cls,
        *,
        code: str,
        subject: TypedObjectRef1,
        affected_rule_ids: tuple[str, ...],
        evidence: tuple[TypedObjectRef1, ...],
        budget: PolicyReadBudget1,
    ) -> PolicyHold1:
        """Bind an explicit declared reason to complete subject and evidence identities.

        Parameters
        ----------
        code : str
            Authored opaque reason identifier, without raw exception diagnostics.
        subject : TypedObjectRef1
            Exact supported target reference. Its actual owner must resolve it.
        affected_rule_ids : tuple[str, ...]
            Sorted unique affected rule identities, empty when none are declared.
        evidence : tuple[TypedObjectRef1, ...]
            Supporting references sorted uniquely by kind, format and object ID.
        budget : PolicyReadBudget1
            Explicit complete byte, nesting, rule and aggregate reference ceilings.

        Returns
        -------
        PolicyHold1
            Integrity-checked declaration without source or applicability acceptance.

        Raises
        ------
        ValueError
            Inputs are malformed, reordered, duplicated or exceed their bounds.
        """
        candidate = cls(code, subject, affected_rule_ids, evidence, "")
        result = replace(candidate, hold_digest=canonical_digest(candidate._body(budget=budget)))
        result.to_dict(budget=budget)
        return result

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Recheck complete direct inputs and digest before returning the exact seven fields."""
        body = self._body(budget=budget)
        digest = require_digest(self.hold_digest, "policy hold digest")
        if digest != canonical_digest(body):
            raise ValueError("policy hold digest differs")
        result = {**body, "hold_digest": digest}
        policy_wire_size(result, budget=budget)
        return result

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> PolicyHold1:
        """Bound the entire wire and collections before parsing exact original references."""
        data = policy_record_mapping(
            value,
            fields=_FIELDS,
            object_kind="policy-hold",
            schema_version=POLICY_HOLD_SCHEMA_VERSION,
            budget=budget,
        )
        rules, evidence = data["affected_rule_ids"], data["evidence"]
        if type(rules) is not list or type(evidence) is not list:
            raise ValueError("policy hold collections require exact arrays")
        if len(rules) > budget.max_rules or 1 + len(rules) + len(evidence) > budget.max_references:
            raise ValueError("policy hold exceeds its collection allocation budget")
        result = cls(
            require_identifier(data["code"], "policy hold reason code"),
            TypedObjectRef1.from_dict(data["subject"]),
            cast(tuple[str, ...], tuple(rules)),
            tuple(TypedObjectRef1.from_dict(item) for item in evidence),
            require_digest(data["hold_digest"], "policy hold digest"),
        )
        result.to_dict(budget=budget)
        return result
