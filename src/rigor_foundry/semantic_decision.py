# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — explicit semantic decision records
"""Retain exact directed semantic decisions separately from issuer authentication."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, cast

from .audit_primitives import canonical_digest, require_string
from .condition_language import ConditionExpression
from .context_owner_proof import OwnerProof1
from .model_primitives import require_digest, require_identifier
from .policy_model_inputs import (
    checked_policy_budget,
    checked_policy_condition,
    policy_condition_from_dict,
    policy_identifiers,
    policy_record_mapping,
    policy_source_spans,
    policy_wire_size,
)
from .policy_read_budget import PolicyReadBudget1
from .policy_source_spans import SourceSpan1
from .typed_object_reference import TypedObjectRef1

SEMANTIC_DECISION_SCHEMA_VERSION = "1.0"
_RELATIONS = frozenset({"supersedes", "exception", "exclusion", "interpretation", "adoption"})
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "decision_id",
        "relation",
        "issuer_id",
        "issuer_class",
        "source_spans",
        "affected_rule_ids",
        "successor_rule_ids",
        "condition",
        "rationale",
        "authority_proof",
        "decision_digest",
    }
)


@dataclass(frozen=True)
class SemanticDecision1:
    """A source-bound declaration, without granting competent semantic authority.

    The original owner proof is integrity metadata. Installed consumers must
    authenticate its issuer, retained source, exception permission and current
    snapshot, then resolve the complete rule graph before applying this decision.
    Rationale and source text retain their source classification.
    """

    decision_id: str
    relation: str
    issuer_id: str
    issuer_class: str
    source_spans: tuple[SourceSpan1, ...]
    affected_rule_ids: tuple[str, ...]
    successor_rule_ids: tuple[str, ...]
    condition: ConditionExpression | None
    rationale: str
    authority_proof: OwnerProof1
    decision_digest: str

    schema_version: ClassVar[str] = SEMANTIC_DECISION_SCHEMA_VERSION
    object_kind: ClassVar[str] = "semantic-decision"

    def _body(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Revalidate original children, directed sets and aggregate parser bounds."""
        limits = checked_policy_budget(budget)
        relation = require_string(self.relation, "semantic relation")
        if relation not in _RELATIONS:
            raise ValueError("unsupported semantic relation")
        spans = policy_source_spans(self.source_spans, budget=limits)
        affected = policy_identifiers(self.affected_rule_ids, budget=limits)
        successors = policy_identifiers(self.successor_rule_ids, budget=limits)
        if relation == "supersedes" and (
            not affected or not successors or set(affected).intersection(successors)
        ):
            raise ValueError("supersession requires nonempty directed distinct rule sets")
        if type(self.authority_proof) is not OwnerProof1:
            raise ValueError("semantic decision requires an original owner proof")
        proof = OwnerProof1.from_dict(self.authority_proof.to_dict(), budget=limits)
        condition = (
            None
            if self.condition is None
            else checked_policy_condition(self.condition, budget=limits)
        )
        count = len(spans) + len(affected) + len(successors) + 2
        if condition is not None:
            count += len(condition.references)
        if count > limits.max_references:
            raise ValueError("semantic decision exceeds the aggregate reference budget")
        body: dict[str, object] = {
            "schema_version": SEMANTIC_DECISION_SCHEMA_VERSION,
            "object_kind": "semantic-decision",
            "decision_id": require_identifier(self.decision_id, "semantic decision identity"),
            "relation": relation,
            "issuer_id": require_identifier(self.issuer_id, "semantic issuer identity"),
            "issuer_class": require_identifier(self.issuer_class, "semantic issuer class"),
            "source_spans": [span.to_dict() for span in spans],
            "affected_rule_ids": list(affected),
            "successor_rule_ids": list(successors),
            "condition": None if condition is None else condition.to_dict(),
            "rationale": require_string(self.rationale, "semantic rationale"),
            "authority_proof": proof.to_dict(),
        }
        policy_wire_size(body, budget=limits)
        return body

    @classmethod
    def build(
        cls,
        *,
        decision_id: str,
        relation: str,
        issuer_id: str,
        issuer_class: str,
        source_spans: tuple[SourceSpan1, ...],
        affected_rule_ids: tuple[str, ...],
        successor_rule_ids: tuple[str, ...],
        condition: ConditionExpression | None,
        rationale: str,
        authority_proof: OwnerProof1,
        budget: PolicyReadBudget1,
    ) -> SemanticDecision1:
        """Bind explicit inputs without inferring precedence from dates or hashes."""
        candidate = cls(
            decision_id,
            relation,
            issuer_id,
            issuer_class,
            source_spans,
            affected_rule_ids,
            successor_rule_ids,
            condition,
            rationale,
            authority_proof,
            "",
        )
        body = candidate._body(budget=budget)
        result = cls(
            decision_id,
            relation,
            issuer_id,
            issuer_class,
            source_spans,
            affected_rule_ids,
            successor_rule_ids,
            condition,
            rationale,
            authority_proof,
            canonical_digest(body),
        )
        result.to_dict(budget=budget)
        return result

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Recheck direct records and emit exact fields after complete digest validation."""
        body = self._body(budget=budget)
        digest = require_digest(self.decision_digest, "semantic decision digest")
        if digest != canonical_digest(body):
            raise ValueError("semantic decision digest differs")
        result = {**body, "decision_digest": digest}
        policy_wire_size(result, budget=budget)
        return result

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> SemanticDecision1:
        """Parse closed declarations with original child owners and no authority fallback."""
        data = policy_record_mapping(
            value,
            fields=_FIELDS,
            object_kind="semantic-decision",
            schema_version=SEMANTIC_DECISION_SCHEMA_VERSION,
            budget=budget,
        )
        arrays: dict[str, tuple[object, ...]] = {}
        for name in ("source_spans", "affected_rule_ids", "successor_rule_ids"):
            items = data[name]
            if type(items) is not list or len(items) > budget.max_references:
                raise ValueError("semantic decision requires bounded arrays")
            arrays[name] = tuple(items)
        condition = data["condition"]
        result = cls(
            require_identifier(data["decision_id"], "semantic decision identity"),
            require_string(data["relation"], "semantic relation"),
            require_identifier(data["issuer_id"], "semantic issuer identity"),
            require_identifier(data["issuer_class"], "semantic issuer class"),
            tuple(SourceSpan1.from_dict(item) for item in arrays["source_spans"]),
            cast(tuple[str, ...], arrays["affected_rule_ids"]),
            cast(tuple[str, ...], arrays["successor_rule_ids"]),
            None if condition is None else policy_condition_from_dict(condition, budget=budget),
            require_string(data["rationale"], "semantic rationale"),
            OwnerProof1.from_dict(data["authority_proof"], budget=budget),
            require_digest(data["decision_digest"], "semantic decision digest"),
        )
        result.to_dict(budget=budget)
        return result

    def reference(self, *, budget: PolicyReadBudget1) -> TypedObjectRef1:
        """Bind this complete declaration without authenticating its issuer or accepting its decision."""
        self.to_dict(budget=budget)
        return TypedObjectRef1.build(
            kind="semantic-decision",
            format_version=SEMANTIC_DECISION_SCHEMA_VERSION,
            object_id=self.decision_id,
            object_digest=self.decision_digest,
        )
