# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — exact policy component target resolution
"""Resolve fixed policy targets while retaining their actual owning formats."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypeAlias, cast

from .audit_primitives import require_exact_fields, require_mapping
from .control_definition_v2 import ControlDefinition2
from .evidence_contract_v2 import EvidenceContract2
from .evidence_reference_v2 import EvidenceReference2
from .policy_model_inputs import checked_policy_budget, policy_wire_size
from .policy_read_budget import PolicyReadBudget1
from .review_policy import ReviewPolicy1
from .rule_chain_pack_v2 import AuthorityClauseV2, FreshnessPolicyV2, StandardPackV2
from .semantic_decision import SemanticDecision1
from .signed_rule_chain_v2 import RULE_CHAIN_V2_SCHEMA_VERSION, RuleChainV2Signature
from .source_component_reader import (
    SUPPORTED_ORIGINAL_COMPONENT_FORMATS,
    PolicyComponent,
    PolicyComponent1,
)
from .standard_pack import ControlDefinition
from .typed_object_reference import TypedObjectRef1

PolicyComponentTarget: TypeAlias = (
    PolicyComponent
    | ControlDefinition2
    | EvidenceContract2
    | ReviewPolicy1
    | StandardPackV2
    | EvidenceReference2
    | SemanticDecision1
)
SUPPORTED_POLICY_TARGET_FORMATS = SUPPORTED_ORIGINAL_COMPONENT_FORMATS | frozenset(
    {
        ("control-definition", ControlDefinition2.schema_version),
        ("evidence-contract", EvidenceContract2.schema_version),
        ("review-policy", ReviewPolicy1.schema_version),
        ("standard-pack", RULE_CHAIN_V2_SCHEMA_VERSION),
        ("evidence-reference", EvidenceReference2.schema_version),
        ("semantic-decision", SemanticDecision1.schema_version),
    }
)
_PACK_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "pack_id",
        "version",
        "source_uri",
        "source_digest",
        "transition_digest",
        "licence",
        "controls",
        "authority_clauses",
        "freshness_policies",
        "signature",
        "pack_digest",
    }
)
_PACK_CHILDREN = (
    ("controls", "control-definition", ControlDefinition),
    ("authority_clauses", "authority-clause", AuthorityClauseV2),
    ("freshness_policies", "freshness-policy", FreshnessPolicyV2),
)


def _child_references(record: ControlDefinition | AuthorityClauseV2 | FreshnessPolicyV2) -> int:
    """Count original child references after the actual bounded owner has validated them."""
    if type(record) is ControlDefinition:
        return sum(
            len(rows)
            for rows in (
                record.evidence.required_adapters,
                record.evidence.evidence_types,
                record.remediation.dependencies,
                record.remediation.procedure_ids,
                record.remediation.acceptance_gates,
                record.remediation.reopen_triggers,
            )
        ) + (len(record.condition.references) if record.condition is not None else 0)
    if type(record) is AuthorityClauseV2:
        return len(record.grantor_classes)
    return len(cast(FreshnessPolicyV2, record).invalidator_ids)


def _parse_pack(value: object, budget: PolicyReadBudget1) -> StandardPackV2:
    """Bound complete original arrays before the unchanged signed-pack parser allocates them."""
    policy_wire_size(value, budget=budget)
    data = require_mapping(value, "original signed pack")
    require_exact_fields(data, _PACK_FIELDS, "original signed pack")
    if (
        data["schema_version"] != RULE_CHAIN_V2_SCHEMA_VERSION
        or data["object_kind"] != "standard-pack"
    ):
        raise ValueError("unsupported original signed pack format")
    count = 0
    for name, kind, _ in _PACK_CHILDREN:
        rows = data[name]
        if type(rows) is not list:
            raise ValueError("original signed pack requires exact component arrays")
        if name == "controls" and len(rows) > budget.max_rules:
            raise ValueError("original signed pack exceeds the control budget")
        count += len(rows)
        if count > budget.max_references:
            raise ValueError("original signed pack exceeds the aggregate reference budget")
        for row in rows:
            parsed = PolicyComponent1.from_dict(kind, row, budget=budget).record
            count += _child_references(
                cast(ControlDefinition | AuthorityClauseV2 | FreshnessPolicyV2, parsed)
            )
            if count > budget.max_references:
                raise ValueError("original signed pack exceeds the aggregate reference budget")
    parsed_pack = StandardPackV2.from_dict(data)
    if parsed_pack.to_dict() != data:
        raise ValueError("original signed pack wire must remain unchanged")
    return parsed_pack


@dataclass(frozen=True)
class StandardPackSource2:
    """Bounded reader of the complete unchanged original signed pack2.

    The original signature, all controls and their numeric evidence obligations
    remain present. Structural identity never verifies current trust, semantic
    acceptance, source custody or host selection.
    """

    record: StandardPackV2
    budget: PolicyReadBudget1 = field(compare=False, repr=False)

    def __post_init__(self) -> None:
        """Validate direct original instances before any reference is derived."""
        self.to_dict()

    def to_dict(self) -> dict[str, object]:
        """Recheck direct child types and limits before original recursive serialization."""
        limits = checked_policy_budget(self.budget)
        if (
            type(self.record) is not StandardPackV2
            or type(self.record.signature) is not RuleChainV2Signature
        ):
            raise ValueError("an actual original signed pack and signature are required")
        count = 0
        for name, _, child_type in _PACK_CHILDREN:
            rows = getattr(self.record, name)
            if type(rows) is not tuple:
                raise ValueError("original signed pack requires immutable component tuples")
            if name == "controls" and len(rows) > limits.max_rules:
                raise ValueError("original signed pack exceeds the control budget")
            count += len(rows)
            if count > limits.max_references:
                raise ValueError("original signed pack exceeds the aggregate reference budget")
            for row in rows:
                if type(row) is not child_type:
                    raise ValueError(
                        "original signed pack requires actual original component owners"
                    )
                component = PolicyComponent1(row, limits)
                count += _child_references(
                    cast(
                        ControlDefinition | AuthorityClauseV2 | FreshnessPolicyV2, component.record
                    )
                )
                if count > limits.max_references:
                    raise ValueError("original signed pack exceeds the aggregate reference budget")
        return _parse_pack(self.record.to_dict(), limits).to_dict()

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> StandardPackSource2:
        """Parse the exact original pack without migrating it or replacing its signature."""
        limits = checked_policy_budget(budget)
        return cls(_parse_pack(value, limits), limits)

    def reference(self) -> TypedObjectRef1:
        """Bind the actual original pack ID and complete pack_digest, including its signature."""
        self.to_dict()
        return TypedObjectRef1.build(
            kind="standard-pack",
            format_version=RULE_CHAIN_V2_SCHEMA_VERSION,
            object_id=self.record.pack_id,
            object_digest=self.record.pack_digest,
        )


def parse_policy_component_target(
    reference: TypedObjectRef1, value: object, *, budget: PolicyReadBudget1
) -> PolicyComponentTarget:
    """Resolve one exact target through its fixed owning parser and complete identity.

    Parameters
    ----------
    reference : TypedObjectRef1
        Supported actual target kind, version, original ID and owning digest.
    value : object
        Complete inert target wire. No path, callback or loader is accepted.
    budget : PolicyReadBudget1
        Explicit bounds for the complete target and its original children.

    Returns
    -------
    PolicyComponentTarget
        Actual original or new owning record after exact reference comparison.

    Raises
    ------
    ValueError
        The pair is unsupported or any target identity, field or limit differs.
    """
    limits = checked_policy_budget(budget)
    if type(reference) is not TypedObjectRef1:
        raise ValueError("an actual typed policy target reference is required")
    checked = TypedObjectRef1.from_dict(reference.to_dict())
    pair = (checked.kind, checked.format_version)
    if pair not in SUPPORTED_POLICY_TARGET_FORMATS:
        raise ValueError("unsupported policy component target pair")
    target: PolicyComponentTarget
    if pair in SUPPORTED_ORIGINAL_COMPONENT_FORMATS:
        original = PolicyComponent1.from_dict(checked.kind, value, budget=limits)
        target, actual = original.record, original.reference()
    elif checked.kind == "standard-pack":
        pack = StandardPackSource2.from_dict(value, budget=limits)
        target, actual = pack.record, pack.reference()
    elif checked.kind == "evidence-reference":
        evidence = EvidenceReference2.from_dict(value, budget=limits)
        target, actual = evidence, evidence.object_reference(budget=limits)
    elif checked.kind == "semantic-decision":
        decision = SemanticDecision1.from_dict(value, budget=limits)
        target, actual = decision, decision.reference(budget=limits)
    else:
        if checked.kind == "control-definition":
            new: ControlDefinition2 | EvidenceContract2 | ReviewPolicy1 = (
                ControlDefinition2.from_dict(value, budget=limits)
            )
        elif checked.kind == "evidence-contract":
            new = EvidenceContract2.from_dict(value, budget=limits)
        else:
            new = ReviewPolicy1.from_dict(value, budget=limits)
        target, actual = new, new.reference(budget=limits)
    if actual != checked:
        raise ValueError("policy target differs from its exact original identity or owning digest")
    return target
