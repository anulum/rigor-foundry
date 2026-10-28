# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete selected quality projection rows
"""Retain exact original and qualitative control obligations in enclosing3 rows."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Literal, cast

from .audit_primitives import canonical_digest, require_string
from .condition_language import ConditionExpression
from .control_definition_v2 import ControlDefinition2
from .model_primitives import require_boolean, require_digest
from .policy_model_inputs import (
    checked_policy_budget,
    checked_policy_condition,
    policy_condition_from_dict,
    policy_identifiers,
    policy_record_mapping,
    policy_reference,
    policy_wire_size,
)
from .policy_read_budget import PolicyReadBudget1
from .rule_scope import RuleScope1
from .source_component_reader import PolicyComponent1
from .standard_pack import TARGET_LEVEL_ORDER, ControlDefinition, TargetLevel
from .typed_object_reference import TypedObjectRef1

QUALITY_PROJECTION_V3_SCHEMA_VERSION = "3.0"
ContractCase = Literal["legacy1", "qualitative2"]
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "control",
        "source_rule_ids",
        "scope",
        "contract_case",
        "evidence_contract",
        "review_policy",
        "target_level",
        "default_applicable",
        "condition",
        "applicability_decisions",
        "row_digest",
    }
)


@dataclass(frozen=True)
class QualityProjectionRowV3:
    """One complete source-related row, preserving its actual control generation.

    Parsing and exact control binding do not select a lock, authenticate source
    decisions, evaluate applicability or grant a gate result. The enclosing
    owner must enumerate every selected control and verify all source relations.
    """

    control: TypedObjectRef1
    source_rule_ids: tuple[str, ...]
    scope: RuleScope1
    contract_case: ContractCase
    evidence_contract: TypedObjectRef1
    review_policy: TypedObjectRef1 | None
    target_level: TargetLevel
    default_applicable: bool | None
    condition: ConditionExpression | None
    applicability_decisions: tuple[TypedObjectRef1, ...]
    row_digest: str

    schema_version: ClassVar[str] = QUALITY_PROJECTION_V3_SCHEMA_VERSION
    object_kind: ClassVar[str] = "quality-projection-row"

    def _body(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Validate both cases and all reference allocations before serializing a row."""
        limits = checked_policy_budget(budget)
        case = require_string(self.contract_case, "quality projection contract case")
        if case not in {"legacy1", "qualitative2"}:
            raise ValueError("unsupported quality projection contract case")
        version = "1.0" if self.contract_case == "legacy1" else "2.0"
        control = policy_reference(
            self.control, allowed=frozenset({("control-definition", version)})
        )
        evidence = policy_reference(
            self.evidence_contract, allowed=frozenset({("evidence-contract", version)})
        )
        rules = policy_identifiers(self.source_rule_ids, budget=limits)
        if not rules or type(self.scope) is not RuleScope1:
            raise ValueError("quality projection requires source rules and an actual scope")
        scope = self.scope.to_dict(budget=limits)
        target = require_string(self.target_level, "quality projection target maturity")
        if target not in TARGET_LEVEL_ORDER:
            raise ValueError("unsupported quality projection target maturity")
        condition = (
            None
            if self.condition is None
            else checked_policy_condition(self.condition, budget=limits)
        )
        if self.contract_case == "legacy1":
            default: bool | None = require_boolean(
                self.default_applicable, "original default applicability"
            )
            if self.review_policy is not None:
                raise ValueError("legacy quality projection retains its original reviewer count")
            review = None
        else:
            if self.default_applicable is not None or condition is not None:
                raise ValueError("qualitative quality projection applicability belongs to scope")
            default = None
            review = policy_reference(
                self.review_policy, allowed=frozenset({("review-policy", "1.0")})
            ).to_dict()
        if (
            type(self.applicability_decisions) is not tuple
            or len(self.applicability_decisions) > limits.max_references
        ):
            raise ValueError("quality projection requires bounded immutable decision references")
        decisions = tuple(
            policy_reference(item, allowed=frozenset({("semantic-decision", "1.0")}))
            for item in self.applicability_decisions
        )
        identities = tuple(item.object_id for item in decisions)
        if identities != tuple(sorted(set(identities))):
            raise ValueError("quality projection decisions must be sorted and unique")
        count = 2 + len(rules) + len(decisions) + (review is not None)
        count += 0 if condition is None else len(condition.references)
        count += 0 if self.scope.condition is None else len(self.scope.condition.references)
        if count > limits.max_references:
            raise ValueError("quality projection exceeds the aggregate reference budget")
        body: dict[str, object] = {
            "schema_version": QUALITY_PROJECTION_V3_SCHEMA_VERSION,
            "object_kind": "quality-projection-row",
            "control": control.to_dict(),
            "source_rule_ids": list(rules),
            "scope": scope,
            "contract_case": self.contract_case,
            "evidence_contract": evidence.to_dict(),
            "review_policy": review,
            "target_level": target,
            "default_applicable": default,
            "condition": None if condition is None else condition.to_dict(),
            "applicability_decisions": [item.to_dict() for item in decisions],
        }
        policy_wire_size(body, budget=limits)
        return body

    @classmethod
    def build(
        cls,
        *,
        control: TypedObjectRef1,
        source_rule_ids: tuple[str, ...],
        scope: RuleScope1,
        contract_case: ContractCase,
        evidence_contract: TypedObjectRef1,
        review_policy: TypedObjectRef1 | None,
        target_level: TargetLevel,
        default_applicable: bool | None,
        condition: ConditionExpression | None,
        applicability_decisions: tuple[TypedObjectRef1, ...],
        budget: PolicyReadBudget1,
    ) -> QualityProjectionRowV3:
        """Bind explicit original or qualitative inputs without deriving applicability."""
        candidate = cls(
            control,
            source_rule_ids,
            scope,
            contract_case,
            evidence_contract,
            review_policy,
            target_level,
            default_applicable,
            condition,
            applicability_decisions,
            "",
        )
        body = candidate._body(budget=budget)
        return cls.from_dict({**body, "row_digest": canonical_digest(body)}, budget=budget)

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Revalidate the entire row and its owning digest without normalization."""
        body = self._body(budget=budget)
        digest = require_digest(self.row_digest, "quality projection row digest")
        if digest != canonical_digest(body):
            raise ValueError("quality projection row digest differs")
        result = {**body, "row_digest": digest}
        policy_wire_size(result, budget=budget)
        return result

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> QualityProjectionRowV3:
        """Parse exact fields and bound complete arrays before constructing children."""
        data = policy_record_mapping(
            value,
            fields=_FIELDS,
            object_kind="quality-projection-row",
            schema_version=QUALITY_PROJECTION_V3_SCHEMA_VERSION,
            budget=budget,
        )
        count = 2 + (data["review_policy"] is not None)
        for name in ("source_rule_ids", "applicability_decisions"):
            rows = data[name]
            if type(rows) is not list:
                raise ValueError("quality projection requires exact arrays")
            count += len(rows)
            if count > budget.max_references:
                raise ValueError("quality projection exceeds the reference allocation budget")
        result = cls(
            TypedObjectRef1.from_dict(data["control"]),
            cast(tuple[str, ...], tuple(cast(list[object], data["source_rule_ids"]))),
            RuleScope1.from_dict(data["scope"], budget=budget),
            cast(ContractCase, data["contract_case"]),
            TypedObjectRef1.from_dict(data["evidence_contract"]),
            None
            if data["review_policy"] is None
            else TypedObjectRef1.from_dict(data["review_policy"]),
            cast(TargetLevel, data["target_level"]),
            cast(bool | None, data["default_applicable"]),
            None
            if data["condition"] is None
            else policy_condition_from_dict(data["condition"], budget=budget),
            tuple(
                TypedObjectRef1.from_dict(item)
                for item in cast(list[object], data["applicability_decisions"])
            ),
            require_digest(data["row_digest"], "quality projection row digest"),
        )
        result.to_dict(budget=budget)
        return result

    def verify_control_binding(self, control: object, *, budget: PolicyReadBudget1) -> None:
        """Require the actual complete control's exact contract, maturity and applicability.

        Parameters
        ----------
        control : object
            Actual original ``ControlDefinition`` or qualitative ``ControlDefinition2``.
        budget : PolicyReadBudget1
            Explicit bounds for the row, complete control and all original children.

        Raises
        ------
        ValueError
            The actual control generation or any projected obligation differs.

        Notes
        -----
        Complete source relations, selected-control enumeration, semantic issuer
        acceptance and current applicability remain the enclosing owner's checks.
        """
        self.to_dict(budget=budget)
        if self.contract_case == "legacy1" and type(control) is ControlDefinition:
            actual = PolicyComponent1(control, budget).reference()
            evidence = PolicyComponent1(control.evidence, budget).reference()
            exact = (
                self.default_applicable == control.default_applicable
                and self.condition == control.condition
            )
        elif self.contract_case == "qualitative2" and type(control) is ControlDefinition2:
            actual = control.reference(budget=budget)
            evidence = control.evidence.reference(budget=budget)
            exact = (
                self.scope == control.scope
                and control.rule_id in self.source_rule_ids
                and self.review_policy == control.evidence.review_policy
            )
        else:
            raise ValueError("quality projection requires its actual owning control generation")
        if (
            actual != self.control
            or evidence != self.evidence_contract
            or self.target_level != control.target_level
            or not exact
        ):
            raise ValueError("quality projection differs from its complete owning control")


def validate_quality_projection(
    rows: tuple[QualityProjectionRowV3, ...],
    controls: tuple[ControlDefinition | ControlDefinition2, ...],
    *,
    budget: PolicyReadBudget1,
) -> None:
    """Require exactly one ordered complete row per actual supplied selected control.

    Parameters
    ----------
    rows : tuple[QualityProjectionRowV3, ...]
        Entire quality projection, sorted by exact versioned control identity.
    controls : tuple[ControlDefinition | ControlDefinition2, ...]
        Entire selected original and qualitative control cohort. The enclosing
        owner must derive this cohort from the actual selected signed generation.
    budget : PolicyReadBudget1
        Explicit complete cohort count, reference and canonical byte bounds.

    Raises
    ------
    ValueError
        A row or control is malformed, missing, duplicated, reordered, unrelated
        or exceeds the complete allocation budget.

    Notes
    -----
    Successful structural validation authenticates no selected generation,
    semantic decision, source completeness, applicability or gate result.
    """
    limits = checked_policy_budget(budget)
    if (
        type(rows) is not tuple
        or type(controls) is not tuple
        or len(rows) > limits.max_rules
        or len(controls) > limits.max_rules
    ):
        raise ValueError("quality projection requires bounded immutable control and row cohorts")
    selected: dict[str, ControlDefinition | ControlDefinition2] = {}
    for control in controls:
        if type(control) is ControlDefinition:
            ref = PolicyComponent1(control, limits).reference()
        elif type(control) is ControlDefinition2:
            ref = control.reference(budget=limits)
        else:
            raise ValueError("quality projection requires actual complete selected controls")
        if ref.object_id in selected:
            raise ValueError("quality projection selected controls have a duplicate identity")
        selected[ref.object_id] = control
    previous: str | None = None
    references = 0
    size = policy_wire_size([], budget=limits)
    for row in rows:
        if type(row) is not QualityProjectionRowV3:
            raise ValueError("quality projection requires actual complete rows")
        wire = row.to_dict(budget=limits)
        identity = row.control.object_id
        if previous is not None and identity <= previous:
            raise ValueError("quality projection rows must be sorted and unique")
        if identity not in selected:
            raise ValueError("quality projection row has no actual selected control")
        row.verify_control_binding(selected.pop(identity), budget=limits)
        references += 2 + len(row.source_rule_ids) + len(row.applicability_decisions)
        references += row.review_policy is not None
        references += 0 if row.condition is None else len(row.condition.references)
        references += 0 if row.scope.condition is None else len(row.scope.condition.references)
        if references > limits.max_references:
            raise ValueError("quality projection cohort exceeds the aggregate reference budget")
        size += policy_wire_size(wire, budget=limits) + (previous is not None)
        if size > limits.max_document_bytes:
            raise ValueError("quality projection cohort exceeds the aggregate byte budget")
        previous = identity
    if selected:
        raise ValueError("quality projection is missing a selected control row")
