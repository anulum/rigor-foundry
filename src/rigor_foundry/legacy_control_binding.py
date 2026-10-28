# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete original control bindings
"""Bind a source rule to an unchanged control in its actual original signed pack2."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from .audit_primitives import canonical_digest
from .component_source_resolution import StandardPackSource2
from .model_primitives import require_digest, require_identifier
from .policy_model_inputs import (
    checked_policy_budget,
    policy_identifiers,
    policy_record_mapping,
    policy_reference,
    policy_wire_size,
)
from .policy_read_budget import PolicyReadBudget1
from .rule_chain_pack_v2 import StandardPackV2
from .signed_rule_chain_v2 import RULE_CHAIN_V2_SCHEMA_VERSION
from .source_component_reader import PolicyComponent1
from .standard_pack import PACK_COMPONENT_SCHEMA_VERSION, ControlDefinition
from .typed_object_reference import TypedObjectRef1

LEGACY_CONTROL_BINDING_SCHEMA_VERSION = "1.0"
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "rule_id",
        "pack",
        "control",
        "source_decision_ids",
        "binding_digest",
    }
)


@dataclass(frozen=True)
class LegacyControlBinding1:
    """Exact source relation preserving every original selected control obligation.

    This declaration grants no applicability exception, waiver, source acceptance
    or gate approval. Complete selected-control enumeration and authenticated
    source decisions remain required at the consuming projection boundary.
    """

    rule_id: str
    pack: TypedObjectRef1
    control: TypedObjectRef1
    source_decision_ids: tuple[str, ...]
    binding_digest: str

    schema_version: ClassVar[str] = LEGACY_CONTROL_BINDING_SCHEMA_VERSION
    object_kind: ClassVar[str] = "legacy-control-binding"

    def _body(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Revalidate the closed original pairs and bounded complete source-decision set."""
        limits = checked_policy_budget(budget)
        pack = policy_reference(
            self.pack, allowed=frozenset({("standard-pack", RULE_CHAIN_V2_SCHEMA_VERSION)})
        )
        control = policy_reference(
            self.control,
            allowed=frozenset({("control-definition", PACK_COMPONENT_SCHEMA_VERSION)}),
        )
        decisions = policy_identifiers(self.source_decision_ids, budget=limits)
        if 2 + len(decisions) > limits.max_references:
            raise ValueError("legacy binding exceeds the aggregate reference budget")
        body: dict[str, object] = {
            "schema_version": LEGACY_CONTROL_BINDING_SCHEMA_VERSION,
            "object_kind": "legacy-control-binding",
            "rule_id": require_identifier(self.rule_id, "legacy source rule identity"),
            "pack": pack.to_dict(),
            "control": control.to_dict(),
            "source_decision_ids": list(decisions),
        }
        policy_wire_size(body, budget=limits)
        return body

    @classmethod
    def build(
        cls,
        *,
        rule_id: str,
        pack: TypedObjectRef1,
        control: TypedObjectRef1,
        source_decision_ids: tuple[str, ...],
        budget: PolicyReadBudget1,
    ) -> LegacyControlBinding1:
        """Build an explicit relation without changing any legacy control or evidence contract."""
        candidate = cls(rule_id, pack, control, source_decision_ids, "0" * 64)
        body = candidate._body(budget=budget)
        return cls.from_dict({**body, "binding_digest": canonical_digest(body)}, budget=budget)

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Return the exact complete relation after checking its owning digest."""
        body = self._body(budget=budget)
        digest = require_digest(self.binding_digest, "legacy binding digest")
        if digest != canonical_digest(body):
            raise ValueError("legacy binding digest differs")
        result = {**body, "binding_digest": digest}
        policy_wire_size(result, budget=budget)
        return result

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> LegacyControlBinding1:
        """Parse only exact original pack2/control1 relations with explicit allocation bounds."""
        data = policy_record_mapping(
            value,
            fields=_FIELDS,
            object_kind="legacy-control-binding",
            schema_version=LEGACY_CONTROL_BINDING_SCHEMA_VERSION,
            budget=budget,
        )
        rows = data["source_decision_ids"]
        limits = checked_policy_budget(budget)
        if type(rows) is not list or len(rows) + 2 > limits.max_references:
            raise ValueError("legacy binding requires a bounded source-decision array")
        result = cls(
            require_identifier(data["rule_id"], "legacy source rule identity"),
            TypedObjectRef1.from_dict(data["pack"]),
            TypedObjectRef1.from_dict(data["control"]),
            tuple(require_identifier(row, "legacy source decision") for row in rows),
            require_digest(data["binding_digest"], "legacy binding digest"),
        )
        result.to_dict(budget=limits)
        return result

    def verify_pack(self, pack: object, *, budget: PolicyReadBudget1) -> ControlDefinition:
        """Return the exact unchanged member of the complete actual original signed pack.

        Parameters
        ----------
        pack : object
            Actual original ``StandardPackV2``, revalidated before membership use.
        budget : PolicyReadBudget1
            Explicit limits for the relation, whole pack and all child controls.

        Returns
        -------
        ControlDefinition
            Original matching control, including its full numeric evidence,
            target maturity, condition/default and remediation obligations.

        Raises
        ------
        ValueError
            The original pack identity or exact complete control membership differs.
        """
        self.to_dict(budget=budget)
        if type(pack) is not StandardPackV2:
            raise ValueError("legacy binding requires the actual original pack2")
        source = StandardPackSource2(pack, budget)
        if source.reference() != self.pack:
            raise ValueError("legacy binding differs from its complete original pack")
        for control in source.record.controls:
            if PolicyComponent1(control, budget).reference() == self.control:
                return control
        raise ValueError("legacy binding control is not an exact member of the original pack")
