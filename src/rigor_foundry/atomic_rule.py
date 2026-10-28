# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — exact source-bound atomic rule records
"""Bind statements, source spans, explicit scope and original enforcement references."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import ClassVar, cast

from .audit_primitives import canonical_digest, require_string
from .control_assessment import Classification
from .control_definition_v2 import CONTROL_DEFINITION_V2_SCHEMA_VERSION
from .model_primitives import require_boolean, require_digest, require_identifier
from .policy_model_inputs import (
    checked_policy_budget,
    policy_identifiers,
    policy_record_mapping,
    policy_source_spans,
    policy_wire_size,
)
from .policy_read_budget import PolicyReadBudget1
from .policy_source_spans import SourceSpan1
from .review_policy import REVIEW_POLICY_SCHEMA_VERSION
from .rule_scope import RuleScope1
from .source_component_reader import SUPPORTED_POLICY_COMPONENT_FORMATS
from .typed_object_reference import TypedObjectRef1

ATOMIC_RULE_SCHEMA_VERSION = "1.0"
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "rule_id",
        "revision",
        "statement",
        "statement_digest",
        "issuer_id",
        "issuer_class",
        "source_spans",
        "scope",
        "lifecycle",
        "mode",
        "mandatory_floor",
        "dependency_rule_ids",
        "decision_ids",
        "component_refs",
        "classification",
        "rule_digest",
    }
)
_ENFORCEMENT_FORMATS = SUPPORTED_POLICY_COMPONENT_FORMATS | frozenset(
    {
        ("control-definition", CONTROL_DEFINITION_V2_SCHEMA_VERSION),
        ("review-policy", REVIEW_POLICY_SCHEMA_VERSION),
    }
)
_LIFECYCLES = frozenset({"proposed", "active", "held", "superseded", "retired"})
_CLASSIFICATIONS = frozenset({"public", "internal", "confidential", "secret"})


def _components(
    value: tuple[TypedObjectRef1, ...], budget: PolicyReadBudget1
) -> tuple[TypedObjectRef1, ...]:
    """Check exact component kinds and sorted unique kind/version/object identities."""
    if type(value) is not tuple or len(value) > budget.max_references:
        raise ValueError("atomic components require a bounded immutable reference tuple")
    checked: list[TypedObjectRef1] = []
    identities: list[tuple[str, str, str]] = []
    for item in value:
        if type(item) is not TypedObjectRef1:
            raise ValueError("atomic components require actual typed references")
        ref = TypedObjectRef1.from_dict(item.to_dict())
        if (ref.kind, ref.format_version) not in _ENFORCEMENT_FORMATS:
            raise ValueError("unsupported atomic enforcement component kind")
        identities.append((ref.kind, ref.format_version, ref.object_id))
        checked.append(ref)
    if identities != sorted(set(identities)):
        raise ValueError("atomic component identities must be sorted and unique")
    return tuple(checked)


@dataclass(frozen=True)
class AtomicRule1:
    """Exact declarative rule inputs, without semantic acceptance or runtime admission.

    Statement bytes and source selection order are retained. Component references
    sort by (kind, format_version, object_id), with one digest per identity.
    Installed consumers must verify source custody, competent semantic decisions,
    the complete dependency graph and every original enforcement component.
    Historical and held rules remain explicit; a lifecycle string grants nothing.
    """

    rule_id: str
    revision: str
    statement: str
    statement_digest: str
    issuer_id: str
    issuer_class: str
    source_spans: tuple[SourceSpan1, ...]
    scope: RuleScope1
    lifecycle: str
    mode: str
    mandatory_floor: bool
    dependency_rule_ids: tuple[str, ...]
    decision_ids: tuple[str, ...]
    component_refs: tuple[TypedObjectRef1, ...]
    classification: Classification
    rule_digest: str

    schema_version: ClassVar[str] = ATOMIC_RULE_SCHEMA_VERSION
    object_kind: ClassVar[str] = "atomic-rule"

    def _body(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Revalidate immutable original inputs and complete structural reference counts."""
        limits = checked_policy_budget(budget)
        rule_id = require_identifier(self.rule_id, "atomic rule identity")
        statement = require_string(self.statement, "atomic rule statement")
        policy_wire_size(statement, budget=limits)
        statement_digest = require_digest(self.statement_digest, "atomic statement digest")
        if statement_digest != hashlib.sha256(statement.encode("utf-8")).hexdigest():
            raise ValueError("atomic statement digest differs from exact UTF8 bytes")
        spans = policy_source_spans(self.source_spans, budget=limits)
        if type(self.scope) is not RuleScope1:
            raise ValueError("atomic rule requires an actual explicit scope")
        scope = self.scope.to_dict(budget=limits)
        dependencies = policy_identifiers(self.dependency_rule_ids, budget=limits)
        decisions = policy_identifiers(self.decision_ids, budget=limits)
        if rule_id in dependencies:
            raise ValueError("atomic rule cannot depend on itself")
        components = _components(self.component_refs, limits)
        lifecycle = require_string(self.lifecycle, "atomic lifecycle")
        mode = require_string(self.mode, "atomic mode")
        classification = require_string(self.classification, "atomic classification")
        if (
            lifecycle not in _LIFECYCLES
            or mode not in {"require", "deny"}
            or classification not in _CLASSIFICATIONS
        ):
            raise ValueError("unsupported atomic lifecycle, mode or classification")
        count = len(spans) + len(dependencies) + len(decisions) + len(components)
        if self.scope.condition is not None:
            count += len(self.scope.condition.references)
        if count > limits.max_references:
            raise ValueError("atomic rule exceeds the aggregate reference budget")
        body: dict[str, object] = {
            "schema_version": ATOMIC_RULE_SCHEMA_VERSION,
            "object_kind": "atomic-rule",
            "rule_id": rule_id,
            "revision": require_string(self.revision, "atomic revision"),
            "statement": statement,
            "statement_digest": statement_digest,
            "issuer_id": require_identifier(self.issuer_id, "atomic issuer identity"),
            "issuer_class": require_identifier(self.issuer_class, "atomic issuer class"),
            "source_spans": [span.to_dict() for span in spans],
            "scope": scope,
            "lifecycle": lifecycle,
            "mode": mode,
            "mandatory_floor": require_boolean(self.mandatory_floor, "atomic mandatory floor"),
            "dependency_rule_ids": list(dependencies),
            "decision_ids": list(decisions),
            "component_refs": [ref.to_dict() for ref in components],
            "classification": classification,
        }
        policy_wire_size(body, budget=limits)
        return body

    @classmethod
    def build(
        cls,
        *,
        rule_id: str,
        revision: str,
        statement: str,
        issuer_id: str,
        issuer_class: str,
        source_spans: tuple[SourceSpan1, ...],
        scope: RuleScope1,
        lifecycle: str,
        mode: str,
        mandatory_floor: bool,
        dependency_rule_ids: tuple[str, ...],
        decision_ids: tuple[str, ...],
        component_refs: tuple[TypedObjectRef1, ...],
        classification: Classification,
        budget: PolicyReadBudget1,
    ) -> AtomicRule1:
        """Build exact original statement identity without normalizing its UTF8 text."""
        checked_policy_budget(budget)
        text = require_string(statement, "atomic rule statement")
        policy_wire_size(text, budget=budget)
        statement_digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        candidate = cls(
            rule_id,
            revision,
            text,
            statement_digest,
            issuer_id,
            issuer_class,
            source_spans,
            scope,
            lifecycle,
            mode,
            mandatory_floor,
            dependency_rule_ids,
            decision_ids,
            component_refs,
            classification,
            "",
        )
        body = candidate._body(budget=budget)
        result = cls(
            rule_id,
            revision,
            text,
            statement_digest,
            issuer_id,
            issuer_class,
            source_spans,
            scope,
            lifecycle,
            mode,
            mandatory_floor,
            dependency_rule_ids,
            decision_ids,
            component_refs,
            classification,
            canonical_digest(body),
        )
        result.to_dict(budget=budget)
        return result

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Check direct records and return exact fields with their complete owning digest."""
        body = self._body(budget=budget)
        digest = require_digest(self.rule_digest, "atomic rule digest")
        if digest != canonical_digest(body):
            raise ValueError("atomic rule digest differs")
        result = {**body, "rule_digest": digest}
        policy_wire_size(result, budget=budget)
        return result

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> AtomicRule1:
        """Parse fixed fields and original spans/components without inferring admission."""
        data = policy_record_mapping(
            value,
            fields=_FIELDS,
            object_kind="atomic-rule",
            schema_version=ATOMIC_RULE_SCHEMA_VERSION,
            budget=budget,
        )
        arrays: dict[str, tuple[object, ...]] = {}
        for name in ("source_spans", "dependency_rule_ids", "decision_ids", "component_refs"):
            items = data[name]
            if type(items) is not list or len(items) > budget.max_references:
                raise ValueError("atomic rule requires bounded arrays")
            arrays[name] = tuple(items)
        result = cls(
            require_identifier(data["rule_id"], "atomic rule identity"),
            require_string(data["revision"], "atomic revision"),
            require_string(data["statement"], "atomic statement"),
            require_digest(data["statement_digest"], "atomic statement digest"),
            require_identifier(data["issuer_id"], "atomic issuer identity"),
            require_identifier(data["issuer_class"], "atomic issuer class"),
            tuple(SourceSpan1.from_dict(item) for item in arrays["source_spans"]),
            RuleScope1.from_dict(data["scope"], budget=budget),
            require_string(data["lifecycle"], "atomic lifecycle"),
            require_string(data["mode"], "atomic mode"),
            require_boolean(data["mandatory_floor"], "atomic mandatory floor"),
            cast(tuple[str, ...], arrays["dependency_rule_ids"]),
            cast(tuple[str, ...], arrays["decision_ids"]),
            tuple(TypedObjectRef1.from_dict(item) for item in arrays["component_refs"]),
            cast(Classification, require_string(data["classification"], "atomic classification")),
            require_digest(data["rule_digest"], "atomic rule digest"),
        )
        result.to_dict(budget=budget)
        return result
