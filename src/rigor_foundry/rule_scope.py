# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — explicit rule scope and events
"""Represent exact rule scope without inferring applicability or event authority."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Literal, cast

from .audit_primitives import canonical_digest
from .condition_language import ConditionExpression
from .model_primitives import require_digest
from .policy_model_inputs import (
    checked_policy_budget,
    checked_policy_condition,
    policy_condition_from_dict,
    policy_record_mapping,
    policy_wire_size,
)
from .policy_read_budget import PolicyReadBudget1
from .task_context import TASK_CONTEXT_EVENTS

RULE_SCOPE_SCHEMA_VERSION = "1.0"
RuleScopeKind = Literal["global", "scoped"]
_FIELDS = frozenset(
    {"schema_version", "object_kind", "scope_kind", "condition", "events", "scope_digest"}
)


def _body(
    scope_kind: object,
    condition: ConditionExpression | None,
    events: tuple[str, ...],
    budget: PolicyReadBudget1,
) -> dict[str, object]:
    """Validate direct values and retain every event and original condition byte."""
    limits = checked_policy_budget(budget)
    if type(scope_kind) is not str or scope_kind not in {"global", "scoped"}:
        raise ValueError("unsupported rule scope kind")
    if type(events) is not tuple or not events or len(events) > len(TASK_CONTEXT_EVENTS):
        raise ValueError("rule scope requires a bounded nonempty event tuple")
    if any(type(event) is not str or event not in TASK_CONTEXT_EVENTS for event in events):
        raise ValueError("rule scope contains an unsupported event")
    if events != tuple(sorted(set(events))):
        raise ValueError("rule scope events must be sorted and unique")
    if scope_kind == "global":
        if condition is not None or events != tuple(sorted(TASK_CONTEXT_EVENTS)):
            raise ValueError("global rule scope requires all events and no condition")
        raw_condition: object = None
    else:
        raw_condition = checked_policy_condition(condition, budget=limits).to_dict()
    body: dict[str, object] = {
        "schema_version": RULE_SCOPE_SCHEMA_VERSION,
        "object_kind": "rule-scope",
        "scope_kind": scope_kind,
        "condition": raw_condition,
        "events": list(events),
    }
    policy_wire_size(body, budget=limits)
    return body


@dataclass(frozen=True)
class RuleScope1:
    """An immutable explicit event scope, with no implicit global or scoped default.

    Global scope includes all existing task events and has no condition. Scoped
    conditions retain schema1.1 syntax and require later authenticated fact
    evaluation. A parsed scope is not acceptance of a rule or a gate result.
    """

    scope_kind: RuleScopeKind
    condition: ConditionExpression | None
    events: tuple[str, ...]
    scope_digest: str

    schema_version: ClassVar[str] = RULE_SCOPE_SCHEMA_VERSION
    object_kind: ClassVar[str] = "rule-scope"

    @classmethod
    def build(
        cls,
        *,
        scope_kind: RuleScopeKind,
        condition: ConditionExpression | None,
        events: tuple[str, ...],
        budget: PolicyReadBudget1,
    ) -> RuleScope1:
        """Build the exact scope with an explicit, separate parser budget."""
        body = _body(scope_kind, condition, events, budget)
        result = cls(scope_kind, condition, events, canonical_digest(body))
        result.to_dict(budget=budget)
        return result

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Serialize after revalidating direct fields, nested syntax and integrity."""
        body = _body(self.scope_kind, self.condition, self.events, budget)
        digest = require_digest(self.scope_digest, "rule scope digest")
        if digest != canonical_digest(body):
            raise ValueError("rule scope digest differs")
        result = {**body, "scope_digest": digest}
        policy_wire_size(result, budget=budget)
        return result

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> RuleScope1:
        """Parse exact fields and original child syntax without fallback or sorting."""
        data = policy_record_mapping(
            value,
            fields=_FIELDS,
            object_kind="rule-scope",
            schema_version=RULE_SCOPE_SCHEMA_VERSION,
            budget=budget,
        )
        events = data["events"]
        if type(events) is not list:
            raise ValueError("rule scope events must be an array")
        if len(events) > len(TASK_CONTEXT_EVENTS):
            raise ValueError("rule scope contains too many events")
        raw_condition = data["condition"]
        result = cls(
            scope_kind=cast(RuleScopeKind, data["scope_kind"]),
            condition=(
                None
                if raw_condition is None
                else policy_condition_from_dict(raw_condition, budget=budget)
            ),
            events=cast(tuple[str, ...], tuple(events)),
            scope_digest=require_digest(data["scope_digest"], "rule scope digest"),
        )
        result.to_dict(budget=budget)
        return result
