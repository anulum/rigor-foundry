# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — explicit rule scope tests
"""Exercise original condition evaluation and closed rule scopes through public APIs."""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.condition_evaluation import evaluate_condition_state
from rigor_foundry.condition_facts import ConditionFact, ConditionTruth
from rigor_foundry.condition_language import ConditionExpression
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.rule_scope import RuleScope1, RuleScopeKind
from rigor_foundry.task_context import TASK_CONTEXT_EVENTS


def budget() -> PolicyReadBudget1:
    """Supply explicit parser ceilings, separate from rule or event authority."""
    return PolicyReadBudget1.build(
        max_document_bytes=8192,
        max_source_bytes=8192,
        max_total_source_bytes=16384,
        max_sources=8,
        max_rules=16,
        max_references=64,
        max_depth=32,
    )


def scoped() -> RuleScope1:
    """Build a real original schema1.1 expression with an explicit event subset."""
    return RuleScope1.build(
        scope_kind="scoped",
        condition=ConditionExpression.build("eq", reference="inventory.language", value="python"),
        events=("commit", "verification"),
        budget=budget(),
    )


def test_global_scope_retains_every_original_task_event_without_a_condition() -> None:
    """Global scope cannot omit claim, mutation, audit or any other declared event."""
    events = tuple(sorted(TASK_CONTEXT_EVENTS))
    value = RuleScope1.build(scope_kind="global", condition=None, events=events, budget=budget())
    data = value.to_dict(budget=budget())
    assert RuleScope1.from_dict(data, budget=budget()) == value
    assert data["events"] == sorted(TASK_CONTEXT_EVENTS)
    assert data["condition"] is None
    assert data.pop("scope_digest") == canonical_digest(data)


def test_scoped_round_trip_uses_the_original_explicit_tristate_evaluator() -> None:
    """Parsing retains original syntax without converting unknown observations to false."""
    value = scoped()
    data = value.to_dict(budget=budget())
    parsed = RuleScope1.from_dict(data, budget=budget())
    assert parsed == value
    assert parsed.condition is not None
    assert data["condition"] == parsed.condition.to_dict()
    assert evaluate_condition_state(parsed.condition, {}) is ConditionTruth.UNKNOWN
    assert (
        evaluate_condition_state(
            parsed.condition, {"inventory.language": ConditionFact("known", "python")}
        )
        is ConditionTruth.TRUE
    )
    assert (
        evaluate_condition_state(
            parsed.condition, {"inventory.language": ConditionFact("known", "rust")}
        )
        is ConditionTruth.FALSE
    )
    assert data.pop("scope_digest") == canonical_digest(data)


@pytest.mark.parametrize(
    "events",
    [
        (),
        ("commit", "commit"),
        ("verification", "commit"),
        ("unknown",),
        (True,),
        ("commit",) * 13,
        ["commit"],
    ],
)
def test_event_set_is_exact_nonempty_sorted_unique_and_bounded(events: object) -> None:
    """No omitted default, coercion, duplicate, unknown or silent reordering is accepted."""
    with pytest.raises(ValueError):
        RuleScope1.build(
            scope_kind="scoped",
            condition=scoped().condition,
            events=cast(tuple[str, ...], events),
            budget=budget(),
        )


@pytest.mark.parametrize("kind", ["other", "", 1, None, []])
def test_scope_kind_does_not_accept_lookalikes(kind: object) -> None:
    """Unsupported kinds refuse before selecting a condition interpretation."""
    with pytest.raises(ValueError, match="scope kind"):
        RuleScope1.build(
            scope_kind=cast(RuleScopeKind, kind),
            condition=None,
            events=("commit",),
            budget=budget(),
        )


def test_global_cannot_narrow_events_or_attach_a_fact_condition() -> None:
    """A false fact cannot turn a global floor into a selective scope."""
    for events, condition in [
        (("commit",), None),
        (tuple(sorted(TASK_CONTEXT_EVENTS)), scoped().condition),
    ]:
        with pytest.raises(ValueError, match="global rule scope"):
            RuleScope1.build(
                scope_kind="global", condition=condition, events=events, budget=budget()
            )
    with pytest.raises(ValueError, match="exact immutable"):
        RuleScope1.build(scope_kind="scoped", condition=None, events=("commit",), budget=budget())


def test_direct_values_and_late_mutation_are_rechecked_at_the_serialization_boundary() -> None:
    """The public consumer validates direct dataclasses as rigorously as parsed records."""
    with pytest.raises(ValueError, match="digest"):
        replace(scoped(), scope_digest="0" * 64).to_dict(budget=budget())
    with pytest.raises(ValueError):
        replace(scoped(), scope_digest="bad").to_dict(budget=budget())
    value = scoped()
    assert value.condition is not None
    object.__setattr__(value.condition, "expression_digest", "0" * 64)
    with pytest.raises(ValueError, match="digest"):
        value.to_dict(budget=budget())


def test_closed_wire_refuses_unknown_missing_headers_and_malformed_children() -> None:
    """Rehashing malformed input cannot manufacture supported identity or original syntax."""
    data = scoped().to_dict(budget=budget())
    for name, invalid in [
        ("schema_version", "0.9"),
        ("object_kind", "other"),
        ("events", "commit"),
        ("events", ["commit"] * 13),
        ("condition", {}),
        ("scope_digest", "0" * 64),
    ]:
        with pytest.raises(ValueError):
            RuleScope1.from_dict({**data, name: invalid}, budget=budget())
    for malformed in [
        None,
        {**data, "extra": None},
        {k: v for k, v in data.items() if k != "condition"},
    ]:
        with pytest.raises(ValueError):
            RuleScope1.from_dict(malformed, budget=budget())
