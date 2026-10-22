# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — partial-observation condition evaluation
"""Evaluate existing condition syntax with explicit unknown propagation."""

from __future__ import annotations

from collections.abc import Mapping

from .condition_facts import ConditionFact, ConditionTruth
from .condition_language import MAX_CONDITION_DEPTH, MAX_CONDITION_NODES, ConditionExpression

MAX_CONDITION_FACTS = 65_536


def _validated_expression(expression: ConditionExpression) -> ConditionExpression:
    """Check direct trees within the existing grammar budgets before serialization."""
    pending = [(expression, 1)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > MAX_CONDITION_NODES or depth > MAX_CONDITION_DEPTH:
            raise ValueError("condition exceeds the bounded tree budget")
        if type(node) is not ConditionExpression or type(node.children) is not tuple:
            raise ValueError("condition requires an exact immutable expression tree")
        pending.extend((child, depth + 1) for child in node.children)
    try:
        return ConditionExpression.from_dict(expression.to_dict())
    except OverflowError as exc:
        raise ValueError("condition literal exceeds the finite numeric domain") from exc


def _checked_facts(facts: Mapping[str, ConditionFact]) -> dict[str, ConditionFact]:
    """Snapshot and validate each supplied fact without deriving additional absence."""
    if len(facts) > MAX_CONDITION_FACTS:
        raise ValueError("condition facts exceed the bounded observation budget")
    checked: dict[str, ConditionFact] = {}
    for reference, fact in facts.items():
        ConditionExpression.build("exists", reference=reference)
        if type(fact) is not ConditionFact:
            raise ValueError("condition observations must be ConditionFact values")
        checked[reference] = ConditionFact(fact.state, fact.value)
    for reference, fact in checked.items():
        if fact.state != "known":
            continue
        segments = reference.split(".")
        for index in range(1, len(segments)):
            parent = checked.get(".".join(segments[:index]))
            if parent is not None and parent.state != "unknown":
                raise ValueError("condition fact references contradict an observed parent")
    return checked


def _known_leaf(expression: ConditionExpression, fact: ConditionFact) -> ConditionTruth:
    """Reuse the original Boolean leaf evaluator only for an actual known value."""
    segments = expression.reference.split(".")
    context: dict[str, object] = {segments[-1]: fact.value}
    for segment in reversed(segments[:-1]):
        context = {segment: context}
    return ConditionTruth.TRUE if expression.evaluate(context) else ConditionTruth.FALSE


def _evaluate(
    expression: ConditionExpression,
    facts: Mapping[str, ConditionFact],
) -> ConditionTruth:
    """Fold every child so invalid known operands cannot hide behind a sibling."""
    if expression.operator in {"all", "any"}:
        results = tuple(_evaluate(child, facts) for child in expression.children)
        decisive = ConditionTruth.FALSE if expression.operator == "all" else ConditionTruth.TRUE
        if decisive in results:
            return decisive
        if ConditionTruth.UNKNOWN in results:
            return ConditionTruth.UNKNOWN
        return ConditionTruth.TRUE if expression.operator == "all" else ConditionTruth.FALSE
    if expression.operator == "not":
        return {
            ConditionTruth.TRUE: ConditionTruth.FALSE,
            ConditionTruth.FALSE: ConditionTruth.TRUE,
            ConditionTruth.UNKNOWN: ConditionTruth.UNKNOWN,
        }[_evaluate(expression.children[0], facts)]
    fact = facts.get(expression.reference)
    if fact is None or fact.state == "unknown":
        return ConditionTruth.UNKNOWN
    if fact.state == "absent":
        return ConditionTruth.FALSE
    return _known_leaf(expression, fact)


def evaluate_condition_state(
    expression: ConditionExpression,
    facts: Mapping[str, ConditionFact],
) -> ConditionTruth:
    """Evaluate a bounded condition over supplied known, absent and unknown facts.

    Parameters
    ----------
    expression : ConditionExpression
        Existing schema-1.1 condition, revalidated before evaluation.
        Its original Boolean evaluate method and digest are unchanged.
    facts : Mapping[str, ConditionFact]
        Exact dotted references and inert observations. Missing references
        remain unknown. This pure function does not authenticate provenance.

    Returns
    -------
    ConditionTruth
        True, false or unknown under the three-valued all/any/not tables.
        Callers must compare a state explicitly; Boolean conversion refuses.

    Raises
    ------
    ValueError
        The tree, fact reference, state, value, budget or known operand domain
        is invalid. Every known leaf is checked, including decisive groups.

    Notes
    -----
    An installed policy consumer must independently authenticate fact producers,
    source completeness, maintained scope and its held selected context before
    using this calculation. The result grants no permission or gate acceptance.
    """
    parsed = _validated_expression(expression)
    checked = _checked_facts(facts)
    return _evaluate(parsed, checked)
