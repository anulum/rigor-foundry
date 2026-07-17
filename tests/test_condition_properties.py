# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — condition-language property assurance
"""Exercise condition identities and evaluation through the public API."""

from __future__ import annotations

from hypothesis import given, settings
from property_strategies import CONDITIONS, JSON_SCALARS, REFERENCES

from rigor_foundry.condition_language import ConditionExpression

_PROPERTY_SETTINGS = settings(max_examples=100, deadline=None)


@_PROPERTY_SETTINGS
@given(CONDITIONS)
def test_condition_round_trip_preserves_identity(expression: ConditionExpression) -> None:
    """Every generated valid tree survives strict serialization unchanged."""
    assert ConditionExpression.from_dict(expression.to_dict()) == expression


@_PROPERTY_SETTINGS
@given(expression=CONDITIONS, st_context=JSON_SCALARS)
def test_double_negation_preserves_evaluation(
    expression: ConditionExpression,
    st_context: object,
) -> None:
    """Double negation preserves evaluation for arbitrary inert context data."""
    context = {reference.split(".")[0]: st_context for reference in expression.references}
    expected = expression.evaluate(context)
    negated = ConditionExpression.build(
        "not",
        children=(ConditionExpression.build("not", children=(expression,)),),
    )
    assert negated.evaluate(context) is expected


@_PROPERTY_SETTINGS
@given(REFERENCES, JSON_SCALARS)
def test_scalar_equality_is_reflexive(reference: str, value: object) -> None:
    """A JSON scalar equals itself through a generated public reference."""
    expression = ConditionExpression.build("eq", reference=reference, value=value)
    context: dict[str, object] = {}
    cursor = context
    parts = reference.split(".")
    for part in parts[:-1]:
        child: dict[str, object] = {}
        cursor[part] = child
        cursor = child
    cursor[parts[-1]] = value
    assert expression.evaluate(context)


def test_boolean_integer_alias_regression_is_minimal_and_retained() -> None:
    """The shrunk bool/int counterexample remains a permanent semantic regression."""
    expression = ConditionExpression.build("eq", reference="value", value=1)
    assert not expression.evaluate({"value": True})
