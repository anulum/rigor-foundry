# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — partial condition evaluation tests
"""Exercise tri-state evaluation through real condition and observation APIs."""

from __future__ import annotations

from dataclasses import replace
from itertools import product
from typing import cast

import pytest

from rigor_foundry.condition_evaluation import MAX_CONDITION_FACTS, evaluate_condition_state
from rigor_foundry.condition_facts import ConditionFact, ConditionTruth
from rigor_foundry.condition_language import (
    ConditionExpression,
    ConditionOperator,
    ConditionValue,
)


def _boolean_fact(truth: ConditionTruth) -> ConditionFact:
    """Supply an actual Boolean observation or explicit missing knowledge."""
    if truth is ConditionTruth.UNKNOWN:
        return ConditionFact.unknown()
    return ConditionFact.known(truth is ConditionTruth.TRUE)


@pytest.mark.parametrize(("left", "right"), list(product(ConditionTruth, repeat=2)))
def test_every_all_any_truth_pair(left: ConditionTruth, right: ConditionTruth) -> None:
    """All nine input pairs retain decisive results and unresolved knowledge."""
    children = (
        ConditionExpression.build("eq", reference="left", value=True),
        ConditionExpression.build("eq", reference="right", value=True),
    )
    facts = {"left": _boolean_fact(left), "right": _boolean_fact(right)}
    expected_all = {
        ("true", "true"): "true",
        ("true", "false"): "false",
        ("true", "unknown"): "unknown",
        ("false", "true"): "false",
        ("false", "false"): "false",
        ("false", "unknown"): "false",
        ("unknown", "true"): "unknown",
        ("unknown", "false"): "false",
        ("unknown", "unknown"): "unknown",
    }
    expected_any = {
        ("true", "true"): "true",
        ("true", "false"): "true",
        ("true", "unknown"): "true",
        ("false", "true"): "true",
        ("false", "false"): "false",
        ("false", "unknown"): "unknown",
        ("unknown", "true"): "true",
        ("unknown", "false"): "unknown",
        ("unknown", "unknown"): "unknown",
    }
    assert (
        evaluate_condition_state(ConditionExpression.build("all", children=children), facts).value
        == expected_all[left.value, right.value]
    )
    assert (
        evaluate_condition_state(ConditionExpression.build("any", children=children), facts).value
        == expected_any[left.value, right.value]
    )


@pytest.mark.parametrize("truth", list(ConditionTruth))
def test_negation_preserves_unknown(truth: ConditionTruth) -> None:
    """Negation changes a known Boolean and retains unknown as unresolved."""
    expression = ConditionExpression.build(
        "not", children=(ConditionExpression.build("eq", reference="flag", value=True),)
    )
    expected = {"true": "false", "false": "true", "unknown": "unknown"}
    assert (
        evaluate_condition_state(expression, {"flag": _boolean_fact(truth)}).value
        == expected[truth.value]
    )


@pytest.mark.parametrize("operator", ["exists", "eq", "ne", "one-of", "gt"])
def test_known_null_absent_and_unobserved_are_distinct(operator: ConditionOperator) -> None:
    """Only authoritative absence has the old missing-leaf false semantics."""
    value: ConditionValue = (None,) if operator == "one-of" else None
    if operator == "gt":
        value = 0
    expression = ConditionExpression.build(operator, reference="subject", value=value)
    assert evaluate_condition_state(expression, {}) is ConditionTruth.UNKNOWN
    assert evaluate_condition_state(expression, {"subject": ConditionFact.unknown()}) is (
        ConditionTruth.UNKNOWN
    )
    assert evaluate_condition_state(expression, {"subject": ConditionFact.absent()}) is (
        ConditionTruth.FALSE
    )
    if operator == "gt":
        with pytest.raises(ValueError, match="numeric"):
            evaluate_condition_state(expression, {"subject": ConditionFact.known(None)})
    else:
        expected = ConditionTruth.FALSE if operator == "ne" else ConditionTruth.TRUE
        assert (
            evaluate_condition_state(expression, {"subject": ConditionFact.known(None)})
            is expected
        )


def test_nested_missing_reference_does_not_inherit_parent_absence() -> None:
    """A missing descendant remains unknown even if its parent has an absence record."""
    leaf = ConditionExpression.build("exists", reference="project.enabled")
    expression = ConditionExpression.build(
        "all",
        children=(ConditionExpression.build("not", children=(leaf,)),),
    )
    assert evaluate_condition_state(expression, {"project": ConditionFact.absent()}) is (
        ConditionTruth.UNKNOWN
    )
    assert (
        evaluate_condition_state(expression, {"project.enabled": ConditionFact.absent()})
        is ConditionTruth.TRUE
    )
    assert leaf.evaluate({}) is False
    assert ConditionExpression.build("not", children=(leaf,)).evaluate({}) is True


@pytest.mark.parametrize(
    ("operator", "actual", "expected"),
    [
        ("eq", 1, 1.0),
        ("eq", True, 1),
        ("ne", True, 1),
        ("lt", 2, 3),
        ("lt", 3, 2),
        ("lte", 3, 3),
        ("gt", 4, 3),
        ("gt", 2, 3),
        ("gte", 3, 3),
        ("contains", "project-source", "source"),
        ("contains", (True, 1, None), True),
        ("contains", (), True),
        ("one-of", 1, (False, 1.0)),
        ("eq", (1,), 1),
        ("ne", (1,), 1),
    ],
)
def test_known_leaves_preserve_original_boolean_results(
    operator: ConditionOperator, actual: ConditionValue, expected: ConditionValue
) -> None:
    """The new consumer reuses the actual schema1.1 leaf behavior and identities."""
    expression = ConditionExpression.build(operator, reference="project.value", value=expected)
    before = expression.to_dict()
    legacy = expression.evaluate({"project": {"value": actual}})
    result = evaluate_condition_state(expression, {"project.value": ConditionFact.known(actual)})
    assert result is (ConditionTruth.TRUE if legacy else ConditionTruth.FALSE)
    assert expression.to_dict() == before
    assert ConditionExpression.from_dict(before) == expression


@pytest.mark.parametrize(("group", "decisive"), [("all", False), ("any", True)])
def test_decisive_siblings_cannot_hide_invalid_known_operands(
    group: ConditionOperator, decisive: bool
) -> None:
    """Every child is validated even where Boolean short-circuiting would skip it."""
    expression = ConditionExpression.build(
        group,
        children=(
            ConditionExpression.build("eq", reference="flag", value=True),
            ConditionExpression.build("gt", reference="count", value=0),
        ),
    )
    with pytest.raises(ValueError, match="numeric"):
        evaluate_condition_state(
            expression,
            {"flag": ConditionFact.known(decisive), "count": ConditionFact.known("bad")},
        )


def test_an_invalid_contains_domain_refuses_instead_of_returning_false() -> None:
    """An observed scalar number cannot stand in for a string or scalar array."""
    expression = ConditionExpression.build("contains", reference="value", value="item")
    with pytest.raises(ValueError, match="string or array"):
        evaluate_condition_state(expression, {"value": ConditionFact.known(5)})


@pytest.mark.parametrize("reference", ["Bad.Ref", "a..b", "", "a[0]"])
def test_all_supplied_references_are_validated(reference: str) -> None:
    """An unused malformed reference cannot bypass the input contract."""
    expression = ConditionExpression.build("exists", reference="valid")
    with pytest.raises(ValueError):
        evaluate_condition_state(expression, {reference: ConditionFact.unknown()})


@pytest.mark.parametrize("parent", [ConditionFact.known(None), ConditionFact.absent()])
def test_contradictory_parent_and_child_observations_refuse(parent: ConditionFact) -> None:
    """A known descendant cannot contradict an observed scalar or absent parent."""
    expression = ConditionExpression.build("exists", reference="project.name")
    with pytest.raises(ValueError, match="contradict"):
        evaluate_condition_state(
            expression,
            {"project": parent, "project.name": ConditionFact.known("value")},
        )


@pytest.mark.parametrize(
    "parent", [ConditionFact.known(None), ConditionFact.absent(), ConditionFact.unknown()]
)
@pytest.mark.parametrize("child", [ConditionFact.absent(), ConditionFact.unknown()])
def test_noncontradictory_prefix_observations_preserve_exact_lookup(
    parent: ConditionFact, child: ConditionFact
) -> None:
    """An observed parent does not invent a value or absence for a descendant."""
    expression = ConditionExpression.build("exists", reference="project.name")
    expected = ConditionTruth.FALSE if child.state == "absent" else ConditionTruth.UNKNOWN
    assert (
        evaluate_condition_state(expression, {"project": parent, "project.name": child})
        is expected
    )


def test_an_unobserved_parent_does_not_reject_a_known_descendant() -> None:
    """Unknown is not evidence of a conflicting producer or parent value."""
    expression = ConditionExpression.build("exists", reference="project.name")
    assert (
        evaluate_condition_state(
            expression,
            {"project": ConditionFact.unknown(), "project.name": ConditionFact.known("value")},
        )
        is ConditionTruth.TRUE
    )


def test_raw_mappings_do_not_masquerade_as_observation_objects() -> None:
    """Every value, including unused ones, has the actual public observation contract."""
    expression = ConditionExpression.build("exists", reference="valid")
    with pytest.raises(ValueError, match="ConditionFact"):
        evaluate_condition_state(
            expression, {"unused": cast(ConditionFact, {"state": "known", "value": True})}
        )


def test_the_observation_budget_accepts_its_boundary_and_refuses_an_overflow() -> None:
    """Actual bounded dictionaries exercise both sides of the resource ceiling."""
    facts = {f"fact{index}": ConditionFact.unknown() for index in range(MAX_CONDITION_FACTS)}
    expression = ConditionExpression.build("exists", reference="fact0")
    assert evaluate_condition_state(expression, facts) is ConditionTruth.UNKNOWN
    facts["overflow"] = ConditionFact.unknown()
    with pytest.raises(ValueError, match="observation budget"):
        evaluate_condition_state(expression, facts)


def test_direct_expression_digest_and_object_shape_are_revalidated() -> None:
    """Public direct construction cannot bypass grammar or integrity checking."""
    expression = ConditionExpression.build("exists", reference="flag")
    with pytest.raises(ValueError, match="digest"):
        evaluate_condition_state(replace(expression, expression_digest="0" * 64), {})
    with pytest.raises(ValueError, match="immutable expression"):
        evaluate_condition_state(cast(ConditionExpression, None), {})
    invalid_children = replace(expression, children=cast(tuple[ConditionExpression, ...], []))
    with pytest.raises(ValueError, match="immutable expression"):
        evaluate_condition_state(invalid_children, {})


def test_direct_oversized_numeric_literals_have_a_typed_refusal() -> None:
    """A valid JSON integer outside the numeric domain cannot escape as OverflowError."""
    expression = ConditionExpression.build("eq", reference="count", value=1)
    oversized = replace(expression, value=10**400)
    with pytest.raises(ValueError, match="finite numeric domain"):
        evaluate_condition_state(oversized, {})


def test_direct_oversized_and_deep_trees_are_bounded_before_serialization() -> None:
    """Hostile direct trees cannot recurse unboundedly before the wire parser runs."""
    leaf = ConditionExpression.build("exists", reference="flag")
    oversized = replace(leaf, children=(leaf,) * 65)
    with pytest.raises(ValueError, match="bounded tree"):
        evaluate_condition_state(oversized, {})
    deep = leaf
    for _ in range(8):
        deep = replace(deep, children=(deep,))
    with pytest.raises(ValueError, match="bounded tree"):
        evaluate_condition_state(deep, {})
