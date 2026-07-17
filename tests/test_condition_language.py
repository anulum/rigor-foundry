# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — condition-language tests
"""Verify the bounded declarative condition language without execution hooks."""

from __future__ import annotations

from copy import deepcopy

import pytest

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.condition_language import ConditionExpression


def test_all_operators_evaluate_over_inert_mapping_data() -> None:
    """Every supported operator has deterministic mapping-only semantics."""
    context: dict[str, object] = {
        "project": {
            "name": "rigor-foundry",
            "level": 3,
            "tags": ["python", "audit"],
        }
    }
    expressions = (
        ConditionExpression.build("exists", reference="project.name"),
        ConditionExpression.build("eq", reference="project.level", value=3),
        ConditionExpression.build("ne", reference="project.name", value="other"),
        ConditionExpression.build("lt", reference="project.level", value=4),
        ConditionExpression.build("lte", reference="project.level", value=3),
        ConditionExpression.build("gt", reference="project.level", value=2),
        ConditionExpression.build("gte", reference="project.level", value=3),
        ConditionExpression.build("contains", reference="project.name", value="foundry"),
        ConditionExpression.build("contains", reference="project.tags", value="audit"),
        ConditionExpression.build("one-of", reference="project.level", value=(2, 3, 4)),
    )
    assert all(expression.evaluate(context) for expression in expressions)
    assert not ConditionExpression.build("exists", reference="project.missing").evaluate(context)
    assert not ConditionExpression.build("eq", reference="project.missing", value=1).evaluate(
        context
    )


def test_nested_tree_round_trips_and_reports_references() -> None:
    """Nested all/any/not trees preserve their digest and referenced paths."""
    name = ConditionExpression.build("eq", reference="project.name", value="rigor")
    risky = ConditionExpression.build("gte", reference="project.risk", value=3)
    missing = ConditionExpression.build("exists", reference="project.blocked")
    expression = ConditionExpression.build(
        "all",
        children=(
            name,
            ConditionExpression.build(
                "any",
                children=(risky, ConditionExpression.build("not", children=(missing,))),
            ),
        ),
    )
    assert expression.evaluate({"project": {"name": "rigor", "risk": 4}})
    assert expression.evaluate({"project": {"name": "rigor", "risk": 0}})
    assert expression.references == {"project.name", "project.risk", "project.blocked"}
    assert ConditionExpression.from_dict(expression.to_dict()) == expression

    tampered = deepcopy(expression.to_dict())
    tampered["expression_digest"] = "0" * 64
    with pytest.raises(ValueError, match="digest"):
        ConditionExpression.from_dict(tampered)
    unsupported = deepcopy(expression.to_dict())
    unsupported["schema_version"] = "9.0"
    with pytest.raises(ValueError, match="schema"):
        ConditionExpression.from_dict(unsupported)


@pytest.mark.parametrize(
    ("operator", "kwargs"),
    [
        ("exists", {"reference": "Bad.Ref"}),
        ("exists", {"reference": "project.name", "value": True}),
        ("eq", {"reference": "project.name", "value": ("x",)}),
        ("one-of", {"reference": "project.name", "value": ()}),
        ("all", {"children": ()}),
        ("not", {"children": ()}),
    ],
)
def test_invalid_shapes_are_rejected(operator: str, kwargs: dict[str, object]) -> None:
    """Operators reject executable references, ambiguous values, and invalid arity."""
    with pytest.raises(ValueError):
        ConditionExpression.build(operator, **kwargs)


def test_depth_budget_and_context_types_fail_closed() -> None:
    """Over-deep trees and invalid ordered/contains inputs fail closed."""
    expression = ConditionExpression.build("exists", reference="project.enabled")
    for _ in range(7):
        expression = ConditionExpression.build("not", children=(expression,))
    with pytest.raises(ValueError, match="bounded tree budget"):
        ConditionExpression.build("not", children=(expression,))
    with pytest.raises(ValueError, match="numeric"):
        ConditionExpression.build("gt", reference="project.name", value=1).evaluate(
            {"project": {"name": "rigor"}}
        )
    with pytest.raises(ValueError, match="string or array"):
        ConditionExpression.build("contains", reference="project.count", value=1).evaluate(
            {"project": {"count": 5}}
        )


def test_parser_and_remaining_shape_branches_fail_closed() -> None:
    """Malformed serialized shapes, duplicate sets, and unsupported operators are rejected."""
    leaf = ConditionExpression.build("exists", reference="project.enabled")
    with pytest.raises(ValueError, match="unique"):
        ConditionExpression.build("one-of", reference="project.level", value=(1, 1))
    with pytest.raises(ValueError, match="children only"):
        ConditionExpression.build("all", reference="project.enabled", children=(leaf,))
    with pytest.raises(ValueError, match="exactly one"):
        ConditionExpression.build("not", reference="project.enabled", children=(leaf,))
    with pytest.raises(ValueError, match="unsupported"):
        ConditionExpression.build("execute")

    overdeep_child = leaf
    for _ in range(7):
        overdeep_child = ConditionExpression.build("not", children=(overdeep_child,))
    overdeep_body: dict[str, object] = {
        "schema_version": "1.0",
        "op": "not",
        "ref": "",
        "value": None,
        "children": [overdeep_child.to_dict()],
    }
    overdeep_body["expression_digest"] = canonical_digest(overdeep_body)
    with pytest.raises(ValueError, match="bounded tree budget"):
        ConditionExpression.from_dict(overdeep_body)

    malformed = leaf.to_dict()
    malformed["op"] = "execute"
    with pytest.raises(ValueError, match="unsupported"):
        ConditionExpression.from_dict(malformed)
    malformed = leaf.to_dict()
    malformed["children"] = "none"
    with pytest.raises(ValueError, match="array"):
        ConditionExpression.from_dict(malformed)
    one_of = ConditionExpression.build("one-of", reference="project.level", value=(1, 2))
    malformed = one_of.to_dict()
    malformed["value"] = 1
    with pytest.raises(ValueError, match="array"):
        ConditionExpression.from_dict(malformed)
    malformed = leaf.to_dict()
    malformed["unexpected"] = True
    with pytest.raises(ValueError, match="fields"):
        ConditionExpression.from_dict(malformed)


def test_boolean_and_numeric_condition_values_are_not_aliases() -> None:
    """JSON booleans remain distinct from numerically equal integers."""
    assert not ConditionExpression.build("eq", reference="value", value=1).evaluate(
        {"value": True}
    )
    assert ConditionExpression.build("ne", reference="value", value=1).evaluate({"value": True})
    assert not ConditionExpression.build("one-of", reference="value", value=(1,)).evaluate(
        {"value": True}
    )
    assert not ConditionExpression.build("contains", reference="values", value=1).evaluate(
        {"values": [True]}
    )
    expression = ConditionExpression.build("one-of", reference="value", value=(True, 1))
    assert expression.evaluate({"value": True})
    assert expression.evaluate({"value": 1})
    assert ConditionExpression.from_dict(expression.to_dict()) == expression
    assert not ConditionExpression.build("eq", reference="value", value=1).evaluate({"value": [1]})
