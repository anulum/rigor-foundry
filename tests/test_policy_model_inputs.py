# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — policy input allocation boundary tests
"""Exercise public input validation with exact canonical bytes and original syntax."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import replace
from typing import cast

import pytest

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.condition_language import ConditionExpression
from rigor_foundry.policy_model_inputs import (
    checked_policy_budget,
    checked_policy_condition,
    policy_condition_from_dict,
    policy_identifiers,
    policy_owner_proof,
    policy_record_mapping,
    policy_source_spans,
    policy_wire_size,
)
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_spans import SourceSpan1


def test_original_owner_proof_metadata_is_bounded_without_source_authentication() -> None:
    """The actual original envelope and both references are rechecked before a new consumer uses them."""
    from test_context_owner_proof import proof

    original = proof()
    assert policy_owner_proof(original, budget=budget()) == original
    with pytest.raises(ValueError, match="actual original owner proof"):
        policy_owner_proof({}, budget=budget())
    with pytest.raises(ValueError, match="reference budget"):
        policy_owner_proof(original, budget=budget(references=1))
    object.__setattr__(original, "proof_digest", "0" * 64)
    with pytest.raises(ValueError, match="owner proof digest"):
        policy_owner_proof(original, budget=budget())


def budget(*, size: int = 8192, depth: int = 32, references: int = 128) -> PolicyReadBudget1:
    """Keep every allocation dimension explicit at the public boundary."""
    return PolicyReadBudget1.build(
        max_document_bytes=size,
        max_source_bytes=8192,
        max_total_source_bytes=16384,
        max_sources=16,
        max_rules=32,
        max_references=references,
        max_depth=depth,
    )


@pytest.mark.parametrize(
    "value",
    [None, True, False, 0, -1, 1.25, "", 'ž\n"\\', [], {}, [1, ["x"]], {"z": [None], "a": {}}],
)
def test_byte_count_matches_the_original_canonical_encoding(value: object) -> None:
    """Bounded validation counts UTF8, escapes, separators and nested data exactly."""
    encoded = json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    assert policy_wire_size(value, budget=budget(size=len(encoded))) == len(encoded)
    if len(encoded) > 1:
        with pytest.raises(ValueError, match="byte budget"):
            policy_wire_size(value, budget=budget(size=len(encoded) - 1))


@pytest.mark.parametrize(
    "value", [(1,), {1: "x"}, {"x"}, b"x", object(), float("nan"), float("inf"), "\ud800"]
)
def test_custom_nonjson_and_nonfinite_values_refuse(value: object) -> None:
    """No custom scalar/container, nonfinite number or invalid UTF8 crosses the reader."""
    with pytest.raises(ValueError):
        policy_wire_size(value, budget=budget())


def test_cyclic_and_excessively_nested_wire_refuses_within_explicit_depth() -> None:
    """A cycle cannot recurse to Python's stack limit or bypass a smaller budget."""
    cycle: list[object] = []
    cycle.append(cycle)
    with pytest.raises(ValueError, match="depth budget"):
        policy_wire_size(cycle, budget=budget(depth=4))
    assert policy_wire_size({"x": [None]}, budget=budget(depth=2)) == 12
    with pytest.raises(ValueError, match="depth budget"):
        policy_wire_size({"x": [None]}, budget=budget(depth=1))


def test_budget_snapshot_requires_the_actual_revalidated_record() -> None:
    """A same-shaped dictionary or mutated immutable budget carries no valid limits."""
    limits = budget()
    assert checked_policy_budget(limits) == limits
    assert checked_policy_budget(limits) is not limits
    with pytest.raises(ValueError, match="exact policy read budget"):
        checked_policy_budget(cast(PolicyReadBudget1, limits.to_dict()))
    object.__setattr__(limits, "max_depth", 0)
    with pytest.raises(ValueError):
        policy_wire_size({}, budget=limits)


def test_record_identity_fields_and_budget_are_checked_before_children() -> None:
    """No extra, missing, version-fallback or unrelated kind is interpreted."""
    data: dict[str, object] = {"schema_version": "1.0", "object_kind": "example", "body": []}
    fields = frozenset(data)
    assert (
        policy_record_mapping(
            data, fields=fields, object_kind="example", schema_version="1.0", budget=budget()
        )
        == data
    )
    for invalid in [
        None,
        {**data, "extra": False},
        {key: value for key, value in data.items() if key != "body"},
        {**data, "schema_version": "1"},
        {**data, "object_kind": "other"},
    ]:
        with pytest.raises(ValueError):
            policy_record_mapping(
                invalid,
                fields=fields,
                object_kind="example",
                schema_version="1.0",
                budget=budget(),
            )


def test_original_condition_is_revalidated_without_changing_its_identity() -> None:
    """Existing condition1.1 bytes and references survive the new input boundary."""
    expression = ConditionExpression.build(
        "all",
        children=(
            ConditionExpression.build("exists", reference="project.id"),
            ConditionExpression.build("eq", reference="inventory.language", value="python"),
        ),
    )
    result = checked_policy_condition(expression, budget=budget())
    assert result == expression
    assert result.to_dict() == expression.to_dict()
    with pytest.raises(ValueError, match="reference budget"):
        checked_policy_condition(expression, budget=budget(references=1))
    with pytest.raises(ValueError, match="byte budget"):
        checked_policy_condition(expression, budget=budget(size=100))


def test_invalid_direct_condition_shape_and_digest_refuse() -> None:
    """Direct construction and late frozen-field mutation never bypass the original parser."""
    leaf = ConditionExpression.build("exists", reference="project.id")
    invalid = replace(leaf, expression_digest="0" * 64)
    with pytest.raises(ValueError, match="digest"):
        checked_policy_condition(invalid, budget=budget())
    with pytest.raises(ValueError, match="exact immutable"):
        checked_policy_condition(None, budget=budget())
    invalid = replace(leaf)
    object.__setattr__(invalid, "children", [])
    with pytest.raises(ValueError, match="exact immutable"):
        checked_policy_condition(invalid, budget=budget())
    wide = ConditionExpression("all", "", None, (leaf,) * 64, "0" * 64)
    with pytest.raises(ValueError, match="node budget"):
        checked_policy_condition(wide, budget=budget())


def test_original_depth_node_and_explicit_parser_depth_limits_all_apply() -> None:
    """Wide or deep direct trees are bounded before their recursive serialization."""
    leaf = ConditionExpression.build("exists", reference="project.id")
    group = ConditionExpression.build("all", children=(leaf,) * 16)
    wide = ConditionExpression("all", "", None, (group,) * 4, "0" * 64)
    with pytest.raises(ValueError, match="node budget"):
        checked_policy_condition(wide, budget=budget())
    deep = leaf
    for _ in range(8):
        deep = ConditionExpression("not", "", None, (deep,), "0" * 64)
    with pytest.raises(ValueError, match="tree budget"):
        checked_policy_condition(deep, budget=budget())
    pair = ConditionExpression.build("not", children=(leaf,))
    with pytest.raises(ValueError, match="tree budget"):
        checked_policy_condition(pair, budget=budget(depth=1))
    assert canonical_digest(leaf.to_dict()) != leaf.expression_digest


def test_large_text_refuses_before_allocating_its_escaped_representation() -> None:
    """A short explicit budget rejects oversized scalar text before JSON escaping."""
    with pytest.raises(ValueError, match="byte budget"):
        policy_wire_size("\n" * 10000, budget=budget(size=32))


def test_sorted_identity_sets_refuse_mutability_reordering_and_invalid_members() -> None:
    """Opaque IDs remain sorted unique metadata and are never interpreted as paths."""
    assert policy_identifiers((), budget=budget()) == ()
    assert policy_identifiers(("a", "b"), budget=budget()) == ("a", "b")
    for invalid in [("b", "a"), ("a", "a"), ("bad identity",), ["a"], (True,)]:
        with pytest.raises(ValueError):
            policy_identifiers(invalid, budget=budget())
    with pytest.raises(ValueError, match="reference budget"):
        policy_identifiers(("a", "b"), budget=budget(references=1))


def test_original_spans_keep_source_order_and_require_bounded_unique_real_records() -> None:
    """Span metadata is revalidated without sorting or claiming retained-byte observation."""
    payload = b"first second"
    first = SourceSpan1.build(
        span_id="z", source_id="one", start_byte=0, end_byte=5, payload=payload
    )
    second = SourceSpan1.build(
        span_id="a", source_id="two", start_byte=6, end_byte=12, payload=payload
    )
    assert policy_source_spans((first, second), budget=budget()) == (first, second)
    for invalid in [(), [first], (first, first), ({},)]:
        with pytest.raises(ValueError):
            policy_source_spans(invalid, budget=budget())
    with pytest.raises(ValueError, match="immutable tuple"):
        policy_source_spans((first, second), budget=budget(references=1))
    limits = budget().to_dict()
    limits.pop("budget_digest")
    limits["max_sources"] = 1
    with pytest.raises(ValueError, match="source budget"):
        policy_source_spans(
            (first, second),
            budget=PolicyReadBudget1.from_dict(
                {**limits, "budget_digest": canonical_digest(limits)}
            ),
        )
    object.__setattr__(first, "byte_digest", "0" * 64)
    with pytest.raises(ValueError, match="digest"):
        policy_source_spans((first,), budget=budget())


def test_original_one_of_literals_keep_their_exact_sequence_and_parser_limits() -> None:
    """Tuple literals are validated before the original serializer allocates their JSON array."""
    expression = ConditionExpression.build("one-of", reference="project.id", value=("a", "b"))
    assert checked_policy_condition(expression, budget=budget()) == expression
    with pytest.raises(ValueError, match="literals exceed"):
        checked_policy_condition(expression, budget=budget(references=1))


def test_original_finite_numeric_domain_refuses_overflow_at_both_input_boundaries() -> None:
    """A finite JSON integer outside the original numeric domain yields bounded ValueError."""
    expression = ConditionExpression.build("eq", reference="project.id", value=1)
    invalid = replace(expression, value=10**400)
    with pytest.raises(ValueError, match="finite numeric domain"):
        checked_policy_condition(invalid, budget=budget())
    with pytest.raises(ValueError, match="finite numeric domain"):
        policy_condition_from_dict(invalid.to_dict(), budget=budget())
    assert policy_condition_from_dict(expression.to_dict(), budget=budget()) == expression


class ExecutableTuple(tuple[int, ...]):
    """Represent a hostile tuple subclass whose iteration would execute caller code."""

    def __iter__(self) -> Iterator[int]:
        """Prove the sentinel would run if a consumer invoked its iterator."""
        raise RuntimeError("caller iterator executed")


def test_custom_condition_literal_is_refused_before_its_iterator_can_execute() -> None:
    """Original recursive serialization receives only exact inert tuple/scalar types."""
    hostile = ExecutableTuple((1, 2))
    with pytest.raises(RuntimeError, match="caller iterator executed"):
        tuple(hostile)
    expression = ConditionExpression("one-of", "project.id", hostile, (), "0" * 64)
    with pytest.raises(ValueError, match="inert JSON"):
        checked_policy_condition(expression, budget=budget())
