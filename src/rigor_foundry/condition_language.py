# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — bounded policy condition language
"""Evaluate a small, side-effect-free condition tree without code execution."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, TypeAlias, cast

from .model_primitives import JsonScalar, require_digest, require_json_scalar
from .models import canonical_digest, require_mapping, require_string

ConditionOperator = Literal[
    "exists",
    "eq",
    "ne",
    "lt",
    "lte",
    "gt",
    "gte",
    "contains",
    "one-of",
    "all",
    "any",
    "not",
]
ConditionValue: TypeAlias = JsonScalar | tuple[JsonScalar, ...]

MAX_CONDITION_DEPTH = 8
MAX_CONDITION_NODES = 64
MAX_GROUP_CHILDREN = 16

_REFERENCE = re.compile(r"[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*){0,15}\Z")
_COMPARISONS = frozenset({"eq", "ne", "lt", "lte", "gt", "gte", "contains"})
_GROUPS = frozenset({"all", "any"})
_SERIALISED_FIELDS = frozenset(
    {"schema_version", "op", "ref", "value", "children", "expression_digest"}
)
_MISSING = object()


def _reference(value: object) -> str:
    """Return one bounded dotted context reference."""
    text = require_string(value, "condition.ref")
    if _REFERENCE.fullmatch(text) is None:
        raise ValueError("condition.ref must be a bounded dotted identifier")
    return text


def _serialise_value(value: ConditionValue) -> object:
    """Return a JSON-compatible condition value."""
    return list(value) if isinstance(value, tuple) else value


def _numeric(value: object, field: str) -> int | float:
    """Return one finite non-boolean number for ordered comparisons."""
    scalar = require_json_scalar(value, field)
    if isinstance(scalar, bool) or not isinstance(scalar, (int, float)):
        raise ValueError(f"{field} must be numeric for ordered comparison")
    return scalar


def _scalar_identity(value: JsonScalar) -> tuple[type[object], JsonScalar]:
    """Return a JSON-scalar identity that keeps booleans distinct from numbers."""
    numeric_type: type[object] = float if isinstance(value, (int, float)) else type(value)
    if isinstance(value, bool):
        numeric_type = bool
    return numeric_type, value


def _scalar_equal(left: object, right: JsonScalar) -> bool:
    """Compare JSON scalars without Python's boolean/integer aliasing."""
    if not isinstance(left, (str, int, float, bool)) and left is not None:
        return False
    return _scalar_identity(left) == _scalar_identity(right)


@dataclass(frozen=True)
class ConditionExpression:
    """One immutable node in the bounded declarative condition language."""

    operator: ConditionOperator
    reference: str
    value: ConditionValue
    children: tuple[ConditionExpression, ...]
    expression_digest: str

    @classmethod
    def build(
        cls,
        operator: ConditionOperator,
        *,
        reference: str = "",
        value: ConditionValue = None,
        children: tuple[ConditionExpression, ...] = (),
    ) -> ConditionExpression:
        """Build one validated expression and derive its integrity digest."""
        if operator == "exists":
            _reference(reference)
            if value is not None or children:
                raise ValueError("exists accepts only ref")
        elif operator in _COMPARISONS:
            _reference(reference)
            if isinstance(value, tuple) or children:
                raise ValueError(f"{operator} accepts one scalar value and no children")
            require_json_scalar(value, "condition.value")
        elif operator == "one-of":
            _reference(reference)
            if not isinstance(value, tuple) or not value or children:
                raise ValueError("one-of requires a non-empty scalar tuple")
            for index, item in enumerate(value):
                require_json_scalar(item, f"condition.value[{index}]")
            if len(value) != len({_scalar_identity(item) for item in value}):
                raise ValueError("one-of values must be unique")
        elif operator in _GROUPS:
            if reference or value is not None:
                raise ValueError(f"{operator} accepts children only")
            if not 1 <= len(children) <= MAX_GROUP_CHILDREN:
                raise ValueError(f"{operator} requires 1..{MAX_GROUP_CHILDREN} children")
        elif operator == "not":
            if reference or value is not None or len(children) != 1:
                raise ValueError("not requires exactly one child")
        else:
            raise ValueError("unsupported condition operator")
        body: dict[str, object] = {
            "schema_version": "1.0",
            "op": operator,
            "ref": reference,
            "value": _serialise_value(value),
            "children": [item.to_dict() for item in children],
        }
        expression = cls(
            operator=operator,
            reference=reference,
            value=value,
            children=children,
            expression_digest=canonical_digest(body),
        )
        depth, nodes = expression._shape()
        if depth > MAX_CONDITION_DEPTH or nodes > MAX_CONDITION_NODES:
            raise ValueError("condition exceeds the bounded tree budget")
        return expression

    @classmethod
    def from_dict(cls, value: object) -> ConditionExpression:
        """Parse and integrity-check one bounded expression tree."""
        return cls._from_dict(value, depth=1, remaining=MAX_CONDITION_NODES)[0]

    @classmethod
    def _from_dict(
        cls,
        value: object,
        *,
        depth: int,
        remaining: int,
    ) -> tuple[ConditionExpression, int]:
        """Parse one node while enforcing depth and total-node budgets early."""
        if depth > MAX_CONDITION_DEPTH or remaining < 1:
            raise ValueError("condition exceeds the bounded tree budget")
        data = require_mapping(value, "condition")
        if frozenset(data) != _SERIALISED_FIELDS:
            raise ValueError("condition fields do not match the schema")
        if data.get("schema_version") != "1.0":
            raise ValueError("unsupported condition schema version")
        raw_operator = require_string(data.get("op"), "condition.op")
        supported = {
            "exists",
            "eq",
            "ne",
            "lt",
            "lte",
            "gt",
            "gte",
            "contains",
            "one-of",
            "all",
            "any",
            "not",
        }
        if raw_operator not in supported:
            raise ValueError("unsupported condition operator")
        raw_children = data.get("children", [])
        if not isinstance(raw_children, list):
            raise ValueError("condition.children must be an array")
        children: list[ConditionExpression] = []
        used = 1
        for child in cast(list[object], raw_children):
            parsed, child_nodes = cls._from_dict(
                child,
                depth=depth + 1,
                remaining=remaining - used,
            )
            children.append(parsed)
            used += child_nodes
        raw_value = data.get("value")
        condition_value: ConditionValue
        if raw_operator == "one-of":
            if not isinstance(raw_value, list):
                raise ValueError("one-of value must be an array")
            condition_value = tuple(
                require_json_scalar(item, f"condition.value[{index}]")
                for index, item in enumerate(cast(list[object], raw_value))
            )
        else:
            condition_value = require_json_scalar(raw_value, "condition.value")
        expression = cls.build(
            cast(ConditionOperator, raw_operator),
            reference=require_string(data.get("ref", ""), "condition.ref", allow_empty=True),
            value=condition_value,
            children=tuple(children),
        )
        recorded = require_digest(data.get("expression_digest"), "condition.expression_digest")
        if expression.expression_digest != recorded:
            raise ValueError("condition digest does not match its content")
        return expression, used

    def _shape(self) -> tuple[int, int]:
        """Return recursive depth and node count for budget enforcement."""
        if not self.children:
            return 1, 1
        child_shapes = tuple(child._shape() for child in self.children)
        return 1 + max(depth for depth, _ in child_shapes), 1 + sum(
            nodes for _, nodes in child_shapes
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the complete digest-bound expression tree."""
        return {
            "schema_version": "1.0",
            "op": self.operator,
            "ref": self.reference,
            "value": _serialise_value(self.value),
            "children": [item.to_dict() for item in self.children],
            "expression_digest": self.expression_digest,
        }

    @property
    def references(self) -> frozenset[str]:
        """Return all context paths read by this expression."""
        own = frozenset({self.reference}) if self.reference else frozenset()
        return own.union(*(child.references for child in self.children))

    def evaluate(self, context: Mapping[str, object]) -> bool:
        """Evaluate the expression over inert mapping data only."""
        if self.operator in _GROUPS:
            results = (child.evaluate(context) for child in self.children)
            return all(results) if self.operator == "all" else any(results)
        if self.operator == "not":
            return not self.children[0].evaluate(context)
        actual = self._lookup(context)
        if self.operator == "exists":
            return actual is not _MISSING
        if actual is _MISSING:
            return False
        if self.operator == "eq":
            return _scalar_equal(actual, cast(JsonScalar, self.value))
        if self.operator == "ne":
            return not _scalar_equal(actual, cast(JsonScalar, self.value))
        if self.operator == "one-of":
            return any(
                _scalar_equal(actual, expected)
                for expected in cast(tuple[JsonScalar, ...], self.value)
            )
        if self.operator == "contains":
            if isinstance(actual, str) and isinstance(self.value, str):
                return self.value in actual
            if isinstance(actual, (list, tuple)):
                return any(_scalar_equal(item, cast(JsonScalar, self.value)) for item in actual)
            raise ValueError("contains requires a string or array context value")
        left = _numeric(actual, "condition context value")
        right = _numeric(self.value, "condition.value")
        if self.operator == "lt":
            return left < right
        if self.operator == "lte":
            return left <= right
        if self.operator == "gt":
            return left > right
        return left >= right

    def _lookup(self, context: Mapping[str, object]) -> object:
        """Resolve one dotted path without attribute access or callbacks."""
        cursor: object = context
        for segment in self.reference.split("."):
            if not isinstance(cursor, Mapping) or segment not in cursor:
                return _MISSING
            cursor = cursor[segment]
        return cursor
