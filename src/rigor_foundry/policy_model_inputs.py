# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — bounded common policy model inputs
"""Validate inert policy input before recursive model serialization or parsing."""

from __future__ import annotations

import json
from typing import cast

from .audit_primitives import require_exact_fields, require_mapping
from .condition_language import (
    MAX_CONDITION_DEPTH,
    MAX_CONDITION_NODES,
    ConditionExpression,
)
from .context_owner_proof import OwnerProof1
from .model_primitives import require_identifier
from .policy_read_budget import PolicyReadBudget1
from .policy_source_spans import SourceSpan1
from .typed_object_reference import TypedObjectRef1


def checked_policy_budget(value: PolicyReadBudget1) -> PolicyReadBudget1:
    """Snapshot an exact, revalidated allocation budget without granting authority."""
    if type(value) is not PolicyReadBudget1:
        raise ValueError("an exact policy read budget is required")
    return PolicyReadBudget1.from_dict(value.to_dict())


def _wire_size(value: object, depth: int, remaining: int, maximum_depth: int) -> int:
    """Count exact canonical UTF8 bytes without constructing an enclosing JSON string."""
    if type(value) in {dict, list} and depth > maximum_depth:
        raise ValueError("policy input exceeds the depth budget")
    if type(value) is dict:
        mapping = cast(dict[object, object], value)
        size = 2 + max(0, len(mapping) - 1)
        if size > remaining:
            raise ValueError("policy input exceeds the document byte budget")
        for key, item in mapping.items():
            if type(key) is not str:
                raise ValueError("policy input requires string object keys")
            size += _wire_size(key, depth + 1, remaining - size, maximum_depth) + 1
            size += _wire_size(item, depth + 1, remaining - size, maximum_depth)
        return size
    if type(value) is list:
        items = cast(list[object], value)
        size = 2 + max(0, len(items) - 1)
        if size > remaining:
            raise ValueError("policy input exceeds the document byte budget")
        for item in items:
            size += _wire_size(item, depth + 1, remaining - size, maximum_depth)
        return size
    if value is not None and type(value) not in {str, int, float, bool}:
        raise ValueError("policy input must contain inert JSON values")
    if isinstance(value, str) and len(value) > remaining:
        raise ValueError("policy input exceeds the document byte budget")
    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    size = len(encoded.encode("utf-8"))
    if size > remaining:
        raise ValueError("policy input exceeds the document byte budget")
    return size


def policy_wire_size(value: object, *, budget: PolicyReadBudget1) -> int:
    """Validate a decoded JSON tree and return its exact canonical byte count.

    Parameters
    ----------
    value : object
        Inert decoded JSON using exact dictionaries, lists and scalar types.
        Cycles, nonfinite numbers, surrogate text and custom objects refuse.
    budget : PolicyReadBudget1
        Explicit document byte and nesting limits. Collection owners separately
        enforce their source, rule and reference counts.

    Returns
    -------
    int
        UTF8 byte count under the original canonical JSON encoding. Object key
        order does not change this count; no enclosing JSON copy is allocated.

    Raises
    ------
    ValueError
        The input is not bounded JSON or the budget is malformed.
    """
    limits = checked_policy_budget(budget)
    return _wire_size(value, 1, limits.max_document_bytes, limits.max_depth)


def policy_record_mapping(
    value: object,
    *,
    fields: frozenset[str],
    object_kind: str,
    schema_version: str,
    budget: PolicyReadBudget1,
) -> dict[str, object]:
    """Check bounded JSON and exact owner-specified version fields before parsing any child record."""
    policy_wire_size(value, budget=budget)
    data = require_mapping(value, "policy record")
    require_exact_fields(data, fields, "policy record")
    if data["schema_version"] != schema_version or data["object_kind"] != object_kind:
        raise ValueError("unsupported policy record identity")
    return data


def checked_policy_condition(
    value: object,
    *,
    budget: PolicyReadBudget1,
) -> ConditionExpression:
    """Revalidate the original expression with bounds before recursive serialization.

    A condition remains declarative syntax. This operation observes no facts,
    authenticates no producer and supplies no applicability or permission result.
    """
    limits = checked_policy_budget(budget)
    pending: list[tuple[object, int]] = [(value, 1)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > MAX_CONDITION_NODES or depth > min(MAX_CONDITION_DEPTH, limits.max_depth):
            raise ValueError("policy condition exceeds the original tree budget")
        if type(node) is not ConditionExpression or type(node.children) is not tuple:
            raise ValueError("policy condition requires an exact immutable expression")
        if len(node.children) > MAX_CONDITION_NODES - count:
            raise ValueError("policy condition exceeds the original node budget")
        literal = node.value
        if type(literal) is tuple:
            if len(literal) > limits.max_references:
                raise ValueError("policy condition literals exceed the reference budget")
            policy_wire_size(list(literal), budget=limits)
        else:
            policy_wire_size(literal, budget=limits)
        pending.extend((child, depth + 1) for child in node.children)
    wire = cast(ConditionExpression, value).to_dict()
    policy_wire_size(wire, budget=limits)
    try:
        parsed = ConditionExpression.from_dict(wire)
    except OverflowError as exc:
        raise ValueError("policy condition literal exceeds the finite numeric domain") from exc
    if len(parsed.references) > limits.max_references:
        raise ValueError("policy condition exceeds the reference budget")
    return parsed


def policy_identifiers(value: object, *, budget: PolicyReadBudget1) -> tuple[str, ...]:
    """Check a bounded immutable sorted identity set without changing its order."""
    limits = checked_policy_budget(budget)
    if type(value) is not tuple or len(value) > limits.max_references:
        raise ValueError("policy identity set exceeds its immutable reference budget")
    items = tuple(require_identifier(item, "policy identity") for item in value)
    if items != tuple(sorted(set(items))):
        raise ValueError("policy identities must be sorted and unique")
    return items


def policy_source_spans(value: object, *, budget: PolicyReadBudget1) -> tuple[SourceSpan1, ...]:
    """Check original nonempty span metadata while retaining exact source selection order.

    Actual byte custody and semantic acceptance require the installed source owner;
    structural parsing alone establishes neither.
    """
    limits = checked_policy_budget(budget)
    if type(value) is not tuple or not value or len(value) > limits.max_references:
        raise ValueError("policy source spans require a bounded nonempty immutable tuple")
    checked: list[SourceSpan1] = []
    identities: set[str] = set()
    sources: set[str] = set()
    for item in value:
        if type(item) is not SourceSpan1:
            raise ValueError("policy source spans require actual original records")
        span = SourceSpan1.from_dict(item.to_dict())
        if span.span_id in identities:
            raise ValueError("policy source span identity is duplicated")
        identities.add(span.span_id)
        sources.add(span.source_id)
        checked.append(span)
    if len(sources) > limits.max_sources:
        raise ValueError("policy source spans exceed the source budget")
    return tuple(checked)


def policy_condition_from_dict(value: object, *, budget: PolicyReadBudget1) -> ConditionExpression:
    """Parse original condition syntax with bounded JSON and finite numeric refusal."""
    policy_wire_size(value, budget=budget)
    try:
        parsed = ConditionExpression.from_dict(value)
    except OverflowError as exc:
        raise ValueError("policy condition literal exceeds the finite numeric domain") from exc
    return checked_policy_condition(parsed, budget=budget)


def policy_reference(value: object, *, allowed: frozenset[tuple[str, str]]) -> TypedObjectRef1:
    """Revalidate an actual reference within a consuming owner's closed format subset.

    The format subset selects integrity syntax only. The installed consuming
    owner must resolve the actual target and authenticate its selected source.
    """
    if type(value) is not TypedObjectRef1:
        raise ValueError("an actual typed policy reference is required")
    reference = TypedObjectRef1.from_dict(value.to_dict())
    if (reference.kind, reference.format_version) not in allowed:
        raise ValueError("typed reference has the wrong policy component format")
    return reference


def policy_owner_proof(value: object, *, budget: PolicyReadBudget1) -> OwnerProof1:
    """Revalidate bounded original proof metadata without authenticating its source owner.

    Parameters
    ----------
    value : object
        Actual original ``OwnerProof1`` with its complete independent subject.
    budget : PolicyReadBudget1
        Explicit byte, depth and reference limits for the original envelope.

    Returns
    -------
    OwnerProof1
        Reparsed original metadata. Actual contract/source/current-observation
        verification remains the installed owner's responsibility.
    """
    limits = checked_policy_budget(budget)
    if type(value) is not OwnerProof1:
        raise ValueError("an actual original owner proof is required")
    wire = value.to_dict()
    policy_wire_size(wire, budget=limits)
    return OwnerProof1.from_dict(wire, budget=limits)
