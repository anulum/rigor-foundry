# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — protocol parser and digest properties
"""Prove strict public parsing and canonical identity invariants."""

from __future__ import annotations

from copy import deepcopy

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from property_strategies import JSON_SCALARS

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.models import AuditPolicy

_PROPERTY_SETTINGS = settings(max_examples=100, deadline=None)


@_PROPERTY_SETTINGS
@given(st.dictionaries(st.text(min_size=1, max_size=12), JSON_SCALARS, max_size=12))
def test_canonical_digest_ignores_mapping_insertion_order(value: dict[str, object]) -> None:
    """Equivalent mappings have one identity regardless of insertion order."""
    assert canonical_digest(value) == canonical_digest(dict(reversed(tuple(value.items()))))


@_PROPERTY_SETTINGS
@given(st.permutations(tuple(AuditPolicy().to_dict())))
def test_policy_parser_ignores_field_insertion_order(order: tuple[str, ...]) -> None:
    """The strict parser accepts every ordering of the exact policy schema."""
    source = AuditPolicy().to_dict()
    reordered = {field: source[field] for field in order}
    assert AuditPolicy.from_dict(reordered) == AuditPolicy()


@_PROPERTY_SETTINGS
@given(st.sampled_from(tuple(AuditPolicy().to_dict())))
def test_policy_parser_rejects_every_missing_field(field: str) -> None:
    """Every top-level policy field is mandatory under schema 1.1."""
    value = AuditPolicy().to_dict()
    del value[field]
    with pytest.raises(ValueError, match="fields"):
        AuditPolicy.from_dict(value)


def test_policy_parser_rejects_unknown_fields_without_digest_bypass() -> None:
    """Unknown top-level data cannot enter or silently escape the policy identity."""
    value = deepcopy(AuditPolicy().to_dict())
    value["unexpected"] = True
    with pytest.raises(ValueError, match="fields"):
        AuditPolicy.from_dict(value)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_digest_regressions_are_retained(value: float) -> None:
    """Non-interoperable JSON numbers never receive protocol identities."""
    with pytest.raises(ValueError, match="JSON compliant"):
        canonical_digest(value)
