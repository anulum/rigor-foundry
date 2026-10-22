# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — condition observation contract tests
"""Exercise immutable supplied observations and explicit truth conversion."""

from __future__ import annotations

from typing import cast

import pytest

from rigor_foundry.condition_facts import ConditionFact, ConditionTruth, ObservationState
from rigor_foundry.condition_language import ConditionValue


@pytest.mark.parametrize("value", [None, True, False, 0, 1, 0.5, "", (), (True, 1, None)])
def test_known_values_round_trip_without_null_or_boolean_coercion(
    value: ConditionValue,
) -> None:
    """Known null, booleans, numbers and empty arrays keep their actual values."""
    fact = ConditionFact.known(value)
    assert fact.state == "known"
    assert fact.value == value
    assert ConditionFact.from_dict(fact.to_dict()) == fact


@pytest.mark.parametrize("fact", [ConditionFact.absent(), ConditionFact.unknown()])
def test_nonobserved_states_are_distinct_from_known_null(fact: ConditionFact) -> None:
    """Absence and unknown preserve separate states despite sharing null payloads."""
    assert fact != ConditionFact.known(None)
    assert ConditionFact.from_dict(fact.to_dict()) == fact
    assert fact.value is None


def test_parsed_array_does_not_retain_the_mutable_input() -> None:
    """Editing a caller-owned JSON list cannot change a parsed observation."""
    values: list[object] = [1, None, False]
    fact = ConditionFact.from_dict({"state": "known", "value": values})
    values.append("later")
    assert fact.value == (1, None, False)
    assert fact.to_dict() == {"state": "known", "value": [1, None, False]}


def test_observation_identity_does_not_merge_booleans_and_numbers() -> None:
    """A cache or set cannot collapse semantically different Boolean observations."""
    facts = {ConditionFact.known(True), ConditionFact.known(1)}
    assert len(facts) == 2
    arrays = {ConditionFact.known((True,)), ConditionFact.known((1,))}
    assert len(arrays) == 2
    original = ConditionFact.known(0.5)
    parsed = ConditionFact.from_dict(original.to_dict())
    assert original == parsed and hash(original) == hash(parsed)
    assert original != 0.5


@pytest.mark.parametrize("state", ["missing", "KNOWN", None, 1, [], {}])
def test_direct_and_json_state_types_are_checked(state: object) -> None:
    """Unsupported state spellings and wrong JSON types cannot act as known."""
    with pytest.raises(ValueError):
        ConditionFact(cast(ObservationState, state))
    with pytest.raises(ValueError):
        ConditionFact.from_dict({"state": state, "value": None})


@pytest.mark.parametrize("state", ["absent", "unknown"])
@pytest.mark.parametrize("value", [False, 0, "", [], [1]])
def test_absent_and_unknown_cannot_carry_a_hidden_value(state: str, value: object) -> None:
    """Non-known states require actual null rather than a false-like value."""
    with pytest.raises(ValueError, match="require null"):
        ConditionFact(cast(ObservationState, state), cast(ConditionValue, value))
    with pytest.raises(ValueError, match="require null"):
        ConditionFact.from_dict({"state": state, "value": value})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf"), {}, [[1]]])
def test_nonfinite_and_nested_values_refuse_at_both_entrypoints(value: object) -> None:
    """Only finite scalar values or flat scalar arrays cross the observation boundary."""
    with pytest.raises(ValueError):
        ConditionFact.known(cast(ConditionValue, value))
    with pytest.raises(ValueError):
        ConditionFact.from_dict({"state": "known", "value": value})


def test_an_unrepresentable_numeric_domain_is_a_value_refusal() -> None:
    """Huge finite integers cannot leak an implementation OverflowError."""
    with pytest.raises(ValueError, match="finite domain"):
        ConditionFact.known(10**400)
    with pytest.raises(ValueError, match="finite domain"):
        ConditionFact.from_dict({"state": "known", "value": 10**400})


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        "known",
        {},
        {"state": "known"},
        {"state": "known", "value": True, "provenance": "not-authentication"},
    ],
)
def test_json_observations_accept_exact_fields_only(value: object) -> None:
    """Missing or excess metadata cannot silently change the operand contract."""
    with pytest.raises(ValueError):
        ConditionFact.from_dict(value)


@pytest.mark.parametrize("truth", list(ConditionTruth))
def test_truth_requires_an_explicit_comparison(truth: ConditionTruth) -> None:
    """The strings false and unknown cannot become a successful Boolean guard."""
    with pytest.raises(TypeError, match="explicit state comparison"):
        bool(truth)
    assert truth.value in {"true", "false", "unknown"}
