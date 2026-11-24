# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — fixed rule guidance model tests
"""Verify the rule guidance model through the guidance the detectors actually publish."""

from __future__ import annotations

import dataclasses
from collections.abc import MutableMapping
from typing import cast

import pytest

from rigor_foundry.api_compatibility import RULE_GUIDANCE as API_GUIDANCE
from rigor_foundry.reliability import RULE_GUIDANCE as RELIABILITY_GUIDANCE
from rigor_foundry.rule_guidance import RuleGuidance, RuleGuidanceCase


def test_a_two_case_rule_lists_its_primary_situation_before_its_further_case() -> None:
    """The published two-case rule yields both situations, primary first, unchanged."""
    guidance = API_GUIDANCE["AA001-unbound-api-manifest"]
    cases = guidance.all_cases()
    assert len(cases) == 2
    assert cases[0] == RuleGuidanceCase(
        guidance.condition, guidance.rationale, guidance.verification
    )
    assert all(case.condition for case in cases)
    assert cases[1:] == guidance.cases
    assert cases[0] != cases[1]


def test_a_single_case_rule_has_exactly_its_own_situation() -> None:
    """A published single-situation rule yields one case equal to its own fields."""
    guidance = RELIABILITY_GUIDANCE["RL001-bare-except"]
    assert guidance.cases == ()
    assert guidance.condition == ""
    assert guidance.all_cases() == (
        RuleGuidanceCase("", guidance.rationale, guidance.verification),
    )


def test_published_guidance_refuses_mutation() -> None:
    """Neither a guidance entry nor a detector's published mapping can be changed."""
    guidance = RELIABILITY_GUIDANCE["RL001-bare-except"]
    first_field = dataclasses.fields(guidance)[0].name
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(guidance, first_field, "changed")
    writable_view = cast(MutableMapping[str, RuleGuidance], RELIABILITY_GUIDANCE)
    with pytest.raises(TypeError):
        writable_view["RL001-bare-except"] = RuleGuidance("changed", "changed")
    assert RELIABILITY_GUIDANCE["RL001-bare-except"] is guidance


def test_a_multi_case_rule_must_label_every_situation_including_its_primary() -> None:
    """A rule with a further case is refused unless each situation carries its label."""
    labelled = RuleGuidanceCase("a second situation", "second rationale", "second check")
    with pytest.raises(ValueError, match="every situation of a multi-case rule needs a condition"):
        RuleGuidance("primary rationale", "primary check", cases=(labelled,))
    with pytest.raises(ValueError, match="every situation of a multi-case rule needs a condition"):
        RuleGuidance(
            "primary rationale",
            "primary check",
            condition="the primary situation",
            cases=(RuleGuidanceCase("", "second rationale", "second check"),),
        )
    accepted = RuleGuidance(
        "primary rationale", "primary check", condition="the primary situation", cases=(labelled,)
    )
    assert [case.condition for case in accepted.all_cases()] == [
        "the primary situation",
        "a second situation",
    ]
