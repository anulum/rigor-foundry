# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — rule registry properties
"""Exercise every built-in rule against registry and identity invariants."""

from __future__ import annotations

from dataclasses import replace

from hypothesis import given, settings
from hypothesis import strategies as st

from rigor_foundry.rules import RULES, RuleDefinition, rule_pack_digest, validate_rule_registry

_PROPERTY_SETTINGS = settings(max_examples=100, deadline=None)


@_PROPERTY_SETTINGS
@given(st.sampled_from(RULES))
def test_every_builtin_rule_field_is_identity_bound(rule: RuleDefinition) -> None:
    """Changing any public rule field changes the ordered pack identity."""
    index = RULES.index(rule)
    replacements = (
        replace(rule, summary=f"{rule.summary} changed"),
        replace(rule, introduced="rigor-foundry/9.9.9"),
    )
    for changed in replacements:
        mutated = (*RULES[:index], changed, *RULES[index + 1 :])
        assert rule_pack_digest(rules=mutated) != rule_pack_digest()


@_PROPERTY_SETTINGS
@given(st.sampled_from(RULES))
def test_every_builtin_rule_rejects_category_cross_wiring(rule: RuleDefinition) -> None:
    """A valid identifier cannot be cross-wired to another scanner category."""
    other = "architecture" if rule.category != "architecture" else "governance"
    errors = validate_rule_registry((replace(rule, category=other),))
    assert any("does not match category" in error for error in errors)


@_PROPERTY_SETTINGS
@given(st.sampled_from(RULES), st.sampled_from(("bad id", "TA1-short", "ZZ001-owner")))
def test_every_builtin_rule_rejects_malformed_identifier(
    rule: RuleDefinition,
    rule_id: str,
) -> None:
    """Malformed identifiers fail the finite public identifier grammar."""
    errors = validate_rule_registry((replace(rule, rule_id=rule_id),))
    assert any("identifier is invalid" in error for error in errors)
