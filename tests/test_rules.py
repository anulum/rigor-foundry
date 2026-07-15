# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — audit rule-pack and domain coverage tests
"""Verify immutable rule identity and mandatory domain-control mapping."""

from __future__ import annotations

from rigor_foundry.rules import (
    RULES,
    RULES_BY_ID,
    rule_pack_digest,
    validate_rule_registry,
)


def test_rule_registry_is_unique_complete_and_content_addressed() -> None:
    """Every scanner identifier has one stable registry definition and pack digest."""
    assert validate_rule_registry() == ()
    assert len(RULES) == len(RULES_BY_ID)
    assert len(rule_pack_digest()) == 64
    assert {rule.category for rule in RULES} == {
        "test-authenticity",
        "architecture",
        "godfile",
        "governance",
    }
