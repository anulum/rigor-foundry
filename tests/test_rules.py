# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — audit rule-pack and domain coverage tests
"""Verify immutable rule identity and mandatory domain-control mapping."""

from __future__ import annotations

from dataclasses import replace

import pytest

import rigor_foundry.rules as rules_module
from rigor_foundry.rules import (
    INITIAL_RULE_PACK_VERSION,
    RULE_PACK_SCHEMA_VERSION,
    RULE_PACK_VERSION,
    RULES,
    RULES_BY_ID,
    rule_pack_digest,
    validate_rule_registry,
)


def test_rule_registry_is_unique_complete_and_content_addressed() -> None:
    """Every scanner identifier has one stable registry definition and pack digest."""
    assert validate_rule_registry() == ()
    assert len(RULES) == len(RULES_BY_ID)
    assert rule_pack_digest() == "53f28fda84cfaf03b267fb7c489e5bd8507f0dfd8e71f1db06b247611a9c8a1a"
    assert {rule.category for rule in RULES} == {
        "test-authenticity",
        "architecture",
        "godfile",
        "governance",
    }
    assert RULE_PACK_SCHEMA_VERSION == "1.0"
    assert RULE_PACK_VERSION == "rigor-foundry/1.1.0"
    assert {rule.introduced for rule in RULES} == {INITIAL_RULE_PACK_VERSION}


def test_rule_pack_digest_binds_version_envelope_and_every_rule_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pack identity changes for version or ordered registry content mutations."""
    baseline = rule_pack_digest()
    monkeypatch.setattr(rules_module, "RULE_PACK_VERSION", "rigor-foundry/1.1.1")
    assert rule_pack_digest() != baseline

    monkeypatch.setattr(rules_module, "RULE_PACK_VERSION", RULE_PACK_VERSION)
    variants = (
        (replace(RULES[0], rule_id="TA001-test-double-v2"), *RULES[1:]),
        (replace(RULES[0], category="architecture"), *RULES[1:]),
        (replace(RULES[0], summary=f"{RULES[0].summary} changed"), *RULES[1:]),
        (replace(RULES[0], introduced="rigor-foundry/1.0.1"), *RULES[1:]),
        (RULES[1], RULES[0], *RULES[2:]),
    )
    for changed_rules in variants:
        monkeypatch.setattr(rules_module, "RULES", changed_rules)
        assert rule_pack_digest() != baseline


@pytest.mark.parametrize(
    "rules, message",
    [
        ((RULES[0], RULES[0]), "unique"),
        ((replace(RULES[0], category="unknown"),), "unsupported category"),
        ((replace(RULES[0], summary=" "),), "summary is empty"),
        ((replace(RULES[0], introduced="unversioned"),), "introduced version"),
    ],
)
def test_rule_registry_validation_rejects_ambiguous_metadata(
    monkeypatch: pytest.MonkeyPatch,
    rules: tuple[rules_module.RuleDefinition, ...],
    message: str,
) -> None:
    """Registry validation reports duplicate, unsupported, and empty metadata."""
    monkeypatch.setattr(rules_module, "RULES", rules)
    assert any(message in error for error in validate_rule_registry())
