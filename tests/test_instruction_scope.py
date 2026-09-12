# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — exact action scope contracts
"""Check public scope matching and provenance identity validation."""

from dataclasses import fields, replace
from typing import cast

import pytest

from rigor_foundry.instruction_scope import ActionScope, InstructionScope, ScopedInstruction


def test_each_scope_dimension_changes_matching_and_digest() -> None:
    """Every principal, target and route dimension participates in exact binding."""
    action = ActionScope(
        "actor",
        "runtime",
        "project",
        "task",
        "write",
        "target",
        "provider",
        "account",
        "cost",
        "privacy",
    )
    assert InstructionScope().matches(action)
    for field in fields(action):
        scope = InstructionScope(**{field.name: getattr(action, field.name)})
        assert scope.matches(action)
        changed = replace(action, **{field.name: "changed"})
        assert not scope.matches(changed)
        assert action.digest != changed.digest


def test_empty_action_identity_is_not_a_wildcard() -> None:
    """An empty actor cannot masquerade as an unrestricted action identity."""
    with pytest.raises(ValueError):
        ActionScope(
            "", "runtime", "project", "task", "read", "target", "local", "account", "free", "local"
        )


def test_duplicate_override_references_are_rejected() -> None:
    """An instruction identifies every explicit predecessor once."""
    with pytest.raises(ValueError, match="unique"):
        ScopedInstruction(
            "source", "issuer", "permission", InstructionScope(), True, ("old", "old")
        )


def test_integer_is_not_an_instruction_permission() -> None:
    """Python truthiness cannot turn a malformed integer into a host permission."""
    rule = ScopedInstruction("source", "issuer", "permission", InstructionScope(), True)
    with pytest.raises(ValueError, match="boolean"):
        replace(rule, allow=cast(bool, 1))
