# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — instruction resolver provenance contracts
"""Check public resolution records without interpreting them as execution proof."""

from dataclasses import replace

import pytest

from rigor_foundry.instruction_resolution import InstructionPolicy, resolve_instruction_action
from rigor_foundry.instruction_scope import ActionScope, InstructionScope, ScopedInstruction


def test_write_conflict_does_not_poison_read_resolution() -> None:
    """Independent read scope remains permitted while a write conflict is retained."""
    action = ActionScope(
        "actor",
        "runtime",
        "project",
        "task",
        "read",
        "target",
        "local",
        "account",
        "free",
        "local",
    )
    rules = (
        ScopedInstruction("grant", "owner", "permission", InstructionScope(), True),
        ScopedInstruction(
            "write-limit", "owner", "permission", InstructionScope(effect="write"), False
        ),
    )
    policy = InstructionPolicy(rules, ("owner",), frozenset({"owner"}))
    read = resolve_instruction_action(policy, action)
    write = resolve_instruction_action(policy, replace(action, effect="write"))
    assert read.allowed and read.excluded == ("write-limit",)
    assert not write.allowed
    assert write.contradictions[0].code == "instruction-conflict"
    assert write.contradictions[0].sources == ("grant", "write-limit")


@pytest.mark.parametrize("fault", ["sources", "issuers", "grantors"])
def test_ambiguous_policy_identity_is_rejected(fault: str) -> None:
    """Duplicate identities and foreign grantors cannot enter policy resolution."""
    rule = ScopedInstruction("grant", "owner", "permission", InstructionScope(), True)
    with pytest.raises(ValueError):
        InstructionPolicy(
            (rule, rule) if fault == "sources" else (rule,),
            ("owner", "owner") if fault == "issuers" else ("owner",),
            frozenset({"unknown" if fault == "grantors" else "owner"}),
        )
