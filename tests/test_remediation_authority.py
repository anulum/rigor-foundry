# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — remediation execution authority tests
"""Verify explicit, independent, budget-bounded remediation execution authority."""

from __future__ import annotations

from typing import cast

import pytest
from remediation_execution_support import (
    EXPIRES_AT,
    GRANTED_AT,
    approved_plan,
    authority,
    budget,
)
from test_remediation_plan import advisory

from rigor_foundry.remediation_authority import (
    ExecutionAuthority,
    ExecutionBudget,
    ExecutionMode,
)


def test_budget_admits_steps_within_ceiling_and_round_trips() -> None:
    """A budget admits fitting steps and consumption and rejects oversize ones."""
    plan = approved_plan()
    step = plan.lanes[0].steps[0]
    ceiling = budget(wall_seconds=200, cpu_seconds=100, memory_mb=1024, max_steps=3)
    assert ceiling.admits_step(step) is True
    assert budget(memory_mb=256).admits_step(step) is False
    assert ceiling.within(wall_seconds=200, cpu_seconds=100, peak_memory_mb=1024, executed_steps=3)
    assert not ceiling.within(
        wall_seconds=201,
        cpu_seconds=100,
        peak_memory_mb=1024,
        executed_steps=3,
    )
    assert ceiling.to_dict()["budget_digest"] == ceiling.budget_digest
    assert ExecutionBudget.from_dict(ceiling.to_dict()) == ceiling


def test_budget_rejects_out_of_range_and_tampering() -> None:
    """Below-floor, above-ceiling, malformed-schema, and re-digested budgets fail closed."""
    with pytest.raises(ValueError, match="integer >= 1"):
        budget(wall_seconds=0)
    with pytest.raises(ValueError, match="aggregate ceiling"):
        budget(wall_seconds=90_000)
    good = budget().to_dict()
    bad_schema = dict(good)
    bad_schema["schema_version"] = "9.9"
    with pytest.raises(ValueError, match="unsupported budget schema"):
        ExecutionBudget.from_dict(bad_schema)
    bad_digest = dict(good)
    bad_digest["budget_digest"] = "0" * 64
    with pytest.raises(ValueError, match="budget digest"):
        ExecutionBudget.from_dict(bad_digest)


def test_authority_requires_an_independently_approved_plan() -> None:
    """Only an approved plan, never by its author, may be authorised for execution."""
    unapproved = advisory()
    with pytest.raises(ValueError, match="approved plan"):
        ExecutionAuthority.build(
            unapproved,
            budget(),
            authority_id="authority-1",
            repository_id="rigor-foundry",
            granted_by="execution-owner",
            granted_at=GRANTED_AT,
            expires_at=EXPIRES_AT,
            mode="execute",
        )
    plan = approved_plan()
    with pytest.raises(ValueError, match="author cannot authorise"):
        ExecutionAuthority.build(
            plan,
            budget(),
            authority_id="authority-1",
            repository_id="rigor-foundry",
            granted_by=plan.created_by,
            granted_at=GRANTED_AT,
            expires_at=EXPIRES_AT,
            mode="execute",
        )
    grant = authority(plan)
    assert grant.authorises(plan) is True
    assert grant.authorises(approved_plan(dependent=False)) is False
    assert grant.authorises(advisory()) is False


def test_authority_rejects_bad_mode_and_expiry() -> None:
    """An unknown mode or a non-increasing validity window fails closed."""
    plan = approved_plan()
    with pytest.raises(ValueError, match="mode is unsupported"):
        ExecutionAuthority.build(
            plan,
            budget(),
            authority_id="authority-1",
            repository_id="rigor-foundry",
            granted_by="execution-owner",
            granted_at=GRANTED_AT,
            expires_at=EXPIRES_AT,
            mode=cast(ExecutionMode, "delete"),
        )
    with pytest.raises(ValueError, match="later than granted_at"):
        ExecutionAuthority.build(
            plan,
            budget(),
            authority_id="authority-1",
            repository_id="rigor-foundry",
            granted_by="execution-owner",
            granted_at=GRANTED_AT,
            expires_at="2026-07-15T12:00:00Z",
            mode="execute",
        )


def test_authority_round_trips_and_rejects_tampering() -> None:
    """A grant round-trips and rejects schema and content-digest tampering."""
    grant = authority(approved_plan(), mode="observe")
    assert grant.mode == "observe"
    assert ExecutionAuthority.from_dict(grant.to_dict()) == grant
    bad_schema = dict(grant.to_dict())
    bad_schema["schema_version"] = "9.9"
    with pytest.raises(ValueError, match="unsupported authority schema"):
        ExecutionAuthority.from_dict(bad_schema)
    bad_digest = dict(grant.to_dict())
    bad_digest["authority_digest"] = "0" * 64
    with pytest.raises(ValueError, match="authority digest"):
        ExecutionAuthority.from_dict(bad_digest)
