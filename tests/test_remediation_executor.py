# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — attested remediation execution ledger tests
"""Verify the attested execution ledger records but never runs remediation."""

from __future__ import annotations

from typing import cast

import pytest
from remediation_execution_support import (
    EVIDENCE_DIGEST,
    FINISHED_AT,
    STARTED_AT,
    approved_plan,
    authority,
    budget,
    claim,
    lane_execution,
    outcome,
    rollback_base_plan,
)

from rigor_foundry.claim_isolation import ExecutionClaim
from rigor_foundry.remediation_executor import (
    ExecutionLedger,
    LaneExecution,
    LaneStatus,
    StepOutcome,
    StepStatus,
    _transitive_prerequisites,
)
from rigor_foundry.remediation_plan import ProcedureStep, RemediationLane


def _outcome(step_id: str, key: str, wall: int) -> StepOutcome:
    """Return one succeeded outcome bound to a given idempotency key."""
    return StepOutcome.build(
        step_id=step_id,
        idempotency_key=key,
        status="succeeded",
        attempts=1,
        consumed_wall_seconds=wall,
        consumed_cpu_seconds=1,
        peak_memory_mb=16,
        evidence=((f"{step_id}-evidence", EVIDENCE_DIGEST),),
    )


def test_step_outcome_status_invariants_hold() -> None:
    """Each status binds exactly its own attempts, evidence, and rollback shape."""
    step = approved_plan().lanes[0].steps[0]
    assert outcome(step, status="succeeded").status == "succeeded"
    assert outcome(step, status="failed").status == "failed"
    assert outcome(step, status="rolled-back", rollback_ran=True).rollback_ran is True
    assert outcome(step, status="skipped").attempts == 0
    with pytest.raises(ValueError, match="status is unsupported"):
        StepOutcome.build(step_id="s", idempotency_key="k", status=cast(StepStatus, "queued"))
    with pytest.raises(ValueError, match="at least one attempt"):
        StepOutcome.build(
            step_id="s",
            idempotency_key="k",
            status="succeeded",
            evidence=(("o", EVIDENCE_DIGEST),),
        )
    with pytest.raises(ValueError, match="must capture evidence"):
        StepOutcome.build(step_id="s", idempotency_key="k", status="succeeded", attempts=1)
    with pytest.raises(ValueError, match="must record no execution"):
        StepOutcome.build(step_id="s", idempotency_key="k", status="skipped", attempts=1)
    with pytest.raises(ValueError, match="rollback ran"):
        StepOutcome.build(
            step_id="s",
            idempotency_key="k",
            status="rolled-back",
            attempts=1,
            evidence=(("o", EVIDENCE_DIGEST),),
        )
    with pytest.raises(ValueError, match="only a rolled-back"):
        StepOutcome.build(
            step_id="s",
            idempotency_key="k",
            status="succeeded",
            attempts=1,
            evidence=(("o", EVIDENCE_DIGEST),),
            rollback_ran=True,
        )


def test_step_outcome_evidence_and_serialisation() -> None:
    """Evidence pairs are validated and the record round-trips and detects tampering."""
    with pytest.raises(ValueError, match="pairs"):
        StepOutcome.build(
            step_id="s",
            idempotency_key="k",
            status="succeeded",
            attempts=1,
            evidence=cast("tuple[tuple[str, str], ...]", (("o",),)),
        )
    with pytest.raises(ValueError, match="must be unique"):
        StepOutcome.build(
            step_id="s",
            idempotency_key="k",
            status="succeeded",
            attempts=1,
            evidence=(("o", EVIDENCE_DIGEST), ("o", "b" * 64)),
        )
    record = _outcome("step-base", "repair-base-v1", 10)
    assert StepOutcome.from_dict(record.to_dict()) == record
    bad_schema = dict(record.to_dict())
    bad_schema["schema_version"] = "9.9"
    with pytest.raises(ValueError, match="unsupported outcome schema"):
        StepOutcome.from_dict(bad_schema)
    bad_evidence = dict(record.to_dict())
    bad_evidence["evidence"] = "not-a-list"
    with pytest.raises(ValueError, match="evidence must be an array"):
        StepOutcome.from_dict(bad_evidence)
    bad_digest = dict(record.to_dict())
    bad_digest["outcome_digest"] = "0" * 64
    with pytest.raises(ValueError, match="outcome digest"):
        StepOutcome.from_dict(bad_digest)


def test_lane_execution_status_is_derived_from_step_outcomes() -> None:
    """The lane status is the only one consistent with its step outcomes."""
    lane = approved_plan().lanes[0]
    step = lane.steps[0]
    assert lane_execution(lane, status="succeeded").status == "succeeded"
    assert lane_execution(lane, status="skipped").status == "skipped"
    assert lane_execution(lane, status="failed").status == "failed"
    with pytest.raises(ValueError, match="status is unsupported"):
        LaneExecution.build(
            lane_id="lane",
            claim_id="claim",
            status=cast(LaneStatus, "aborted"),
            step_outcomes=(outcome(step),),
        )
    with pytest.raises(ValueError, match="must not be empty"):
        LaneExecution.build(lane_id="lane", claim_id="claim", status="succeeded", step_outcomes=())
    with pytest.raises(ValueError, match="must be unique"):
        LaneExecution.build(
            lane_id="lane",
            claim_id="claim",
            status="succeeded",
            step_outcomes=(_outcome("dup", "k1", 1), _outcome("dup", "k2", 1)),
        )
    with pytest.raises(ValueError, match="must be"):
        LaneExecution.build(
            lane_id="lane",
            claim_id="claim",
            status="failed",
            step_outcomes=(outcome(step, status="succeeded"),),
        )


def test_lane_execution_rollback_and_inconsistent_mixes() -> None:
    """Rolled-back status requires a failure; a skip requires a failure too."""
    base = rollback_base_plan().lanes[0]
    step_a, step_b = base.steps
    rolled = LaneExecution.build(
        lane_id=base.lane_id,
        claim_id="claim-lane-base",
        status="rolled-back",
        step_outcomes=(
            outcome(step_a, status="rolled-back", rollback_ran=True),
            outcome(step_b, status="failed"),
        ),
    )
    assert rolled.status == "rolled-back"
    assert LaneExecution.from_dict(rolled.to_dict()) == rolled
    with pytest.raises(ValueError, match="requires a failed step"):
        LaneExecution.build(
            lane_id=base.lane_id,
            claim_id="claim-lane-base",
            status="rolled-back",
            step_outcomes=(
                outcome(step_a, status="rolled-back", rollback_ran=True),
                outcome(step_b, status="succeeded"),
            ),
        )
    with pytest.raises(ValueError, match="requires a failure"):
        LaneExecution.build(
            lane_id=base.lane_id,
            claim_id="claim-lane-base",
            status="failed",
            step_outcomes=(outcome(step_a, status="succeeded"), outcome(step_b, status="skipped")),
        )


def test_lane_execution_rejects_schema_and_digest_tampering() -> None:
    """A serialised lane execution fails closed on malformed or altered fields."""
    lane = approved_plan().lanes[0]
    record = lane_execution(lane)
    bad_schema = dict(record.to_dict())
    bad_schema["schema_version"] = "9.9"
    with pytest.raises(ValueError, match="unsupported lane execution schema"):
        LaneExecution.from_dict(bad_schema)
    bad_outcomes = dict(record.to_dict())
    bad_outcomes["step_outcomes"] = "not-a-list"
    with pytest.raises(ValueError, match="step_outcomes must be an array"):
        LaneExecution.from_dict(bad_outcomes)
    bad_digest = dict(record.to_dict())
    bad_digest["lane_digest"] = "0" * 64
    with pytest.raises(ValueError, match="lane execution digest"):
        LaneExecution.from_dict(bad_digest)


def test_ledger_admits_a_faithful_execution_and_round_trips() -> None:
    """A covering, in-budget, ordered execution is admitted and round-trips."""
    plan = approved_plan()
    grant = authority(plan)
    base, dependent = plan.lanes
    ledger = ExecutionLedger.admit(
        plan=plan,
        authority=grant,
        lane_executions=(lane_execution(base), lane_execution(dependent)),
        claims=(claim(base), claim(dependent)),
        started_at=STARTED_AT,
        finished_at=FINISHED_AT,
    )
    assert ledger.resolution == "succeeded"
    assert ExecutionLedger.from_dict(ledger.to_dict()) == ledger


def test_ledger_binds_plan_authority_and_batch_order() -> None:
    """The ledger binds the exact plan, a forward window, and the batch order."""
    plan = approved_plan()
    other = approved_plan(dependent=False)
    grant = authority(plan)
    base, dependent = plan.lanes
    with pytest.raises(ValueError, match="does not bind"):
        ExecutionLedger.admit(
            plan=other,
            authority=grant,
            lane_executions=(lane_execution(base), lane_execution(dependent)),
            claims=(claim(base), claim(dependent)),
            started_at=STARTED_AT,
            finished_at=FINISHED_AT,
        )
    with pytest.raises(ValueError, match="must not precede"):
        ExecutionLedger.admit(
            plan=plan,
            authority=grant,
            lane_executions=(lane_execution(base), lane_execution(dependent)),
            claims=(claim(base), claim(dependent)),
            started_at=FINISHED_AT,
            finished_at=STARTED_AT,
        )
    with pytest.raises(ValueError, match="must not be empty"):
        ExecutionLedger.admit(
            plan=plan,
            authority=grant,
            lane_executions=(),
            claims=(claim(base), claim(dependent)),
            started_at=STARTED_AT,
            finished_at=FINISHED_AT,
        )
    with pytest.raises(ValueError, match="must follow the plan"):
        ExecutionLedger.admit(
            plan=plan,
            authority=grant,
            lane_executions=(lane_execution(dependent), lane_execution(base)),
            claims=(claim(base), claim(dependent)),
            started_at=STARTED_AT,
            finished_at=FINISHED_AT,
        )


def test_ledger_claims_must_cover_each_lane_in_repository() -> None:
    """Every lane needs a unique in-repository claim covering its write set."""
    plan = approved_plan()
    grant = authority(plan)
    base, dependent = plan.lanes

    def admit(claims: tuple[ExecutionClaim, ...]) -> ExecutionLedger:
        return ExecutionLedger.admit(
            plan=plan,
            authority=grant,
            lane_executions=(lane_execution(base), lane_execution(dependent)),
            claims=claims,
            started_at=STARTED_AT,
            finished_at=FINISHED_AT,
        )

    with pytest.raises(ValueError, match="unknown claim"):
        admit((claim(base),))
    with pytest.raises(ValueError, match="does not bind lane"):
        admit(
            (claim(base, claim_id="claim-lane-base"), claim(base, claim_id="claim-lane-dependent"))
        )
    with pytest.raises(ValueError, match="outside the authority repository"):
        admit((claim(base, repository_id="other-repo"), claim(dependent)))
    with pytest.raises(ValueError, match="does not cover the lane write set"):
        admit((claim(base, write_set=("src/unrelated.py",)), claim(dependent)))
    with pytest.raises(ValueError, match="supplied more than once"):
        admit((claim(base), claim(base), claim(dependent)))


def test_ledger_steps_match_plan_budget_and_evidence() -> None:
    """Outcomes must match plan steps, keys, per-step budget, and declared outputs."""
    plan = approved_plan()
    base, dependent = plan.lanes
    grant = authority(plan)
    tight = authority(plan, ceiling=budget(memory_mb=256))
    with pytest.raises(ValueError, match="must match the plan steps"):
        ExecutionLedger.admit(
            plan=plan,
            authority=grant,
            lane_executions=(
                LaneExecution.build(
                    lane_id=base.lane_id,
                    claim_id="claim-lane-base",
                    status="succeeded",
                    step_outcomes=(_outcome("wrong-step", base.steps[0].idempotency_key, 10),),
                ),
                lane_execution(dependent),
            ),
            claims=(claim(base), claim(dependent)),
            started_at=STARTED_AT,
            finished_at=FINISHED_AT,
        )
    forged_key = LaneExecution.build(
        lane_id=base.lane_id,
        claim_id="claim-lane-base",
        status="succeeded",
        step_outcomes=(
            StepOutcome.build(
                step_id=base.steps[0].step_id,
                idempotency_key="not-the-plan-key",
                status="succeeded",
                attempts=1,
                evidence=((base.steps[0].evidence_output_ids[0], EVIDENCE_DIGEST),),
            ),
        ),
    )
    with pytest.raises(ValueError, match="does not match the plan"):
        ExecutionLedger.admit(
            plan=plan,
            authority=grant,
            lane_executions=(forged_key, lane_execution(dependent)),
            claims=(claim(base), claim(dependent)),
            started_at=STARTED_AT,
            finished_at=FINISHED_AT,
        )
    with pytest.raises(ValueError, match="authority ceiling"):
        ExecutionLedger.admit(
            plan=plan,
            authority=tight,
            lane_executions=(lane_execution(base), lane_execution(dependent)),
            claims=(claim(base), claim(dependent)),
            started_at=STARTED_AT,
            finished_at=FINISHED_AT,
        )
    wrong_evidence = LaneExecution.build(
        lane_id=base.lane_id,
        claim_id="claim-lane-base",
        status="succeeded",
        step_outcomes=(
            outcome(base.steps[0], evidence=(("unexpected-output", EVIDENCE_DIGEST),)),
        ),
    )
    with pytest.raises(ValueError, match="must cover its declared outputs"):
        ExecutionLedger.admit(
            plan=plan,
            authority=grant,
            lane_executions=(wrong_evidence, lane_execution(dependent)),
            claims=(claim(base), claim(dependent)),
            started_at=STARTED_AT,
            finished_at=FINISHED_AT,
        )


def test_ledger_mode_and_aggregate_budget_are_enforced() -> None:
    """Observe forbids execution; the aggregate step ceiling is enforced."""
    plan = approved_plan()
    base, dependent = plan.lanes
    observe = authority(plan, mode="observe")
    with pytest.raises(ValueError, match="observe authority"):
        ExecutionLedger.admit(
            plan=plan,
            authority=observe,
            lane_executions=(lane_execution(base), lane_execution(dependent)),
            claims=(claim(base), claim(dependent)),
            started_at=STARTED_AT,
            finished_at=FINISHED_AT,
        )
    dry_run = ExecutionLedger.admit(
        plan=plan,
        authority=observe,
        lane_executions=(
            lane_execution(base, status="skipped"),
            lane_execution(dependent, status="skipped"),
        ),
        claims=(claim(base), claim(dependent)),
        started_at=STARTED_AT,
        finished_at=FINISHED_AT,
    )
    assert dry_run.resolution == "succeeded"
    capped = authority(plan, ceiling=budget(max_steps=1))
    with pytest.raises(ValueError, match="authority budget"):
        ExecutionLedger.admit(
            plan=plan,
            authority=capped,
            lane_executions=(lane_execution(base), lane_execution(dependent)),
            claims=(claim(base), claim(dependent)),
            started_at=STARTED_AT,
            finished_at=FINISHED_AT,
        )


def test_ledger_propagates_failure_and_rollback_across_lanes() -> None:
    """A failed lane forces dependants to skip; a rollback resolves the ledger."""
    plan = approved_plan()
    base, dependent = plan.lanes
    grant = authority(plan)
    failed = ExecutionLedger.admit(
        plan=plan,
        authority=grant,
        lane_executions=(
            lane_execution(base, status="failed"),
            lane_execution(dependent, status="skipped"),
        ),
        claims=(claim(base), claim(dependent)),
        started_at=STARTED_AT,
        finished_at=FINISHED_AT,
    )
    assert failed.resolution == "failed"
    with pytest.raises(ValueError, match="must be skipped"):
        ExecutionLedger.admit(
            plan=plan,
            authority=grant,
            lane_executions=(
                lane_execution(base, status="failed"),
                lane_execution(dependent, status="succeeded"),
            ),
            claims=(claim(base), claim(dependent)),
            started_at=STARTED_AT,
            finished_at=FINISHED_AT,
        )
    with pytest.raises(ValueError, match="without a failed prerequisite"):
        ExecutionLedger.admit(
            plan=plan,
            authority=grant,
            lane_executions=(lane_execution(base), lane_execution(dependent, status="skipped")),
            claims=(claim(base), claim(dependent)),
            started_at=STARTED_AT,
            finished_at=FINISHED_AT,
        )
    rollback_plan = rollback_base_plan()
    rb_base, rb_dependent = rollback_plan.lanes
    step_a, step_b = rb_base.steps
    rolled = ExecutionLedger.admit(
        plan=rollback_plan,
        authority=authority(rollback_plan),
        lane_executions=(
            LaneExecution.build(
                lane_id=rb_base.lane_id,
                claim_id="claim-lane-base",
                status="rolled-back",
                step_outcomes=(
                    outcome(step_a, status="rolled-back", rollback_ran=True),
                    outcome(step_b, status="failed"),
                ),
            ),
            lane_execution(rb_dependent, status="skipped"),
        ),
        claims=(claim(rb_base), claim(rb_dependent)),
        started_at=STARTED_AT,
        finished_at=FINISHED_AT,
    )
    assert rolled.resolution == "rolled-back"
    with pytest.raises(ValueError, match="declared rollback"):
        ExecutionLedger.admit(
            plan=rollback_plan,
            authority=authority(rollback_plan),
            lane_executions=(
                LaneExecution.build(
                    lane_id=rb_base.lane_id,
                    claim_id="claim-lane-base",
                    status="rolled-back",
                    step_outcomes=(
                        outcome(step_a, status="failed"),
                        outcome(step_b, status="rolled-back", rollback_ran=True),
                    ),
                ),
                lane_execution(rb_dependent, status="skipped"),
            ),
            claims=(claim(rb_base), claim(rb_dependent)),
            started_at=STARTED_AT,
            finished_at=FINISHED_AT,
        )


def test_ledger_serialisation_rejects_tampering_and_divergent_idempotency() -> None:
    """A ledger fails closed on schema, shape, resolution, digest, and key divergence."""
    plan = approved_plan()
    base, dependent = plan.lanes
    ledger = ExecutionLedger.admit(
        plan=plan,
        authority=authority(plan),
        lane_executions=(lane_execution(base), lane_execution(dependent)),
        claims=(claim(base), claim(dependent)),
        started_at=STARTED_AT,
        finished_at=FINISHED_AT,
    )
    serialised = ledger.to_dict()
    bad_schema = dict(serialised)
    bad_schema["schema_version"] = "9.9"
    with pytest.raises(ValueError, match="unsupported ledger schema"):
        ExecutionLedger.from_dict(bad_schema)
    bad_shape = dict(serialised)
    bad_shape["lane_executions"] = "not-a-list"
    with pytest.raises(ValueError, match="lane_executions must be an array"):
        ExecutionLedger.from_dict(bad_shape)
    empty = dict(serialised)
    empty["lane_executions"] = []
    with pytest.raises(ValueError, match="must not be empty"):
        ExecutionLedger.from_dict(empty)
    bad_resolution = dict(serialised)
    bad_resolution["resolution"] = "failed"
    with pytest.raises(ValueError, match="inconsistent with its lane outcomes"):
        ExecutionLedger.from_dict(bad_resolution)
    bad_digest = dict(serialised)
    bad_digest["ledger_digest"] = "0" * 64
    with pytest.raises(ValueError, match="ledger digest"):
        ExecutionLedger.from_dict(bad_digest)
    left = LaneExecution.build(
        lane_id="lane-left",
        claim_id="claim-left",
        status="succeeded",
        step_outcomes=(_outcome("step-left", "shared-key-v1", 10),),
    )
    right = LaneExecution.build(
        lane_id="lane-right",
        claim_id="claim-right",
        status="succeeded",
        step_outcomes=(_outcome("step-right", "shared-key-v1", 20),),
    )
    divergent = dict(serialised)
    divergent["lane_executions"] = [left.to_dict(), right.to_dict()]
    with pytest.raises(ValueError, match="divergent outcomes"):
        ExecutionLedger.from_dict(divergent)


def test_transitive_prerequisites_visits_each_lane_once() -> None:
    """Diamond prerequisite paths are traversed without revisiting a shared lane."""

    def lane(lane_id: str, prerequisites: tuple[str, ...]) -> RemediationLane:
        return RemediationLane.build(
            lane_id=lane_id,
            gap_ids=(f"gap-{lane_id}",),
            root_cause="cause",
            risk="risk",
            blast_radius="bounded",
            affected_surfaces=(f"src/{lane_id}.py",),
            write_set=(f"src/{lane_id}.py",),
            semantic_dependencies=(),
            prerequisite_lane_ids=prerequisites,
            serialization_keys=(),
            non_goals=("no unrelated work",),
            migration_plan="bounded repair",
            rollback_plan="restore baseline",
            steps=(
                ProcedureStep.build(
                    step_id=f"step-{lane_id}",
                    adapter_id="adapter",
                    argv=("rigor-adapter", "repair"),
                    input_schema_ids=(),
                    output_schema_ids=(),
                    timeout_seconds=10,
                    cpu_seconds=10,
                    memory_mb=64,
                    retries=0,
                    idempotency_key=f"key-{lane_id}",
                    approval_boundary=True,
                    evidence_output_ids=("evidence",),
                ),
            ),
            acceptance_gates=("verify",),
            required_verifier="independent-verifier",
        )

    lane_by_id = {
        "a": lane("a", ()),
        "b": lane("b", ("a",)),
        "c": lane("c", ("a",)),
        "d": lane("d", ("b", "c")),
    }
    assert _transitive_prerequisites("d", lane_by_id) == {"a", "b", "c"}
