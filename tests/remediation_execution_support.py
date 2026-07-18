# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — remediation execution test builders
"""Build approved plans, authorities, claims, and attested outcomes for tests."""

from __future__ import annotations

from test_remediation_plan import advisory, assessments, gap, lane, locked_controls

from rigor_foundry.claim_isolation import ExecutionClaim
from rigor_foundry.remediation_authority import (
    ExecutionAuthority,
    ExecutionBudget,
    ExecutionMode,
)
from rigor_foundry.remediation_executor import (
    LaneExecution,
    LaneStatus,
    StepOutcome,
    StepStatus,
)
from rigor_foundry.remediation_plan import ProcedureStep, RemediationLane, RemediationPlan

REPOSITORY = "rigor-foundry"
APPROVED_AT = "2026-07-15T12:05:00Z"
GRANTED_AT = "2026-07-15T12:10:00Z"
EXPIRES_AT = "2026-07-15T18:10:00Z"
STARTED_AT = "2026-07-15T12:15:00Z"
FINISHED_AT = "2026-07-15T12:20:00Z"
CLAIMED_AT = "2026-07-15T12:11:00Z"
CLAIM_EXPIRES_AT = "2026-07-15T18:11:00Z"
EVIDENCE_DIGEST = "a" * 64


def approved_plan(*, dependent: bool = True) -> RemediationPlan:
    """Return an independently approved two-lane remediation plan."""
    return advisory(dependent=dependent).approve(
        approver="independent-approver",
        approved_at=APPROVED_AT,
        evidence_digest=EVIDENCE_DIGEST,
    )


def _base_step(
    *, step_id: str, key: str, depends_on: tuple[str, ...], rollback: bool
) -> ProcedureStep:
    """Return one locked ``src/base.py`` repair step, with or without a rollback."""
    return ProcedureStep.build(
        step_id=step_id,
        adapter_id="architecture-base-adapter",
        argv=("rigor-adapter", "repair", "src/base.py"),
        input_schema_ids=("architecture-finding-v1",),
        output_schema_ids=("patch-evidence-v1",),
        timeout_seconds=120,
        cpu_seconds=60,
        memory_mb=512,
        retries=1,
        idempotency_key=key,
        approval_boundary=True,
        rollback_adapter_id="architecture-base-rollback" if rollback else "",
        rollback_argv=("rigor-adapter", "rollback", "src/base.py") if rollback else (),
        evidence_output_ids=(f"{step_id}-evidence",),
        depends_on=depends_on,
    )


def rollback_base_plan() -> RemediationPlan:
    """Return an approved plan whose base lane is a two-step, rollback-capable DAG.

    ``step-base-a`` declares a rollback and precedes ``step-base-b``, which does
    not. A failure of ``step-base-b`` therefore rolls back ``step-base-a``.
    """
    lock, controls = locked_controls(dependent=True)
    records = assessments(lock, controls)
    gaps = (
        gap(lock, controls[0], records[0], suffix="base"),
        gap(lock, controls[1], records[1], suffix="dependent"),
    )
    base_lane = RemediationLane.build(
        lane_id="lane-base",
        gap_ids=(gaps[0].gap_id,),
        root_cause=gaps[0].root_cause,
        risk=gaps[0].risk,
        blast_radius=gaps[0].blast_radius,
        affected_surfaces=gaps[0].affected_surfaces,
        write_set=("src/base.py",),
        semantic_dependencies=("src/base_api.py",),
        prerequisite_lane_ids=(),
        serialization_keys=(),
        non_goals=("no unrelated refactor",),
        migration_plan="preserve public behaviour while moving responsibility",
        rollback_plan="restore the exact baseline tree",
        steps=(
            _base_step(
                step_id="step-base-a", key="repair-base-a-v1", depends_on=(), rollback=True
            ),
            _base_step(
                step_id="step-base-b",
                key="repair-base-b-v1",
                depends_on=("step-base-a",),
                rollback=False,
            ),
        ),
        acceptance_gates=("verify-base",),
        required_verifier="independent-verifier",
    )
    dependent_lane = lane(gaps[1], suffix="dependent", prerequisites=("lane-base",))
    return RemediationPlan.build_advisory(
        lock,
        assessments=records,
        gaps=gaps,
        lanes=(base_lane, dependent_lane),
        created_by="planning-agent",
        created_at="2026-07-15T12:00:00Z",
    ).approve(
        approver="independent-approver",
        approved_at=APPROVED_AT,
        evidence_digest=EVIDENCE_DIGEST,
    )


def budget(
    *,
    wall_seconds: int = 3600,
    cpu_seconds: int = 3600,
    memory_mb: int = 1024,
    max_steps: int = 10,
) -> ExecutionBudget:
    """Return an aggregate budget that admits the fixture steps by default."""
    return ExecutionBudget.build(
        wall_seconds=wall_seconds,
        cpu_seconds=cpu_seconds,
        memory_mb=memory_mb,
        max_steps=max_steps,
    )


def authority(
    plan: RemediationPlan,
    *,
    mode: ExecutionMode = "execute",
    ceiling: ExecutionBudget | None = None,
    granted_by: str = "execution-owner",
    repository_id: str = REPOSITORY,
) -> ExecutionAuthority:
    """Return an explicit authority over ``plan`` for the fixture repository."""
    return ExecutionAuthority.build(
        plan,
        ceiling or budget(),
        authority_id="authority-1",
        repository_id=repository_id,
        granted_by=granted_by,
        granted_at=GRANTED_AT,
        expires_at=EXPIRES_AT,
        mode=mode,
    )


def claim(
    lane: RemediationLane,
    *,
    repository_id: str = REPOSITORY,
    write_set: tuple[str, ...] | None = None,
    claim_id: str | None = None,
) -> ExecutionClaim:
    """Return an active claim covering ``lane`` for the fixture repository."""
    return ExecutionClaim.build(
        claim_id=claim_id or f"claim-{lane.lane_id}",
        repository_id=repository_id,
        campaign_id="campaign-1",
        lane_id=lane.lane_id,
        claimant="executor-agent",
        write_set=write_set if write_set is not None else lane.write_set,
        claimed_at=CLAIMED_AT,
        expires_at=CLAIM_EXPIRES_AT,
        status="active",
    )


def outcome(
    step: ProcedureStep,
    *,
    status: StepStatus = "succeeded",
    attempts: int = 1,
    consumed_wall_seconds: int = 10,
    consumed_cpu_seconds: int = 5,
    peak_memory_mb: int = 256,
    rollback_ran: bool = False,
    evidence: tuple[tuple[str, str], ...] | None = None,
) -> StepOutcome:
    """Return an attested outcome for ``step`` in the requested status."""
    if status == "skipped":
        return StepOutcome.build(
            step_id=step.step_id,
            idempotency_key=step.idempotency_key,
            status="skipped",
        )
    captured = (
        evidence
        if evidence is not None
        else tuple((output_id, EVIDENCE_DIGEST) for output_id in step.evidence_output_ids)
    )
    return StepOutcome.build(
        step_id=step.step_id,
        idempotency_key=step.idempotency_key,
        status=status,
        attempts=attempts,
        consumed_wall_seconds=consumed_wall_seconds,
        consumed_cpu_seconds=consumed_cpu_seconds,
        peak_memory_mb=peak_memory_mb,
        rollback_ran=rollback_ran,
        evidence=captured,
    )


def lane_execution(
    lane: RemediationLane,
    *,
    status: LaneStatus = "succeeded",
    claim_id: str | None = None,
    outcomes: tuple[StepOutcome, ...] | None = None,
) -> LaneExecution:
    """Return a lane execution whose outcome matches its single fixture step."""
    if outcomes is None:
        step_status: StepStatus = "skipped" if status == "skipped" else status
        outcomes = (outcome(lane.steps[0], status=step_status),)
    return LaneExecution.build(
        lane_id=lane.lane_id,
        claim_id=claim_id or f"claim-{lane.lane_id}",
        status=status,
        step_outcomes=outcomes,
    )
