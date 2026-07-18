# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — attested remediation execution ledger
"""Record an attested, authority-bound remediation execution without running it."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, cast

from .claim_isolation import ExecutionClaim
from .model_primitives import (
    parse_utc_timestamp,
    require_boolean,
    require_digest,
    require_identifier,
    require_utc_timestamp,
    validate_unique_strings,
)
from .models import canonical_digest, require_integer, require_mapping, require_string
from .remediation_authority import ExecutionAuthority
from .remediation_plan import RemediationLane, RemediationPlan

EXECUTOR_SCHEMA_VERSION = "1.0"

StepStatus = Literal["succeeded", "failed", "skipped", "rolled-back"]
LaneStatus = Literal["succeeded", "failed", "skipped", "rolled-back"]
Resolution = Literal["succeeded", "failed", "rolled-back"]

_STEP_STATUSES: frozenset[str] = frozenset({"succeeded", "failed", "skipped", "rolled-back"})
_LANE_STATUSES: frozenset[str] = frozenset({"succeeded", "failed", "skipped", "rolled-back"})
_EXECUTED: frozenset[str] = frozenset({"succeeded", "failed", "rolled-back"})

EXECUTION_NOTICE = (
    "This ledger records an attested remediation execution admitted under an "
    "explicit authority and isolated claims. It never runs a procedure, spawns a "
    "process, or mutates a repository; the attested outcome is supplied by the "
    "authorised executor and only validated and content-addressed here."
)


def _validate_evidence(evidence: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    """Return unique captured (output id, content digest) pairs, sorted by id."""
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in evidence:
        if not isinstance(item, tuple) or len(item) != 2:
            raise ValueError("outcome.evidence entries must be (output_id, digest) pairs")
        output_id = require_identifier(item[0], "outcome.evidence.output_id")
        digest = require_digest(item[1], "outcome.evidence.evidence_digest")
        if output_id in seen:
            raise ValueError("outcome.evidence output ids must be unique")
        seen.add(output_id)
        pairs.append((output_id, digest))
    return tuple(sorted(pairs))


@dataclass(frozen=True)
class StepOutcome:
    """One attested outcome for a single planned procedure step.

    Parameters
    ----------
    step_id:
        The plan step this outcome attests.
    idempotency_key:
        The plan step's idempotency key; identical keys must attest identically.
    status:
        ``succeeded``, ``failed``, ``rolled-back`` (a prior success undone), or
        ``skipped`` (never executed because the lane could not proceed).
    attempts:
        Executions attempted; zero exactly when the step was skipped.
    consumed_wall_seconds, consumed_cpu_seconds, peak_memory_mb:
        Attested resource consumption; all zero when skipped.
    evidence:
        Captured (output id, content digest) pairs for an executed step.
    rollback_ran:
        Whether the declared rollback executed; only a rolled-back step sets it.

    """

    step_id: str
    idempotency_key: str
    status: StepStatus
    attempts: int
    consumed_wall_seconds: int
    consumed_cpu_seconds: int
    peak_memory_mb: int
    evidence: tuple[tuple[str, str], ...]
    rollback_ran: bool
    outcome_digest: str

    @classmethod
    def build(
        cls,
        *,
        step_id: str,
        idempotency_key: str,
        status: StepStatus,
        attempts: int = 0,
        consumed_wall_seconds: int = 0,
        consumed_cpu_seconds: int = 0,
        peak_memory_mb: int = 0,
        evidence: tuple[tuple[str, str], ...] = (),
        rollback_ran: bool = False,
    ) -> StepOutcome:
        """Build one self-consistent, content-addressed step outcome."""
        if status not in _STEP_STATUSES:
            raise ValueError("outcome.status is unsupported")
        identifier = require_identifier(step_id, "outcome.step_id")
        key = require_identifier(idempotency_key, "outcome.idempotency_key")
        attempt_count = require_integer(attempts, "outcome.attempts", minimum=0)
        wall = require_integer(consumed_wall_seconds, "outcome.consumed_wall_seconds", minimum=0)
        cpu = require_integer(consumed_cpu_seconds, "outcome.consumed_cpu_seconds", minimum=0)
        memory = require_integer(peak_memory_mb, "outcome.peak_memory_mb", minimum=0)
        rolled = require_boolean(rollback_ran, "outcome.rollback_ran")
        captured = _validate_evidence(evidence)
        if status in _EXECUTED:
            if attempt_count < 1:
                raise ValueError("an executed step outcome requires at least one attempt")
            if not captured:
                raise ValueError("an executed step outcome must capture evidence")
        elif attempt_count or wall or cpu or memory or captured or rolled:
            raise ValueError("a skipped step outcome must record no execution")
        if status == "rolled-back" and not rolled:
            raise ValueError("a rolled-back step outcome must record that its rollback ran")
        if status in {"succeeded", "failed"} and rolled:
            raise ValueError("only a rolled-back step outcome may record a rollback")
        body: dict[str, object] = {
            "schema_version": EXECUTOR_SCHEMA_VERSION,
            "step_id": identifier,
            "idempotency_key": key,
            "status": status,
            "attempts": attempt_count,
            "consumed_wall_seconds": wall,
            "consumed_cpu_seconds": cpu,
            "peak_memory_mb": memory,
            "evidence": [list(pair) for pair in captured],
            "rollback_ran": rolled,
        }
        return cls(
            step_id=identifier,
            idempotency_key=key,
            status=status,
            attempts=attempt_count,
            consumed_wall_seconds=wall,
            consumed_cpu_seconds=cpu,
            peak_memory_mb=memory,
            evidence=captured,
            rollback_ran=rolled,
            outcome_digest=canonical_digest(body),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one step outcome."""
        return {
            "schema_version": EXECUTOR_SCHEMA_VERSION,
            "step_id": self.step_id,
            "idempotency_key": self.idempotency_key,
            "status": self.status,
            "attempts": self.attempts,
            "consumed_wall_seconds": self.consumed_wall_seconds,
            "consumed_cpu_seconds": self.consumed_cpu_seconds,
            "peak_memory_mb": self.peak_memory_mb,
            "evidence": [
                {"output_id": output_id, "evidence_digest": digest}
                for output_id, digest in self.evidence
            ],
            "rollback_ran": self.rollback_ran,
            "outcome_digest": self.outcome_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> StepOutcome:
        """Parse and integrity-check one step outcome."""
        data = require_mapping(value, "outcome")
        if data.get("schema_version") != EXECUTOR_SCHEMA_VERSION:
            raise ValueError("unsupported outcome schema version")
        outcome = cls.build(
            step_id=require_string(data.get("step_id"), "outcome.step_id"),
            idempotency_key=require_string(data.get("idempotency_key"), "outcome.idempotency_key"),
            status=cast(StepStatus, require_string(data.get("status"), "outcome.status")),
            attempts=require_integer(data.get("attempts"), "outcome.attempts", minimum=0),
            consumed_wall_seconds=require_integer(
                data.get("consumed_wall_seconds"),
                "outcome.consumed_wall_seconds",
                minimum=0,
            ),
            consumed_cpu_seconds=require_integer(
                data.get("consumed_cpu_seconds"),
                "outcome.consumed_cpu_seconds",
                minimum=0,
            ),
            peak_memory_mb=require_integer(
                data.get("peak_memory_mb"),
                "outcome.peak_memory_mb",
                minimum=0,
            ),
            evidence=_parse_evidence(data.get("evidence")),
            rollback_ran=_require_bool(data.get("rollback_ran"), "outcome.rollback_ran"),
        )
        if data.get("outcome_digest") != outcome.outcome_digest:
            raise ValueError("outcome digest does not match its content")
        return outcome


def _require_bool(value: object, field: str) -> bool:
    """Return one strict boolean without coercion."""
    return require_boolean(value, field)


def _parse_evidence(value: object) -> tuple[tuple[str, str], ...]:
    """Parse a serialised evidence array into (output id, digest) pairs."""
    if not isinstance(value, list):
        raise ValueError("outcome.evidence must be an array")
    pairs: list[tuple[str, str]] = []
    for item in cast(list[object], value):
        entry = require_mapping(item, "outcome.evidence[]")
        pairs.append(
            (
                require_string(entry.get("output_id"), "outcome.evidence.output_id"),
                require_string(entry.get("evidence_digest"), "outcome.evidence.evidence_digest"),
            )
        )
    return tuple(pairs)


@dataclass(frozen=True)
class LaneExecution:
    """The attested execution of one remediation lane's step DAG.

    Parameters
    ----------
    lane_id:
        The plan lane executed.
    claim_id:
        The isolation claim held while executing the lane.
    status:
        Derived from the step outcomes: all succeeded, all skipped, at least one
        failure without any undo (``failed``), or a failure with prior successes
        undone (``rolled-back``).
    step_outcomes:
        One outcome per lane step.

    """

    lane_id: str
    claim_id: str
    status: LaneStatus
    step_outcomes: tuple[StepOutcome, ...]
    lane_digest: str

    @classmethod
    def build(
        cls,
        *,
        lane_id: str,
        claim_id: str,
        status: LaneStatus,
        step_outcomes: tuple[StepOutcome, ...],
    ) -> LaneExecution:
        """Build one lane execution and reject inconsistent aggregate status."""
        if status not in _LANE_STATUSES:
            raise ValueError("lane_execution.status is unsupported")
        identifier = require_identifier(lane_id, "lane_execution.lane_id")
        claim = require_identifier(claim_id, "lane_execution.claim_id")
        if not step_outcomes:
            raise ValueError("lane_execution.step_outcomes must not be empty")
        validate_unique_strings(
            tuple(item.step_id for item in step_outcomes),
            "lane_execution.step_ids",
            minimum=1,
        )
        expected = _derive_lane_status(step_outcomes)
        if status != expected:
            raise ValueError(f"lane_execution.status must be {expected} for these step outcomes")
        body: dict[str, object] = {
            "schema_version": EXECUTOR_SCHEMA_VERSION,
            "lane_id": identifier,
            "claim_id": claim,
            "status": status,
            "step_outcomes": [item.to_dict() for item in step_outcomes],
        }
        return cls(
            lane_id=identifier,
            claim_id=claim,
            status=status,
            step_outcomes=step_outcomes,
            lane_digest=canonical_digest(body),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one lane execution."""
        return {
            "schema_version": EXECUTOR_SCHEMA_VERSION,
            "lane_id": self.lane_id,
            "claim_id": self.claim_id,
            "status": self.status,
            "step_outcomes": [item.to_dict() for item in self.step_outcomes],
            "lane_digest": self.lane_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> LaneExecution:
        """Parse and integrity-check one lane execution."""
        data = require_mapping(value, "lane_execution")
        if data.get("schema_version") != EXECUTOR_SCHEMA_VERSION:
            raise ValueError("unsupported lane execution schema version")
        outcomes = data.get("step_outcomes")
        if not isinstance(outcomes, list):
            raise ValueError("lane_execution.step_outcomes must be an array")
        lane = cls.build(
            lane_id=require_string(data.get("lane_id"), "lane_execution.lane_id"),
            claim_id=require_string(data.get("claim_id"), "lane_execution.claim_id"),
            status=cast(LaneStatus, require_string(data.get("status"), "lane_execution.status")),
            step_outcomes=tuple(
                StepOutcome.from_dict(item) for item in cast(list[object], outcomes)
            ),
        )
        if data.get("lane_digest") != lane.lane_digest:
            raise ValueError("lane execution digest does not match its content")
        return lane


def _derive_lane_status(step_outcomes: tuple[StepOutcome, ...]) -> LaneStatus:
    """Return the only lane status consistent with the step outcomes."""
    statuses = tuple(item.status for item in step_outcomes)
    failed = any(status == "failed" for status in statuses)
    rolled = any(status == "rolled-back" for status in statuses)
    if rolled and not failed:
        raise ValueError("a rolled-back step requires a failed step in the same lane")
    if all(status == "succeeded" for status in statuses):
        return "succeeded"
    if all(status == "skipped" for status in statuses):
        return "skipped"
    if failed:
        return "rolled-back" if rolled else "failed"
    raise ValueError("lane step outcomes are inconsistent: a skipped step requires a failure")


@dataclass(frozen=True)
class ExecutionLedger:
    """An attested, authority-bound, isolated remediation execution record.

    The ledger is only ever admitted through :meth:`admit`, which binds it to an
    exact approved plan, an explicit authority, and covering isolation claims. It
    proves budget, idempotency, rollback, evidence, and dependency invariants; it
    never executes anything itself.
    """

    authority: ExecutionAuthority
    plan_digest: str
    lane_executions: tuple[LaneExecution, ...]
    started_at: str
    finished_at: str
    resolution: Resolution
    ledger_digest: str

    @classmethod
    def admit(
        cls,
        *,
        plan: RemediationPlan,
        authority: ExecutionAuthority,
        lane_executions: tuple[LaneExecution, ...],
        claims: tuple[ExecutionClaim, ...],
        started_at: str,
        finished_at: str,
    ) -> ExecutionLedger:
        """Admit an attested execution against a plan, authority, and claims."""
        if not authority.authorises(plan):
            raise ValueError("authority does not bind this exact approved plan")
        started = require_utc_timestamp(started_at, "ledger.started_at")
        finished = require_utc_timestamp(finished_at, "ledger.finished_at")
        if parse_utc_timestamp(finished, "ledger.finished_at") < parse_utc_timestamp(
            started,
            "ledger.started_at",
        ):
            raise ValueError("ledger.finished_at must not precede started_at")
        if not lane_executions:
            raise ValueError("ledger.lane_executions must not be empty")
        ordered = tuple(lane_id for batch in plan.execution_batches() for lane_id in batch)
        if tuple(item.lane_id for item in lane_executions) != ordered:
            raise ValueError(
                "lane executions must follow the plan dependency and conflict batches"
            )
        lane_by_id = {lane.lane_id: lane for lane in plan.lanes}
        claim_by_id = _unique_claims(claims)
        for lane_execution in lane_executions:
            _assert_lane_claim(
                lane_by_id[lane_execution.lane_id], lane_execution, authority, claim_by_id
            )
            _assert_lane_steps(lane_by_id[lane_execution.lane_id], lane_execution, authority)
        resolution = _aggregate_and_check(lane_executions, authority)
        if authority.mode == "execute":
            _assert_lane_propagation(plan, lane_executions)
        return cls._assemble(
            authority=authority,
            plan_digest=plan.plan_digest,
            lane_executions=lane_executions,
            started_at=started,
            finished_at=finished,
            resolution=resolution,
        )

    @classmethod
    def _assemble(
        cls,
        *,
        authority: ExecutionAuthority,
        plan_digest: str,
        lane_executions: tuple[LaneExecution, ...],
        started_at: str,
        finished_at: str,
        resolution: Resolution,
    ) -> ExecutionLedger:
        """Assemble and content-address a validated ledger."""
        body: dict[str, object] = {
            "schema_version": EXECUTOR_SCHEMA_VERSION,
            "authority": authority.to_dict(),
            "plan_digest": plan_digest,
            "lane_executions": [item.to_dict() for item in lane_executions],
            "started_at": started_at,
            "finished_at": finished_at,
            "resolution": resolution,
        }
        return cls(
            authority=authority,
            plan_digest=plan_digest,
            lane_executions=lane_executions,
            started_at=started_at,
            finished_at=finished_at,
            resolution=resolution,
            ledger_digest=canonical_digest(body),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the whole attested execution ledger."""
        return {
            "schema_version": EXECUTOR_SCHEMA_VERSION,
            "authority": self.authority.to_dict(),
            "plan_digest": self.plan_digest,
            "lane_executions": [item.to_dict() for item in self.lane_executions],
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "resolution": self.resolution,
            "ledger_digest": self.ledger_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> ExecutionLedger:
        """Parse and integrity-check one ledger without its plan or claims.

        Structural integrity, the resolution, and the mode, budget, and
        idempotency invariants that are self-contained are re-verified. The
        plan-bound checks (batch order, claim coverage, step matching) are the
        admission gate in :meth:`admit`.
        """
        data = require_mapping(value, "ledger")
        if data.get("schema_version") != EXECUTOR_SCHEMA_VERSION:
            raise ValueError("unsupported ledger schema version")
        executions = data.get("lane_executions")
        if not isinstance(executions, list):
            raise ValueError("ledger.lane_executions must be an array")
        if not executions:
            raise ValueError("ledger.lane_executions must not be empty")
        authority = ExecutionAuthority.from_dict(data.get("authority"))
        lane_executions = tuple(
            LaneExecution.from_dict(item) for item in cast(list[object], executions)
        )
        resolution = _aggregate_and_check(lane_executions, authority)
        if data.get("resolution") != resolution:
            raise ValueError("ledger resolution is inconsistent with its lane outcomes")
        ledger = cls._assemble(
            authority=authority,
            plan_digest=require_digest(data.get("plan_digest"), "ledger.plan_digest"),
            lane_executions=lane_executions,
            started_at=require_utc_timestamp(data.get("started_at"), "ledger.started_at"),
            finished_at=require_utc_timestamp(data.get("finished_at"), "ledger.finished_at"),
            resolution=resolution,
        )
        if data.get("ledger_digest") != ledger.ledger_digest:
            raise ValueError("ledger digest does not match its content")
        return ledger


def _unique_claims(claims: tuple[ExecutionClaim, ...]) -> dict[str, ExecutionClaim]:
    """Return claims keyed by id, rejecting duplicate claim ids."""
    by_id: dict[str, ExecutionClaim] = {}
    for claim in claims:
        if claim.claim_id in by_id:
            raise ValueError(f"ledger claim {claim.claim_id} is supplied more than once")
        by_id[claim.claim_id] = claim
    return by_id


def _assert_lane_claim(
    lane: RemediationLane,
    lane_execution: LaneExecution,
    authority: ExecutionAuthority,
    claim_by_id: dict[str, ExecutionClaim],
) -> None:
    """Prove the lane's claim exists, is in-repository, and covers its writes."""
    claim = claim_by_id.get(lane_execution.claim_id)
    if claim is None:
        raise ValueError(
            f"lane {lane_execution.lane_id} references unknown claim {lane_execution.claim_id}"
        )
    if claim.lane_id != lane_execution.lane_id:
        raise ValueError(f"claim {claim.claim_id} does not bind lane {lane_execution.lane_id}")
    if claim.repository_id != authority.repository_id:
        raise ValueError(f"claim {claim.claim_id} is outside the authority repository")
    if not set(lane.write_set).issubset(claim.write_set):
        raise ValueError(f"claim {claim.claim_id} does not cover the lane write set")


def _assert_lane_steps(
    lane: RemediationLane,
    lane_execution: LaneExecution,
    authority: ExecutionAuthority,
) -> None:
    """Prove each outcome matches its plan step, budget, and evidence contract."""
    plan_steps = {step.step_id: step for step in lane.steps}
    if {item.step_id for item in lane_execution.step_outcomes} != set(plan_steps):
        raise ValueError(f"lane {lane_execution.lane_id} outcomes must match the plan steps")
    for outcome in lane_execution.step_outcomes:
        step = plan_steps[outcome.step_id]
        if outcome.idempotency_key != step.idempotency_key:
            raise ValueError(f"step {outcome.step_id} idempotency key does not match the plan")
        if not authority.budget.admits_step(step):
            raise ValueError(f"step {outcome.step_id} budget exceeds the authority ceiling")
        if outcome.status in _EXECUTED:
            if {output_id for output_id, _ in outcome.evidence} != set(step.evidence_output_ids):
                raise ValueError(
                    f"step {outcome.step_id} evidence must cover its declared outputs"
                )
            if outcome.status == "rolled-back" and not step.rollback_adapter_id:
                raise ValueError(
                    f"step {outcome.step_id} cannot roll back without a declared rollback"
                )


def _aggregate_and_check(
    lane_executions: tuple[LaneExecution, ...],
    authority: ExecutionAuthority,
) -> Resolution:
    """Enforce mode, budget, and idempotency invariants and derive the resolution."""
    total_wall = 0
    total_cpu = 0
    peak_memory = 0
    executed = 0
    outcome_by_key: dict[str, str] = {}
    for lane_execution in lane_executions:
        for outcome in lane_execution.step_outcomes:
            if outcome.status not in _EXECUTED:
                continue
            total_wall += outcome.consumed_wall_seconds
            total_cpu += outcome.consumed_cpu_seconds
            peak_memory = max(peak_memory, outcome.peak_memory_mb)
            executed += 1
            prior = outcome_by_key.get(outcome.idempotency_key)
            if prior is not None and prior != outcome.outcome_digest:
                raise ValueError(
                    f"idempotency key {outcome.idempotency_key} has divergent outcomes"
                )
            outcome_by_key[outcome.idempotency_key] = outcome.outcome_digest
    if authority.mode == "observe" and executed:
        raise ValueError("observe authority cannot record an executed step")
    if not authority.budget.within(
        wall_seconds=total_wall,
        cpu_seconds=total_cpu,
        peak_memory_mb=peak_memory,
        executed_steps=executed,
    ):
        raise ValueError("execution exceeds the authority budget")
    return _derive_resolution(tuple(item.status for item in lane_executions))


def _derive_resolution(statuses: tuple[str, ...]) -> Resolution:
    """Return the ledger resolution from lane statuses."""
    if any(status == "rolled-back" for status in statuses):
        return "rolled-back"
    if any(status == "failed" for status in statuses):
        return "failed"
    return "succeeded"


def _assert_lane_propagation(
    plan: RemediationPlan,
    lane_executions: tuple[LaneExecution, ...],
) -> None:
    """Prove a lane is skipped exactly when a prerequisite lane failed."""
    lane_by_id = {lane.lane_id: lane for lane in plan.lanes}
    failed = {item.lane_id for item in lane_executions if item.status in {"failed", "rolled-back"}}
    for lane_execution in lane_executions:
        prerequisites = _transitive_prerequisites(lane_execution.lane_id, lane_by_id)
        has_failed_prerequisite = bool(prerequisites & failed)
        if has_failed_prerequisite and lane_execution.status != "skipped":
            raise ValueError(
                f"lane {lane_execution.lane_id} depends on a failed lane and must be skipped"
            )
        if not has_failed_prerequisite and lane_execution.status == "skipped":
            raise ValueError(
                f"lane {lane_execution.lane_id} was skipped without a failed prerequisite"
            )


def _transitive_prerequisites(
    lane_id: str,
    lane_by_id: dict[str, RemediationLane],
) -> set[str]:
    """Return every lane reachable from ``lane_id`` through prerequisite edges."""
    seen: set[str] = set()
    stack = list(lane_by_id[lane_id].prerequisite_lane_ids)
    while stack:
        prerequisite = stack.pop()
        if prerequisite in seen:
            continue
        seen.add(prerequisite)
        stack.extend(lane_by_id[prerequisite].prerequisite_lane_ids)
    return seen
