# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — advisory remediation DAGs
"""Plan bounded remediation lanes without granting autonomous execution authority."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from typing import Literal, cast

from ._remediation_graph import assert_dag, assert_locked_commands, paths_overlap
from .control_assessment import AssessmentStatus, ControlAssessment
from .effective_profile import EffectiveControl, EffectiveProfileLock
from .model_primitives import (
    require_boolean,
    require_digest,
    require_identifier,
    require_nonempty_strings,
    require_optional_string,
    require_utc_timestamp,
    validate_unique_strings,
)
from .models import canonical_digest, require_integer, require_string

PLAN_SCHEMA_VERSION = "1.0"

PlanState = Literal["advisory", "approved"]


def _relative_paths(
    paths: tuple[str, ...],
    field: str,
    *,
    minimum: int = 0,
) -> tuple[str, ...]:
    """Return unique repository-relative POSIX paths."""
    values = validate_unique_strings(paths, field, minimum=minimum)
    for value in values:
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or ".." in path.parts
            or value in {"", "."}
            or "\\" in value
            or "\x00" in value
            or path.as_posix() != value
        ):
            raise ValueError(f"{field} must contain repository-relative paths")
    return values


@dataclass(frozen=True)
class TargetGap:
    """Evidence-backed delta from one assessment to the required pass state."""

    gap_id: str
    lock_digest: str
    assessment_digest: str
    effective_control_digest: str
    control_id: str
    current_status: AssessmentStatus
    root_cause: str
    risk: str
    blast_radius: str
    affected_surfaces: tuple[str, ...]
    control_dependencies: tuple[str, ...]
    gap_digest: str

    @classmethod
    def build(
        cls,
        lock: EffectiveProfileLock,
        control: EffectiveControl,
        assessment: ControlAssessment,
        *,
        gap_id: str,
        root_cause: str,
        risk: str,
        blast_radius: str,
        affected_surfaces: tuple[str, ...],
    ) -> TargetGap:
        """Build a gap only for an applicable control that has not passed."""
        if assessment.lock_digest != lock.lock_digest:
            raise ValueError("gap assessment does not bind the effective profile lock")
        if assessment.effective_control_digest != control.effective_digest:
            raise ValueError("gap assessment does not bind the effective control")
        if not control.applicable or assessment.status == "pass":
            raise ValueError("a gap requires an applicable control that has not passed")
        fields: dict[str, object] = {
            "schema_version": PLAN_SCHEMA_VERSION,
            "gap_id": require_identifier(gap_id, "gap.gap_id"),
            "lock_digest": lock.lock_digest,
            "assessment_digest": assessment.assessment_digest,
            "effective_control_digest": control.effective_digest,
            "control_id": control.control.versioned_id,
            "current_status": assessment.status,
            "target_status": "pass",
            "root_cause": require_string(root_cause, "gap.root_cause"),
            "risk": require_string(risk, "gap.risk"),
            "blast_radius": require_string(blast_radius, "gap.blast_radius"),
            "affected_surfaces": list(
                validate_unique_strings(
                    affected_surfaces,
                    "gap.affected_surfaces",
                    minimum=1,
                )
            ),
            "control_dependencies": list(control.control.remediation.dependencies),
        }
        return cls(
            gap_id=cast(str, fields["gap_id"]),
            lock_digest=lock.lock_digest,
            assessment_digest=assessment.assessment_digest,
            effective_control_digest=control.effective_digest,
            control_id=control.control.versioned_id,
            current_status=assessment.status,
            root_cause=cast(str, fields["root_cause"]),
            risk=cast(str, fields["risk"]),
            blast_radius=cast(str, fields["blast_radius"]),
            affected_surfaces=tuple(cast(list[str], fields["affected_surfaces"])),
            control_dependencies=control.control.remediation.dependencies,
            gap_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one target gap."""
        fields: dict[str, object] = asdict(self)
        fields["schema_version"] = PLAN_SCHEMA_VERSION
        fields["target_status"] = "pass"
        fields["affected_surfaces"] = list(self.affected_surfaces)
        fields["control_dependencies"] = list(self.control_dependencies)
        return fields


@dataclass(frozen=True)
class ProcedureStep:
    """One resource-bounded argv-only adapter invocation in a procedure DAG."""

    step_id: str
    adapter_id: str
    argv: tuple[str, ...]
    input_schema_ids: tuple[str, ...]
    output_schema_ids: tuple[str, ...]
    timeout_seconds: int
    cpu_seconds: int
    memory_mb: int
    retries: int
    idempotency_key: str
    approval_boundary: bool
    rollback_adapter_id: str
    rollback_argv: tuple[str, ...]
    evidence_output_ids: tuple[str, ...]
    depends_on: tuple[str, ...]
    step_digest: str

    @classmethod
    def build(
        cls,
        *,
        step_id: str,
        adapter_id: str,
        argv: tuple[str, ...],
        input_schema_ids: tuple[str, ...],
        output_schema_ids: tuple[str, ...],
        timeout_seconds: int,
        cpu_seconds: int,
        memory_mb: int,
        retries: int,
        idempotency_key: str,
        approval_boundary: bool,
        rollback_adapter_id: str = "",
        rollback_argv: tuple[str, ...] = (),
        evidence_output_ids: tuple[str, ...] = (),
        depends_on: tuple[str, ...] = (),
    ) -> ProcedureStep:
        """Build one declarative step without shell or callback execution."""
        validated_argv = require_nonempty_strings(list(argv), "step.argv", minimum=1)
        if any("\x00" in item for item in validated_argv):
            raise ValueError("step.argv must not contain NUL bytes")
        if PurePosixPath(validated_argv[0]).name in {
            "sh",
            "bash",
            "dash",
            "ksh",
            "zsh",
            "fish",
        }:
            raise ValueError("step.argv must not invoke a command shell")
        rollback_id = require_optional_string(rollback_adapter_id, "step.rollback_adapter_id")
        validated_rollback = (
            require_nonempty_strings(list(rollback_argv), "step.rollback_argv", minimum=1)
            if rollback_argv
            else ()
        )
        if bool(rollback_id) != bool(validated_rollback):
            raise ValueError("rollback adapter and argv must be declared together")
        fields: dict[str, object] = {
            "step_id": require_identifier(step_id, "step.step_id"),
            "adapter_id": require_identifier(adapter_id, "step.adapter_id"),
            "argv": list(validated_argv),
            "input_schema_ids": list(
                validate_unique_strings(input_schema_ids, "step.input_schema_ids")
            ),
            "output_schema_ids": list(
                validate_unique_strings(output_schema_ids, "step.output_schema_ids")
            ),
            "timeout_seconds": require_integer(
                timeout_seconds,
                "step.timeout_seconds",
                minimum=1,
            ),
            "cpu_seconds": require_integer(cpu_seconds, "step.cpu_seconds", minimum=1),
            "memory_mb": require_integer(memory_mb, "step.memory_mb", minimum=16),
            "retries": require_integer(retries, "step.retries", minimum=0),
            "idempotency_key": require_identifier(
                idempotency_key,
                "step.idempotency_key",
            ),
            "approval_boundary": require_boolean(
                approval_boundary,
                "step.approval_boundary",
            ),
            "rollback_adapter_id": rollback_id,
            "rollback_argv": list(validated_rollback),
            "evidence_output_ids": list(
                validate_unique_strings(
                    evidence_output_ids,
                    "step.evidence_output_ids",
                    minimum=1,
                )
            ),
            "depends_on": list(validate_unique_strings(depends_on, "step.depends_on")),
        }
        if cast(int, fields["retries"]) > 5:
            raise ValueError("step.retries must not exceed 5")
        for field, maximum in (
            ("timeout_seconds", 3600),
            ("cpu_seconds", 3600),
            ("memory_mb", 65536),
        ):
            if cast(int, fields[field]) > maximum:
                raise ValueError(f"step.{field} exceeds the resource ceiling")
        return cls(
            step_id=cast(str, fields["step_id"]),
            adapter_id=cast(str, fields["adapter_id"]),
            argv=validated_argv,
            input_schema_ids=tuple(cast(list[str], fields["input_schema_ids"])),
            output_schema_ids=tuple(cast(list[str], fields["output_schema_ids"])),
            timeout_seconds=cast(int, fields["timeout_seconds"]),
            cpu_seconds=cast(int, fields["cpu_seconds"]),
            memory_mb=cast(int, fields["memory_mb"]),
            retries=cast(int, fields["retries"]),
            idempotency_key=cast(str, fields["idempotency_key"]),
            approval_boundary=cast(bool, fields["approval_boundary"]),
            rollback_adapter_id=rollback_id,
            rollback_argv=validated_rollback,
            evidence_output_ids=tuple(cast(list[str], fields["evidence_output_ids"])),
            depends_on=tuple(cast(list[str], fields["depends_on"])),
            step_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one declarative procedure step."""
        return {
            "step_id": self.step_id,
            "adapter_id": self.adapter_id,
            "argv": list(self.argv),
            "input_schema_ids": list(self.input_schema_ids),
            "output_schema_ids": list(self.output_schema_ids),
            "timeout_seconds": self.timeout_seconds,
            "cpu_seconds": self.cpu_seconds,
            "memory_mb": self.memory_mb,
            "retries": self.retries,
            "idempotency_key": self.idempotency_key,
            "approval_boundary": self.approval_boundary,
            "rollback_adapter_id": self.rollback_adapter_id,
            "rollback_argv": list(self.rollback_argv),
            "evidence_output_ids": list(self.evidence_output_ids),
            "depends_on": list(self.depends_on),
            "step_digest": self.step_digest,
        }


@dataclass(frozen=True)
class RemediationLane:
    """One bounded responsibility lane with exact conflict and acceptance sets."""

    lane_id: str
    gap_ids: tuple[str, ...]
    root_cause: str
    risk: str
    blast_radius: str
    affected_surfaces: tuple[str, ...]
    write_set: tuple[str, ...]
    semantic_dependencies: tuple[str, ...]
    prerequisite_lane_ids: tuple[str, ...]
    serialization_keys: tuple[str, ...]
    non_goals: tuple[str, ...]
    migration_plan: str
    rollback_plan: str
    steps: tuple[ProcedureStep, ...]
    acceptance_gates: tuple[str, ...]
    required_verifier: str
    lane_digest: str

    @classmethod
    def build(
        cls,
        *,
        lane_id: str,
        gap_ids: tuple[str, ...],
        root_cause: str,
        risk: str,
        blast_radius: str,
        affected_surfaces: tuple[str, ...],
        write_set: tuple[str, ...],
        semantic_dependencies: tuple[str, ...],
        prerequisite_lane_ids: tuple[str, ...],
        serialization_keys: tuple[str, ...],
        non_goals: tuple[str, ...],
        migration_plan: str,
        rollback_plan: str,
        steps: tuple[ProcedureStep, ...],
        acceptance_gates: tuple[str, ...],
        required_verifier: str,
    ) -> RemediationLane:
        """Build one lane and reject cyclic or under-specified procedures."""
        if not steps:
            raise ValueError("lane.steps must not be empty")
        step_ids = tuple(item.step_id for item in steps)
        validate_unique_strings(step_ids, "lane.step_ids", minimum=1)
        assert_dag(
            set(step_ids),
            {item.step_id: item.depends_on for item in steps},
            "lane.steps",
        )
        fields: dict[str, object] = {
            "lane_id": require_identifier(lane_id, "lane.lane_id"),
            "gap_ids": list(validate_unique_strings(gap_ids, "lane.gap_ids", minimum=1)),
            "root_cause": require_string(root_cause, "lane.root_cause"),
            "risk": require_string(risk, "lane.risk"),
            "blast_radius": require_string(blast_radius, "lane.blast_radius"),
            "affected_surfaces": list(
                validate_unique_strings(
                    affected_surfaces,
                    "lane.affected_surfaces",
                    minimum=1,
                )
            ),
            "write_set": list(_relative_paths(write_set, "lane.write_set", minimum=1)),
            "semantic_dependencies": list(
                _relative_paths(semantic_dependencies, "lane.semantic_dependencies")
            ),
            "prerequisite_lane_ids": list(
                validate_unique_strings(
                    prerequisite_lane_ids,
                    "lane.prerequisite_lane_ids",
                )
            ),
            "serialization_keys": list(
                validate_unique_strings(serialization_keys, "lane.serialization_keys")
            ),
            "non_goals": list(validate_unique_strings(non_goals, "lane.non_goals", minimum=1)),
            "migration_plan": require_string(migration_plan, "lane.migration_plan"),
            "rollback_plan": require_string(rollback_plan, "lane.rollback_plan"),
            "steps": [item.to_dict() for item in steps],
            "acceptance_gates": list(
                validate_unique_strings(
                    acceptance_gates,
                    "lane.acceptance_gates",
                    minimum=1,
                )
            ),
            "required_verifier": require_string(required_verifier, "lane.required_verifier"),
        }
        return cls(
            lane_id=cast(str, fields["lane_id"]),
            gap_ids=tuple(cast(list[str], fields["gap_ids"])),
            root_cause=cast(str, fields["root_cause"]),
            risk=cast(str, fields["risk"]),
            blast_radius=cast(str, fields["blast_radius"]),
            affected_surfaces=tuple(cast(list[str], fields["affected_surfaces"])),
            write_set=tuple(cast(list[str], fields["write_set"])),
            semantic_dependencies=tuple(cast(list[str], fields["semantic_dependencies"])),
            prerequisite_lane_ids=tuple(cast(list[str], fields["prerequisite_lane_ids"])),
            serialization_keys=tuple(cast(list[str], fields["serialization_keys"])),
            non_goals=tuple(cast(list[str], fields["non_goals"])),
            migration_plan=cast(str, fields["migration_plan"]),
            rollback_plan=cast(str, fields["rollback_plan"]),
            steps=steps,
            acceptance_gates=tuple(cast(list[str], fields["acceptance_gates"])),
            required_verifier=cast(str, fields["required_verifier"]),
            lane_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one bounded remediation lane."""
        return {
            "lane_id": self.lane_id,
            "gap_ids": list(self.gap_ids),
            "root_cause": self.root_cause,
            "risk": self.risk,
            "blast_radius": self.blast_radius,
            "affected_surfaces": list(self.affected_surfaces),
            "write_set": list(self.write_set),
            "semantic_dependencies": list(self.semantic_dependencies),
            "prerequisite_lane_ids": list(self.prerequisite_lane_ids),
            "serialization_keys": list(self.serialization_keys),
            "non_goals": list(self.non_goals),
            "migration_plan": self.migration_plan,
            "rollback_plan": self.rollback_plan,
            "steps": [item.to_dict() for item in self.steps],
            "acceptance_gates": list(self.acceptance_gates),
            "required_verifier": self.required_verifier,
            "lane_digest": self.lane_digest,
        }


@dataclass(frozen=True)
class PlanApproval:
    """Independent approval bound to the exact advisory plan body."""

    approver: str
    approved_at: str
    evidence_digest: str
    lock_digest: str
    body_digest: str
    approval_digest: str

    @classmethod
    def build(
        cls,
        *,
        approver: str,
        approved_at: str,
        evidence_digest: str,
        lock_digest: str,
        body_digest: str,
    ) -> PlanApproval:
        """Build one exact independent approval record."""
        fields = {
            "approver": require_string(approver, "approval.approver"),
            "approved_at": require_utc_timestamp(approved_at, "approval.approved_at"),
            "evidence_digest": require_digest(
                evidence_digest,
                "approval.evidence_digest",
            ),
            "lock_digest": require_digest(lock_digest, "approval.lock_digest"),
            "body_digest": require_digest(body_digest, "approval.body_digest"),
        }
        return cls(
            approver=fields["approver"],
            approved_at=fields["approved_at"],
            evidence_digest=fields["evidence_digest"],
            lock_digest=fields["lock_digest"],
            body_digest=fields["body_digest"],
            approval_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, str]:
        """Serialise independent plan approval."""
        return cast(dict[str, str], asdict(self))


@dataclass(frozen=True)
class RemediationPlan:
    """Advisory or independently approved conflict-safe remediation DAG."""

    lock_digest: str
    assessment_digests: tuple[str, ...]
    gaps: tuple[TargetGap, ...]
    lanes: tuple[RemediationLane, ...]
    state: PlanState
    created_by: str
    created_at: str
    body_digest: str
    approval: PlanApproval | None
    plan_digest: str

    @classmethod
    def build_advisory(
        cls,
        lock: EffectiveProfileLock,
        *,
        assessments: tuple[ControlAssessment, ...],
        gaps: tuple[TargetGap, ...],
        lanes: tuple[RemediationLane, ...],
        created_by: str,
        created_at: str,
    ) -> RemediationPlan:
        """Build an advisory-only plan; generation never grants execution authority."""
        assessment_digests = tuple(item.assessment_digest for item in assessments)
        validate_unique_strings(assessment_digests, "plan.assessment_digests", minimum=1)
        validate_unique_strings(
            tuple(item.control_id for item in assessments),
            "plan.assessment_control_ids",
            minimum=1,
        )
        gap_ids = tuple(item.gap_id for item in gaps)
        lane_ids = tuple(item.lane_id for item in lanes)
        validate_unique_strings(gap_ids, "plan.gap_ids", minimum=1)
        validate_unique_strings(lane_ids, "plan.lane_ids", minimum=1)
        procedures = tuple(step for lane in lanes for step in lane.steps)
        assert_locked_commands(lock.adapters, procedures)
        if {item.lock_digest for item in assessments} != {lock.lock_digest}:
            raise ValueError("all plan assessments must bind the effective profile lock")
        if {item.assessment_digest for item in gaps} != set(assessment_digests):
            raise ValueError("every plan assessment must have exactly one target gap")
        assessment_by_digest = {item.assessment_digest: item for item in assessments}
        for gap in gaps:
            assessment = assessment_by_digest[gap.assessment_digest]
            controls = tuple(
                item
                for item in lock.controls
                if item.effective_digest == assessment.effective_control_digest
            )
            if len(controls) != 1 or gap != TargetGap.build(
                lock,
                controls[0],
                assessment,
                gap_id=gap.gap_id,
                root_cause=gap.root_cause,
                risk=gap.risk,
                blast_radius=gap.blast_radius,
                affected_surfaces=gap.affected_surfaces,
            ):
                raise ValueError("target gap is inconsistent with its assessment")
        lane_gap_ids = tuple(gap_id for lane in lanes for gap_id in lane.gap_ids)
        if len(lane_gap_ids) != len(set(lane_gap_ids)) or set(lane_gap_ids) != set(gap_ids):
            raise ValueError("every target gap must belong to exactly one remediation lane")
        lane_by_gap = {gap_id: lane for lane in lanes for gap_id in lane.gap_ids}
        lane_by_control = {
            gap.control_id.partition("@")[0]: lane_by_gap[gap.gap_id] for gap in gaps
        }
        for gap in gaps:
            lane = lane_by_gap[gap.gap_id]
            for dependency in gap.control_dependencies:
                prerequisite = lane_by_control.get(dependency)
                if (
                    prerequisite is not None
                    and prerequisite.lane_id != lane.lane_id
                    and prerequisite.lane_id not in lane.prerequisite_lane_ids
                ):
                    raise ValueError("control dependency is missing its lane prerequisite")
        assert_dag(
            set(lane_ids),
            {item.lane_id: item.prerequisite_lane_ids for item in lanes},
            "plan.lanes",
        )
        body: dict[str, object] = {
            "schema_version": PLAN_SCHEMA_VERSION,
            "lock_digest": lock.lock_digest,
            "assessment_digests": sorted(assessment_digests),
            "gaps": [item.to_dict() for item in sorted(gaps, key=lambda item: item.gap_id)],
            "lanes": [item.to_dict() for item in sorted(lanes, key=lambda item: item.lane_id)],
            "created_by": require_string(created_by, "plan.created_by"),
            "created_at": require_utc_timestamp(created_at, "plan.created_at"),
        }
        body_digest = canonical_digest(body)
        envelope = {**body, "state": "advisory", "approval": None, "body_digest": body_digest}
        return cls(
            lock_digest=lock.lock_digest,
            assessment_digests=tuple(sorted(assessment_digests)),
            gaps=tuple(sorted(gaps, key=lambda item: item.gap_id)),
            lanes=tuple(sorted(lanes, key=lambda item: item.lane_id)),
            state="advisory",
            created_by=cast(str, body["created_by"]),
            created_at=cast(str, body["created_at"]),
            body_digest=body_digest,
            approval=None,
            plan_digest=canonical_digest(envelope),
        )

    def approve(
        self,
        *,
        approver: str,
        approved_at: str,
        evidence_digest: str,
    ) -> RemediationPlan:
        """Return an independently approved copy of this exact advisory plan."""
        if self.state != "advisory" or self.approval is not None:
            raise ValueError("only an advisory plan can be approved")
        if approver == self.created_by:
            raise ValueError("plan author cannot approve the plan")
        approval = PlanApproval.build(
            approver=approver,
            approved_at=approved_at,
            evidence_digest=evidence_digest,
            lock_digest=self.lock_digest,
            body_digest=self.body_digest,
        )
        envelope = {
            **self._body_dict(),
            "state": "approved",
            "approval": approval.to_dict(),
            "body_digest": self.body_digest,
        }
        return RemediationPlan(
            lock_digest=self.lock_digest,
            assessment_digests=self.assessment_digests,
            gaps=self.gaps,
            lanes=self.lanes,
            state="approved",
            created_by=self.created_by,
            created_at=self.created_at,
            body_digest=self.body_digest,
            approval=approval,
            plan_digest=canonical_digest(envelope),
        )

    def _body_dict(self) -> dict[str, object]:
        """Return the exact advisory body bound by approval."""
        return {
            "schema_version": PLAN_SCHEMA_VERSION,
            "lock_digest": self.lock_digest,
            "assessment_digests": list(self.assessment_digests),
            "gaps": [item.to_dict() for item in self.gaps],
            "lanes": [item.to_dict() for item in self.lanes],
            "created_by": self.created_by,
            "created_at": self.created_at,
        }

    def to_dict(self) -> dict[str, object]:
        """Serialise the advisory or approved plan envelope."""
        return {
            **self._body_dict(),
            "state": self.state,
            "body_digest": self.body_digest,
            "approval": self.approval.to_dict() if self.approval else None,
            "plan_digest": self.plan_digest,
        }

    def execution_batches(self) -> tuple[tuple[str, ...], ...]:
        """Return deterministic dependency and conflict-safe parallel batches."""
        if self.state != "approved" or self.approval is None:
            raise ValueError("execution scheduling requires an independently approved plan")
        remaining = {lane.lane_id: lane for lane in self.lanes}
        completed: set[str] = set()
        batches: list[tuple[str, ...]] = []
        while remaining:
            ready = tuple(
                lane
                for lane in sorted(remaining.values(), key=lambda item: item.lane_id)
                if set(lane.prerequisite_lane_ids).issubset(completed)
            )
            if not ready:
                raise ValueError("plan lane DAG cannot make progress")
            batch: list[RemediationLane] = []
            for lane in ready:
                if all(not self._conflicts(lane, selected) for selected in batch):
                    batch.append(lane)
            batch_ids = tuple(item.lane_id for item in batch)
            batches.append(batch_ids)
            completed.update(batch_ids)
            for lane_id in batch_ids:
                del remaining[lane_id]
        return tuple(batches)

    @staticmethod
    def _conflicts(left: RemediationLane, right: RemediationLane) -> bool:
        """Return whether two otherwise-ready lanes must be serialized."""
        return bool(
            paths_overlap(left.write_set, right.write_set)
            or paths_overlap(left.write_set, right.semantic_dependencies)
            or paths_overlap(right.write_set, left.semantic_dependencies)
            or set(left.serialization_keys).intersection(right.serialization_keys)
        )
