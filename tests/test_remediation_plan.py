# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — remediation DAG tests
"""Verify evidence-bound advisory plans, approval, dependencies, and conflicts."""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest

from rigor_foundry._remediation_graph import argv_digest
from rigor_foundry.control_assessment import ControlAssessment, EvidenceReference
from rigor_foundry.effective_profile import (
    AdapterLock,
    EffectiveControl,
    EffectiveProfileLock,
    PackVerification,
)
from rigor_foundry.project_profile import (
    REQUIRED_INTENT_CATEGORIES,
    PackSelection,
    ProjectIntent,
    ProjectProfile,
    RequirementBinding,
    RequirementCategory,
)
from rigor_foundry.remediation_plan import (
    ProcedureStep,
    RemediationLane,
    RemediationPlan,
    TargetGap,
)
from rigor_foundry.standard_pack import (
    ControlDefinition,
    EvidenceContract,
    PackSignature,
    RemediationContract,
    StandardPack,
)

NOW = "2026-07-15T12:00:00Z"


def control(name: str, *, dependencies: tuple[str, ...] = ()) -> ControlDefinition:
    """Return one remediable control."""
    return ControlDefinition.build(
        control_id=f"core/{name}",
        version="1.0.0",
        title=f"Verified {name} control",
        domain="architecture-and-wiring",
        severity="P1",
        target_level="production",
        mode="require",
        default_applicable=True,
        condition=None,
        evidence=EvidenceContract.build(
            contract_id=f"core/{name}/evidence",
            required_adapters=("architecture-adapter",),
            evidence_types=("architecture-report",),
            freshness_seconds=3600,
            minimum_independent_reviewers=1,
        ),
        remediation=RemediationContract.build(
            dependencies=dependencies,
            procedure_ids=(f"repair-{name}",),
            acceptance_gates=(f"verify-{name}",),
            reopen_triggers=("source-change",),
            independent_verifier_required=True,
        ),
    )


def adapter_lock(adapter_id: str, argv: tuple[str, ...]) -> AdapterLock:
    """Return one adapter identity bound to exactly one argv vector."""
    return AdapterLock.build(
        adapter_id=adapter_id,
        version="1.0.0",
        executable_digest="5" * 64,
        config_digest="6" * 64,
        command_digest=argv_digest(argv),
        environment_digest="8" * 64,
        domains=("architecture-and-wiring",),
    )


def locked_controls(
    *,
    dependent: bool = True,
) -> tuple[EffectiveProfileLock, tuple[EffectiveControl, EffectiveControl]]:
    """Return an exact lock with two applicable controls."""
    first = control("base")
    second = control("dependent", dependencies=("core/base",) if dependent else ())
    source_digest = "1" * 64
    payload = StandardPack.payload_digest(
        pack_id="core",
        version="1.0.0",
        source_uri="https://standards.example/core",
        source_digest=source_digest,
        licence="MIT",
        controls=(first, second),
    )
    standard = StandardPack.build(
        pack_id="core",
        version="1.0.0",
        source_uri="https://standards.example/core",
        source_digest=source_digest,
        licence="MIT",
        signature=PackSignature("ed25519", "trusted-key", payload, "2" * 64),
        controls=(first, second),
    )
    requirements = tuple(
        RequirementBinding.build(cast(RequirementCategory, category), ("explicit",))
        for category in sorted(REQUIRED_INTENT_CATEGORIES)
    )
    project = ProjectProfile.build(
        profile_id="rigor-foundry",
        intent=ProjectIntent.build(
            risk_class="production",
            regulatory_classes=(),
            target_maturity="production",
            requirements=requirements,
        ),
        packs=(
            PackSelection.build(
                pack_id=standard.pack_id,
                version=standard.version,
                source_digest=standard.source_digest,
                pack_digest=standard.pack_digest,
                trusted_key_ids=(standard.signature.key_id,),
            ),
        ),
        variables=(),
        assignments=(),
        applicability=(),
        overlays=(),
        waivers=(),
        created_by="profile-owner",
        created_at=NOW,
    )
    verification = PackVerification.build(
        pack_digest=standard.pack_digest,
        key_id=standard.signature.key_id,
        proof_digest="3" * 64,
        tool_digest="4" * 64,
        verified_at="2026-07-15T11:50:00Z",
        valid=True,
    )
    adapters = (
        adapter_lock("architecture-adapter", ("rigor-adapter", "audit")),
        adapter_lock(
            "architecture-base-adapter",
            ("rigor-adapter", "repair", "src/base.py"),
        ),
        adapter_lock(
            "architecture-base-rollback",
            ("rigor-adapter", "rollback", "src/base.py"),
        ),
        adapter_lock(
            "architecture-dependent-adapter",
            ("rigor-adapter", "repair", "src/dependent.py"),
        ),
        adapter_lock(
            "architecture-dependent-rollback",
            ("rigor-adapter", "rollback", "src/dependent.py"),
        ),
    )
    effective = tuple(
        EffectiveControl.build(
            source_pack=standard,
            control=item,
            applicable=True,
            applicability_rationale="production architecture is in scope",
            target_level="production",
            mode="require",
            active_waiver_ids=(),
            missing_adapter_ids=(),
        )
        for item in standard.controls
    )
    lock = EffectiveProfileLock.build(
        profile=project,
        packs=(standard,),
        verifications=(verification,),
        adapters=adapters,
        variables=(),
        controls=effective,
        warnings=(),
        toolchain_digest="9" * 64,
        resolved_at=NOW,
    )
    return lock, cast(tuple[EffectiveControl, EffectiveControl], effective)


def assessments(
    lock: EffectiveProfileLock,
    controls: tuple[EffectiveControl, EffectiveControl],
) -> tuple[ControlAssessment, ControlAssessment]:
    """Return factual failed assessments for both controls."""
    records = []
    evidence_adapter = next(
        item for item in lock.adapters if item.adapter_id == "architecture-adapter"
    )
    for index, item in enumerate(controls, start=1):
        evidence = EvidenceReference.build(
            evidence_id=f"architecture-run-{index}",
            evidence_type="architecture-report",
            adapter_id="architecture-adapter",
            adapter_digest=evidence_adapter.adapter_digest,
            artifact_digest=str(index) * 64,
            artifact_size=512,
            classification="internal",
            reference=f"sha256:{index}/architecture.json",
            observed_at="2026-07-15T11:30:00Z",
            expires_at="2026-07-15T13:00:00Z",
        )
        records.append(
            ControlAssessment.build(
                lock,
                item,
                status="fail",
                assessor="audit-agent",
                assessed_at=NOW,
                evidence=(evidence,),
                rationale="verified architecture contract failure",
            )
        )
    return cast(tuple[ControlAssessment, ControlAssessment], tuple(records))


def gap(
    lock: EffectiveProfileLock,
    control: EffectiveControl,
    assessment: ControlAssessment,
    *,
    suffix: str,
) -> TargetGap:
    """Derive one evidence-bound pass target."""
    return TargetGap.build(
        lock,
        control,
        assessment,
        gap_id=f"gap-{suffix}",
        root_cause=f"root cause for {suffix}",
        risk=f"risk from {suffix}",
        blast_radius=f"bounded {suffix} surface",
        affected_surfaces=(f"src/{suffix}.py",),
    )


def step(suffix: str, *, depends_on: tuple[str, ...] = ()) -> ProcedureStep:
    """Return one argv-only, resource-bounded procedure step."""
    return ProcedureStep.build(
        step_id=f"step-{suffix}",
        adapter_id=f"architecture-{suffix}-adapter",
        argv=("rigor-adapter", "repair", f"src/{suffix}.py"),
        input_schema_ids=("architecture-finding-v1",),
        output_schema_ids=("patch-evidence-v1",),
        timeout_seconds=120,
        cpu_seconds=60,
        memory_mb=512,
        retries=1,
        idempotency_key=f"repair-{suffix}-v1",
        approval_boundary=True,
        rollback_adapter_id=f"architecture-{suffix}-rollback",
        rollback_argv=("rigor-adapter", "rollback", f"src/{suffix}.py"),
        evidence_output_ids=(f"repair-{suffix}-evidence",),
        depends_on=depends_on,
    )


def lane(
    target: TargetGap,
    *,
    suffix: str,
    prerequisites: tuple[str, ...] = (),
    serialization_keys: tuple[str, ...] = (),
    write_set: tuple[str, ...] | None = None,
) -> RemediationLane:
    """Return one exact remediation responsibility lane."""
    return RemediationLane.build(
        lane_id=f"lane-{suffix}",
        gap_ids=(target.gap_id,),
        root_cause=target.root_cause,
        risk=target.risk,
        blast_radius=target.blast_radius,
        affected_surfaces=target.affected_surfaces,
        write_set=(f"src/{suffix}.py",) if write_set is None else write_set,
        semantic_dependencies=(f"src/{suffix}_api.py",),
        prerequisite_lane_ids=prerequisites,
        serialization_keys=serialization_keys,
        non_goals=("no unrelated refactor",),
        migration_plan="preserve public behavior while moving responsibility",
        rollback_plan="restore the exact baseline tree",
        steps=(step(suffix),),
        acceptance_gates=(f"verify-{suffix}",),
        required_verifier="independent-verifier",
    )


def advisory(
    *,
    dependent: bool = True,
    serialization_key: str = "",
    base_write_set: tuple[str, ...] | None = None,
    dependent_write_set: tuple[str, ...] | None = None,
) -> RemediationPlan:
    """Return a complete advisory plan for two failed controls."""
    lock, controls = locked_controls(dependent=dependent)
    records = assessments(lock, controls)
    gaps = (
        gap(lock, controls[0], records[0], suffix="base"),
        gap(lock, controls[1], records[1], suffix="dependent"),
    )
    first_lane = lane(
        gaps[0],
        suffix="base",
        serialization_keys=((serialization_key,) if serialization_key else ()),
        write_set=base_write_set,
    )
    second_lane = lane(
        gaps[1],
        suffix="dependent",
        prerequisites=((first_lane.lane_id,) if dependent else ()),
        serialization_keys=((serialization_key,) if serialization_key else ()),
        write_set=dependent_write_set,
    )
    return RemediationPlan.build_advisory(
        lock,
        assessments=records,
        gaps=gaps,
        lanes=(first_lane, second_lane),
        created_by="planning-agent",
        created_at=NOW,
    )


def test_plan_is_advisory_until_independent_exact_approval() -> None:
    """Generation grants no execution schedule; independent approval binds exact body."""
    plan = advisory()
    assert plan.state == "advisory" and plan.approval is None
    with pytest.raises(ValueError, match="approved"):
        plan.execution_batches()
    with pytest.raises(ValueError, match="author cannot approve"):
        plan.approve(
            approver=plan.created_by,
            approved_at="2026-07-15T12:05:00Z",
            evidence_digest="a" * 64,
        )
    approved = plan.approve(
        approver="independent-approver",
        approved_at="2026-07-15T12:05:00Z",
        evidence_digest="a" * 64,
    )
    assert approved.state == "approved"
    assert approved.body_digest == plan.body_digest
    assert approved.plan_digest != plan.plan_digest
    assert approved.to_dict()["approval"] == approved.approval.to_dict()
    assert approved.execution_batches() == (("lane-base",), ("lane-dependent",))
    with pytest.raises(ValueError, match="only an advisory"):
        approved.approve(
            approver="second-approver",
            approved_at="2026-07-15T12:06:00Z",
            evidence_digest="b" * 64,
        )


def test_conflict_safe_batches_serialize_shared_resources() -> None:
    """Independent lanes parallelize unless keys or parent-child paths conflict."""
    parallel = advisory(dependent=False).approve(
        approver="independent-approver",
        approved_at="2026-07-15T12:05:00Z",
        evidence_digest="a" * 64,
    )
    assert parallel.execution_batches() == (("lane-base", "lane-dependent"),)
    serialized = advisory(dependent=False, serialization_key="shared-api").approve(
        approver="independent-approver",
        approved_at="2026-07-15T12:05:00Z",
        evidence_digest="a" * 64,
    )
    assert serialized.execution_batches() == (("lane-base",), ("lane-dependent",))
    nested = advisory(
        dependent=False,
        base_write_set=("src/package",),
        dependent_write_set=("src/package/module.py",),
    ).approve(
        approver="independent-approver",
        approved_at="2026-07-15T12:05:00Z",
        evidence_digest="a" * 64,
    )
    assert nested.execution_batches() == (("lane-base",), ("lane-dependent",))


def test_procedure_and_rollback_bind_exact_locked_adapter_commands() -> None:
    """Trusted adapter names cannot authorize unknown or altered forward/rollback argv."""
    lock, controls = locked_controls()
    records = assessments(lock, controls)
    gaps = (
        gap(lock, controls[0], records[0], suffix="base"),
        gap(lock, controls[1], records[1], suffix="dependent"),
    )
    base_lane = lane(gaps[0], suffix="base")
    dependent_lane = lane(
        gaps[1],
        suffix="dependent",
        prerequisites=(base_lane.lane_id,),
    )
    base_step = base_lane.steps[0]
    invalid_steps = (
        (replace(base_step, adapter_id="unlocked-adapter"), "procedure references unlocked"),
        (
            replace(base_step, argv=("rigor-adapter", "repair", "src/other.py")),
            "procedure argv",
        ),
        (
            replace(base_step, rollback_adapter_id="unlocked-rollback"),
            "rollback references unlocked",
        ),
        (
            replace(
                base_step,
                rollback_argv=("rigor-adapter", "rollback", "src/other.py"),
            ),
            "rollback argv",
        ),
    )
    for invalid_step, message in invalid_steps:
        with pytest.raises(ValueError, match=message):
            RemediationPlan.build_advisory(
                lock,
                assessments=records,
                gaps=gaps,
                lanes=(replace(base_lane, steps=(invalid_step,)), dependent_lane),
                created_by="planning-agent",
                created_at=NOW,
            )


def test_control_dependencies_must_be_reflected_in_lane_dag() -> None:
    """A dependent failed control cannot omit the prerequisite remediation lane."""
    lock, controls = locked_controls()
    records = assessments(lock, controls)
    gaps = (
        gap(lock, controls[0], records[0], suffix="base"),
        gap(lock, controls[1], records[1], suffix="dependent"),
    )
    with pytest.raises(ValueError, match="missing its lane prerequisite"):
        RemediationPlan.build_advisory(
            lock,
            assessments=records,
            gaps=gaps,
            lanes=(lane(gaps[0], suffix="base"), lane(gaps[1], suffix="dependent")),
            created_by="planning-agent",
            created_at=NOW,
        )
    forged = replace(gaps[0], root_cause="unbound changed cause")
    with pytest.raises(ValueError, match="inconsistent"):
        RemediationPlan.build_advisory(
            lock,
            assessments=records,
            gaps=(forged, gaps[1]),
            lanes=(
                lane(forged, suffix="base"),
                lane(gaps[1], suffix="dependent", prerequisites=("lane-base",)),
            ),
            created_by="planning-agent",
            created_at=NOW,
        )


def test_steps_and_path_sets_are_strictly_bounded() -> None:
    """Shell invocation, excessive resources, ambiguous paths, and cycles are rejected."""
    with pytest.raises(ValueError, match="command shell"):
        ProcedureStep.build(
            step_id="shell-step",
            adapter_id="architecture-adapter",
            argv=("bash", "-c", "rm -rf ."),
            input_schema_ids=(),
            output_schema_ids=(),
            timeout_seconds=10,
            cpu_seconds=10,
            memory_mb=64,
            retries=0,
            idempotency_key="shell-step-v1",
            approval_boundary=True,
            evidence_output_ids=("evidence",),
        )
    with pytest.raises(ValueError, match="resource ceiling"):
        ProcedureStep.build(
            step_id="unbounded-step",
            adapter_id="architecture-adapter",
            argv=("rigor-adapter", "repair"),
            input_schema_ids=(),
            output_schema_ids=(),
            timeout_seconds=3601,
            cpu_seconds=10,
            memory_mb=64,
            retries=0,
            idempotency_key="unbounded-step-v1",
            approval_boundary=True,
            evidence_output_ids=("evidence",),
        )
    lock, controls = locked_controls()
    records = assessments(lock, controls)
    target = gap(lock, controls[0], records[0], suffix="base")
    with pytest.raises(ValueError, match="repository-relative"):
        RemediationLane.build(
            lane_id="unsafe-lane",
            gap_ids=(target.gap_id,),
            root_cause=target.root_cause,
            risk=target.risk,
            blast_radius=target.blast_radius,
            affected_surfaces=target.affected_surfaces,
            write_set=("src//base.py",),
            semantic_dependencies=(),
            prerequisite_lane_ids=(),
            serialization_keys=(),
            non_goals=("no unrelated work",),
            migration_plan="bounded repair",
            rollback_plan="restore baseline",
            steps=(step("base"),),
            acceptance_gates=("verify-base",),
            required_verifier="independent-verifier",
        )


def test_gap_and_plan_crosswiring_is_rejected() -> None:
    """Gaps must bind their exact lock/control and plans must partition every assessment."""
    lock, controls = locked_controls()
    records = assessments(lock, controls)
    with pytest.raises(ValueError, match="profile lock"):
        TargetGap.build(
            lock,
            controls[0],
            replace(records[0], lock_digest="0" * 64),
            gap_id="wrong-lock",
            root_cause="crosswired",
            risk="unknown",
            blast_radius="unknown",
            affected_surfaces=("src/base.py",),
        )
    with pytest.raises(ValueError, match="effective control"):
        TargetGap.build(
            lock,
            controls[0],
            replace(records[0], effective_control_digest="0" * 64),
            gap_id="wrong-control",
            root_cause="crosswired",
            risk="unknown",
            blast_radius="unknown",
            affected_surfaces=("src/base.py",),
        )
    with pytest.raises(ValueError, match="applicable control"):
        TargetGap.build(
            lock,
            replace(controls[0], applicable=False),
            records[0],
            gap_id="not-applicable",
            root_cause="none",
            risk="none",
            blast_radius="none",
            affected_surfaces=("src/base.py",),
        )
    gaps = (
        gap(lock, controls[0], records[0], suffix="base"),
        gap(lock, controls[1], records[1], suffix="dependent"),
    )
    lanes = (
        lane(gaps[0], suffix="base"),
        lane(gaps[1], suffix="dependent", prerequisites=("lane-base",)),
    )
    with pytest.raises(ValueError, match="bind the effective profile lock"):
        RemediationPlan.build_advisory(
            lock,
            assessments=(replace(records[0], lock_digest="0" * 64), records[1]),
            gaps=gaps,
            lanes=lanes,
            created_by="planning-agent",
            created_at=NOW,
        )
    with pytest.raises(ValueError, match="every plan assessment"):
        RemediationPlan.build_advisory(
            lock,
            assessments=records,
            gaps=(gaps[0],),
            lanes=(lanes[0],),
            created_by="planning-agent",
            created_at=NOW,
        )
    with pytest.raises(ValueError, match="exactly one remediation lane"):
        RemediationPlan.build_advisory(
            lock,
            assessments=records,
            gaps=gaps,
            lanes=(replace(lanes[0], gap_ids=(gaps[0].gap_id, gaps[1].gap_id)), lanes[1]),
            created_by="planning-agent",
            created_at=NOW,
        )


def test_step_rollback_retry_and_execution_progress_are_bounded() -> None:
    """Malformed argv/rollback/retry and impossible approved schedules fail closed."""
    base = step("base")
    with pytest.raises(ValueError, match="NUL"):
        ProcedureStep.build(
            step_id="nul-step",
            adapter_id="architecture-adapter",
            argv=("rigor-adapter\x00",),
            input_schema_ids=(),
            output_schema_ids=(),
            timeout_seconds=10,
            cpu_seconds=10,
            memory_mb=64,
            retries=0,
            idempotency_key="nul-step-v1",
            approval_boundary=True,
            evidence_output_ids=("evidence",),
        )
    with pytest.raises(ValueError, match="declared together"):
        ProcedureStep.build(
            step_id="rollback-step",
            adapter_id="architecture-adapter",
            argv=("rigor-adapter", "repair"),
            input_schema_ids=(),
            output_schema_ids=(),
            timeout_seconds=10,
            cpu_seconds=10,
            memory_mb=64,
            retries=0,
            idempotency_key="rollback-step-v1",
            approval_boundary=True,
            rollback_adapter_id="architecture-adapter",
            evidence_output_ids=("evidence",),
        )
    with pytest.raises(ValueError, match="must not exceed 5"):
        ProcedureStep.build(
            step_id="retry-step",
            adapter_id="architecture-adapter",
            argv=("rigor-adapter", "repair"),
            input_schema_ids=(),
            output_schema_ids=(),
            timeout_seconds=10,
            cpu_seconds=10,
            memory_mb=64,
            retries=6,
            idempotency_key="retry-step-v1",
            approval_boundary=True,
            evidence_output_ids=("evidence",),
        )
    lock, controls = locked_controls()
    records = assessments(lock, controls)
    target = gap(lock, controls[0], records[0], suffix="base")
    with pytest.raises(ValueError, match="must not be empty"):
        RemediationLane.build(
            lane_id="empty-lane",
            gap_ids=(target.gap_id,),
            root_cause=target.root_cause,
            risk=target.risk,
            blast_radius=target.blast_radius,
            affected_surfaces=target.affected_surfaces,
            write_set=("src/base.py",),
            semantic_dependencies=(),
            prerequisite_lane_ids=(),
            serialization_keys=(),
            non_goals=("no unrelated work",),
            migration_plan="bounded repair",
            rollback_plan="restore baseline",
            steps=(),
            acceptance_gates=("verify-base",),
            required_verifier="independent-verifier",
        )
    approved = advisory().approve(
        approver="independent-approver",
        approved_at="2026-07-15T12:05:00Z",
        evidence_digest="a" * 64,
    )
    first, second = approved.lanes
    impossible = replace(
        approved,
        lanes=(
            replace(first, prerequisite_lane_ids=(second.lane_id,)),
            replace(second, prerequisite_lane_ids=(first.lane_id,)),
        ),
    )
    with pytest.raises(ValueError, match="cannot make progress"):
        impossible.execution_batches()
    assert base.to_dict()["argv"] == list(base.argv)
    cyclic = replace(step("base"), depends_on=("step-base",))
    with pytest.raises(ValueError, match="cycle"):
        RemediationLane.build(
            lane_id="cyclic-lane",
            gap_ids=(target.gap_id,),
            root_cause=target.root_cause,
            risk=target.risk,
            blast_radius=target.blast_radius,
            affected_surfaces=target.affected_surfaces,
            write_set=("src/base.py",),
            semantic_dependencies=(),
            prerequisite_lane_ids=(),
            serialization_keys=(),
            non_goals=("no unrelated work",),
            migration_plan="bounded repair",
            rollback_plan="restore baseline",
            steps=(cyclic,),
            acceptance_gates=("verify-base",),
            required_verifier="independent-verifier",
        )
