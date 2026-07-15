# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — work lifecycle tests
"""Verify evidence-bound task promotion and append-only lifecycle wiring."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from typing import cast

import pytest

from rigor_foundry.model_primitives import WorkEvidence
from rigor_foundry.models import (
    AUDIT_DOMAINS,
    AuditDomainSpec,
    AuditPolicy,
    AuditReport,
    Candidate,
    ReviewRecord,
    canonical_digest,
)
from rigor_foundry.work_models import WorkEvent, WorkRecord, WorkTask

HEAD = "1" * 40
TREE = "2" * 40
CONTENT = "3" * 64
COMMIT = "4" * 40
COMMIT_TREE = "5" * 40


def source_records() -> tuple[AuditReport, ReviewRecord]:
    """Return one exact audit report and completed valid review."""
    candidate = Candidate.build(
        category="architecture",
        rule_id="AR001-first-party-import-cycle",
        path="src/rigor_foundry/a.py",
        line=10,
        symbol="a -> b -> a",
        evidence="first-party import graph contains a cycle",
        confidence="high",
        rationale="runtime ownership requires verification",
        verification="import both public modules in an isolated interpreter",
    )
    policy = AuditPolicy(
        audit_domains=tuple(
            AuditDomainSpec(name, "not-applicable", "covered outside this unit record")
            for name in AUDIT_DOMAINS
        )
    )
    report = AuditReport.build(
        repository_root="/workspace/rigor-foundry",
        head=HEAD,
        head_tree=TREE,
        branch="main",
        tracked_content_digest=CONTENT,
        dirty_paths=("src/rigor_foundry/a.py",),
        tracked_file_count=12,
        policy=policy,
        candidates=(candidate,),
    )
    review = ReviewRecord(
        report_digest=report.report_digest,
        candidate_id=candidate.candidate_id,
        decision="valid",
        reviewer="audit-reviewer",
        reviewed_at="2026-07-15T10:00:00Z",
        rationale="cycle reproduced from the exact report tree",
        evidence=("sha256:review-evidence",),
        severity="P1",
        owner="implementation-owner",
        dependencies=(),
        acceptance_gates=("focused-import-test",),
        title="Remove first-party import cycle",
        boundary_justification="not an accepted architecture boundary",
        expires_at="",
        reopen_triggers=("import-graph-change",),
    )
    return report, review


def task() -> WorkTask:
    """Promote one verified review into a bounded work task."""
    report, review = source_records()
    return WorkTask.build(
        report,
        review,
        task_id="architecture-import-cycle",
        production_impact="cycle can create partial module initialization",
        affected_surfaces=("src/rigor_foundry/a.py", "src/rigor_foundry/b.py"),
        prohibited_shortcuts=("no lazy-import masking", "no test deletion"),
        required_verifier="independent-verifier",
        created_by="planning-agent",
        created_at="2026-07-15T10:05:00Z",
    )


def evidence(label: str) -> WorkEvidence:
    """Return one exact focused command observation."""
    return WorkEvidence(
        description=f"{label} completed against exact tree",
        command=("python", "-m", "pytest", f"tests/{label}.py"),
        exit_code=0,
        output_digest=(label[0].encode().hex()[0] if label else "a") * 64,
    )


def lifecycle(*, verifier: str = "independent-verifier", verified_commit: str = COMMIT):
    """Return a complete immutable lifecycle for one task."""
    definition = task()
    events = []
    proposed = WorkEvent.build(
        sequence=1,
        task_id=definition.task_id,
        previous_state=None,
        state="proposed-task",
        actor="planning-agent",
        occurred_at="2026-07-15T10:05:00Z",
        head=HEAD,
        head_tree=TREE,
        tracked_content_digest=CONTENT,
    )
    events.append(proposed)
    revalidated = WorkEvent.build(
        sequence=2,
        task_id=definition.task_id,
        previous_state=proposed.state,
        state="revalidated",
        actor="audit-reviewer",
        occurred_at="2026-07-15T10:10:00Z",
        head=HEAD,
        head_tree=TREE,
        tracked_content_digest=CONTENT,
        candidate_id=definition.candidate.candidate_id,
        report_digest=definition.source_report_digest,
        evidence=(evidence("revalidation"),),
        previous_event_digest=proposed.event_digest,
    )
    events.append(revalidated)
    claimed = WorkEvent.build(
        sequence=3,
        task_id=definition.task_id,
        previous_state=revalidated.state,
        state="claimed",
        actor="implementation-owner",
        occurred_at="2026-07-15T10:15:00Z",
        head=HEAD,
        head_tree=TREE,
        tracked_content_digest=CONTENT,
        owner="implementation-owner",
        previous_event_digest=revalidated.event_digest,
    )
    events.append(claimed)
    in_progress = WorkEvent.build(
        sequence=4,
        task_id=definition.task_id,
        previous_state=claimed.state,
        state="in-progress",
        actor="implementation-owner",
        occurred_at="2026-07-15T10:20:00Z",
        head=HEAD,
        head_tree=TREE,
        tracked_content_digest=CONTENT,
        owner="implementation-owner",
        previous_event_digest=claimed.event_digest,
    )
    events.append(in_progress)
    resolved = WorkEvent.build(
        sequence=5,
        task_id=definition.task_id,
        previous_state=in_progress.state,
        state="resolved-pending-verification",
        actor="implementation-owner",
        occurred_at="2026-07-15T11:00:00Z",
        head=COMMIT,
        head_tree=COMMIT_TREE,
        tracked_content_digest="6" * 64,
        owner="implementation-owner",
        commit_sha=COMMIT,
        commit_tree=COMMIT_TREE,
        evidence=(evidence("focused_resolution"),),
        previous_event_digest=in_progress.event_digest,
    )
    events.append(resolved)
    verified = WorkEvent.build(
        sequence=6,
        task_id=definition.task_id,
        previous_state=resolved.state,
        state="independently-verified",
        actor=verifier,
        occurred_at="2026-07-15T11:15:00Z",
        head=COMMIT,
        head_tree=COMMIT_TREE,
        tracked_content_digest="6" * 64,
        commit_sha=verified_commit,
        commit_tree=COMMIT_TREE,
        verifier=verifier,
        evidence=(evidence("independent_verification"),),
        previous_event_digest=resolved.event_digest,
    )
    events.append(verified)
    closed = WorkEvent.build(
        sequence=7,
        task_id=definition.task_id,
        previous_state=verified.state,
        state="closed",
        actor=verifier,
        occurred_at="2026-07-15T11:20:00Z",
        head=COMMIT,
        head_tree=COMMIT_TREE,
        tracked_content_digest="6" * 64,
        commit_sha=verified_commit,
        commit_tree=COMMIT_TREE,
        verifier=verifier,
        previous_event_digest=verified.event_digest,
    )
    events.append(closed)
    archived = WorkEvent.build(
        sequence=8,
        task_id=definition.task_id,
        previous_state=closed.state,
        state="archived",
        actor="registry-maintainer",
        occurred_at="2026-07-15T11:30:00Z",
        head=COMMIT,
        head_tree=COMMIT_TREE,
        tracked_content_digest="6" * 64,
        reason="closed record moved to bounded archive",
        evidence=(evidence("archive_integrity"),),
        previous_event_digest=closed.event_digest,
    )
    events.append(archived)
    return definition, tuple(events)


def test_task_and_full_lifecycle_round_trip_with_registry_projection() -> None:
    """Valid review promotion and every transition preserve exact immutable digests."""
    definition, events = lifecycle()
    assert WorkTask.from_dict(definition.to_dict()) == definition
    assert tuple(WorkEvent.from_dict(event.to_dict()) for event in events) == events
    record = WorkRecord.build(definition, events)
    assert record.current.state == "archived"
    assert record.owner == "implementation-owner"
    assert record.resolution == events[4]
    registry = record.registry_entry(".rigor/tasks/architecture-import-cycle.jsonl")
    assert registry["resolving_commit"] == COMMIT
    assert registry["event_count"] == 8


def test_only_completed_valid_reviews_can_define_tasks() -> None:
    """Needs-evidence reviews and owner/verifier self-review never promote."""
    report, review = source_records()
    with pytest.raises(ValueError, match="valid review"):
        WorkTask.build(
            report,
            ReviewRecord.template(report.report_digest, report.candidates[0].candidate_id),
            task_id="invalid-promotion",
            production_impact="unknown",
            affected_surfaces=("src/a.py",),
            prohibited_shortcuts=("no guessing",),
            required_verifier="independent-verifier",
            created_by="planning-agent",
            created_at="2026-07-15T10:05:00Z",
        )
    with pytest.raises(ValueError, match="must differ"):
        WorkTask.build(
            report,
            review,
            task_id="self-review",
            production_impact="cycle",
            affected_surfaces=("src/a.py",),
            prohibited_shortcuts=("no masking",),
            required_verifier=review.owner,
            created_by="planning-agent",
            created_at="2026-07-15T10:05:00Z",
        )


def test_event_digests_and_transition_contracts_fail_closed() -> None:
    """Tampering, skipped states, and duplicate evidence cannot enter the chain."""
    definition = task()
    first = WorkEvent.build(
        sequence=1,
        task_id=definition.task_id,
        previous_state=None,
        state="proposed-task",
        actor="planning-agent",
        occurred_at="2026-07-15T10:05:00Z",
        head=HEAD,
        head_tree=TREE,
        tracked_content_digest=CONTENT,
    )
    tampered = deepcopy(first.to_dict())
    tampered["actor"] = "other-agent"
    with pytest.raises(ValueError, match="digest"):
        WorkEvent.from_dict(tampered)
    with pytest.raises(ValueError, match="allowed forward transition"):
        WorkEvent.build(
            sequence=2,
            task_id=definition.task_id,
            previous_state="proposed-task",
            state="claimed",
            actor="owner",
            occurred_at="2026-07-15T10:10:00Z",
            head=HEAD,
            head_tree=TREE,
            tracked_content_digest=CONTENT,
            owner="owner",
            previous_event_digest=first.event_digest,
        )
    duplicate = evidence("same")
    with pytest.raises(ValueError, match="must be unique"):
        WorkEvent.build(
            sequence=2,
            task_id=definition.task_id,
            previous_state="proposed-task",
            state="revalidated",
            actor="reviewer",
            occurred_at="2026-07-15T10:10:00Z",
            head=HEAD,
            head_tree=TREE,
            tracked_content_digest=CONTENT,
            candidate_id=definition.candidate.candidate_id,
            report_digest=definition.source_report_digest,
            evidence=(duplicate, duplicate),
            previous_event_digest=first.event_digest,
        )


@pytest.mark.parametrize(
    ("verifier", "commit", "message"),
    [
        ("implementation-owner", COMMIT, "independently assigned"),
        ("independent-verifier", "7" * 40, "resolving commit"),
    ],
)
def test_record_rejects_self_review_and_commit_crosswiring(
    verifier: str,
    commit: str,
    message: str,
) -> None:
    """Independent verification must be assigned correctly and bind the exact resolution."""
    definition, events = lifecycle(verifier=verifier, verified_commit=commit)
    with pytest.raises(ValueError, match=message):
        WorkRecord.build(definition, events)


def test_task_crosswiring_completeness_schema_and_severity_fail_closed() -> None:
    """Review/report mismatch, incomplete review/task, and serialized tampering are rejected."""
    report, review = source_records()
    with pytest.raises(ValueError, match="exactly one"):
        WorkTask.build(
            report,
            replace(review, report_digest="0" * 64),
            task_id="crosswired",
            production_impact="unknown",
            affected_surfaces=("src/a.py",),
            prohibited_shortcuts=("no guessing",),
            required_verifier="independent-verifier",
            created_by="planner",
            created_at="2026-07-15T10:05:00Z",
        )
    with pytest.raises(ValueError, match="lacks severity"):
        WorkTask.build(
            report,
            replace(review, severity=None),
            task_id="incomplete",
            production_impact="unknown",
            affected_surfaces=("src/a.py",),
            prohibited_shortcuts=("no guessing",),
            required_verifier="independent-verifier",
            created_by="planner",
            created_at="2026-07-15T10:05:00Z",
        )
    with pytest.raises(ValueError, match="must be explicit"):
        WorkTask.build(
            report,
            review,
            task_id="unbounded",
            production_impact="unknown",
            affected_surfaces=(),
            prohibited_shortcuts=("no guessing",),
            required_verifier="independent-verifier",
            created_by="planner",
            created_at="2026-07-15T10:05:00Z",
        )
    expected = task()
    encoded = expected.to_dict()
    encoded["schema_version"] = "9.0"
    with pytest.raises(ValueError, match="schema"):
        WorkTask.from_dict(encoded)
    encoded = expected.to_dict()
    encoded["severity"] = "P9"
    encoded["definition_digest"] = canonical_digest(
        {key: value for key, value in encoded.items() if key != "definition_digest"}
    )
    with pytest.raises(ValueError, match="severity"):
        WorkTask.from_dict(encoded)
    encoded = expected.to_dict()
    encoded["definition_digest"] = "0" * 64
    with pytest.raises(ValueError, match="definition digest"):
        WorkTask.from_dict(encoded)


def event_kwargs() -> dict[str, object]:
    """Return common exact Git identity for negative transition tests."""
    return {
        "task_id": task().task_id,
        "actor": "agent",
        "occurred_at": "2026-07-15T10:00:00Z",
        "head": HEAD,
        "head_tree": TREE,
        "tracked_content_digest": CONTENT,
    }


def test_state_specific_event_requirements_cover_every_clearance_boundary() -> None:
    """Creation, ownership, resolution, verification, and terminal reasons are mandatory."""
    common = event_kwargs()
    with pytest.raises(ValueError, match="unsupported work state"):
        WorkEvent.build(
            sequence=1,
            previous_state=None,
            state=cast(object, "unknown"),
            **common,
        )
    with pytest.raises(ValueError, match="first event"):
        WorkEvent.build(
            sequence=1,
            previous_state=None,
            state="needs-evidence",
            reason="missing",
            evidence=(evidence("missing"),),
            **common,
        )
    previous = "a" * 64
    cases = (
        ("revalidated", {}, "revalidation requires"),
        ("claimed", {}, "requires an owner"),
        (
            "resolved-pending-verification",
            {"owner": "owner"},
            "resolution requires",
        ),
        (
            "independently-verified",
            {"commit_sha": COMMIT, "commit_tree": COMMIT_TREE, "verifier": "verifier"},
            "reproducible evidence",
        ),
        ("needs-evidence", {}, "requires a reason"),
    )
    previous_states = {
        "revalidated": "proposed-task",
        "claimed": "revalidated",
        "resolved-pending-verification": "in-progress",
        "independently-verified": "resolved-pending-verification",
        "needs-evidence": "proposed-task",
    }
    for state, additions, message in cases:
        with pytest.raises(ValueError, match=message):
            WorkEvent.build(
                sequence=2,
                previous_state=cast(object, previous_states[state]),
                state=cast(object, state),
                previous_event_digest=previous,
                **common,
                **additions,
            )


def test_event_parser_and_record_chain_edges_are_revalidated() -> None:
    """Serialized event shapes and record sequence/link/closure invariants are rechecked."""
    definition, events = lifecycle()
    first = events[0]
    for field, value, message in (
        ("schema_version", "9.0", "schema"),
        ("state", "unknown", "unsupported work state"),
        ("previous_state", "unknown", "previous work state"),
        ("evidence", "all", "array"),
    ):
        encoded = first.to_dict()
        encoded[field] = value
        with pytest.raises(ValueError, match=message):
            WorkEvent.from_dict(encoded)
    with pytest.raises(ValueError, match="at least one"):
        WorkRecord.build(definition, ())
    with pytest.raises(ValueError, match="task or sequence"):
        WorkRecord.build(definition, (replace(first, task_id="other-task"),))
    with pytest.raises(ValueError, match="discontinuous"):
        WorkRecord.build(
            definition,
            (first, replace(events[1], previous_event_digest="0" * 64)),
        )
    with pytest.raises(ValueError, match="bind independent verification"):
        WorkRecord.build(
            definition,
            (*events[:6], replace(events[6], verifier="other-verifier")),
        )
    proposed_record = WorkRecord.build(definition, (first,))
    assert proposed_record.owner == definition.suggested_owner
    assert proposed_record.resolution is None
