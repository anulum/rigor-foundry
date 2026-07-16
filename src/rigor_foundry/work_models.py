# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — audited work-lifecycle records
"""Define integrity-checked tasks and append-only lifecycle events."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, cast

from .model_primitives import (
    WorkEvidence,
    require_digest,
    require_git_object,
    require_identifier,
    require_optional_string,
    require_utc_timestamp,
    validate_unique_strings,
)
from .models import (
    AuditReport,
    Candidate,
    ReviewRecord,
    Severity,
    canonical_digest,
    require_integer,
    require_mapping,
    require_string,
    require_string_tuple,
)

WORK_SCHEMA_VERSION = "1.0"

WorkState = Literal[
    "proposed-task",
    "needs-evidence",
    "revalidated",
    "claimed",
    "in-progress",
    "resolved-pending-verification",
    "independently-verified",
    "closed",
    "superseded",
    "invalid",
    "archived",
]

ALLOWED_TRANSITIONS: dict[WorkState, frozenset[WorkState]] = {
    "proposed-task": frozenset({"revalidated", "needs-evidence", "superseded", "invalid"}),
    "needs-evidence": frozenset({"revalidated", "superseded", "invalid"}),
    "revalidated": frozenset({"claimed", "needs-evidence", "superseded", "invalid"}),
    "claimed": frozenset({"in-progress", "revalidated", "needs-evidence"}),
    "in-progress": frozenset({"resolved-pending-verification", "needs-evidence"}),
    "resolved-pending-verification": frozenset(
        {"independently-verified", "in-progress", "needs-evidence"}
    ),
    "independently-verified": frozenset({"closed", "in-progress"}),
    "closed": frozenset({"archived"}),
    "superseded": frozenset({"archived"}),
    "invalid": frozenset({"archived"}),
    "archived": frozenset(),
}

ARCHIVABLE_STATES = frozenset({"closed", "superseded", "invalid"})
TERMINAL_STATES = frozenset({"closed", "superseded", "invalid", "archived"})


@dataclass(frozen=True)
class WorkTask:
    """Immutable definition of one verified, bounded remediation lane."""

    task_id: str
    candidate: Candidate
    source_report_digest: str
    source_policy_digest: str
    source_rule_pack_digest: str
    baseline_head: str
    baseline_head_tree: str
    baseline_tracked_content_digest: str
    title: str
    severity: Severity
    rationale: str
    production_impact: str
    suggested_owner: str
    dependencies: tuple[str, ...]
    acceptance_gates: tuple[str, ...]
    affected_surfaces: tuple[str, ...]
    prohibited_shortcuts: tuple[str, ...]
    required_verifier: str
    review_digest: str
    created_by: str
    created_at: str
    definition_digest: str

    @classmethod
    def build(
        cls,
        report: AuditReport,
        review: ReviewRecord,
        *,
        task_id: str,
        production_impact: str,
        affected_surfaces: tuple[str, ...],
        prohibited_shortcuts: tuple[str, ...],
        required_verifier: str,
        created_by: str,
        created_at: str,
    ) -> WorkTask:
        """Build a task only from one completed valid review."""
        if review.decision != "valid":
            raise ValueError("only a valid review can define a work task")
        candidates = tuple(
            candidate
            for candidate in report.candidates
            if candidate.candidate_id == review.candidate_id
        )
        if len(candidates) != 1 or review.report_digest != report.report_digest:
            raise ValueError("review does not identify exactly one report candidate")
        if review.severity is None or not review.owner or not review.acceptance_gates:
            raise ValueError("valid review lacks severity, owner, or acceptance gates")
        if not affected_surfaces or not prohibited_shortcuts:
            raise ValueError("task surfaces and prohibited shortcuts must be explicit")
        if required_verifier == review.owner:
            raise ValueError("required verifier must differ from the suggested owner")
        fields: dict[str, object] = {
            "schema_version": WORK_SCHEMA_VERSION,
            "task_id": require_identifier(task_id, "task_id"),
            "candidate": candidates[0].to_dict(),
            "source_report_digest": report.report_digest,
            "source_policy_digest": report.policy_digest,
            "source_rule_pack_digest": report.rule_pack_digest,
            "baseline_head": report.head,
            "baseline_head_tree": report.head_tree,
            "baseline_tracked_content_digest": report.tracked_content_digest,
            "title": require_string(review.title, "title"),
            "severity": review.severity,
            "rationale": require_string(review.rationale, "rationale"),
            "production_impact": require_string(production_impact, "production_impact"),
            "suggested_owner": require_string(review.owner, "suggested_owner"),
            "dependencies": list(validate_unique_strings(review.dependencies, "dependencies")),
            "acceptance_gates": list(
                validate_unique_strings(
                    review.acceptance_gates,
                    "acceptance_gates",
                    minimum=1,
                )
            ),
            "affected_surfaces": list(
                validate_unique_strings(
                    affected_surfaces,
                    "affected_surfaces",
                    minimum=1,
                )
            ),
            "prohibited_shortcuts": list(
                validate_unique_strings(
                    prohibited_shortcuts,
                    "prohibited_shortcuts",
                    minimum=1,
                )
            ),
            "required_verifier": require_string(required_verifier, "required_verifier"),
            "review_digest": review.review_digest,
            "created_by": require_string(created_by, "created_by"),
            "created_at": require_utc_timestamp(created_at, "created_at"),
        }
        return cls._from_fields(fields, canonical_digest(fields))

    @classmethod
    def _from_fields(cls, fields: dict[str, object], digest: str) -> WorkTask:
        """Construct a task from validated canonical fields."""
        severity = cast(str, fields["severity"])
        if severity not in {"P0", "P1", "P2", "P3", "P4"}:
            raise ValueError("task severity is unsupported")
        return cls(
            task_id=cast(str, fields["task_id"]),
            candidate=Candidate.from_dict(fields["candidate"]),
            source_report_digest=cast(str, fields["source_report_digest"]),
            source_policy_digest=cast(str, fields["source_policy_digest"]),
            source_rule_pack_digest=cast(str, fields["source_rule_pack_digest"]),
            baseline_head=cast(str, fields["baseline_head"]),
            baseline_head_tree=cast(str, fields["baseline_head_tree"]),
            baseline_tracked_content_digest=cast(
                str,
                fields["baseline_tracked_content_digest"],
            ),
            title=cast(str, fields["title"]),
            severity=cast(Severity, severity),
            rationale=cast(str, fields["rationale"]),
            production_impact=cast(str, fields["production_impact"]),
            suggested_owner=cast(str, fields["suggested_owner"]),
            dependencies=tuple(cast(list[str], fields["dependencies"])),
            acceptance_gates=tuple(cast(list[str], fields["acceptance_gates"])),
            affected_surfaces=tuple(cast(list[str], fields["affected_surfaces"])),
            prohibited_shortcuts=tuple(cast(list[str], fields["prohibited_shortcuts"])),
            required_verifier=cast(str, fields["required_verifier"]),
            review_digest=cast(str, fields["review_digest"]),
            created_by=cast(str, fields["created_by"]),
            created_at=cast(str, fields["created_at"]),
            definition_digest=digest,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the immutable task definition."""
        return {
            "schema_version": WORK_SCHEMA_VERSION,
            "task_id": self.task_id,
            "candidate": self.candidate.to_dict(),
            "source_report_digest": self.source_report_digest,
            "source_policy_digest": self.source_policy_digest,
            "source_rule_pack_digest": self.source_rule_pack_digest,
            "baseline_head": self.baseline_head,
            "baseline_head_tree": self.baseline_head_tree,
            "baseline_tracked_content_digest": self.baseline_tracked_content_digest,
            "title": self.title,
            "severity": self.severity,
            "rationale": self.rationale,
            "production_impact": self.production_impact,
            "suggested_owner": self.suggested_owner,
            "dependencies": list(self.dependencies),
            "acceptance_gates": list(self.acceptance_gates),
            "affected_surfaces": list(self.affected_surfaces),
            "prohibited_shortcuts": list(self.prohibited_shortcuts),
            "required_verifier": self.required_verifier,
            "review_digest": self.review_digest,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "definition_digest": self.definition_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> WorkTask:
        """Parse and integrity-check one immutable task definition."""
        data = require_mapping(value, "task")
        if data.get("schema_version") != WORK_SCHEMA_VERSION:
            raise ValueError("unsupported work-task schema version")
        fields: dict[str, object] = {
            "schema_version": WORK_SCHEMA_VERSION,
            "task_id": require_identifier(data.get("task_id"), "task_id"),
            "candidate": Candidate.from_dict(data.get("candidate")).to_dict(),
            "source_report_digest": require_digest(
                data.get("source_report_digest"),
                "source_report_digest",
            ),
            "source_policy_digest": require_digest(
                data.get("source_policy_digest"),
                "source_policy_digest",
            ),
            "source_rule_pack_digest": require_digest(
                data.get("source_rule_pack_digest"),
                "source_rule_pack_digest",
            ),
            "baseline_head": require_git_object(data.get("baseline_head"), "baseline_head"),
            "baseline_head_tree": require_git_object(
                data.get("baseline_head_tree"),
                "baseline_head_tree",
            ),
            "baseline_tracked_content_digest": require_digest(
                data.get("baseline_tracked_content_digest"),
                "baseline_tracked_content_digest",
            ),
            "title": require_string(data.get("title"), "title"),
            "severity": require_string(data.get("severity"), "severity"),
            "rationale": require_string(data.get("rationale"), "rationale"),
            "production_impact": require_string(
                data.get("production_impact"),
                "production_impact",
            ),
            "suggested_owner": require_string(
                data.get("suggested_owner"),
                "suggested_owner",
            ),
            "dependencies": list(require_string_tuple(data.get("dependencies"), "dependencies")),
            "acceptance_gates": list(
                require_string_tuple(data.get("acceptance_gates"), "acceptance_gates")
            ),
            "affected_surfaces": list(
                require_string_tuple(data.get("affected_surfaces"), "affected_surfaces")
            ),
            "prohibited_shortcuts": list(
                require_string_tuple(
                    data.get("prohibited_shortcuts"),
                    "prohibited_shortcuts",
                )
            ),
            "required_verifier": require_string(
                data.get("required_verifier"),
                "required_verifier",
            ),
            "review_digest": require_digest(data.get("review_digest"), "review_digest"),
            "created_by": require_string(data.get("created_by"), "created_by"),
            "created_at": require_utc_timestamp(data.get("created_at"), "created_at"),
        }
        recorded = require_digest(data.get("definition_digest"), "definition_digest")
        if recorded != canonical_digest(fields):
            raise ValueError("task definition digest does not match its content")
        return cls._from_fields(fields, recorded)


@dataclass(frozen=True)
class WorkEvent:
    """One immutable state transition in a remediation lane."""

    sequence: int
    task_id: str
    previous_state: WorkState | None
    state: WorkState
    actor: str
    occurred_at: str
    head: str
    head_tree: str
    tracked_content_digest: str
    owner: str
    candidate_id: str
    report_digest: str
    commit_sha: str
    commit_tree: str
    verifier: str
    reason: str
    evidence: tuple[WorkEvidence, ...]
    limitations: tuple[str, ...]
    previous_event_digest: str
    event_digest: str

    @classmethod
    def build(
        cls,
        *,
        sequence: int,
        task_id: str,
        previous_state: WorkState | None,
        state: WorkState,
        actor: str,
        occurred_at: str,
        head: str,
        head_tree: str,
        tracked_content_digest: str,
        owner: str = "",
        candidate_id: str = "",
        report_digest: str = "",
        commit_sha: str = "",
        commit_tree: str = "",
        verifier: str = "",
        reason: str = "",
        evidence: tuple[WorkEvidence, ...] = (),
        limitations: tuple[str, ...] = (),
        previous_event_digest: str = "",
    ) -> WorkEvent:
        """Build and validate one forward lifecycle transition."""
        if state not in ALLOWED_TRANSITIONS:
            raise ValueError("unsupported work state")
        if sequence == 1:
            if previous_state is not None or state != "proposed-task" or previous_event_digest:
                raise ValueError("first event must create the proposed-task state")
        else:
            if (
                previous_state not in ALLOWED_TRANSITIONS
                or state not in ALLOWED_TRANSITIONS[previous_state]
            ):
                raise ValueError("work event is not an allowed forward transition")
            require_digest(previous_event_digest, "previous_event_digest")
        for field, value in (
            ("owner", owner),
            ("candidate_id", candidate_id),
            ("report_digest", report_digest),
            ("commit_sha", commit_sha),
            ("commit_tree", commit_tree),
            ("verifier", verifier),
            ("reason", reason),
        ):
            require_optional_string(value, field)
        validate_unique_strings(limitations, "limitations")
        evidence_digests = tuple(canonical_digest(item.to_dict()) for item in evidence)
        validate_unique_strings(evidence_digests, "evidence_digests")
        _validate_state_fields(
            state,
            owner=owner,
            candidate_id=candidate_id,
            report_digest=report_digest,
            commit_sha=commit_sha,
            commit_tree=commit_tree,
            verifier=verifier,
            reason=reason,
            evidence=evidence,
        )
        fields: dict[str, object] = {
            "schema_version": WORK_SCHEMA_VERSION,
            "sequence": require_integer(sequence, "sequence", minimum=1),
            "task_id": require_identifier(task_id, "task_id"),
            "previous_state": previous_state,
            "state": state,
            "actor": require_string(actor, "actor"),
            "occurred_at": require_utc_timestamp(occurred_at, "occurred_at"),
            "head": require_git_object(head, "head"),
            "head_tree": require_git_object(head_tree, "head_tree"),
            "tracked_content_digest": require_digest(
                tracked_content_digest,
                "tracked_content_digest",
            ),
            "owner": owner,
            "candidate_id": candidate_id,
            "report_digest": report_digest,
            "commit_sha": commit_sha,
            "commit_tree": commit_tree,
            "verifier": verifier,
            "reason": reason,
            "evidence": [item.to_dict() for item in evidence],
            "limitations": list(limitations),
            "previous_event_digest": previous_event_digest,
        }
        return cls._from_fields(fields, canonical_digest(fields))

    @classmethod
    def _from_fields(cls, fields: dict[str, object], digest: str) -> WorkEvent:
        """Construct one event from canonical validated fields."""
        raw_evidence = cast(list[object], fields["evidence"])
        return cls(
            sequence=cast(int, fields["sequence"]),
            task_id=cast(str, fields["task_id"]),
            previous_state=cast(WorkState | None, fields["previous_state"]),
            state=cast(WorkState, fields["state"]),
            actor=cast(str, fields["actor"]),
            occurred_at=cast(str, fields["occurred_at"]),
            head=cast(str, fields["head"]),
            head_tree=cast(str, fields["head_tree"]),
            tracked_content_digest=cast(str, fields["tracked_content_digest"]),
            owner=cast(str, fields["owner"]),
            candidate_id=cast(str, fields["candidate_id"]),
            report_digest=cast(str, fields["report_digest"]),
            commit_sha=cast(str, fields["commit_sha"]),
            commit_tree=cast(str, fields["commit_tree"]),
            verifier=cast(str, fields["verifier"]),
            reason=cast(str, fields["reason"]),
            evidence=tuple(
                WorkEvidence.from_dict(item, index) for index, item in enumerate(raw_evidence)
            ),
            limitations=tuple(cast(list[str], fields["limitations"])),
            previous_event_digest=cast(str, fields["previous_event_digest"]),
            event_digest=digest,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one immutable lifecycle event."""
        return {
            "schema_version": WORK_SCHEMA_VERSION,
            "sequence": self.sequence,
            "task_id": self.task_id,
            "previous_state": self.previous_state,
            "state": self.state,
            "actor": self.actor,
            "occurred_at": self.occurred_at,
            "head": self.head,
            "head_tree": self.head_tree,
            "tracked_content_digest": self.tracked_content_digest,
            "owner": self.owner,
            "candidate_id": self.candidate_id,
            "report_digest": self.report_digest,
            "commit_sha": self.commit_sha,
            "commit_tree": self.commit_tree,
            "verifier": self.verifier,
            "reason": self.reason,
            "evidence": [item.to_dict() for item in self.evidence],
            "limitations": list(self.limitations),
            "previous_event_digest": self.previous_event_digest,
            "event_digest": self.event_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> WorkEvent:
        """Parse and integrity-check one lifecycle event."""
        data = require_mapping(value, "event")
        if data.get("schema_version") != WORK_SCHEMA_VERSION:
            raise ValueError("unsupported work-event schema version")
        state = require_string(data.get("state"), "state")
        if state not in ALLOWED_TRANSITIONS:
            raise ValueError("unsupported work state")
        previous_raw = data.get("previous_state")
        if previous_raw is not None and previous_raw not in ALLOWED_TRANSITIONS:
            raise ValueError("unsupported previous work state")
        raw_evidence = data.get("evidence")
        if not isinstance(raw_evidence, list):
            raise ValueError("evidence must be an array")
        evidence = tuple(
            WorkEvidence.from_dict(item, index) for index, item in enumerate(raw_evidence)
        )
        fields: dict[str, object] = {
            "schema_version": WORK_SCHEMA_VERSION,
            "sequence": require_integer(data.get("sequence"), "sequence", minimum=1),
            "task_id": require_identifier(data.get("task_id"), "task_id"),
            "previous_state": previous_raw,
            "state": state,
            "actor": require_string(data.get("actor"), "actor"),
            "occurred_at": require_utc_timestamp(data.get("occurred_at"), "occurred_at"),
            "head": require_git_object(data.get("head"), "head"),
            "head_tree": require_git_object(data.get("head_tree"), "head_tree"),
            "tracked_content_digest": require_digest(
                data.get("tracked_content_digest"),
                "tracked_content_digest",
            ),
            "owner": require_optional_string(data.get("owner", ""), "owner"),
            "candidate_id": require_optional_string(
                data.get("candidate_id", ""),
                "candidate_id",
            ),
            "report_digest": require_optional_string(
                data.get("report_digest", ""),
                "report_digest",
            ),
            "commit_sha": require_optional_string(data.get("commit_sha", ""), "commit_sha"),
            "commit_tree": require_optional_string(data.get("commit_tree", ""), "commit_tree"),
            "verifier": require_optional_string(data.get("verifier", ""), "verifier"),
            "reason": require_optional_string(data.get("reason", ""), "reason"),
            "evidence": [item.to_dict() for item in evidence],
            "limitations": list(require_string_tuple(data.get("limitations", []), "limitations")),
            "previous_event_digest": require_optional_string(
                data.get("previous_event_digest", ""),
                "previous_event_digest",
            ),
        }
        rebuilt = cls.build(
            sequence=cast(int, fields["sequence"]),
            task_id=cast(str, fields["task_id"]),
            previous_state=cast(WorkState | None, fields["previous_state"]),
            state=cast(WorkState, fields["state"]),
            actor=cast(str, fields["actor"]),
            occurred_at=cast(str, fields["occurred_at"]),
            head=cast(str, fields["head"]),
            head_tree=cast(str, fields["head_tree"]),
            tracked_content_digest=cast(str, fields["tracked_content_digest"]),
            owner=cast(str, fields["owner"]),
            candidate_id=cast(str, fields["candidate_id"]),
            report_digest=cast(str, fields["report_digest"]),
            commit_sha=cast(str, fields["commit_sha"]),
            commit_tree=cast(str, fields["commit_tree"]),
            verifier=cast(str, fields["verifier"]),
            reason=cast(str, fields["reason"]),
            evidence=evidence,
            limitations=tuple(cast(list[str], fields["limitations"])),
            previous_event_digest=cast(str, fields["previous_event_digest"]),
        )
        recorded = require_digest(data.get("event_digest"), "event_digest")
        if rebuilt.event_digest != recorded:
            raise ValueError("work-event digest does not match its content")
        return rebuilt


def _validate_state_fields(
    state: WorkState,
    *,
    owner: str,
    candidate_id: str,
    report_digest: str,
    commit_sha: str,
    commit_tree: str,
    verifier: str,
    reason: str,
    evidence: tuple[WorkEvidence, ...],
) -> None:
    """Enforce evidence required by each lifecycle boundary."""
    if candidate_id:
        require_digest(candidate_id, "candidate_id")
    if report_digest:
        require_digest(report_digest, "report_digest")
    if commit_sha:
        require_git_object(commit_sha, "commit_sha")
    if commit_tree:
        require_git_object(commit_tree, "commit_tree")
    if state == "revalidated" and (not candidate_id or not report_digest or not evidence):
        raise ValueError("revalidation requires candidate, report, and reproducible evidence")
    if state in {"claimed", "in-progress", "resolved-pending-verification"} and not owner:
        raise ValueError(f"{state} requires an owner")
    if state == "resolved-pending-verification" and (
        not commit_sha or not commit_tree or not evidence
    ):
        raise ValueError("resolution requires commit, tree, and focused evidence")
    if state in {"independently-verified", "closed"} and (
        not verifier or not commit_sha or not commit_tree
    ):
        raise ValueError(f"{state} requires verifier and resolving commit identity")
    if state == "independently-verified" and not evidence:
        raise ValueError("independent verification requires reproducible evidence")
    if state in {"needs-evidence", "superseded", "invalid", "archived"} and (
        not reason or not evidence
    ):
        raise ValueError(f"{state} requires a reason and evidence")


@dataclass(frozen=True)
class WorkRecord:
    """Integrity-verified task definition plus its complete event chain."""

    task: WorkTask
    events: tuple[WorkEvent, ...]

    @classmethod
    def build(cls, task: WorkTask, events: tuple[WorkEvent, ...]) -> WorkRecord:
        """Validate task identity, event ordering, and digest linkage."""
        if not events:
            raise ValueError("work record requires at least one lifecycle event")
        previous: WorkEvent | None = None
        active_owner = task.suggested_owner
        resolution: WorkEvent | None = None
        verified: WorkEvent | None = None
        for expected_sequence, event in enumerate(events, start=1):
            if event.task_id != task.task_id or event.sequence != expected_sequence:
                raise ValueError("work event task or sequence mismatch")
            if previous is None:
                if event.state != "proposed-task" or event.previous_state is not None:
                    raise ValueError("work record must begin at proposed-task")
                if (
                    event.head != task.baseline_head
                    or event.head_tree != task.baseline_head_tree
                    or event.tracked_content_digest != task.baseline_tracked_content_digest
                ):
                    raise ValueError("work proposal does not bind the task baseline")
            elif (
                event.previous_state != previous.state
                or event.previous_event_digest != previous.event_digest
            ):
                raise ValueError("work event chain is discontinuous")
            if event.state == "revalidated" and (
                event.candidate_id != task.candidate.candidate_id
                or event.report_digest != task.source_report_digest
            ):
                raise ValueError("work revalidation does not bind the task source")
            if event.owner:
                active_owner = event.owner
            if event.state == "resolved-pending-verification":
                resolution = event
            if event.state == "independently-verified":
                if event.verifier != task.required_verifier or event.verifier == active_owner:
                    raise ValueError("work verification is not independently assigned")
                if resolution is None or (
                    event.commit_sha != resolution.commit_sha
                    or event.commit_tree != resolution.commit_tree
                ):
                    raise ValueError("work verification does not bind the resolving commit")
                verified = event
            if event.state == "closed" and (
                verified is None
                or event.verifier != verified.verifier
                or event.commit_sha != verified.commit_sha
                or event.commit_tree != verified.commit_tree
            ):
                raise ValueError("work closure does not bind independent verification")
            previous = event
        return cls(task=task, events=events)

    @property
    def current(self) -> WorkEvent:
        """Return the latest immutable lifecycle event."""
        return self.events[-1]

    @property
    def owner(self) -> str:
        """Return the latest explicit owner or the suggested owner."""
        for event in reversed(self.events):
            if event.owner:
                return event.owner
        return self.task.suggested_owner

    @property
    def resolution(self) -> WorkEvent | None:
        """Return the latest resolution event when one exists."""
        return next(
            (
                event
                for event in reversed(self.events)
                if event.state == "resolved-pending-verification"
            ),
            None,
        )

    def registry_entry(self, lane_path: str) -> dict[str, object]:
        """Return the bounded materialised registry view for this task."""
        resolution = self.resolution
        return {
            "task_id": self.task.task_id,
            "finding_id": self.task.candidate.candidate_id,
            "title": self.task.title,
            "severity": self.task.severity,
            "state": self.current.state,
            "owner": self.owner,
            "dependencies": list(self.task.dependencies),
            "lane_path": lane_path,
            "definition_digest": self.task.definition_digest,
            "latest_event_digest": self.current.event_digest,
            "event_count": len(self.events),
            "resolving_commit": resolution.commit_sha if resolution is not None else "",
        }
