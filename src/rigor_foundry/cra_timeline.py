# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — CRA Article 14 operational timeline
"""Compute deterministic reporting states without making legal verdicts."""

from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal, Protocol, TypeVar

from .audit_primitives import canonical_digest
from .cra_events import SecurityEventRevision
from .cra_protocol import JsonObject, Stage, json_text, parse_cra_timestamp
from .cra_submissions import (
    StageDraft,
    StageSkip,
    SubmissionReceipt,
    validate_receipt_binding,
    validate_skip_binding,
)

StageState = Literal[
    "not-started",
    "pending",
    "submitted-unverified",
    "submitted",
    "skipped",
    "overdue",
]


class _HasStage(Protocol):
    @property
    def stage(self) -> Stage:
        """Return the record stage."""
        ...


_StageRecord = TypeVar("_StageRecord", bound=_HasStage)


def _format(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def add_calendar_month_conservative(value: datetime) -> datetime:
    """Shift by one calendar month at the same instant, clamping month end.

    This operational boundary is intentionally conservative. It does not model
    full-day or non-working-day extensions and is not a legal interpretation.
    """
    year = value.year + (1 if value.month == 12 else 0)
    month = 1 if value.month == 12 else value.month + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


@dataclass(frozen=True)
class TimelineStage:
    """Describe one evidence-bound operational stage state."""

    stage: Stage
    deadline: str | None
    state: StageState
    submitted_at: str | None
    late: bool
    operational_alert: bool

    def to_dict(self) -> JsonObject:
        """Serialise the stage state."""
        return {
            "stage": self.stage,
            "deadline": self.deadline,
            "state": self.state,
            "submitted_at": self.submitted_at,
            "late": self.late,
            "operational_alert": self.operational_alert,
        }


@dataclass(frozen=True)
class ReportingTimeline:
    """Expose one deterministic Article 14 operational timeline."""

    event_key: str
    track: str
    revision_digest: str
    evaluated_at: str
    stages: tuple[TimelineStage, ...]
    timeline_digest: str

    def to_dict(self) -> JsonObject:
        """Serialise the timeline and its content digest."""
        return {
            "event_key": self.event_key,
            "track": self.track,
            "revision_digest": self.revision_digest,
            "evaluated_at": self.evaluated_at,
            "stages": [stage.to_dict() for stage in self.stages],
            "timeline_digest": self.timeline_digest,
        }

    def to_json(self) -> str:
        """Serialise deterministic human-readable JSON."""
        return json_text(self.to_dict())

    @property
    def alerted(self) -> bool:
        """Return whether any stage has an overdue or stale-draft alert."""
        return any(stage.operational_alert for stage in self.stages)


def _unique_by_stage(records: tuple[_StageRecord, ...], label: str) -> dict[Stage, _StageRecord]:
    selected: dict[Stage, _StageRecord] = {}
    for record in records:
        stage = record.stage
        if stage in selected:
            raise ValueError(f"multiple {label} records exist for stage {stage}")
        selected[stage] = record
    return selected


def _validate_records(
    event: SecurityEventRevision,
    drafts: tuple[StageDraft, ...],
    receipts: tuple[SubmissionReceipt, ...],
    skips: tuple[StageSkip, ...],
    accepted_revision_digests: frozenset[str],
) -> tuple[
    dict[Stage, StageDraft],
    dict[Stage, SubmissionReceipt],
    dict[Stage, StageSkip],
]:
    identity = (event.product_key, event.event_key, event.track)
    if any(
        (draft.product_key, draft.event_key, draft.track) != identity
        or draft.revision_digest not in accepted_revision_digests
        for draft in drafts
    ):
        raise ValueError("draft belongs to another event revision")
    if any(
        (receipt.product_key, receipt.event_key, receipt.track) != identity for receipt in receipts
    ):
        raise ValueError("receipt belongs to another event")
    if any((skip.product_key, skip.event_key, skip.track) != identity for skip in skips):
        raise ValueError("skip belongs to another event")
    draft_by_stage = _unique_by_stage(drafts, "draft")
    receipt_by_stage = _unique_by_stage(receipts, "receipt")
    skip_by_stage = _unique_by_stage(skips, "skip")
    for receipt in receipts:
        draft = draft_by_stage.get(receipt.stage)
        if draft is None:
            raise ValueError("receipt has no available draft")
        validate_receipt_binding(draft, receipt)
    for skip in skips:
        validate_skip_binding(skip, receipts)
        if skip.stage in receipt_by_stage:
            raise ValueError("a stage cannot be both receipt-bound and skipped")
    return draft_by_stage, receipt_by_stage, skip_by_stage


def _deadlines(
    event: SecurityEventRevision,
    receipts: dict[Stage, SubmissionReceipt],
    skips: dict[Stage, StageSkip],
) -> dict[Stage, datetime | None]:
    aware = parse_cra_timestamp(event.aware_at)
    final: datetime | None = None
    if event.track == "vulnerability":
        if event.corrective_measure_available_at is not None:
            final = parse_cra_timestamp(event.corrective_measure_available_at) + timedelta(days=14)
    else:
        notification = receipts.get("notification")
        if notification is not None:
            final = add_calendar_month_conservative(parse_cra_timestamp(notification.submitted_at))
        else:
            skip = skips.get("notification")
            if skip is not None:
                source = next(
                    receipt
                    for receipt in receipts.values()
                    if receipt.receipt_digest == skip.provided_in_receipt_digest
                )
                final = add_calendar_month_conservative(parse_cra_timestamp(source.submitted_at))
    return {
        "early-warning": aware + timedelta(hours=24),
        "notification": aware + timedelta(hours=72),
        "final-report": final,
        "intermediate": (
            None
            if event.intermediate_due_at is None
            else parse_cra_timestamp(event.intermediate_due_at)
        ),
    }


def _stage_state(
    stage: Stage,
    deadline: datetime | None,
    now: datetime,
    drafts: dict[Stage, StageDraft],
    receipts: dict[Stage, SubmissionReceipt],
    skips: dict[Stage, StageSkip],
) -> TimelineStage:
    receipt = receipts.get(stage)
    skip = skips.get(stage)
    draft = drafts.get(stage)
    submitted_at: str | None = None
    late = False
    alert = False
    if receipt is not None:
        submitted_at = receipt.submitted_at
        late = deadline is not None and parse_cra_timestamp(receipt.submitted_at) > deadline
        state: StageState = "submitted"
    elif skip is not None:
        submitted_at = skip.skipped_at
        late = deadline is not None and parse_cra_timestamp(skip.skipped_at) > deadline
        state = "skipped"
    elif draft is not None:
        state = "submitted-unverified"
        alert = now > parse_cra_timestamp(draft.generated_at) + timedelta(hours=24)
    elif deadline is None:
        state = "not-started"
    elif now > deadline:
        state = "overdue"
        alert = True
    else:
        state = "pending"
    return TimelineStage(
        stage=stage,
        deadline=None if deadline is None else _format(deadline),
        state=state,
        submitted_at=submitted_at,
        late=late,
        operational_alert=alert or late,
    )


def compute_reporting_timeline(
    event: SecurityEventRevision,
    *,
    drafts: tuple[StageDraft, ...] = (),
    receipts: tuple[SubmissionReceipt, ...] = (),
    skips: tuple[StageSkip, ...] = (),
    now: str,
    accepted_revision_digests: frozenset[str] | None = None,
) -> ReportingTimeline:
    """Compute one fail-closed operational timeline for an event revision."""
    instant = parse_cra_timestamp(now)
    accepted = (
        frozenset({event.revision_digest})
        if accepted_revision_digests is None
        else accepted_revision_digests
    )
    if event.revision_digest not in accepted:
        raise ValueError("accepted revision chain must contain the current event revision")
    draft_by_stage, receipt_by_stage, skip_by_stage = _validate_records(
        event, drafts, receipts, skips, accepted
    )
    deadlines = _deadlines(event, receipt_by_stage, skip_by_stage)
    stages = tuple(
        _stage_state(
            stage,
            deadlines[stage],
            instant,
            draft_by_stage,
            receipt_by_stage,
            skip_by_stage,
        )
        for stage in ("early-warning", "notification", "final-report", "intermediate")
    )
    body: JsonObject = {
        "event_key": event.event_key,
        "track": event.track,
        "revision_digest": event.revision_digest,
        "evaluated_at": _format(instant),
        "stages": [stage.to_dict() for stage in stages],
    }
    return ReportingTimeline(
        event_key=event.event_key,
        track=event.track,
        revision_digest=event.revision_digest,
        evaluated_at=_format(instant),
        stages=stages,
        timeline_digest=canonical_digest(body),
    )
