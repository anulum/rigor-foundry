# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — CRA operational timeline tests

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from rigor_foundry.cra_events import SecurityEventRevision
from rigor_foundry.cra_submissions import StageDraft, StageSkip, SubmissionReceipt
from rigor_foundry.cra_timeline import (
    ReportingTimeline,
    TimelineStage,
    add_calendar_month_conservative,
    compute_reporting_timeline,
)

AWARE = "2026-07-20T00:00:00Z"


def event(*, track: str = "vulnerability", **changes: object) -> SecurityEventRevision:
    values: dict[str, object] = {
        "event_key": "EV-1",
        "product_key": "widget",
        "track": track,
        "aware_at": AWARE,
        "aware_evidence_ref": "evidence/aware.json",
        "exploitation_evidence": ("evidence/exploit.json",),
        "recorded_at": AWARE,
    }
    if track == "incident":
        values.update(
            exploitation_evidence=(),
            severe_prong="data-or-functions",
            severe_evidence_ref="evidence/severe.json",
            suspected_cause="unknown",
        )
    values.update(changes)
    return SecurityEventRevision.build(**values)  # type: ignore[arg-type] # typed timeline fixture


def draft(selected: SecurityEventRevision, stage: str, generated_at: str = AWARE) -> StageDraft:
    return StageDraft.build(
        product_key=selected.product_key,
        event_key=selected.event_key,
        track=selected.track,
        stage=stage,  # type: ignore[arg-type] # parametrised stage fixture
        revision_digest=selected.revision_digest,
        payload_path=f".rigor/cra/outbox/{selected.event_key}/{stage}/payload.json",
        payload_digest="b" * 64,
        markdown_path=f".rigor/cra/outbox/{selected.event_key}/{stage}/payload.md",
        markdown_payload_digest="d" * 64,
        generated_at=generated_at,
        tool_version="0.1.1",
    )


def receipt(selected: StageDraft, submitted_at: str) -> SubmissionReceipt:
    return SubmissionReceipt.build(
        product_key=selected.product_key,
        event_key=selected.event_key,
        track=selected.track,
        stage=selected.stage,
        draft_digest=selected.draft_digest,
        payload_digest=selected.payload_digest,
        submitted_at=submitted_at,
        platform_ref="operator-reference",
        csirt_endpoint_id="de-csirt",
        evidence_sha256="c" * 64,
        bound_at=submitted_at,
    )


def state(timeline: ReportingTimeline, stage: str) -> TimelineStage:
    return next(item for item in timeline.stages if item.stage == stage)


def test_early_and_notification_boundaries_are_strictly_after_deadline() -> None:
    selected = event()
    at_24 = compute_reporting_timeline(selected, now="2026-07-21T00:00:00Z")
    assert state(at_24, "early-warning").state == "pending"
    after_24 = compute_reporting_timeline(selected, now="2026-07-21T00:00:01Z")
    assert state(after_24, "early-warning").state == "overdue"
    at_72 = compute_reporting_timeline(selected, now="2026-07-23T00:00:00Z")
    assert state(at_72, "notification").state == "pending"
    after_72 = compute_reporting_timeline(selected, now="2026-07-23T00:00:01Z")
    assert state(after_72, "notification").state == "overdue"


def test_vulnerability_final_clock_starts_only_when_measure_exists() -> None:
    no_measure = compute_reporting_timeline(event(), now="2027-01-01T00:00:00Z")
    assert state(no_measure, "final-report").state == "not-started"
    selected = event(corrective_measure_available_at="2026-07-25T00:00:00Z")
    at_due = compute_reporting_timeline(selected, now="2026-08-08T00:00:00Z")
    assert state(at_due, "final-report").state == "pending"
    after_due = compute_reporting_timeline(selected, now="2026-08-08T00:00:01Z")
    assert state(after_due, "final-report").state == "overdue"


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ((2026, 1, 31), (2026, 2, 28)),
        ((2028, 1, 31), (2028, 2, 29)),
        ((2026, 12, 31), (2027, 1, 31)),
        ((2026, 4, 30), (2026, 5, 30)),
    ],
)
def test_calendar_month_clamps_end_of_month(
    source: tuple[int, int, int], expected: tuple[int, int, int]
) -> None:
    value = datetime(*source, 12, 30, tzinfo=UTC)
    shifted = add_calendar_month_conservative(value)
    assert (shifted.year, shifted.month, shifted.day) == expected
    assert (shifted.hour, shifted.minute) == (12, 30)


def test_incident_final_clock_uses_notification_receipt() -> None:
    selected = event(track="incident")
    notification = draft(selected, "notification")
    bound = receipt(notification, "2026-07-31T12:00:00Z")
    timeline = compute_reporting_timeline(
        selected,
        drafts=(notification,),
        receipts=(bound,),
        now="2026-08-31T12:00:00Z",
    )
    final = state(timeline, "final-report")
    assert final.deadline == "2026-08-31T12:00:00Z"
    assert final.state == "pending"
    assert state(timeline, "notification").state == "submitted"


def test_incident_final_clock_is_not_started_without_notification_evidence() -> None:
    timeline = compute_reporting_timeline(event(track="incident"), now="2027-01-01T00:00:00Z")
    assert state(timeline, "final-report").state == "not-started"


def test_incident_skip_uses_referenced_earlier_receipt() -> None:
    selected = event(track="incident")
    early = draft(selected, "early-warning")
    bound = receipt(early, "2026-07-20T01:00:00Z")
    skip = StageSkip.build(
        product_key=selected.product_key,
        event_key=selected.event_key,
        track=selected.track,
        stage="notification",
        provided_in_stage="early-warning",
        provided_in_receipt_digest=bound.receipt_digest,
        reason="notification information already provided",
        evidence_ref="evidence/operator-decision.json",
        skipped_at="2026-07-20T01:01:00Z",
    )
    timeline = compute_reporting_timeline(
        selected,
        drafts=(early,),
        receipts=(bound,),
        skips=(skip,),
        now="2026-07-20T02:00:00Z",
    )
    assert state(timeline, "notification").state == "skipped"
    assert state(timeline, "final-report").deadline == "2026-08-20T01:00:00Z"


def test_draft_without_receipt_is_explicit_and_eventually_alerts() -> None:
    selected = event()
    early = draft(selected, "early-warning")
    fresh = compute_reporting_timeline(selected, drafts=(early,), now="2026-07-21T00:00:00Z")
    assert state(fresh, "early-warning").state == "submitted-unverified"
    assert not state(fresh, "early-warning").operational_alert
    stale = compute_reporting_timeline(selected, drafts=(early,), now="2026-07-21T00:00:01Z")
    assert state(stale, "early-warning").operational_alert
    assert stale.alerted


def test_timeline_rejects_ambiguous_or_cross_wired_records() -> None:
    selected = event()
    early = draft(selected, "early-warning")
    with pytest.raises(ValueError, match="multiple draft"):
        compute_reporting_timeline(selected, drafts=(early, early), now=AWARE)
    other = draft(event(event_key="OTHER"), "early-warning")
    with pytest.raises(ValueError, match="another event revision"):
        compute_reporting_timeline(selected, drafts=(other,), now=AWARE)
    orphan = receipt(early, "2026-07-20T01:00:00Z")
    with pytest.raises(ValueError, match="no available draft"):
        compute_reporting_timeline(selected, receipts=(orphan,), now=AWARE)
    other_receipt = receipt(early, "2026-07-20T01:00:00Z")
    with pytest.raises(ValueError, match="another event"):
        compute_reporting_timeline(
            selected,
            drafts=(early,),
            receipts=(replace(other_receipt, event_key="OTHER"),),
            now=AWARE,
        )
    skip = StageSkip.build(
        product_key=selected.product_key,
        event_key=selected.event_key,
        track=selected.track,
        stage="notification",
        provided_in_stage="early-warning",
        provided_in_receipt_digest=other_receipt.receipt_digest,
        reason="already provided",
        evidence_ref="evidence/operator.json",
        skipped_at=AWARE,
    )
    with pytest.raises(ValueError, match="another event"):
        compute_reporting_timeline(
            selected,
            drafts=(early,),
            receipts=(other_receipt,),
            skips=(replace(skip, event_key="OTHER"),),
            now=AWARE,
        )
    notification = draft(selected, "notification")
    notification_receipt = receipt(notification, "2026-07-20T02:00:00Z")
    conflicting = StageSkip.build(
        product_key=selected.product_key,
        event_key=selected.event_key,
        track=selected.track,
        stage="notification",
        provided_in_stage="early-warning",
        provided_in_receipt_digest=other_receipt.receipt_digest,
        reason="conflicting state",
        evidence_ref="evidence/operator.json",
        skipped_at=AWARE,
    )
    with pytest.raises(ValueError, match="both"):
        compute_reporting_timeline(
            selected,
            drafts=(early, notification),
            receipts=(other_receipt, notification_receipt),
            skips=(conflicting,),
            now=AWARE,
        )


def test_late_receipt_and_intermediate_deadline_remain_visible() -> None:
    selected = event(
        intermediate_requested_at="2026-07-20T01:00:00Z",
        intermediate_due_at="2026-07-20T03:00:00Z",
        intermediate_evidence_ref="evidence/request.json",
    )
    early = draft(selected, "early-warning")
    bound = receipt(early, "2026-07-21T00:00:01Z")
    timeline = compute_reporting_timeline(
        selected,
        drafts=(early,),
        receipts=(bound,),
        now="2026-07-20T03:00:01Z",
    )
    assert state(timeline, "early-warning").late
    assert state(timeline, "early-warning").operational_alert
    assert state(timeline, "intermediate").state == "overdue"
    assert timeline.timeline_digest in timeline.to_json()


def test_timeline_requires_current_revision_in_accepted_chain() -> None:
    selected = event()
    with pytest.raises(ValueError, match="must contain"):
        compute_reporting_timeline(
            selected,
            now=AWARE,
            accepted_revision_digests=frozenset(),
        )
