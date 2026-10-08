# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — CRA record protocol tests
"""Exercise digest-bound CRA records, trigger fields and revision/submission relationships."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from rigor_foundry.cra_events import SecurityEventRevision, validate_revision_successor
from rigor_foundry.cra_protocol import require_enum, require_relative_path
from rigor_foundry.cra_registration import ProductRegistration
from rigor_foundry.cra_submissions import (
    StageDraft,
    StageSkip,
    SubmissionReceipt,
    UserNoticeDraft,
    validate_receipt_binding,
    validate_skip_binding,
)

NOW = "2026-07-20T00:00:00Z"
DIGEST = "a" * 64


def registration(**changes: object) -> ProductRegistration:
    """Build a product registration with explicit fixture-field mutations.

    Parameters
    ----------
    **changes
        Values replacing the fixed registration inputs, including deliberate invalid inputs.

    Returns
    -------
    ProductRegistration
        Validated registration when all supplied fields satisfy the public protocol.
    """
    values: dict[str, object] = {
        "product_key": "widget",
        "product_name": "Widget",
        "manufacturer_name": "Example AG",
        "main_establishment_ms": "DE",
        "establishment_basis": "decisions",
        "csirt_endpoint_id": "de-csirt",
        "user_notice_channel": "security.example.test",
        "support_period_months": 60,
        "expected_use_months": None,
        "expected_use_evidence_ref": None,
        "registered_at": NOW,
    }
    values.update(changes)
    return ProductRegistration.build(**values)  # type: ignore[arg-type] # typed mutation fixture


def vulnerability(**changes: object) -> SecurityEventRevision:
    """Build a vulnerability revision with explicit fixture-field mutations.

    Parameters
    ----------
    **changes
        Values replacing the fixed vulnerability trigger or revision fields.

    Returns
    -------
    SecurityEventRevision
        Validated vulnerability revision when the supplied trigger remains coherent.
    """
    values: dict[str, object] = {
        "event_key": "VULN-1",
        "product_key": "widget",
        "track": "vulnerability",
        "aware_at": NOW,
        "aware_evidence_ref": "evidence/awareness.json",
        "exploitation_evidence": ("evidence/exploitation.json",),
        "external_ids": ("CVE-2026-0001",),
        "affected_components": ("widget-core@1.x",),
        "member_states": ("DE", "FR"),
        "recorded_at": NOW,
    }
    values.update(changes)
    return SecurityEventRevision.build(**values)  # type: ignore[arg-type] # typed mutation fixture


def incident(**changes: object) -> SecurityEventRevision:
    """Build an incident revision with explicit fixture-field mutations.

    Parameters
    ----------
    **changes
        Values replacing the fixed incident trigger or revision fields.

    Returns
    -------
    SecurityEventRevision
        Validated incident revision when the supplied trigger remains coherent.
    """
    values: dict[str, object] = {
        "event_key": "INC-1",
        "product_key": "widget",
        "track": "incident",
        "aware_at": NOW,
        "aware_evidence_ref": "evidence/awareness.json",
        "severe_prong": "malicious-code",
        "severe_evidence_ref": "evidence/severe.json",
        "suspected_cause": "unknown",
        "member_states": ("DE",),
        "recorded_at": NOW,
    }
    values.update(changes)
    return SecurityEventRevision.build(**values)  # type: ignore[arg-type] # typed mutation fixture


def draft(**changes: object) -> StageDraft:
    """Build a stage draft from fixed outbox paths and explicit field mutations.

    Parameters
    ----------
    **changes
        Values replacing the selected stage, revision, payload or generation fields.

    Returns
    -------
    StageDraft
        Validated prepare-only draft without a submission receipt.
    """
    values: dict[str, object] = {
        "product_key": "widget",
        "event_key": "VULN-1",
        "track": "vulnerability",
        "stage": "early-warning",
        "revision_digest": DIGEST,
        "payload_path": ".rigor/cra/outbox/VULN-1/early-warning/a.json",
        "payload_digest": "b" * 64,
        "markdown_path": ".rigor/cra/outbox/VULN-1/early-warning/a.md",
        "markdown_payload_digest": "f" * 64,
        "generated_at": NOW,
        "tool_version": "0.1.1",
    }
    values.update(changes)
    return StageDraft.build(**values)  # type: ignore[arg-type] # typed mutation fixture


def receipt(selected: StageDraft, **changes: object) -> SubmissionReceipt:
    """Build a submission receipt for the selected draft with explicit mutations.

    Parameters
    ----------
    selected
        Draft supplying the original event, stage and payload bindings.
    **changes
        Values replacing the fixed submission evidence or selected draft bindings.

    Returns
    -------
    SubmissionReceipt
        Validated receipt data; separate binding validation checks it against the draft.
    """
    values: dict[str, object] = {
        "product_key": selected.product_key,
        "event_key": selected.event_key,
        "track": selected.track,
        "stage": selected.stage,
        "draft_digest": selected.draft_digest,
        "payload_digest": selected.payload_digest,
        "submitted_at": "2026-07-20T01:00:00Z",
        "platform_ref": "SRP-operator-reference",
        "csirt_endpoint_id": "de-csirt",
        "evidence_sha256": "c" * 64,
        "bound_at": "2026-07-20T01:01:00Z",
    }
    values.update(changes)
    return SubmissionReceipt.build(**values)  # type: ignore[arg-type] # typed mutation fixture


@pytest.mark.parametrize(
    "value",
    ["2026-07-20T00:00:00+00:00", "2026-07-20T00:00:00.1Z", "2026-07-20"],
)
def test_cra_records_reject_noncanonical_timestamps(value: str) -> None:
    """Require whole-second UTC spelling rather than accepting alternate timestamp representations."""
    with pytest.raises(ValueError, match="UTC whole seconds"):
        registration(registered_at=value)


def test_cra_primitives_reject_invalid_values() -> None:
    """Reject nonexistent UTC dates, unknown enum values and escaping relative paths."""
    with pytest.raises(ValueError, match="valid UTC"):
        registration(registered_at="2026-02-30T00:00:00Z")
    with pytest.raises(ValueError, match="unsupported"):
        require_enum("other", "choice", frozenset({"known"}))
    with pytest.raises(ValueError, match="repository-relative"):
        require_relative_path("../escape", "path")


def test_product_registration_round_trip_and_expected_use_exception() -> None:
    """Bind registration round trips and shorter-support evidence; reject tampering and wrong roles."""
    expected = registration(
        support_period_months=36,
        expected_use_months=36,
        expected_use_evidence_ref="evidence/expected-use.json",
    )
    assert ProductRegistration.from_dict(json.loads(expected.to_json())) == expected
    tampered = expected.to_dict()
    tampered["support_period_months"] = 35
    with pytest.raises(ValueError, match="digest"):
        ProductRegistration.from_dict(tampered)
    with pytest.raises(ValueError, match="requires expected_use_months"):
        registration(expected_use_evidence_ref="evidence/orphan.json")
    with pytest.raises(ValueError, match="below 60"):
        registration(expected_use_months=60, expected_use_evidence_ref="evidence/use.json")
    with pytest.raises(ValueError, match="alpha-2"):
        registration(main_establishment_ms="de")
    wrong_schema = expected.to_dict()
    wrong_schema["schema_version"] = "2.0"
    with pytest.raises(ValueError, match="schema_version"):
        ProductRegistration.from_dict(wrong_schema)
    wrong_role = expected.to_dict()
    wrong_role["operator_role"] = "importer"
    with pytest.raises(ValueError, match="operator_role"):
        ProductRegistration.from_dict(wrong_role)


def test_track_trigger_fields_fail_closed() -> None:
    """Keep vulnerability exploitation evidence and incident severity triggers separate and complete."""
    with pytest.raises(ValueError, match="at least 1"):
        vulnerability(exploitation_evidence=())
    with pytest.raises(ValueError, match="incident trigger"):
        vulnerability(severe_prong="malicious-code")
    with pytest.raises(ValueError, match="must not carry exploitation"):
        incident(exploitation_evidence=("unexpected",))
    with pytest.raises(ValueError, match="severe_prong"):
        incident(severe_prong=None)


def test_event_round_trip_and_revision_chain() -> None:
    """Preserve event identity, immutable triggers, ordered transitions and digest-bound round trips."""
    first = vulnerability()
    assert SecurityEventRevision.from_dict(json.loads(first.to_json())) == first
    second = vulnerability(
        status="fixing",
        recorded_at="2026-07-20T00:01:00Z",
        previous_revision_digest=first.revision_digest,
    )
    validate_revision_successor(first, second)
    with pytest.raises(ValueError, match="current digest"):
        validate_revision_successor(first, replace(second, previous_revision_digest=DIGEST))
    with pytest.raises(ValueError, match="immutable trigger"):
        validate_revision_successor(first, replace(second, aware_evidence_ref="changed"))
    with pytest.raises(ValueError, match="transition"):
        validate_revision_successor(first, replace(second, status="disclosed"))
    with pytest.raises(ValueError, match="must follow"):
        validate_revision_successor(first, replace(second, recorded_at=first.recorded_at))
    wrong_schema = first.to_dict()
    wrong_schema["schema_version"] = "2.0"
    with pytest.raises(ValueError, match="schema_version"):
        SecurityEventRevision.from_dict(wrong_schema)
    wrong_digest = first.to_dict()
    wrong_digest["revision_digest"] = DIGEST
    with pytest.raises(ValueError, match="digest"):
        SecurityEventRevision.from_dict(wrong_digest)


def test_event_optional_fields_are_coherent() -> None:
    """Require paired severity and intermediate-request evidence with ordered times and valid state codes."""
    with pytest.raises(ValueError, match="declared together"):
        vulnerability(severity_value="high")
    with pytest.raises(ValueError, match="all required"):
        vulnerability(intermediate_requested_at=NOW)
    with pytest.raises(ValueError, match="must follow"):
        vulnerability(
            intermediate_requested_at="2026-07-20T02:00:00Z",
            intermediate_due_at="2026-07-20T01:00:00Z",
            intermediate_evidence_ref="evidence/request.json",
        )
    with pytest.raises(ValueError, match="alpha-2"):
        vulnerability(member_states=("de",))


def test_draft_receipt_skip_and_notice_round_trip() -> None:
    """Round-trip each closed CRA record and reject changed schemas or bound digests."""
    selected = draft()
    bound = receipt(selected)
    validate_receipt_binding(selected, bound)
    assert StageDraft.from_dict(json.loads(selected.to_json())) == selected
    assert SubmissionReceipt.from_dict(json.loads(bound.to_json())) == bound
    skip = StageSkip.build(
        product_key="widget",
        event_key="VULN-1",
        track="vulnerability",
        stage="notification",
        provided_in_stage="early-warning",
        provided_in_receipt_digest=bound.receipt_digest,
        reason="notification information was included in the early warning",
        evidence_ref="evidence/operator-decision.json",
        skipped_at="2026-07-20T01:02:00Z",
    )
    validate_skip_binding(skip, (bound,))
    assert StageSkip.from_dict(json.loads(skip.to_json())) == skip
    notice = UserNoticeDraft.build(
        product_key="widget",
        event_key="VULN-1",
        track="vulnerability",
        revision_digest=DIGEST,
        audience="impacted",
        machine_readable=True,
        json_payload_digest="d" * 64,
        markdown_payload_digest="e" * 64,
        generated_at=NOW,
    )
    assert UserNoticeDraft.from_dict(json.loads(notice.to_json())) == notice
    records = (
        (selected, StageDraft.from_dict, "draft_digest"),
        (bound, SubmissionReceipt.from_dict, "receipt_digest"),
        (skip, StageSkip.from_dict, "skip_digest"),
        (notice, UserNoticeDraft.from_dict, "notice_digest"),
    )
    for value, parser, digest_field in records:
        wrong_schema = value.to_dict()
        wrong_schema["schema_version"] = "2.0"
        with pytest.raises(ValueError, match="schema_version"):
            parser(wrong_schema)
        wrong_digest = value.to_dict()
        wrong_digest[digest_field] = DIGEST
        with pytest.raises(ValueError, match="digest"):
            parser(wrong_digest)


def test_submission_bindings_reject_cross_wiring() -> None:
    """Reject receipts for other payloads and skips without one matching earlier-stage receipt."""
    selected = draft()
    bound = receipt(selected)
    with pytest.raises(ValueError, match="selected draft"):
        validate_receipt_binding(selected, replace(bound, payload_digest=DIGEST))
    with pytest.raises(ValueError, match="must precede"):
        StageSkip.build(
            product_key="widget",
            event_key="VULN-1",
            track="vulnerability",
            stage="notification",
            provided_in_stage="notification",
            provided_in_receipt_digest=bound.receipt_digest,
            reason="self reference",
            evidence_ref="evidence/operator-decision.json",
            skipped_at=NOW,
        )
    skip = StageSkip.build(
        product_key="widget",
        event_key="VULN-1",
        track="vulnerability",
        stage="notification",
        provided_in_stage="early-warning",
        provided_in_receipt_digest=bound.receipt_digest,
        reason="already provided",
        evidence_ref="evidence/operator-decision.json",
        skipped_at=NOW,
    )
    with pytest.raises(ValueError, match="exactly one"):
        validate_skip_binding(skip, ())
    with pytest.raises(ValueError, match="identity"):
        validate_skip_binding(replace(skip, event_key="OTHER"), (bound,))
