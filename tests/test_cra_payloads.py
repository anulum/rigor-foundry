# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — deterministic CRA payload tests
"""Exercise deterministic prepare-only CRA payloads and explicit operator-input boundaries."""

from __future__ import annotations

import hashlib
import json
from typing import Literal, cast

import pytest

from rigor_foundry.cra_events import SecurityEventRevision
from rigor_foundry.cra_payloads import (
    PreparedPayload,
    prepare_stage_payload,
    prepare_user_notice,
    validate_prepared_payload,
)
from rigor_foundry.cra_protocol import Stage, Track
from rigor_foundry.cra_registration import ProductRegistration

NOW = "2026-07-20T00:00:00Z"


def registration(product_key: str = "widget") -> ProductRegistration:
    """Build the fixed manufacturer/product registration used by public payload tests.

    Parameters
    ----------
    product_key
        Product identity used to exercise matching and cross-product rejection.

    Returns
    -------
    ProductRegistration
        Validated registration with the fixed manufacturer and support-period fields.
    """
    return ProductRegistration.build(
        product_key=product_key,
        product_name="Widget",
        manufacturer_name="Example Manufacturer",
        main_establishment_ms="DE",
        establishment_basis="decisions",
        csirt_endpoint_id="de-csirt",
        user_notice_channel="https://example.invalid/security-notices",
        support_period_months=60,
        expected_use_months=None,
        expected_use_evidence_ref=None,
        registered_at=NOW,
    )


def event(track: Track = "vulnerability", **changes: object) -> SecurityEventRevision:
    """Build a selected vulnerability or incident revision with explicit field changes.

    Parameters
    ----------
    track
        Trigger track determining the required exploitation or severity evidence.
    **changes
        Values replacing the fixed revision inputs, including invalid test cases.

    Returns
    -------
    SecurityEventRevision
        Validated revision when all supplied trigger and optional fields are coherent.
    """
    values: dict[str, object] = {
        "event_key": "EVENT-1",
        "product_key": "widget",
        "track": track,
        "aware_at": NOW,
        "aware_evidence_ref": "evidence/awareness.json",
        "exploitation_evidence": ("evidence/exploitation.json",),
        "external_ids": ("CVE-2026-0001",),
        "affected_components": ("widget-core@1",),
        "severity_value": "operator-declared-high",
        "severity_source_ref": "evidence/severity.json",
        "member_states": ("DE",),
        "recorded_at": NOW,
    }
    if track == "incident":
        values.update(
            exploitation_evidence=(),
            severe_prong="data-or-functions",
            severe_evidence_ref="evidence/severe.json",
            suspected_cause="unknown",
        )
    values.update(changes)
    return SecurityEventRevision.build(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize("track", ["vulnerability", "incident"])
@pytest.mark.parametrize("stage", ["early-warning", "notification", "final-report"])
def test_all_six_statutory_payload_partitions_are_deterministic(
    track: Track,
    stage: Stage,
) -> None:
    """Keep each track/stage payload deterministic and retain exact JSON/Markdown and field partitions."""
    selected = event(track)
    first = prepare_stage_payload(
        registration(),
        selected,
        stage=stage,
        generated_at=NOW,
    )
    second = prepare_stage_payload(
        registration(),
        selected,
        stage=stage,
        generated_at=NOW,
    )
    assert first == second
    assert first.json_digest == hashlib.sha256(first.json_text.encode()).hexdigest()
    assert first.markdown_digest == hashlib.sha256(first.markdown_text.encode()).hexdigest()
    payload = json.loads(first.json_text)
    assert set(payload) == {
        "boundary_notice",
        "generated_at",
        "operator_context",
        "product",
        "record_schema_version",
        "revision_digest",
        "stage",
        "statutory_minimum",
        "track",
    }
    assert payload["operator_context"]["event_key"] == "EVENT-1"
    assert "not legal advice" in payload["boundary_notice"]
    assert "successful submission" in payload["boundary_notice"]
    assert first.json_text in first.markdown_text
    minimum = payload["statutory_minimum"]
    if stage == "early-warning":
        assert "sensitivity" not in minimum
        assert ("suspected_unlawful_or_malicious_cause" in minimum) == (track == "incident")
    elif stage == "notification":
        assert minimum["measures_taken"] is None
        assert ("general_exploit_nature" in minimum) == (track == "vulnerability")
        assert ("incident_nature" in minimum) == (track == "incident")
    elif track == "vulnerability":
        assert minimum["malicious_actor_information"] is None
    else:
        assert minimum["applied_and_ongoing_mitigations"] is None


def test_intermediate_requires_explicit_request_and_keeps_it_separate() -> None:
    """Require an operator-declared intermediate request and preserve its due time in the payload."""
    with pytest.raises(ValueError, match="no operator-declared"):
        prepare_stage_payload(registration(), event(), stage="intermediate", generated_at=NOW)
    selected = event(
        intermediate_requested_at="2026-07-20T01:00:00Z",
        intermediate_due_at="2026-07-20T02:00:00Z",
        intermediate_evidence_ref="evidence/csirt-request.json",
    )
    payload = prepare_stage_payload(
        registration(), selected, stage="intermediate", generated_at=NOW
    )
    minimum = json.loads(payload.json_text)["statutory_minimum"]
    assert minimum["operator_update"] is None
    assert minimum["csirt_request_due_at"] == "2026-07-20T02:00:00Z"


def test_payload_rejects_cross_product_and_unsupported_stage() -> None:
    """Reject events belonging to another registered product and unknown reporting stages."""
    with pytest.raises(ValueError, match="does not match"):
        prepare_stage_payload(
            registration("other"), event(), stage="notification", generated_at=NOW
        )
    with pytest.raises(ValueError, match="unsupported"):
        prepare_stage_payload(registration(), event(), stage=cast(Stage, "bad"), generated_at=NOW)


def test_user_notice_is_prepare_only_and_strict() -> None:
    """Prepare an incomplete notice without submission and reject invalid audiences, flags or products."""
    selected = event()
    payload = prepare_user_notice(
        registration(),
        selected,
        audience="impacted",
        machine_readable=True,
        generated_at=NOW,
    )
    data = json.loads(payload.json_text)
    assert data["operator_input_required"]["impact_and_risk_explanation"] is None
    assert data["machine_readable"] is True
    assert "prepare" not in data
    with pytest.raises(ValueError, match="audience"):
        prepare_user_notice(
            registration(),
            selected,
            audience=cast(Literal["impacted", "all"], "bad"),
            machine_readable=True,
            generated_at=NOW,
        )
    with pytest.raises(ValueError, match="machine_readable"):
        prepare_user_notice(
            registration(),
            selected,
            audience="all",
            machine_readable=cast(bool, 1),
            generated_at=NOW,
        )
    with pytest.raises(ValueError, match="does not match"):
        prepare_user_notice(
            registration("other"),
            selected,
            audience="all",
            machine_readable=False,
            generated_at=NOW,
        )


def test_prepared_payload_validation_rejects_either_digest_mismatch() -> None:
    """Validate both JSON and Markdown payload digests independently."""
    valid = prepare_stage_payload(registration(), event(), stage="early-warning", generated_at=NOW)
    validate_prepared_payload(valid)
    with pytest.raises(ValueError, match="JSON payload"):
        validate_prepared_payload(
            PreparedPayload(valid.json_text, valid.markdown_text, "a" * 64, valid.markdown_digest)
        )
    with pytest.raises(ValueError, match="Markdown payload"):
        validate_prepared_payload(
            PreparedPayload(valid.json_text, valid.markdown_text, valid.json_digest, "b" * 64)
        )
