# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — deterministic offline CRA drafting payloads
"""Prepare deterministic Article 14 drafting aids without network activity."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal

from .cra_events import SecurityEventRevision
from .cra_protocol import (
    CRA_SCHEMA_VERSION,
    JsonObject,
    Stage,
    json_text,
    require_cra_timestamp,
    require_stage,
)
from .cra_registration import ProductRegistration
from .model_primitives import require_boolean

_BOUNDARY = (
    "RIGOR-FOUNDRY drafting aid only; not legal advice. Submission remains the "
    "manufacturer's act. This payload does not claim compliance, legal sufficiency, "
    "CE readiness, authority acceptance, or successful submission."
)


def _digest(text: str) -> str:
    """Return the lowercase SHA-256 digest of exact UTF-8 bytes."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _product(registration: ProductRegistration) -> JsonObject:
    """Return general product information without applicability conclusions."""
    return {
        "manufacturer_name": registration.manufacturer_name,
        "product_key": registration.product_key,
        "product_name": registration.product_name,
    }


def _early_warning(event: SecurityEventRevision) -> JsonObject:
    """Return the exact early-warning minimum partition."""
    minimum: JsonObject = {"member_states": list(event.member_states)}
    if event.track == "incident":
        minimum["suspected_unlawful_or_malicious_cause"] = event.suspected_cause
    return minimum


def _notification(
    registration: ProductRegistration,
    event: SecurityEventRevision,
) -> JsonObject:
    """Return the exact notification minimum partition."""
    common: JsonObject = {
        "general_product_information": _product(registration),
        "measures_taken": None,
        "sensitivity": event.sensitivity,
        "user_measures": None,
    }
    if event.track == "vulnerability":
        common.update(
            {
                "general_exploit_nature": list(event.exploitation_evidence),
                "general_vulnerability_nature": {
                    "affected_components": list(event.affected_components),
                    "external_ids": list(event.external_ids),
                },
            }
        )
    else:
        common.update(
            {
                "incident_nature": event.severe_prong,
                "initial_assessment": None,
            }
        )
    return common


def _final_report(event: SecurityEventRevision) -> JsonObject:
    """Return the exact final-report minimum partition."""
    severity: JsonObject = {
        "declared_value": event.severity_value,
        "source_reference": event.severity_source_ref,
    }
    if event.track == "vulnerability":
        return {
            "malicious_actor_information": None,
            "update_or_corrective_measure_details": {
                "available_at": event.corrective_measure_available_at,
                "operator_input_required": True,
            },
            "vulnerability_description": {
                "affected_components": list(event.affected_components),
                "declared_severity": severity,
                "impact": None,
            },
        }
    return {
        "applied_and_ongoing_mitigations": None,
        "detailed_incident_description": {
            "declared_severity": severity,
            "impact": None,
        },
        "threat_type_or_likely_root_cause": event.suspected_cause,
    }


def _intermediate(event: SecurityEventRevision) -> JsonObject:
    """Return operator-declared intermediate-report request context."""
    if event.intermediate_requested_at is None:
        raise ValueError("event has no operator-declared intermediate report request")
    return {
        "csirt_request_due_at": event.intermediate_due_at,
        "csirt_request_evidence_ref": event.intermediate_evidence_ref,
        "csirt_request_received_at": event.intermediate_requested_at,
        "operator_update": None,
    }


def _context(event: SecurityEventRevision) -> JsonObject:
    """Return optional operator context kept outside statutory minima."""
    return {
        "affected_components": list(event.affected_components),
        "awareness_evidence_ref": event.aware_evidence_ref,
        "awareness_time": event.aware_at,
        "event_key": event.event_key,
        "evidence_references": list(event.exploitation_evidence)
        + ([event.severe_evidence_ref] if event.severe_evidence_ref is not None else []),
        "external_ids": list(event.external_ids),
        "status": event.status,
    }


def _markdown(title: str, payload: JsonObject) -> str:
    """Render one deterministic Markdown mirror of the canonical JSON payload."""
    return (
        f"# {title}\n\n"
        f"{_BOUNDARY}\n\n"
        "The JSON block below is the exact deterministic drafting payload. Null values "
        "are unresolved operator inputs and must not be interpreted as supplied facts.\n\n"
        "```json\n"
        f"{json_text(payload)}"
        "```\n"
    )


@dataclass(frozen=True)
class PreparedPayload:
    """Carry exact JSON and Markdown bytes with their independent digests."""

    json_text: str
    markdown_text: str
    json_digest: str
    markdown_digest: str


def validate_prepared_payload(payload: PreparedPayload) -> None:
    """Require both payload digests to match their exact UTF-8 bytes.

    Parameters
    ----------
    payload:
        Prepared payload pair crossing a persistence boundary.

    Raises
    ------
    ValueError
        If either claimed digest differs from the supplied bytes.

    """
    if payload.json_digest != _digest(payload.json_text):
        raise ValueError("JSON payload digest does not match its bytes")
    if payload.markdown_digest != _digest(payload.markdown_text):
        raise ValueError("Markdown payload digest does not match its bytes")


def prepare_stage_payload(
    registration: ProductRegistration,
    event: SecurityEventRevision,
    *,
    stage: Stage,
    generated_at: str,
) -> PreparedPayload:
    """Prepare one deterministic Article 14 stage payload.

    Parameters
    ----------
    registration:
        Current operator-declared product registration.
    event:
        Current verified event revision.
    stage:
        Requested reporting stage.
    generated_at:
        Exact whole-second UTC generation time already chosen by the operator.

    Returns
    -------
    PreparedPayload
        Byte-stable JSON and Markdown representations with SHA-256 digests.

    Raises
    ------
    ValueError
        If identities differ or the stage lacks its required trigger.

    """
    stage = require_stage(stage)
    generated_at = require_cra_timestamp(generated_at, "generated_at")
    if registration.product_key != event.product_key:
        raise ValueError("registration does not match the selected event")
    if stage == "early-warning":
        minimum = _early_warning(event)
    elif stage == "notification":
        minimum = _notification(registration, event)
    elif stage == "final-report":
        minimum = _final_report(event)
    else:
        minimum = _intermediate(event)
    payload: JsonObject = {
        "boundary_notice": _BOUNDARY,
        "generated_at": generated_at,
        "operator_context": _context(event),
        "product": _product(registration),
        "record_schema_version": CRA_SCHEMA_VERSION,
        "revision_digest": event.revision_digest,
        "stage": stage,
        "statutory_minimum": minimum,
        "track": event.track,
    }
    rendered = json_text(payload)
    markdown = _markdown(f"CRA {event.track} {stage} draft", payload)
    return PreparedPayload(rendered, markdown, _digest(rendered), _digest(markdown))


def prepare_user_notice(
    registration: ProductRegistration,
    event: SecurityEventRevision,
    *,
    audience: Literal["impacted", "all"],
    machine_readable: bool,
    generated_at: str,
) -> PreparedPayload:
    """Prepare one deterministic Article 14(8) user-notice payload pair.

    Parameters
    ----------
    registration:
        Current product registration.
    event:
        Current event revision.
    audience:
        Operator-declared intended audience.
    machine_readable:
        Whether the operator intends machine-readable distribution.
    generated_at:
        Exact whole-second UTC generation time.

    Returns
    -------
    PreparedPayload
        Prepare-only JSON and Markdown notice bytes.

    """
    if audience not in {"impacted", "all"}:
        raise ValueError("audience is unsupported")
    machine_readable = require_boolean(machine_readable, "machine_readable")
    generated_at = require_cra_timestamp(generated_at, "generated_at")
    if registration.product_key != event.product_key:
        raise ValueError("registration does not match the selected event")
    payload: JsonObject = {
        "audience": audience,
        "boundary_notice": _BOUNDARY,
        "event_key": event.event_key,
        "generated_at": generated_at,
        "machine_readable": machine_readable,
        "operator_input_required": {
            "impact_and_risk_explanation": None,
            "mitigation_or_corrective_measures": None,
        },
        "product": _product(registration),
        "record_schema_version": CRA_SCHEMA_VERSION,
        "revision_digest": event.revision_digest,
        "track": event.track,
        "user_notice_channel": registration.user_notice_channel,
    }
    rendered = json_text(payload)
    markdown = _markdown(f"CRA Article 14(8) user notice for {event.event_key}", payload)
    return PreparedPayload(rendered, markdown, _digest(rendered), _digest(markdown))
