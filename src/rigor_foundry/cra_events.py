# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — CRA vulnerability and incident revision records
"""Define append-only vulnerability and severe-incident revision records."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from .audit_primitives import canonical_digest, require_exact_fields
from .cra_protocol import (
    CRA_SCHEMA_VERSION,
    STATUS_TRANSITIONS,
    EventStatus,
    JsonObject,
    Sensitivity,
    SevereProng,
    SuspectedCause,
    Track,
    json_text,
    optional_string,
    optional_timestamp,
    parse_cra_timestamp,
    record_fields,
    require_cra_timestamp,
    require_enum,
    require_member_states,
    require_status,
    require_track,
)
from .model_primitives import require_digest, require_identifier, require_unique_strings
from .models import require_mapping, require_string

_FIELDS = frozenset(
    {
        "schema_version",
        "event_key",
        "product_key",
        "track",
        "aware_at",
        "aware_evidence_ref",
        "exploitation_evidence",
        "severe_prong",
        "severe_evidence_ref",
        "suspected_cause",
        "external_ids",
        "affected_components",
        "severity_value",
        "severity_source_ref",
        "member_states",
        "sensitivity",
        "status",
        "corrective_measure_available_at",
        "intermediate_requested_at",
        "intermediate_due_at",
        "intermediate_evidence_ref",
        "recorded_at",
        "previous_revision_digest",
        "revision_digest",
    }
)


@dataclass(frozen=True)
class SecurityEventRevision:
    """Store one immutable revision of a vulnerability or incident record."""

    event_key: str
    product_key: str
    track: Track
    aware_at: str
    aware_evidence_ref: str
    exploitation_evidence: tuple[str, ...]
    severe_prong: SevereProng | None
    severe_evidence_ref: str | None
    suspected_cause: SuspectedCause | None
    external_ids: tuple[str, ...]
    affected_components: tuple[str, ...]
    severity_value: str | None
    severity_source_ref: str | None
    member_states: tuple[str, ...]
    sensitivity: Sensitivity
    status: EventStatus
    corrective_measure_available_at: str | None
    intermediate_requested_at: str | None
    intermediate_due_at: str | None
    intermediate_evidence_ref: str | None
    recorded_at: str
    previous_revision_digest: str | None
    revision_digest: str

    @classmethod
    def build(
        cls,
        *,
        event_key: str,
        product_key: str,
        track: Track,
        aware_at: str,
        aware_evidence_ref: str,
        exploitation_evidence: tuple[str, ...] = (),
        severe_prong: SevereProng | None = None,
        severe_evidence_ref: str | None = None,
        suspected_cause: SuspectedCause | None = None,
        external_ids: tuple[str, ...] = (),
        affected_components: tuple[str, ...] = (),
        severity_value: str | None = None,
        severity_source_ref: str | None = None,
        member_states: tuple[str, ...] = (),
        sensitivity: Sensitivity = "normal",
        status: EventStatus = "triaged",
        corrective_measure_available_at: str | None = None,
        intermediate_requested_at: str | None = None,
        intermediate_due_at: str | None = None,
        intermediate_evidence_ref: str | None = None,
        recorded_at: str,
        previous_revision_digest: str | None = None,
    ) -> SecurityEventRevision:
        """Build one strict digest-bound event revision."""
        track = require_track(track)
        event_key = require_identifier(event_key, "event_key")
        product_key = require_identifier(product_key, "product_key")
        aware_at = require_cra_timestamp(aware_at, "aware_at")
        aware_evidence_ref = require_string(aware_evidence_ref, "aware_evidence_ref")
        exploitation_evidence = require_unique_strings(
            list(exploitation_evidence),
            "exploitation_evidence",
            minimum=1 if track == "vulnerability" else 0,
        )
        if track == "vulnerability":
            if (
                severe_prong is not None
                or severe_evidence_ref is not None
                or suspected_cause is not None
            ):
                raise ValueError("vulnerability track must not carry incident trigger fields")
        else:
            if exploitation_evidence:
                raise ValueError("incident track must not carry exploitation_evidence")
            severe_prong = cast(
                SevereProng,
                require_enum(
                    severe_prong,
                    "severe_prong",
                    frozenset({"data-or-functions", "malicious-code"}),
                ),
            )
            severe_evidence_ref = require_string(severe_evidence_ref, "severe_evidence_ref")
            suspected_cause = cast(
                SuspectedCause,
                require_enum(
                    suspected_cause,
                    "suspected_cause",
                    frozenset({"unlawful-or-malicious", "not-suspected", "unknown"}),
                ),
            )
        external_ids = require_unique_strings(list(external_ids), "external_ids")
        affected_components = require_unique_strings(
            list(affected_components), "affected_components"
        )
        if (severity_value is None) != (severity_source_ref is None):
            raise ValueError("severity_value and severity_source_ref must be declared together")
        severity_value = optional_string(severity_value, "severity_value")
        severity_source_ref = optional_string(severity_source_ref, "severity_source_ref")
        member_states = require_member_states(list(member_states))
        sensitivity = cast(
            Sensitivity,
            require_enum(sensitivity, "sensitivity", frozenset({"normal", "sensitive"})),
        )
        status = require_status(status)
        corrective_measure_available_at = optional_timestamp(
            corrective_measure_available_at, "corrective_measure_available_at"
        )
        intermediate = (
            intermediate_requested_at,
            intermediate_due_at,
            intermediate_evidence_ref,
        )
        if any(value is not None for value in intermediate) and not all(
            value is not None for value in intermediate
        ):
            raise ValueError("intermediate request time, due time, and evidence are all required")
        intermediate_requested_at = optional_timestamp(
            intermediate_requested_at, "intermediate_requested_at"
        )
        intermediate_due_at = optional_timestamp(intermediate_due_at, "intermediate_due_at")
        intermediate_evidence_ref = optional_string(
            intermediate_evidence_ref, "intermediate_evidence_ref"
        )
        if (
            intermediate_requested_at is not None
            and intermediate_due_at is not None
            and parse_cra_timestamp(intermediate_due_at)
            <= parse_cra_timestamp(intermediate_requested_at)
        ):
            raise ValueError("intermediate_due_at must follow intermediate_requested_at")
        recorded_at = require_cra_timestamp(recorded_at, "recorded_at")
        if previous_revision_digest is not None:
            previous_revision_digest = require_digest(
                previous_revision_digest, "previous_revision_digest"
            )
        body: JsonObject = {
            "schema_version": CRA_SCHEMA_VERSION,
            "event_key": event_key,
            "product_key": product_key,
            "track": track,
            "aware_at": aware_at,
            "aware_evidence_ref": aware_evidence_ref,
            "exploitation_evidence": list(exploitation_evidence),
            "severe_prong": severe_prong,
            "severe_evidence_ref": severe_evidence_ref,
            "suspected_cause": suspected_cause,
            "external_ids": list(external_ids),
            "affected_components": list(affected_components),
            "severity_value": severity_value,
            "severity_source_ref": severity_source_ref,
            "member_states": list(member_states),
            "sensitivity": sensitivity,
            "status": status,
            "corrective_measure_available_at": corrective_measure_available_at,
            "intermediate_requested_at": intermediate_requested_at,
            "intermediate_due_at": intermediate_due_at,
            "intermediate_evidence_ref": intermediate_evidence_ref,
            "recorded_at": recorded_at,
            "previous_revision_digest": previous_revision_digest,
        }
        return cls(
            event_key=event_key,
            product_key=product_key,
            track=track,
            aware_at=aware_at,
            aware_evidence_ref=aware_evidence_ref,
            exploitation_evidence=exploitation_evidence,
            severe_prong=severe_prong,
            severe_evidence_ref=severe_evidence_ref,
            suspected_cause=suspected_cause,
            external_ids=external_ids,
            affected_components=affected_components,
            severity_value=severity_value,
            severity_source_ref=severity_source_ref,
            member_states=member_states,
            sensitivity=sensitivity,
            status=status,
            corrective_measure_available_at=corrective_measure_available_at,
            intermediate_requested_at=intermediate_requested_at,
            intermediate_due_at=intermediate_due_at,
            intermediate_evidence_ref=intermediate_evidence_ref,
            recorded_at=recorded_at,
            previous_revision_digest=previous_revision_digest,
            revision_digest=canonical_digest(body),
        )

    def to_dict(self) -> JsonObject:
        """Serialise the exact event revision."""
        return {"schema_version": CRA_SCHEMA_VERSION, **record_fields(self)}

    def to_json(self) -> str:
        """Serialise deterministic human-readable JSON."""
        return json_text(self.to_dict())

    @classmethod
    def from_dict(cls, value: object) -> SecurityEventRevision:
        """Parse and integrity-check one event revision."""
        data = require_mapping(value, "security_event_revision")
        require_exact_fields(data, _FIELDS, "security_event_revision")
        if data.get("schema_version") != CRA_SCHEMA_VERSION:
            raise ValueError("security_event_revision schema_version is unsupported")
        expected = cls.build(
            event_key=require_string(data.get("event_key"), "event_key"),
            product_key=require_string(data.get("product_key"), "product_key"),
            track=require_track(data.get("track")),
            aware_at=require_string(data.get("aware_at"), "aware_at"),
            aware_evidence_ref=require_string(
                data.get("aware_evidence_ref"), "aware_evidence_ref"
            ),
            exploitation_evidence=require_unique_strings(
                data.get("exploitation_evidence"), "exploitation_evidence"
            ),
            severe_prong=cast(SevereProng | None, data.get("severe_prong")),
            severe_evidence_ref=optional_string(
                data.get("severe_evidence_ref"), "severe_evidence_ref"
            ),
            suspected_cause=cast(SuspectedCause | None, data.get("suspected_cause")),
            external_ids=require_unique_strings(data.get("external_ids"), "external_ids"),
            affected_components=require_unique_strings(
                data.get("affected_components"), "affected_components"
            ),
            severity_value=optional_string(data.get("severity_value"), "severity_value"),
            severity_source_ref=optional_string(
                data.get("severity_source_ref"), "severity_source_ref"
            ),
            member_states=require_member_states(data.get("member_states")),
            sensitivity=cast(Sensitivity, data.get("sensitivity")),
            status=require_status(data.get("status")),
            corrective_measure_available_at=optional_string(
                data.get("corrective_measure_available_at"),
                "corrective_measure_available_at",
            ),
            intermediate_requested_at=optional_string(
                data.get("intermediate_requested_at"), "intermediate_requested_at"
            ),
            intermediate_due_at=optional_string(
                data.get("intermediate_due_at"), "intermediate_due_at"
            ),
            intermediate_evidence_ref=optional_string(
                data.get("intermediate_evidence_ref"), "intermediate_evidence_ref"
            ),
            recorded_at=require_string(data.get("recorded_at"), "recorded_at"),
            previous_revision_digest=(
                None
                if data.get("previous_revision_digest") is None
                else require_digest(
                    data.get("previous_revision_digest"), "previous_revision_digest"
                )
            ),
        )
        if (
            require_digest(data.get("revision_digest"), "revision_digest")
            != expected.revision_digest
        ):
            raise ValueError("event revision digest does not match its content")
        return expected


def validate_revision_successor(
    previous: SecurityEventRevision,
    successor: SecurityEventRevision,
) -> None:
    """Reject forks, identity changes, and unsupported event transitions."""
    if successor.previous_revision_digest != previous.revision_digest:
        raise ValueError("event revision does not extend the current digest")
    immutable = (
        "event_key",
        "product_key",
        "track",
        "aware_at",
        "aware_evidence_ref",
        "exploitation_evidence",
        "severe_prong",
        "severe_evidence_ref",
        "suspected_cause",
    )
    if any(getattr(previous, field) != getattr(successor, field) for field in immutable):
        raise ValueError("event successor changed immutable trigger identity")
    if (
        successor.status != previous.status
        and successor.status not in STATUS_TRANSITIONS[previous.status]
    ):
        raise ValueError("event status transition is unsupported")
    if parse_cra_timestamp(successor.recorded_at) <= parse_cra_timestamp(previous.recorded_at):
        raise ValueError("successor recorded_at must follow its predecessor")
