# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — CRA draft, receipt, skip, and notice records
"""Define evidence-bound records without claiming authority submission."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, cast

from .audit_primitives import canonical_digest, require_exact_fields
from .cra_protocol import (
    CRA_SCHEMA_VERSION,
    STAGE_ORDER,
    JsonObject,
    Stage,
    Track,
    json_text,
    record_fields,
    require_cra_timestamp,
    require_enum,
    require_relative_path,
    require_stage,
    require_track,
)
from .model_primitives import require_boolean, require_digest, require_identifier
from .models import require_mapping, require_string

_DRAFT_FIELDS = frozenset(
    {
        "schema_version",
        "product_key",
        "event_key",
        "track",
        "stage",
        "revision_digest",
        "payload_path",
        "payload_digest",
        "markdown_path",
        "markdown_payload_digest",
        "generated_at",
        "tool_version",
        "draft_digest",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "product_key",
        "event_key",
        "track",
        "stage",
        "draft_digest",
        "payload_digest",
        "submitted_at",
        "platform_ref",
        "csirt_endpoint_id",
        "evidence_sha256",
        "bound_at",
        "receipt_digest",
    }
)
_SKIP_FIELDS = frozenset(
    {
        "schema_version",
        "product_key",
        "event_key",
        "track",
        "stage",
        "provided_in_stage",
        "provided_in_receipt_digest",
        "reason",
        "evidence_ref",
        "skipped_at",
        "skip_digest",
    }
)
_NOTICE_FIELDS = frozenset(
    {
        "schema_version",
        "product_key",
        "event_key",
        "track",
        "revision_digest",
        "audience",
        "machine_readable",
        "json_payload_digest",
        "markdown_payload_digest",
        "generated_at",
        "notice_digest",
    }
)


@dataclass(frozen=True)
class StageDraft:
    """Bind one deterministic stage payload to an exact event revision."""

    product_key: str
    event_key: str
    track: Track
    stage: Stage
    revision_digest: str
    payload_path: str
    payload_digest: str
    markdown_path: str
    markdown_payload_digest: str
    generated_at: str
    tool_version: str
    draft_digest: str

    @classmethod
    def build(
        cls,
        *,
        product_key: str,
        event_key: str,
        track: Track,
        stage: Stage,
        revision_digest: str,
        payload_path: str,
        payload_digest: str,
        markdown_path: str,
        markdown_payload_digest: str,
        generated_at: str,
        tool_version: str,
    ) -> StageDraft:
        """Build one digest-bound draft record."""
        product_key = require_identifier(product_key, "product_key")
        event_key = require_identifier(event_key, "event_key")
        track = require_track(track)
        stage = require_stage(stage)
        revision_digest = require_digest(revision_digest, "revision_digest")
        payload_path = require_relative_path(payload_path, "payload_path")
        payload_digest = require_digest(payload_digest, "payload_digest")
        markdown_path = require_relative_path(markdown_path, "markdown_path")
        markdown_payload_digest = require_digest(
            markdown_payload_digest, "markdown_payload_digest"
        )
        generated_at = require_cra_timestamp(generated_at, "generated_at")
        tool_version = require_string(tool_version, "tool_version")
        body: JsonObject = {
            "schema_version": CRA_SCHEMA_VERSION,
            "product_key": product_key,
            "event_key": event_key,
            "track": track,
            "stage": stage,
            "revision_digest": revision_digest,
            "payload_path": payload_path,
            "payload_digest": payload_digest,
            "markdown_path": markdown_path,
            "markdown_payload_digest": markdown_payload_digest,
            "generated_at": generated_at,
            "tool_version": tool_version,
        }
        return cls(
            product_key=product_key,
            event_key=event_key,
            track=track,
            stage=stage,
            revision_digest=revision_digest,
            payload_path=payload_path,
            payload_digest=payload_digest,
            markdown_path=markdown_path,
            markdown_payload_digest=markdown_payload_digest,
            generated_at=generated_at,
            tool_version=tool_version,
            draft_digest=canonical_digest(body),
        )

    def to_dict(self) -> JsonObject:
        """Serialise the exact draft record."""
        return {"schema_version": CRA_SCHEMA_VERSION, **record_fields(self)}

    def to_json(self) -> str:
        """Serialise deterministic human-readable JSON."""
        return json_text(self.to_dict())

    @classmethod
    def from_dict(cls, value: object) -> StageDraft:
        """Parse and integrity-check one draft record."""
        data = require_mapping(value, "stage_draft")
        require_exact_fields(data, _DRAFT_FIELDS, "stage_draft")
        if data.get("schema_version") != CRA_SCHEMA_VERSION:
            raise ValueError("stage_draft schema_version is unsupported")
        expected = cls.build(
            product_key=require_string(data.get("product_key"), "product_key"),
            event_key=require_string(data.get("event_key"), "event_key"),
            track=require_track(data.get("track")),
            stage=require_stage(data.get("stage")),
            revision_digest=require_digest(data.get("revision_digest"), "revision_digest"),
            payload_path=require_string(data.get("payload_path"), "payload_path"),
            payload_digest=require_digest(data.get("payload_digest"), "payload_digest"),
            markdown_path=require_string(data.get("markdown_path"), "markdown_path"),
            markdown_payload_digest=require_digest(
                data.get("markdown_payload_digest"), "markdown_payload_digest"
            ),
            generated_at=require_string(data.get("generated_at"), "generated_at"),
            tool_version=require_string(data.get("tool_version"), "tool_version"),
        )
        if require_digest(data.get("draft_digest"), "draft_digest") != expected.draft_digest:
            raise ValueError("draft digest does not match its content")
        return expected


@dataclass(frozen=True)
class SubmissionReceipt:
    """Bind operator-declared submission evidence to one exact draft."""

    product_key: str
    event_key: str
    track: Track
    stage: Stage
    draft_digest: str
    payload_digest: str
    submitted_at: str
    platform_ref: str
    csirt_endpoint_id: str
    evidence_sha256: str
    bound_at: str
    receipt_digest: str

    @classmethod
    def build(
        cls,
        *,
        product_key: str,
        event_key: str,
        track: Track,
        stage: Stage,
        draft_digest: str,
        payload_digest: str,
        submitted_at: str,
        platform_ref: str,
        csirt_endpoint_id: str,
        evidence_sha256: str,
        bound_at: str,
    ) -> SubmissionReceipt:
        """Build one receipt that does not itself claim authority acceptance."""
        product_key = require_identifier(product_key, "product_key")
        event_key = require_identifier(event_key, "event_key")
        track = require_track(track)
        stage = require_stage(stage)
        draft_digest = require_digest(draft_digest, "draft_digest")
        payload_digest = require_digest(payload_digest, "payload_digest")
        submitted_at = require_cra_timestamp(submitted_at, "submitted_at")
        platform_ref = require_string(platform_ref, "platform_ref")
        csirt_endpoint_id = require_identifier(csirt_endpoint_id, "csirt_endpoint_id")
        evidence_sha256 = require_digest(evidence_sha256, "evidence_sha256")
        bound_at = require_cra_timestamp(bound_at, "bound_at")
        body: JsonObject = {
            "schema_version": CRA_SCHEMA_VERSION,
            "product_key": product_key,
            "event_key": event_key,
            "track": track,
            "stage": stage,
            "draft_digest": draft_digest,
            "payload_digest": payload_digest,
            "submitted_at": submitted_at,
            "platform_ref": platform_ref,
            "csirt_endpoint_id": csirt_endpoint_id,
            "evidence_sha256": evidence_sha256,
            "bound_at": bound_at,
        }
        return cls(
            product_key=product_key,
            event_key=event_key,
            track=track,
            stage=stage,
            draft_digest=draft_digest,
            payload_digest=payload_digest,
            submitted_at=submitted_at,
            platform_ref=platform_ref,
            csirt_endpoint_id=csirt_endpoint_id,
            evidence_sha256=evidence_sha256,
            bound_at=bound_at,
            receipt_digest=canonical_digest(body),
        )

    def to_dict(self) -> JsonObject:
        """Serialise the exact receipt record."""
        return {"schema_version": CRA_SCHEMA_VERSION, **record_fields(self)}

    def to_json(self) -> str:
        """Serialise deterministic human-readable JSON."""
        return json_text(self.to_dict())

    @classmethod
    def from_dict(cls, value: object) -> SubmissionReceipt:
        """Parse and integrity-check one receipt record."""
        data = require_mapping(value, "submission_receipt")
        require_exact_fields(data, _RECEIPT_FIELDS, "submission_receipt")
        if data.get("schema_version") != CRA_SCHEMA_VERSION:
            raise ValueError("submission_receipt schema_version is unsupported")
        expected = cls.build(
            product_key=require_string(data.get("product_key"), "product_key"),
            event_key=require_string(data.get("event_key"), "event_key"),
            track=require_track(data.get("track")),
            stage=require_stage(data.get("stage")),
            draft_digest=require_digest(data.get("draft_digest"), "draft_digest"),
            payload_digest=require_digest(data.get("payload_digest"), "payload_digest"),
            submitted_at=require_string(data.get("submitted_at"), "submitted_at"),
            platform_ref=require_string(data.get("platform_ref"), "platform_ref"),
            csirt_endpoint_id=require_string(data.get("csirt_endpoint_id"), "csirt_endpoint_id"),
            evidence_sha256=require_digest(data.get("evidence_sha256"), "evidence_sha256"),
            bound_at=require_string(data.get("bound_at"), "bound_at"),
        )
        if require_digest(data.get("receipt_digest"), "receipt_digest") != expected.receipt_digest:
            raise ValueError("receipt digest does not match its content")
        return expected


def validate_receipt_binding(draft: StageDraft, receipt: SubmissionReceipt) -> None:
    """Reject a receipt that does not bind every draft identity field."""
    if (
        receipt.product_key,
        receipt.event_key,
        receipt.track,
        receipt.stage,
        receipt.draft_digest,
        receipt.payload_digest,
    ) != (
        draft.product_key,
        draft.event_key,
        draft.track,
        draft.stage,
        draft.draft_digest,
        draft.payload_digest,
    ):
        raise ValueError("receipt does not bind the selected draft")


@dataclass(frozen=True)
class StageSkip:
    """Record that a stage's information was already provided in an earlier receipt."""

    product_key: str
    event_key: str
    track: Track
    stage: Literal["notification", "final-report"]
    provided_in_stage: Stage
    provided_in_receipt_digest: str
    reason: str
    evidence_ref: str
    skipped_at: str
    skip_digest: str

    @classmethod
    def build(
        cls,
        *,
        product_key: str,
        event_key: str,
        track: Track,
        stage: Literal["notification", "final-report"],
        provided_in_stage: Stage,
        provided_in_receipt_digest: str,
        reason: str,
        evidence_ref: str,
        skipped_at: str,
    ) -> StageSkip:
        """Build one explicit already-provided stage record."""
        product_key = require_identifier(product_key, "product_key")
        event_key = require_identifier(event_key, "event_key")
        track = require_track(track)
        stage = cast(
            Literal["notification", "final-report"],
            require_enum(stage, "stage", frozenset({"notification", "final-report"})),
        )
        provided_in_stage = require_stage(provided_in_stage, "provided_in_stage")
        if STAGE_ORDER[provided_in_stage] >= STAGE_ORDER[stage]:
            raise ValueError("provided_in_stage must precede the skipped stage")
        provided_in_receipt_digest = require_digest(
            provided_in_receipt_digest, "provided_in_receipt_digest"
        )
        reason = require_string(reason, "reason")
        evidence_ref = require_string(evidence_ref, "evidence_ref")
        skipped_at = require_cra_timestamp(skipped_at, "skipped_at")
        body: JsonObject = {
            "schema_version": CRA_SCHEMA_VERSION,
            "product_key": product_key,
            "event_key": event_key,
            "track": track,
            "stage": stage,
            "provided_in_stage": provided_in_stage,
            "provided_in_receipt_digest": provided_in_receipt_digest,
            "reason": reason,
            "evidence_ref": evidence_ref,
            "skipped_at": skipped_at,
        }
        return cls(
            product_key=product_key,
            event_key=event_key,
            track=track,
            stage=stage,
            provided_in_stage=provided_in_stage,
            provided_in_receipt_digest=provided_in_receipt_digest,
            reason=reason,
            evidence_ref=evidence_ref,
            skipped_at=skipped_at,
            skip_digest=canonical_digest(body),
        )

    def to_dict(self) -> JsonObject:
        """Serialise the exact skip record."""
        return {"schema_version": CRA_SCHEMA_VERSION, **record_fields(self)}

    def to_json(self) -> str:
        """Serialise deterministic human-readable JSON."""
        return json_text(self.to_dict())

    @classmethod
    def from_dict(cls, value: object) -> StageSkip:
        """Parse and integrity-check one skip record."""
        data = require_mapping(value, "stage_skip")
        require_exact_fields(data, _SKIP_FIELDS, "stage_skip")
        if data.get("schema_version") != CRA_SCHEMA_VERSION:
            raise ValueError("stage_skip schema_version is unsupported")
        expected = cls.build(
            product_key=require_string(data.get("product_key"), "product_key"),
            event_key=require_string(data.get("event_key"), "event_key"),
            track=require_track(data.get("track")),
            stage=cast(Literal["notification", "final-report"], data.get("stage")),
            provided_in_stage=require_stage(data.get("provided_in_stage"), "provided_in_stage"),
            provided_in_receipt_digest=require_digest(
                data.get("provided_in_receipt_digest"), "provided_in_receipt_digest"
            ),
            reason=require_string(data.get("reason"), "reason"),
            evidence_ref=require_string(data.get("evidence_ref"), "evidence_ref"),
            skipped_at=require_string(data.get("skipped_at"), "skipped_at"),
        )
        if require_digest(data.get("skip_digest"), "skip_digest") != expected.skip_digest:
            raise ValueError("skip digest does not match its content")
        return expected


def validate_skip_binding(skip: StageSkip, receipts: tuple[SubmissionReceipt, ...]) -> None:
    """Require one exact earlier receipt for an already-provided skip."""
    matches = tuple(
        receipt
        for receipt in receipts
        if receipt.receipt_digest == skip.provided_in_receipt_digest
    )
    if len(matches) != 1:
        raise ValueError("skip must bind exactly one available receipt")
    receipt = matches[0]
    if (
        receipt.product_key,
        receipt.event_key,
        receipt.track,
        receipt.stage,
    ) != (skip.product_key, skip.event_key, skip.track, skip.provided_in_stage):
        raise ValueError("skip receipt identity does not match the skipped event")


@dataclass(frozen=True)
class UserNoticeDraft:
    """Bind one prepare-only Article 14(8) user-notice payload pair."""

    product_key: str
    event_key: str
    track: Track
    revision_digest: str
    audience: Literal["impacted", "all"]
    machine_readable: bool
    json_payload_digest: str
    markdown_payload_digest: str
    generated_at: str
    notice_digest: str

    @classmethod
    def build(
        cls,
        *,
        product_key: str,
        event_key: str,
        track: Track,
        revision_digest: str,
        audience: Literal["impacted", "all"],
        machine_readable: bool,
        json_payload_digest: str,
        markdown_payload_digest: str,
        generated_at: str,
    ) -> UserNoticeDraft:
        """Build one content-addressed user-notice draft."""
        product_key = require_identifier(product_key, "product_key")
        event_key = require_identifier(event_key, "event_key")
        track = require_track(track)
        revision_digest = require_digest(revision_digest, "revision_digest")
        audience = cast(
            Literal["impacted", "all"],
            require_enum(audience, "audience", frozenset({"impacted", "all"})),
        )
        machine_readable = require_boolean(machine_readable, "machine_readable")
        json_payload_digest = require_digest(json_payload_digest, "json_payload_digest")
        markdown_payload_digest = require_digest(
            markdown_payload_digest, "markdown_payload_digest"
        )
        generated_at = require_cra_timestamp(generated_at, "generated_at")
        body: JsonObject = {
            "schema_version": CRA_SCHEMA_VERSION,
            "product_key": product_key,
            "event_key": event_key,
            "track": track,
            "revision_digest": revision_digest,
            "audience": audience,
            "machine_readable": machine_readable,
            "json_payload_digest": json_payload_digest,
            "markdown_payload_digest": markdown_payload_digest,
            "generated_at": generated_at,
        }
        return cls(
            product_key=product_key,
            event_key=event_key,
            track=track,
            revision_digest=revision_digest,
            audience=audience,
            machine_readable=machine_readable,
            json_payload_digest=json_payload_digest,
            markdown_payload_digest=markdown_payload_digest,
            generated_at=generated_at,
            notice_digest=canonical_digest(body),
        )

    def to_dict(self) -> JsonObject:
        """Serialise the exact notice record."""
        return {"schema_version": CRA_SCHEMA_VERSION, **record_fields(self)}

    def to_json(self) -> str:
        """Serialise deterministic human-readable JSON."""
        return json_text(self.to_dict())

    @classmethod
    def from_dict(cls, value: object) -> UserNoticeDraft:
        """Parse and integrity-check one notice record."""
        data = require_mapping(value, "user_notice_draft")
        require_exact_fields(data, _NOTICE_FIELDS, "user_notice_draft")
        if data.get("schema_version") != CRA_SCHEMA_VERSION:
            raise ValueError("user_notice_draft schema_version is unsupported")
        expected = cls.build(
            product_key=require_string(data.get("product_key"), "product_key"),
            event_key=require_string(data.get("event_key"), "event_key"),
            track=require_track(data.get("track")),
            revision_digest=require_digest(data.get("revision_digest"), "revision_digest"),
            audience=cast(Literal["impacted", "all"], data.get("audience")),
            machine_readable=require_boolean(data.get("machine_readable"), "machine_readable"),
            json_payload_digest=require_digest(
                data.get("json_payload_digest"), "json_payload_digest"
            ),
            markdown_payload_digest=require_digest(
                data.get("markdown_payload_digest"), "markdown_payload_digest"
            ),
            generated_at=require_string(data.get("generated_at"), "generated_at"),
        )
        if require_digest(data.get("notice_digest"), "notice_digest") != expected.notice_digest:
            raise ValueError("notice digest does not match its content")
        return expected
