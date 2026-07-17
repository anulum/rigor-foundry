# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — externally cited source provenance
"""Assert and verify externally cited source claims without inventing authority."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Literal, cast

from .audit_primitives import (
    canonical_digest,
    require_exact_fields,
    require_mapping,
    require_string,
)
from .model_primitives import (
    JsonScalar,
    parse_utc_timestamp,
    require_digest,
    require_identifier,
    require_json_scalar,
    require_utc_timestamp,
)
from .source_capture import (
    SOURCE_PROVENANCE_SCHEMA_VERSION,
    SourceCapture,
    require_https_uri,
)

SourceKind = Literal["advisory", "version", "standard", "content-digest"]
ExtractionMethod = Literal["json-pointer", "whole-payload-sha256"]

_SOURCE_KINDS = frozenset({"advisory", "version", "standard", "content-digest"})
_EXTRACTION_METHODS = frozenset({"json-pointer", "whole-payload-sha256"})
_CLAIM_FIELDS = frozenset(
    {
        "schema_version",
        "claim_id",
        "kind",
        "subject",
        "predicate",
        "expected_value",
        "source_uri",
        "extraction_method",
        "selector",
        "claim_digest",
    }
)
_VERIFICATION_FIELDS = frozenset(
    {
        "schema_version",
        "claim",
        "capture",
        "verified_value",
        "verified_at",
        "verifier",
        "authority_scope",
        "verification_digest",
    }
)


def _source_kind(value: object, field: str) -> SourceKind:
    """Return one finite source-claim kind."""
    text = require_string(value, field)
    if text not in _SOURCE_KINDS:
        raise ValueError(f"{field} is unsupported")
    return cast(SourceKind, text)


def _extraction_method(value: object, field: str) -> ExtractionMethod:
    """Return one deterministic extraction method."""
    text = require_string(value, field)
    if text not in _EXTRACTION_METHODS:
        raise ValueError(f"{field} is unsupported")
    return cast(ExtractionMethod, text)


def _bounded_text(value: object, field: str, *, maximum: int) -> str:
    """Return bounded single-line Unicode protocol text without control bytes."""
    text = require_string(value, field)
    if len(text) > maximum or any(character in "\r\n\x00" for character in text):
        raise ValueError(f"{field} must be bounded single-line text")
    return text


@dataclass(frozen=True, init=False)
class ExternalSourceClaim:
    """One exact assertion expected at a named external HTTPS source."""

    claim_id: str
    kind: SourceKind
    subject: str
    predicate: str
    expected_value: JsonScalar
    source_uri: str
    extraction_method: ExtractionMethod
    selector: str
    claim_digest: str

    @classmethod
    def build(
        cls,
        *,
        claim_id: str,
        kind: SourceKind,
        subject: str,
        predicate: str,
        expected_value: JsonScalar,
        source_uri: str,
        extraction_method: ExtractionMethod,
        selector: str,
    ) -> ExternalSourceClaim:
        """Build a content-addressed assertion with relational validation."""
        checked_kind = _source_kind(kind, "source claim.kind")
        checked_method = _extraction_method(
            extraction_method,
            "source claim.extraction_method",
        )
        checked_selector = require_string(selector, "source claim.selector", allow_empty=True)
        checked_expected = require_json_scalar(expected_value, "source claim.expected_value")
        if isinstance(checked_expected, str):
            checked_expected = _bounded_text(
                checked_expected,
                "source claim.expected_value",
                maximum=4096,
            )
        if checked_kind == "content-digest":
            if checked_method != "whole-payload-sha256" or predicate != "sha256":
                raise ValueError(
                    "content-digest claims require predicate sha256 and whole-payload-sha256"
                )
            checked_expected = require_digest(
                checked_expected,
                "source claim.expected_value",
            )
            if checked_selector:
                raise ValueError("whole-payload-sha256 claims require an empty selector")
        elif checked_method != "json-pointer" or not checked_selector.startswith("/"):
            raise ValueError("non-digest claims require a non-empty JSON Pointer selector")
        fields: dict[str, object] = {
            "schema_version": SOURCE_PROVENANCE_SCHEMA_VERSION,
            "claim_id": require_identifier(claim_id, "source claim.claim_id"),
            "kind": checked_kind,
            "subject": _bounded_text(subject, "source claim.subject", maximum=512),
            "predicate": require_identifier(predicate, "source claim.predicate"),
            "expected_value": checked_expected,
            "source_uri": require_https_uri(source_uri, "source claim.source_uri"),
            "extraction_method": checked_method,
            "selector": checked_selector,
        }
        claim = object.__new__(cls)
        object.__setattr__(claim, "claim_id", cast(str, fields["claim_id"]))
        object.__setattr__(claim, "kind", checked_kind)
        object.__setattr__(claim, "subject", cast(str, fields["subject"]))
        object.__setattr__(claim, "predicate", cast(str, fields["predicate"]))
        object.__setattr__(claim, "expected_value", cast(JsonScalar, fields["expected_value"]))
        object.__setattr__(claim, "source_uri", cast(str, fields["source_uri"]))
        object.__setattr__(claim, "extraction_method", checked_method)
        object.__setattr__(claim, "selector", checked_selector)
        object.__setattr__(claim, "claim_digest", canonical_digest(fields))
        return claim

    def to_dict(self) -> dict[str, object]:
        """Serialise the complete assertion."""
        return {
            "schema_version": SOURCE_PROVENANCE_SCHEMA_VERSION,
            "claim_id": self.claim_id,
            "kind": self.kind,
            "subject": self.subject,
            "predicate": self.predicate,
            "expected_value": self.expected_value,
            "source_uri": self.source_uri,
            "extraction_method": self.extraction_method,
            "selector": self.selector,
            "claim_digest": self.claim_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> ExternalSourceClaim:
        """Parse and integrity-check an assertion."""
        data = require_mapping(value, "source claim")
        require_exact_fields(data, _CLAIM_FIELDS, "source claim")
        if data.get("schema_version") != SOURCE_PROVENANCE_SCHEMA_VERSION:
            raise ValueError("unsupported source-provenance schema version")
        claim = cls.build(
            claim_id=require_identifier(data.get("claim_id"), "source claim.claim_id"),
            kind=_source_kind(data.get("kind"), "source claim.kind"),
            subject=require_string(data.get("subject"), "source claim.subject"),
            predicate=require_identifier(data.get("predicate"), "source claim.predicate"),
            expected_value=require_json_scalar(
                data.get("expected_value"),
                "source claim.expected_value",
            ),
            source_uri=require_https_uri(data.get("source_uri"), "source claim.source_uri"),
            extraction_method=_extraction_method(
                data.get("extraction_method"),
                "source claim.extraction_method",
            ),
            selector=require_string(
                data.get("selector"),
                "source claim.selector",
                allow_empty=True,
            ),
        )
        if data.get("claim_digest") != claim.claim_digest:
            raise ValueError("source claim digest does not match its content")
        return claim


def _json_without_duplicate_keys(payload: bytes) -> object:
    """Parse UTF-8 JSON while rejecting duplicate object keys."""

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"source JSON contains duplicate key: {key}")
            result[key] = value
        return result

    try:
        text = payload.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON value: {value}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("source payload must be strict UTF-8 JSON") from exc


def _json_pointer(document: object, pointer: str) -> JsonScalar:
    """Resolve one non-empty RFC 6901 pointer to an exact JSON scalar."""
    current = document
    for raw_token in pointer.split("/")[1:]:
        position = 0
        while position < len(raw_token):
            if raw_token[position] != "~":
                position += 1
                continue
            if position + 1 >= len(raw_token) or raw_token[position + 1] not in {"0", "1"}:
                raise ValueError("source claim selector contains an invalid JSON Pointer escape")
            position += 2
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                raise ValueError("source claim selector is absent from the captured JSON")
            current = cast(dict[str, object], current)[token]
        elif isinstance(current, list):
            if not token.isdigit() or (len(token) > 1 and token.startswith("0")):
                raise ValueError("source claim selector has an invalid array index")
            index = int(token)
            if index >= len(current):
                raise ValueError("source claim selector array index is out of range")
            current = cast(list[object], current)[index]
        else:
            raise ValueError("source claim selector crosses a scalar value")
    return require_json_scalar(current, "source claim selected value")


@dataclass(frozen=True, init=False)
class SourceVerification:
    """Successful offline verification of one claim against exact captured bytes."""

    claim: ExternalSourceClaim
    capture: SourceCapture
    verified_value: JsonScalar
    verified_at: str
    verifier: str
    authority_scope: str
    verification_digest: str

    def to_dict(self) -> dict[str, object]:
        """Serialise complete successful verification evidence."""
        return {
            "schema_version": SOURCE_PROVENANCE_SCHEMA_VERSION,
            "claim": self.claim.to_dict(),
            "capture": self.capture.to_dict(),
            "verified_value": self.verified_value,
            "verified_at": self.verified_at,
            "verifier": self.verifier,
            "authority_scope": self.authority_scope,
            "verification_digest": self.verification_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> SourceVerification:
        """Parse evidence and validate its static success relations.

        This parser cannot replay JSON-pointer extraction because verification
        records intentionally omit retained payload bytes. Call
        :func:`verify_external_source` with the retained payload at trust
        boundaries that require extraction replay.
        """
        data = require_mapping(value, "source verification")
        require_exact_fields(data, _VERIFICATION_FIELDS, "source verification")
        if data.get("schema_version") != SOURCE_PROVENANCE_SCHEMA_VERSION:
            raise ValueError("unsupported source-provenance schema version")
        authority = require_string(
            data.get("authority_scope"), "source verification.authority_scope"
        )
        if authority != "retrieval-policy-only":
            raise ValueError("source verification authority scope is unsupported")
        claim = ExternalSourceClaim.from_dict(data.get("claim"))
        capture = SourceCapture.from_dict(data.get("capture"))
        verified_value = require_json_scalar(
            data.get("verified_value"), "source verification.verified_value"
        )
        verified_at = require_utc_timestamp(
            data.get("verified_at"), "source verification.verified_at"
        )
        _require_success_relations(claim, capture, verified_value, verified_at)
        fields: dict[str, object] = {
            "schema_version": SOURCE_PROVENANCE_SCHEMA_VERSION,
            "claim": claim.to_dict(),
            "capture": capture.to_dict(),
            "verified_value": verified_value,
            "verified_at": verified_at,
            "verifier": require_identifier(data.get("verifier"), "source verification.verifier"),
            "authority_scope": authority,
        }
        if data.get("verification_digest") != canonical_digest(fields):
            raise ValueError("source verification digest does not match its content")
        return cls._create(
            claim=claim,
            capture=capture,
            verified_value=verified_value,
            verified_at=verified_at,
            verifier=cast(str, fields["verifier"]),
            verification_digest=cast(str, data["verification_digest"]),
        )

    @classmethod
    def _create(
        cls,
        *,
        claim: ExternalSourceClaim,
        capture: SourceCapture,
        verified_value: JsonScalar,
        verified_at: str,
        verifier: str,
        verification_digest: str,
    ) -> SourceVerification:
        """Construct already validated evidence without a public unsafe initializer."""
        verification = object.__new__(cls)
        object.__setattr__(verification, "claim", claim)
        object.__setattr__(verification, "capture", capture)
        object.__setattr__(verification, "verified_value", verified_value)
        object.__setattr__(verification, "verified_at", verified_at)
        object.__setattr__(verification, "verifier", verifier)
        object.__setattr__(verification, "authority_scope", "retrieval-policy-only")
        object.__setattr__(verification, "verification_digest", verification_digest)
        return verification


def _require_success_relations(
    claim: ExternalSourceClaim,
    capture: SourceCapture,
    verified_value: JsonScalar,
    verified_at: str,
) -> None:
    """Reject mutually inconsistent success-shaped source evidence."""
    if claim.source_uri != capture.final_uri:
        raise ValueError("source claim URI does not match the final captured URI")
    age = (
        parse_utc_timestamp(verified_at, "source verification.verified_at")
        - parse_utc_timestamp(capture.retrieved_at, "source capture.retrieved_at")
    ).total_seconds()
    if age < 0 or age > capture.retrieval_policy.freshness_seconds:
        raise ValueError("source capture is outside the retrieval-policy freshness window")
    if (
        type(verified_value) is not type(claim.expected_value)
        or verified_value != claim.expected_value
    ):
        raise ValueError("source claim expected value does not match captured source")


def verify_external_source(
    claim: ExternalSourceClaim,
    capture: SourceCapture,
    payload: bytes,
    *,
    verified_at: str,
    verifier: str,
) -> SourceVerification:
    """Verify exact retained bytes, freshness, source binding, and asserted value."""
    checked_claim = ExternalSourceClaim.from_dict(claim.to_dict())
    checked_capture = SourceCapture.from_dict(capture.to_dict())
    if (
        len(payload) != checked_capture.payload_size
        or hashlib.sha256(payload).hexdigest() != checked_capture.payload_digest
    ):
        raise ValueError("source payload does not match capture identity")
    verified = require_utc_timestamp(verified_at, "source verification.verified_at")
    if checked_claim.extraction_method == "whole-payload-sha256":
        observed: JsonScalar = checked_capture.payload_digest
    else:
        observed = _json_pointer(
            _json_without_duplicate_keys(payload),
            checked_claim.selector,
        )
    _require_success_relations(checked_claim, checked_capture, observed, verified)
    fields: dict[str, object] = {
        "schema_version": SOURCE_PROVENANCE_SCHEMA_VERSION,
        "claim": checked_claim.to_dict(),
        "capture": checked_capture.to_dict(),
        "verified_value": observed,
        "verified_at": verified,
        "verifier": require_identifier(verifier, "source verification.verifier"),
        "authority_scope": "retrieval-policy-only",
    }
    return SourceVerification._create(
        claim=checked_claim,
        capture=checked_capture,
        verified_value=observed,
        verified_at=verified,
        verifier=cast(str, fields["verifier"]),
        verification_digest=canonical_digest(fields),
    )


def source_provenance_to_json(value: object) -> str:
    """Serialise one protocol record as deterministic UTF-8 JSON text."""
    if not hasattr(value, "to_dict"):
        raise ValueError("source provenance value must expose to_dict")
    document = value.to_dict()
    return (
        json.dumps(document, allow_nan=False, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )
