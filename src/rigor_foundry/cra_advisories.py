# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — fixed-vulnerability advisory evidence
"""Model append-only advisory preparation, publication, and justified delay."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, cast

from .audit_primitives import canonical_digest, require_exact_fields
from .cra_protocol import (
    CRA_SCHEMA_VERSION,
    JsonObject,
    json_text,
    optional_string,
    optional_timestamp,
    parse_cra_timestamp,
    record_fields,
    require_cra_timestamp,
    require_relative_path,
)
from .model_primitives import require_digest, require_identifier
from .models import require_mapping, require_string

AdvisoryState = Literal["draft", "published", "justified-delay"]

_FIELDS = frozenset(
    {
        "schema_version",
        "product_key",
        "event_key",
        "revision_digest",
        "state",
        "security_update_ref",
        "advisory_path",
        "advisory_sha256",
        "drafted_at",
        "published_at",
        "publication_evidence_path",
        "publication_evidence_sha256",
        "delay_reason",
        "delay_review_at",
        "delay_evidence_path",
        "delay_evidence_sha256",
        "previous_advisory_digest",
        "advisory_digest",
    }
)


@dataclass(frozen=True)
class FixedVulnerabilityAdvisory:
    """Bind operator-declared advisory state without publishing anything."""

    product_key: str
    event_key: str
    revision_digest: str
    state: AdvisoryState
    security_update_ref: str
    advisory_path: str
    advisory_sha256: str
    drafted_at: str
    published_at: str | None
    publication_evidence_path: str | None
    publication_evidence_sha256: str | None
    delay_reason: str | None
    delay_review_at: str | None
    delay_evidence_path: str | None
    delay_evidence_sha256: str | None
    previous_advisory_digest: str | None
    advisory_digest: str

    @classmethod
    def build(
        cls,
        *,
        product_key: str,
        event_key: str,
        revision_digest: str,
        state: AdvisoryState,
        security_update_ref: str,
        advisory_path: str,
        advisory_sha256: str,
        drafted_at: str,
        published_at: str | None = None,
        publication_evidence_path: str | None = None,
        publication_evidence_sha256: str | None = None,
        delay_reason: str | None = None,
        delay_review_at: str | None = None,
        delay_evidence_path: str | None = None,
        delay_evidence_sha256: str | None = None,
        previous_advisory_digest: str | None = None,
    ) -> FixedVulnerabilityAdvisory:
        """Build one exact advisory revision with consistent state fields."""
        if state not in {"draft", "published", "justified-delay"}:
            raise ValueError("advisory.state is unsupported")
        published_at = optional_timestamp(published_at, "advisory.published_at")
        if publication_evidence_path is not None:
            publication_evidence_path = require_relative_path(
                publication_evidence_path,
                "advisory.publication_evidence_path",
            )
        if publication_evidence_sha256 is not None:
            publication_evidence_sha256 = require_digest(
                publication_evidence_sha256,
                "advisory.publication_evidence_sha256",
            )
        delay_reason = optional_string(delay_reason, "advisory.delay_reason")
        delay_review_at = optional_timestamp(delay_review_at, "advisory.delay_review_at")
        if delay_evidence_path is not None:
            delay_evidence_path = require_relative_path(
                delay_evidence_path,
                "advisory.delay_evidence_path",
            )
        if delay_evidence_sha256 is not None:
            delay_evidence_sha256 = require_digest(
                delay_evidence_sha256,
                "advisory.delay_evidence_sha256",
            )
        if state == "draft" and any(
            value is not None
            for value in (
                published_at,
                publication_evidence_path,
                publication_evidence_sha256,
                delay_reason,
                delay_review_at,
                delay_evidence_path,
                delay_evidence_sha256,
            )
        ):
            raise ValueError("draft advisory must not carry publication or delay evidence")
        if state == "published" and (
            published_at is None
            or publication_evidence_path is None
            or publication_evidence_sha256 is None
            or delay_reason is not None
            or delay_review_at is not None
            or delay_evidence_path is not None
            or delay_evidence_sha256 is not None
        ):
            raise ValueError("published advisory requires time and publication evidence only")
        if state == "published" and parse_cra_timestamp(cast(str, published_at)) < (
            parse_cra_timestamp(drafted_at)
        ):
            raise ValueError("advisory publication must not precede its draft")
        if state == "justified-delay" and (
            published_at is not None
            or publication_evidence_path is not None
            or publication_evidence_sha256 is not None
            or delay_reason is None
            or delay_review_at is None
            or delay_evidence_path is None
            or delay_evidence_sha256 is None
        ):
            raise ValueError("justified delay requires reason, review_at, and evidence only")
        if state == "justified-delay" and parse_cra_timestamp(cast(str, delay_review_at)) <= (
            parse_cra_timestamp(drafted_at)
        ):
            raise ValueError("advisory delay review must be after its draft")
        if previous_advisory_digest is not None:
            previous_advisory_digest = require_digest(
                previous_advisory_digest,
                "advisory.previous_advisory_digest",
            )
        body: JsonObject = {
            "schema_version": CRA_SCHEMA_VERSION,
            "product_key": require_identifier(product_key, "advisory.product_key"),
            "event_key": require_identifier(event_key, "advisory.event_key"),
            "revision_digest": require_digest(
                revision_digest,
                "advisory.revision_digest",
            ),
            "state": state,
            "security_update_ref": require_string(
                security_update_ref,
                "advisory.security_update_ref",
            ),
            "advisory_path": require_relative_path(
                advisory_path,
                "advisory.advisory_path",
            ),
            "advisory_sha256": require_digest(
                advisory_sha256,
                "advisory.advisory_sha256",
            ),
            "drafted_at": require_cra_timestamp(drafted_at, "advisory.drafted_at"),
            "published_at": published_at,
            "publication_evidence_path": publication_evidence_path,
            "publication_evidence_sha256": publication_evidence_sha256,
            "delay_reason": delay_reason,
            "delay_review_at": delay_review_at,
            "delay_evidence_path": delay_evidence_path,
            "delay_evidence_sha256": delay_evidence_sha256,
            "previous_advisory_digest": previous_advisory_digest,
        }
        return cls(
            product_key=cast(str, body["product_key"]),
            event_key=cast(str, body["event_key"]),
            revision_digest=cast(str, body["revision_digest"]),
            state=state,
            security_update_ref=cast(str, body["security_update_ref"]),
            advisory_path=cast(str, body["advisory_path"]),
            advisory_sha256=cast(str, body["advisory_sha256"]),
            drafted_at=cast(str, body["drafted_at"]),
            published_at=published_at,
            publication_evidence_path=publication_evidence_path,
            publication_evidence_sha256=publication_evidence_sha256,
            delay_reason=delay_reason,
            delay_review_at=delay_review_at,
            delay_evidence_path=delay_evidence_path,
            delay_evidence_sha256=delay_evidence_sha256,
            previous_advisory_digest=previous_advisory_digest,
            advisory_digest=canonical_digest(body),
        )

    def to_dict(self) -> JsonObject:
        """Serialise one advisory revision."""
        return {"schema_version": CRA_SCHEMA_VERSION, **record_fields(self)}

    def to_json(self) -> str:
        """Serialise canonical human-readable JSON."""
        return json_text(self.to_dict())

    @classmethod
    def from_dict(cls, value: object) -> FixedVulnerabilityAdvisory:
        """Parse and integrity-check one advisory revision."""
        data = require_mapping(value, "fixed_vulnerability_advisory")
        require_exact_fields(data, _FIELDS, "fixed_vulnerability_advisory")
        if data.get("schema_version") != CRA_SCHEMA_VERSION:
            raise ValueError("fixed_vulnerability_advisory schema_version is unsupported")
        state = require_string(data.get("state"), "advisory.state")
        expected = cls.build(
            product_key=require_string(data.get("product_key"), "advisory.product_key"),
            event_key=require_string(data.get("event_key"), "advisory.event_key"),
            revision_digest=require_digest(
                data.get("revision_digest"),
                "advisory.revision_digest",
            ),
            state=cast(AdvisoryState, state),
            security_update_ref=require_string(
                data.get("security_update_ref"),
                "advisory.security_update_ref",
            ),
            advisory_path=require_string(data.get("advisory_path"), "advisory.advisory_path"),
            advisory_sha256=require_digest(
                data.get("advisory_sha256"),
                "advisory.advisory_sha256",
            ),
            drafted_at=require_string(data.get("drafted_at"), "advisory.drafted_at"),
            published_at=cast(str | None, data.get("published_at")),
            publication_evidence_path=cast(
                str | None,
                data.get("publication_evidence_path"),
            ),
            publication_evidence_sha256=cast(
                str | None,
                data.get("publication_evidence_sha256"),
            ),
            delay_reason=cast(str | None, data.get("delay_reason")),
            delay_review_at=cast(str | None, data.get("delay_review_at")),
            delay_evidence_path=cast(str | None, data.get("delay_evidence_path")),
            delay_evidence_sha256=cast(str | None, data.get("delay_evidence_sha256")),
            previous_advisory_digest=cast(str | None, data.get("previous_advisory_digest")),
        )
        if data.get("advisory_digest") != expected.advisory_digest:
            raise ValueError("advisory digest does not match its content")
        return expected


def validate_advisory_successor(
    previous: FixedVulnerabilityAdvisory,
    successor: FixedVulnerabilityAdvisory,
) -> None:
    """Require one identity-preserving monotonic advisory transition."""
    if successor.previous_advisory_digest != previous.advisory_digest:
        raise ValueError("advisory successor does not name the current revision")
    if (
        successor.product_key,
        successor.event_key,
        successor.security_update_ref,
        successor.advisory_path,
        successor.advisory_sha256,
        successor.drafted_at,
    ) != (
        previous.product_key,
        previous.event_key,
        previous.security_update_ref,
        previous.advisory_path,
        previous.advisory_sha256,
        previous.drafted_at,
    ):
        raise ValueError("advisory successor changes immutable identity fields")
    allowed = {
        "draft": {"published", "justified-delay"},
        "justified-delay": {"published"},
        "published": set(),
    }
    if successor.state not in allowed[previous.state]:
        raise ValueError("advisory state transition is unsupported")
