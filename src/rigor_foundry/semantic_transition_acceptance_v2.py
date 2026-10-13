# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — typed signed semantic transition acceptance
"""Parse an exact reviewer-signed transition without granting an effect."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Final
from uuid import UUID

from .audit_primitives import require_exact_fields, require_integer
from .discovery_source_schema import DiscoveryLimits
from .model_primitives import (
    parse_utc_timestamp,
    require_digest,
    require_identifier,
    require_utc_timestamp,
)
from .models import canonical_digest, require_mapping, require_string
from .semantic_acceptance_policy import ProposalAuthorAttribution, ReviewerIdentityPolicy
from .trust import ED25519_ALGORITHM, ED25519_SIGNATURE_HEX_LENGTH, require_lower_hex

ACCEPTANCE_SCHEMA: Final = "accepted-semantic-transition.v2"
ACCEPTANCE_KIND: Final = "semantic-transition-acceptance"
ACCEPTANCE_DOMAIN: Final = "rigor-foundry.semantic-transition-acceptance.v2"
ACCEPTANCE_ROLE: Final = "semantic-reviewer"
_DIGEST_FIELDS: Final = frozenset(
    {
        "proposal_digest",
        "proposal_artifact_sha256",
        "parent_replay_digest",
        "source_verification_digest",
        "discovery_source_selection_digest",
        "normative_source_sha256",
        "author_attribution_digest",
        "owner_ratification_manifest_sha256",
        "owner_question_sha256",
        "owner_reply_sha256",
        "findings_sha256",
    }
)
_IDENTITY_FIELDS: Final = frozenset({"author_id", "reviewer_id", "reviewer_key_id"})
_BODY_FIELDS: Final = (
    _DIGEST_FIELDS
    | _IDENTITY_FIELDS
    | frozenset(
        {
            "schema_version",
            "object_kind",
            "signature_domain",
            "algorithm",
            "signer_role",
            "source_limits",
            "statement_sha256",
            "replacements",
            "verdict",
            "reviewed_at",
        }
    )
)
_ENVELOPE_FIELDS: Final = _BODY_FIELDS | frozenset(
    {"payload_digest", "signature_hex", "signature_digest", "acceptance_digest"}
)
_SOURCE_LIMIT_FIELDS: Final = frozenset(asdict(DiscoveryLimits(1, 1, 1, 1, 1, 1)))
_LINK_FIELDS: Final = frozenset({"predecessor_id", "successor_id", "statement_sha256"})


def _source_limits(value: object) -> dict[str, int]:
    """Return exact positive source-parser budgets in their named form."""
    data = require_mapping(value, "semantic acceptance source limits")
    require_exact_fields(data, _SOURCE_LIMIT_FIELDS, "semantic acceptance source limits")
    limits = DiscoveryLimits(
        total_bytes=require_integer(
            data.get("total_bytes"), "source_limits.total_bytes", minimum=1
        ),
        file_bytes=require_integer(data.get("file_bytes"), "source_limits.file_bytes", minimum=1),
        sources=require_integer(data.get("sources"), "source_limits.sources", minimum=1),
        shards=require_integer(data.get("shards"), "source_limits.shards", minimum=1),
        candidates=require_integer(data.get("candidates"), "source_limits.candidates", minimum=1),
        spans=require_integer(data.get("spans"), "source_limits.spans", minimum=1),
    )
    return asdict(limits)


def _replacements(value: object, statements: list[str]) -> list[dict[str, str]]:
    """Require four unique, ordered replacement links and matching text hashes."""
    if not isinstance(value, list) or len(value) != 4:
        raise ValueError("semantic acceptance requires four replacement links")
    links: list[dict[str, str]] = []
    for raw in value:
        data = require_mapping(raw, "semantic acceptance replacement")
        require_exact_fields(data, _LINK_FIELDS, "semantic acceptance replacement")
        links.append(
            {
                "predecessor_id": require_identifier(
                    data.get("predecessor_id"), "acceptance.predecessor_id"
                ),
                "successor_id": require_identifier(
                    data.get("successor_id"), "acceptance.successor_id"
                ),
                "statement_sha256": require_digest(
                    data.get("statement_sha256"), "acceptance.statement_sha256"
                ),
            }
        )
    if (
        len({item["predecessor_id"] for item in links}) != 4
        or len({item["successor_id"] for item in links}) != 4
        or any(item["predecessor_id"] == item["successor_id"] for item in links)
        or [item["statement_sha256"] for item in links] != statements
    ):
        raise ValueError("semantic acceptance replacement mapping differs")
    return links


def _body(value: object) -> dict[str, object]:
    """Validate and copy every field in the exact signed acceptance body."""
    data = require_mapping(value, "semantic acceptance body")
    require_exact_fields(data, _BODY_FIELDS, "semantic acceptance body")
    constants = {
        "schema_version": ACCEPTANCE_SCHEMA,
        "object_kind": ACCEPTANCE_KIND,
        "signature_domain": ACCEPTANCE_DOMAIN,
        "algorithm": ED25519_ALGORITHM,
        "signer_role": ACCEPTANCE_ROLE,
        "verdict": "clear",
    }
    if any(data.get(field) != expected for field, expected in constants.items()):
        raise ValueError("semantic acceptance type, domain, role or verdict differs")
    raw_statements = data.get("statement_sha256")
    if not isinstance(raw_statements, list) or len(raw_statements) != 4:
        raise ValueError("semantic acceptance requires four statement hashes")
    statements = [require_digest(item, "acceptance.statement_sha256") for item in raw_statements]
    if len(set(statements)) != 4:
        raise ValueError("semantic acceptance statement hashes must be unique")
    body: dict[str, object] = {
        **constants,
        **{
            field: require_digest(data.get(field), f"acceptance.{field}")
            for field in _DIGEST_FIELDS
        },
        **{
            field: require_identifier(data.get(field), f"acceptance.{field}")
            for field in _IDENTITY_FIELDS
        },
        "source_limits": _source_limits(data.get("source_limits")),
        "statement_sha256": statements,
        "replacements": _replacements(data.get("replacements"), statements),
        "reviewed_at": require_utc_timestamp(data.get("reviewed_at"), "acceptance.reviewed_at"),
    }
    author_seat, separator, session = str(body["author_id"]).rpartition("@")
    if not separator or not author_seat or not session or "@" in author_seat:
        raise ValueError("semantic acceptance author needs a qualified session")
    try:
        if str(UUID(session)) != session:
            raise ValueError("semantic acceptance author session is not canonical")
    except ValueError as exc:
        raise ValueError("semantic acceptance author session is not a canonical UUID") from exc
    if (
        "@" in str(body["reviewer_id"])
        or str(body["reviewer_id"]).casefold() == author_seat.casefold()
    ):
        raise ValueError("semantic acceptance author and reviewer must differ")
    return body


@dataclass(frozen=True)
class SemanticAcceptanceBodyV2:
    """Canonical transition acceptance body awaiting a reviewer signature.

    Attributes
    ----------
    canonical_json : str
        Immutable canonical JSON text of the complete validated v2 body.
    payload_digest : str
        Canonical digest over every acceptance-body field.

    Notes
    -----
    The body binds four replacements, bounded source budgets, author attribution and ratification
    hashes. Direct construction is revalidated by consuming APIs.
    """

    canonical_json: str
    payload_digest: str

    @classmethod
    def from_dict(cls, value: object) -> SemanticAcceptanceBodyV2:
        """Parse the complete closed v2 acceptance body.

        Parameters
        ----------
        value : object
            Exact body object including four unique statement hashes and replacement links.

        Returns
        -------
        SemanticAcceptanceBodyV2
            Canonical JSON text and its recomputed digest.

        Raises
        ------
        ValueError
            Schema, fields, budgets, replacement links, identities or timestamps are invalid.
        """
        body = _body(value)
        canonical = json.dumps(
            body, allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        return cls(canonical_json=canonical, payload_digest=canonical_digest(body))

    def to_dict(self) -> dict[str, object]:
        """Revalidate canonical body content before returning a fresh mapping.

        Returns
        -------
        dict[str, object]
            Complete parsed body after recomputing its digest.

        Raises
        ------
        ValueError
            The stored JSON is malformed or its declared digest differs.
        """
        data = _body(json.loads(self.canonical_json))
        if canonical_digest(data) != self.payload_digest:
            raise ValueError("semantic acceptance body digest differs")
        return data


@dataclass(frozen=True)
class SignedSemanticAcceptanceV2:
    """Bind an external reviewer signature without selecting runtime authority.

    Attributes
    ----------
    body : SemanticAcceptanceBodyV2
        Exact canonical transition acceptance body.
    signature_hex : str
        Lowercase 64-byte Ed25519 signature in hexadecimal.
    signature_digest : str
        SHA-256 of the raw signature bytes.
    acceptance_digest : str
        Canonical digest of the complete body and signature envelope.

    Notes
    -----
    Constructing an envelope checks shape and integrity; actual signature admission requires
    verify_signature and protected host composition.
    """

    body: SemanticAcceptanceBodyV2
    signature_hex: str
    signature_digest: str
    acceptance_digest: str

    @classmethod
    def build(
        cls, *, body: SemanticAcceptanceBodyV2, signature_hex: str
    ) -> SignedSemanticAcceptanceV2:
        """Attach an externally produced Ed25519 signature to the canonical body.

        Parameters
        ----------
        body : SemanticAcceptanceBodyV2
            Complete acceptance body, reparsed before binding.
        signature_hex : str
            Exact lowercase Ed25519 signature bytes encoded as 128 hexadecimal characters.

        Returns
        -------
        SignedSemanticAcceptanceV2
            Integrity-bound envelope, awaiting actual signature and lifecycle verification.

        Raises
        ------
        ValueError
            Body validation fails or signature encoding is invalid.
        """
        checked = SemanticAcceptanceBodyV2.from_dict(body.to_dict())
        signature = require_lower_hex(
            signature_hex, "acceptance.signature_hex", length=ED25519_SIGNATURE_HEX_LENGTH
        )
        signature_digest = sha256(bytes.fromhex(signature)).hexdigest()
        envelope = {
            **checked.to_dict(),
            "payload_digest": checked.payload_digest,
            "signature_hex": signature,
            "signature_digest": signature_digest,
        }
        return cls(
            body=checked,
            signature_hex=signature,
            signature_digest=signature_digest,
            acceptance_digest=canonical_digest(envelope),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize the canonical body and detached signature envelope.

        Returns
        -------
        dict[str, object]
            Fresh complete acceptance wire including all integrity digests.

        Raises
        ------
        ValueError
            Stored body JSON or its digest is invalid.
        """
        return {
            **self.body.to_dict(),
            "payload_digest": self.body.payload_digest,
            "signature_hex": self.signature_hex,
            "signature_digest": self.signature_digest,
            "acceptance_digest": self.acceptance_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> SignedSemanticAcceptanceV2:
        """Recompute every envelope digest and reject unknown fields.

        Parameters
        ----------
        value : object
            Exact closed acceptance wire including body, signature and envelope digests.

        Returns
        -------
        SignedSemanticAcceptanceV2
            Validated envelope whose digests agree with all input bytes.

        Raises
        ------
        ValueError
            Fields, body, signature encoding or any integrity digest differs.
        """
        data = require_mapping(value, "semantic acceptance")
        require_exact_fields(data, _ENVELOPE_FIELDS, "semantic acceptance")
        body = SemanticAcceptanceBodyV2.from_dict({field: data[field] for field in _BODY_FIELDS})
        signed = cls.build(
            body=body,
            signature_hex=require_string(data.get("signature_hex"), "acceptance.signature_hex"),
        )
        if (
            data.get("payload_digest") != signed.body.payload_digest
            or data.get("signature_digest") != signed.signature_digest
            or data.get("acceptance_digest") != signed.acceptance_digest
        ):
            raise ValueError("semantic acceptance envelope digest differs")
        return signed

    def verify_signature(
        self,
        *,
        policy: ReviewerIdentityPolicy,
        author: ProposalAuthorAttribution,
        now: datetime,
    ) -> bool:
        """Verify current reviewer identity, authorship relation and real signature.

        Parameters
        ----------
        policy : ReviewerIdentityPolicy
            Protected reviewer policy with key lifecycle and identity bindings.
        author : ProposalAuthorAttribution
            Protected selected attribution for the same proposal and artifact.
        now : datetime
            Current timezone-aware UTC from the trusted host.

        Returns
        -------
        bool
            True only for a valid domain-separated signature with active reviewer key, matching
            attribution and distinct author/reviewer identities. Invalid typed data returns false.

        Notes
        -----
        This does not authenticate policy or attestation custody, prove source spans or owner
        ratification, select a lock, or authorize an effect.
        """
        try:
            signed = SignedSemanticAcceptanceV2.from_dict(self.to_dict())
            selected_policy = ReviewerIdentityPolicy.from_dict(policy.to_dict())
            selected_author = ProposalAuthorAttribution.from_dict(author.to_dict())
            if now.tzinfo is None or now.utcoffset() != UTC.utcoffset(now):
                return False
            data = signed.body.to_dict()
            reviewed = parse_utc_timestamp(data["reviewed_at"], "acceptance.reviewed_at")
            attested = parse_utc_timestamp(
                selected_author.attested_at, "author_attribution.attested_at"
            )
            key_id = require_identifier(data["reviewer_key_id"], "acceptance.reviewer_key_id")
            if (
                attested > reviewed
                or reviewed > now
                or data["proposal_digest"] != selected_author.proposal_digest
                or data["proposal_artifact_sha256"] != selected_author.proposal_artifact_sha256
                or data["author_attribution_digest"] != selected_author.attribution_digest
                or data["author_id"] != selected_author.author_id
                or data["reviewer_id"] != selected_policy.reviewer_for(key_id)
                or "@" in str(data["reviewer_id"])
                or str(data["reviewer_id"]).casefold()
                == selected_author.author_id.rpartition("@")[0].casefold()
                or selected_policy.trust_policy.key_status(key_id, reviewed) != "active"
                or selected_policy.trust_policy.key_status(key_id, now) != "active"
            ):
                return False
            return selected_policy.trust_policy.trust_store().verify(
                key_id=key_id,
                algorithm=ED25519_ALGORITHM,
                signature_domain=ACCEPTANCE_DOMAIN,
                payload_digest=signed.body.payload_digest,
                signature_hex=signed.signature_hex,
            )
        except (TypeError, ValueError):
            return False
