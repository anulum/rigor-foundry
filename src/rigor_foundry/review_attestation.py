# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — signed independent review attestations
"""Model reviewer attestations that only real trusted signatures can clear."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from typing import Literal, cast

from .model_primitives import (
    parse_utc_timestamp,
    require_digest,
    require_identifier,
    require_utc_timestamp,
)
from .models import canonical_digest, require_mapping, require_string
from .trust import (
    ED25519_ALGORITHM,
    ED25519_SIGNATURE_HEX_LENGTH,
    VerificationTrustStore,
    require_lower_hex,
)

ReviewDecision = Literal[
    "unassessed",
    "needs-evidence",
    "blocked",
    "fail",
    "pass",
    "accepted-risk",
]
_DECISIONS = {
    "unassessed",
    "needs-evidence",
    "blocked",
    "fail",
    "pass",
    "accepted-risk",
}


@dataclass(frozen=True)
class ReviewerAttestation:
    """Detached Ed25519 signature over one exact independent review decision."""

    reviewer_id: str
    algorithm: str
    key_id: str
    assessment_body_digest: str
    decision: ReviewDecision
    reviewed_at: str
    expires_at: str
    signed_payload_digest: str
    signature_hex: str
    signature_digest: str
    attestation_digest: str

    @staticmethod
    def payload_digest(
        *,
        reviewer_id: str,
        algorithm: str,
        key_id: str,
        assessment_body_digest: str,
        decision: ReviewDecision,
        reviewed_at: str,
        expires_at: str,
    ) -> str:
        """Return the canonical digest that an independent reviewer must sign."""
        fields = ReviewerAttestation._payload(
            reviewer_id=reviewer_id,
            algorithm=algorithm,
            key_id=key_id,
            assessment_body_digest=assessment_body_digest,
            decision=decision,
            reviewed_at=reviewed_at,
            expires_at=expires_at,
        )
        return canonical_digest(fields)

    @staticmethod
    def _payload(
        *,
        reviewer_id: str,
        algorithm: str,
        key_id: str,
        assessment_body_digest: str,
        decision: ReviewDecision,
        reviewed_at: str,
        expires_at: str,
    ) -> dict[str, str]:
        """Validate and return the complete signed review payload."""
        if algorithm != ED25519_ALGORITHM:
            raise ValueError("review.algorithm must be ed25519")
        if decision not in _DECISIONS:
            raise ValueError("review.decision is unsupported")
        reviewed = require_utc_timestamp(reviewed_at, "review.reviewed_at")
        expires = require_utc_timestamp(expires_at, "review.expires_at")
        if parse_utc_timestamp(expires, "review.expires_at") <= parse_utc_timestamp(
            reviewed,
            "review.reviewed_at",
        ):
            raise ValueError("review.expires_at must be later than reviewed_at")
        return {
            "reviewer_id": require_string(reviewer_id, "review.reviewer_id"),
            "algorithm": algorithm,
            "key_id": require_identifier(key_id, "review.key_id"),
            "assessment_body_digest": require_digest(
                assessment_body_digest,
                "review.assessment_body_digest",
            ),
            "decision": decision,
            "reviewed_at": reviewed,
            "expires_at": expires,
        }

    @classmethod
    def build(
        cls,
        *,
        reviewer_id: str,
        key_id: str,
        assessment_body_digest: str,
        decision: ReviewDecision,
        reviewed_at: str,
        expires_at: str,
        signature_hex: str,
        algorithm: str = ED25519_ALGORITHM,
    ) -> ReviewerAttestation:
        """Build a signed review record without claiming that it is trusted."""
        payload = cls._payload(
            reviewer_id=reviewer_id,
            algorithm=algorithm,
            key_id=key_id,
            assessment_body_digest=assessment_body_digest,
            decision=decision,
            reviewed_at=reviewed_at,
            expires_at=expires_at,
        )
        signed_payload_digest = canonical_digest(payload)
        validated_signature = require_lower_hex(
            signature_hex,
            "review.signature_hex",
            length=ED25519_SIGNATURE_HEX_LENGTH,
        )
        signature_digest = sha256(bytes.fromhex(validated_signature)).hexdigest()
        body: dict[str, object] = {
            **payload,
            "signed_payload_digest": signed_payload_digest,
            "signature_hex": validated_signature,
            "signature_digest": signature_digest,
        }
        return cls(
            reviewer_id=payload["reviewer_id"],
            algorithm=algorithm,
            key_id=payload["key_id"],
            assessment_body_digest=payload["assessment_body_digest"],
            decision=cast(ReviewDecision, payload["decision"]),
            reviewed_at=payload["reviewed_at"],
            expires_at=payload["expires_at"],
            signed_payload_digest=signed_payload_digest,
            signature_hex=validated_signature,
            signature_digest=signature_digest,
            attestation_digest=canonical_digest(body),
        )

    def verified_at(
        self,
        instant: datetime,
        decision: ReviewDecision,
        assessment_body_digest: str,
        trust_store: VerificationTrustStore,
    ) -> bool:
        """Return whether a trusted key signed this current exact review."""
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise ValueError("review evaluation time must be timezone-aware")
        try:
            rebuilt = ReviewerAttestation.build(
                reviewer_id=self.reviewer_id,
                algorithm=self.algorithm,
                key_id=self.key_id,
                assessment_body_digest=self.assessment_body_digest,
                decision=self.decision,
                reviewed_at=self.reviewed_at,
                expires_at=self.expires_at,
                signature_hex=self.signature_hex,
            )
        except ValueError:
            return False
        return (
            rebuilt == self
            and self.decision == decision
            and self.assessment_body_digest == assessment_body_digest
            and parse_utc_timestamp(self.reviewed_at, "review.reviewed_at") <= instant
            and instant < parse_utc_timestamp(self.expires_at, "review.expires_at")
            and trust_store.verify(
                key_id=self.key_id,
                algorithm=self.algorithm,
                payload_digest=self.signed_payload_digest,
                signature_hex=self.signature_hex,
            )
        )

    def to_dict(self) -> dict[str, str]:
        """Serialise the complete detached review signature."""
        return {
            "reviewer_id": self.reviewer_id,
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "assessment_body_digest": self.assessment_body_digest,
            "decision": self.decision,
            "reviewed_at": self.reviewed_at,
            "expires_at": self.expires_at,
            "signed_payload_digest": self.signed_payload_digest,
            "signature_hex": self.signature_hex,
            "signature_digest": self.signature_digest,
            "attestation_digest": self.attestation_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> ReviewerAttestation:
        """Parse and integrity-check one signed reviewer attestation."""
        data = require_mapping(value, "review")
        decision = require_string(data.get("decision"), "review.decision")
        review = cls.build(
            reviewer_id=require_string(data.get("reviewer_id"), "review.reviewer_id"),
            algorithm=require_string(data.get("algorithm"), "review.algorithm"),
            key_id=require_identifier(data.get("key_id"), "review.key_id"),
            assessment_body_digest=require_digest(
                data.get("assessment_body_digest"),
                "review.assessment_body_digest",
            ),
            decision=cast(ReviewDecision, decision),
            reviewed_at=require_utc_timestamp(data.get("reviewed_at"), "review.reviewed_at"),
            expires_at=require_utc_timestamp(data.get("expires_at"), "review.expires_at"),
            signature_hex=require_string(data.get("signature_hex"), "review.signature_hex"),
        )
        for field, expected in (
            ("signed_payload_digest", review.signed_payload_digest),
            ("signature_digest", review.signature_digest),
            ("attestation_digest", review.attestation_digest),
        ):
            if data.get(field) != expected:
                raise ValueError(f"review {field.replace('_', '-')} does not match its content")
        return review
