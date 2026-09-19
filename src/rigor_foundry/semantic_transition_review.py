# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — semantic transition review candidate
"""Bind an independent review verdict to exact transition and source evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Final, Literal, cast

from .audit_primitives import require_exact_fields
from .model_primitives import (
    parse_utc_timestamp,
    require_digest,
    require_identifier,
    require_utc_timestamp,
)
from .models import canonical_digest, require_mapping, require_string
from .signed_rule_chain_v2 import RuleChainV2TrustRoles
from .trust import ED25519_ALGORITHM, ED25519_SIGNATURE_HEX_LENGTH, require_lower_hex

SEMANTIC_REVIEW_SCHEMA: Final = "semantic-transition-review.v1"
SEMANTIC_REVIEW_DOMAIN: Final = "rigor-foundry.semantic-transition-review.v1"
ACCEPTANCE_SCHEMA: Final = "accepted-semantic-transition.v1"
ReviewVerdict = Literal["clear", "changes-requested", "blocked"]
_VERDICTS: Final = frozenset({"clear", "changes-requested", "blocked"})
_REVIEW_FIELDS: Final = frozenset(
    {
        "schema_version",
        "signature_domain",
        "algorithm",
        "proposal_digest",
        "proposal_artifact_digest",
        "source_verification_digest",
        "parent_replay_digest",
        "author_id",
        "reviewer_id",
        "reviewer_key_id",
        "verdict",
        "findings_digest",
        "reviewed_at",
        "payload_digest",
        "signature_hex",
        "signature_digest",
        "review_digest",
    }
)


@dataclass(frozen=True)
class SemanticTransitionReview:
    """Detached review signature with no implicit source or policy authority."""

    proposal_digest: str
    proposal_artifact_digest: str
    source_verification_digest: str
    parent_replay_digest: str
    author_id: str
    reviewer_id: str
    reviewer_key_id: str
    verdict: ReviewVerdict
    findings_digest: str
    reviewed_at: str
    payload_digest: str
    signature_hex: str
    signature_digest: str
    review_digest: str

    @staticmethod
    def payload(
        *,
        proposal_digest: str,
        proposal_artifact_digest: str,
        source_verification_digest: str,
        parent_replay_digest: str,
        author_id: str,
        reviewer_id: str,
        reviewer_key_id: str,
        verdict: ReviewVerdict,
        findings_digest: str,
        reviewed_at: str,
    ) -> dict[str, str]:
        """Return the exact domain-separated body an independent reviewer signs."""
        author = require_identifier(author_id, "transition_review.author_id")
        reviewer = require_identifier(reviewer_id, "transition_review.reviewer_id")
        if author == reviewer:
            raise ValueError("semantic transition author cannot review own proposal")
        if verdict not in _VERDICTS:
            raise ValueError("unsupported semantic transition review verdict")
        return {
            "schema_version": SEMANTIC_REVIEW_SCHEMA,
            "signature_domain": SEMANTIC_REVIEW_DOMAIN,
            "algorithm": ED25519_ALGORITHM,
            "proposal_digest": require_digest(
                proposal_digest, "transition_review.proposal_digest"
            ),
            "proposal_artifact_digest": require_digest(
                proposal_artifact_digest, "transition_review.proposal_artifact_digest"
            ),
            "source_verification_digest": require_digest(
                source_verification_digest, "transition_review.source_verification_digest"
            ),
            "parent_replay_digest": require_digest(
                parent_replay_digest, "transition_review.parent_replay_digest"
            ),
            "author_id": author,
            "reviewer_id": reviewer,
            "reviewer_key_id": require_identifier(
                reviewer_key_id, "transition_review.reviewer_key_id"
            ),
            "verdict": verdict,
            "findings_digest": require_digest(
                findings_digest, "transition_review.findings_digest"
            ),
            "reviewed_at": require_utc_timestamp(reviewed_at, "transition_review.reviewed_at"),
        }

    @classmethod
    def build(
        cls,
        *,
        proposal_digest: str,
        proposal_artifact_digest: str,
        source_verification_digest: str,
        parent_replay_digest: str,
        author_id: str,
        reviewer_id: str,
        reviewer_key_id: str,
        verdict: ReviewVerdict,
        findings_digest: str,
        reviewed_at: str,
        signature_hex: str,
    ) -> SemanticTransitionReview:
        """Validate signed bytes without claiming reviewer trust or acceptance."""
        payload = cls.payload(
            proposal_digest=proposal_digest,
            proposal_artifact_digest=proposal_artifact_digest,
            source_verification_digest=source_verification_digest,
            parent_replay_digest=parent_replay_digest,
            author_id=author_id,
            reviewer_id=reviewer_id,
            reviewer_key_id=reviewer_key_id,
            verdict=verdict,
            findings_digest=findings_digest,
            reviewed_at=reviewed_at,
        )
        signature = require_lower_hex(
            signature_hex,
            "transition_review.signature_hex",
            length=ED25519_SIGNATURE_HEX_LENGTH,
        )
        envelope: dict[str, object] = {
            **payload,
            "payload_digest": canonical_digest(payload),
            "signature_hex": signature,
            "signature_digest": sha256(bytes.fromhex(signature)).hexdigest(),
        }
        return cls(
            proposal_digest=payload["proposal_digest"],
            proposal_artifact_digest=payload["proposal_artifact_digest"],
            source_verification_digest=payload["source_verification_digest"],
            parent_replay_digest=payload["parent_replay_digest"],
            author_id=payload["author_id"],
            reviewer_id=payload["reviewer_id"],
            reviewer_key_id=payload["reviewer_key_id"],
            verdict=cast(ReviewVerdict, payload["verdict"]),
            findings_digest=payload["findings_digest"],
            reviewed_at=payload["reviewed_at"],
            payload_digest=cast(str, envelope["payload_digest"]),
            signature_hex=signature,
            signature_digest=cast(str, envelope["signature_digest"]),
            review_digest=canonical_digest(envelope),
        )

    def to_dict(self) -> dict[str, str]:
        """Serialise the exact typed review and detached signature."""
        return {
            **self.payload(
                proposal_digest=self.proposal_digest,
                proposal_artifact_digest=self.proposal_artifact_digest,
                source_verification_digest=self.source_verification_digest,
                parent_replay_digest=self.parent_replay_digest,
                author_id=self.author_id,
                reviewer_id=self.reviewer_id,
                reviewer_key_id=self.reviewer_key_id,
                verdict=self.verdict,
                findings_digest=self.findings_digest,
                reviewed_at=self.reviewed_at,
            ),
            "payload_digest": self.payload_digest,
            "signature_hex": self.signature_hex,
            "signature_digest": self.signature_digest,
            "review_digest": self.review_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> SemanticTransitionReview:
        """Refuse unknown fields, changed signature metadata and digest aliases."""
        data = require_mapping(value, "semantic transition review")
        require_exact_fields(data, _REVIEW_FIELDS, "semantic transition review")
        if data.get("schema_version") != SEMANTIC_REVIEW_SCHEMA:
            raise ValueError("unsupported semantic transition review schema")
        if data.get("signature_domain") != SEMANTIC_REVIEW_DOMAIN:
            raise ValueError("wrong semantic transition review signature domain")
        if data.get("algorithm") != ED25519_ALGORITHM:
            raise ValueError("semantic transition review requires Ed25519")
        review = cls.build(
            proposal_digest=require_digest(
                data.get("proposal_digest"), "transition_review.proposal_digest"
            ),
            proposal_artifact_digest=require_digest(
                data.get("proposal_artifact_digest"), "transition_review.proposal_artifact_digest"
            ),
            source_verification_digest=require_digest(
                data.get("source_verification_digest"),
                "transition_review.source_verification_digest",
            ),
            parent_replay_digest=require_digest(
                data.get("parent_replay_digest"), "transition_review.parent_replay_digest"
            ),
            author_id=require_identifier(data.get("author_id"), "transition_review.author_id"),
            reviewer_id=require_identifier(
                data.get("reviewer_id"), "transition_review.reviewer_id"
            ),
            reviewer_key_id=require_identifier(
                data.get("reviewer_key_id"), "transition_review.reviewer_key_id"
            ),
            verdict=cast(
                ReviewVerdict, require_string(data.get("verdict"), "transition_review.verdict")
            ),
            findings_digest=require_digest(
                data.get("findings_digest"), "transition_review.findings_digest"
            ),
            reviewed_at=require_utc_timestamp(
                data.get("reviewed_at"), "transition_review.reviewed_at"
            ),
            signature_hex=require_string(
                data.get("signature_hex"), "transition_review.signature_hex"
            ),
        )
        for field in ("payload_digest", "signature_digest", "review_digest"):
            if data.get(field) != getattr(review, field):
                raise ValueError(f"semantic transition review {field} does not match its bytes")
        return review

    def verified_acceptance_digest(
        self,
        *,
        roles: RuleChainV2TrustRoles,
        expected_policy_digest: str,
        expected_proposal_digest: str,
        expected_proposal_artifact_digest: str,
        expected_source_verification_digest: str,
        expected_parent_replay_digest: str,
        expected_author_id: str,
        expected_reviewer_id: str,
        expected_reviewer_key_id: str,
        now: datetime,
    ) -> str | None:
        """Derive a typed digest only from a current trusted CLEAR review.

        The host must authenticate every expected value and the role policies.
        This digest is a source dependency, not a selected profile or grant.
        """
        try:
            SemanticTransitionReview.from_dict(self.to_dict())
            validated_roles = RuleChainV2TrustRoles.build(
                pack_issuers=roles.pack_issuers,
                project_selectors=roles.project_selectors,
                lock_resolvers=roles.lock_resolvers,
                semantic_reviewers=roles.semantic_reviewers,
            )
            policy = validated_roles.semantic_reviewers
            if now.tzinfo is None or now.utcoffset() != UTC.utcoffset(now):
                return None
            reviewed = parse_utc_timestamp(self.reviewed_at, "transition_review.reviewed_at")
            if reviewed > now:
                return None
            if (
                self.verdict != "clear"
                or policy.policy_digest
                != require_digest(
                    expected_policy_digest, "transition_review.expected_policy_digest"
                )
                or self.proposal_digest
                != require_digest(
                    expected_proposal_digest, "transition_review.expected_proposal_digest"
                )
                or self.proposal_artifact_digest
                != require_digest(
                    expected_proposal_artifact_digest,
                    "transition_review.expected_proposal_artifact_digest",
                )
                or self.source_verification_digest
                != require_digest(
                    expected_source_verification_digest,
                    "transition_review.expected_source_verification_digest",
                )
                or self.parent_replay_digest
                != require_digest(
                    expected_parent_replay_digest,
                    "transition_review.expected_parent_replay_digest",
                )
                or self.author_id
                != require_identifier(expected_author_id, "transition_review.expected_author_id")
                or self.reviewer_id
                != require_identifier(
                    expected_reviewer_id, "transition_review.expected_reviewer_id"
                )
                or self.reviewer_key_id
                != require_identifier(
                    expected_reviewer_key_id, "transition_review.expected_reviewer_key_id"
                )
                or policy.key_status(self.reviewer_key_id, reviewed) != "active"
                or policy.key_status(self.reviewer_key_id, now) != "active"
                or not policy.trust_store().verify(
                    key_id=self.reviewer_key_id,
                    algorithm=ED25519_ALGORITHM,
                    signature_domain=SEMANTIC_REVIEW_DOMAIN,
                    payload_digest=self.payload_digest,
                    signature_hex=self.signature_hex,
                )
            ):
                return None
            return canonical_digest(
                {
                    "schema_version": ACCEPTANCE_SCHEMA,
                    "proposal_digest": self.proposal_digest,
                    "review_digest": self.review_digest,
                    "source_verification_digest": self.source_verification_digest,
                }
            )
        except (TypeError, ValueError):
            return None
