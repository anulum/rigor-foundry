# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — semantic acceptance identity policy
"""Bind a reviewer key to one identity and an author attestation to one wire."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final
from uuid import UUID

from .audit_primitives import require_exact_fields
from .model_primitives import require_digest, require_identifier, require_utc_timestamp
from .models import canonical_digest, require_mapping, require_string
from .verification_policy import OfflineTrustPolicy

AUTHOR_ATTRIBUTION_SCHEMA: Final = "proposal-author-attribution.v1"
REVIEWER_IDENTITY_POLICY_SCHEMA: Final = "semantic-reviewer-identity-policy.v1"
_ATTRIBUTION_FIELDS: Final = frozenset(
    {
        "schema_version",
        "proposal_digest",
        "proposal_artifact_sha256",
        "author_id",
        "evidence_sha256",
        "attested_by",
        "attested_at",
        "attribution_digest",
    }
)


@dataclass(frozen=True)
class ProposalAuthorAttribution:
    """Bind one selected attestation of proposal authorship.

    Attributes
    ----------
    proposal_digest : str
        Digest of the exact attributed proposal.
    proposal_artifact_sha256 : str
        Hash of the exact serialized proposal artifact.
    author_id : str
        Qualified author seat and canonical native session UUID.
    evidence_sha256 : str
        Hash of the host- or owner-selected supporting evidence.
    attested_by : str
        Identity declared by the selected attestation provider.
    attested_at : str
        Declared timezone-aware UTC attestation timestamp.
    attribution_digest : str
        Canonical digest of all attribution fields.

    Notes
    -----
    The record establishes an integrity relation. Protected owner or host custody must authenticate
    the attestation; the digest is not proof of authorship.
    """

    proposal_digest: str
    proposal_artifact_sha256: str
    author_id: str
    evidence_sha256: str
    attested_by: str
    attested_at: str
    attribution_digest: str

    @classmethod
    def build(
        cls,
        *,
        proposal_digest: str,
        proposal_artifact_sha256: str,
        author_id: str,
        evidence_sha256: str,
        attested_by: str,
        attested_at: str,
    ) -> ProposalAuthorAttribution:
        """Build an integrity-bound session-qualified author attestation.

        Parameters
        ----------
        proposal_digest : str
            Exact proposal digest.
        proposal_artifact_sha256 : str
            Hash of its exact artifact bytes.
        author_id : str
            Seat followed by @ and a canonical lowercase UUID session.
        evidence_sha256 : str
            Hash of the selected supporting attestation evidence.
        attested_by : str
            Owner- or host-selected attesting identity.
        attested_at : str
            Timezone-aware UTC timestamp declared by the attestation.

        Returns
        -------
        ProposalAuthorAttribution
            Validated attribution with a recomputed canonical digest.

        Raises
        ------
        ValueError
            A digest, qualified identity, UUID or UTC timestamp is malformed.
        """
        author = require_identifier(author_id, "author_attribution.author_id")
        seat, separator, session = author.rpartition("@")
        if not separator or not seat or not session or "@" in seat:
            raise ValueError("author attribution requires a qualified session identity")
        try:
            parsed_session = UUID(session)
        except ValueError as exc:
            raise ValueError("author attribution session must be a UUID") from exc
        if str(parsed_session) != session:
            raise ValueError("author attribution session must use canonical UUID text")
        body = {
            "schema_version": AUTHOR_ATTRIBUTION_SCHEMA,
            "proposal_digest": require_digest(
                proposal_digest, "author_attribution.proposal_digest"
            ),
            "proposal_artifact_sha256": require_digest(
                proposal_artifact_sha256, "author_attribution.proposal_artifact_sha256"
            ),
            "author_id": author,
            "evidence_sha256": require_digest(
                evidence_sha256, "author_attribution.evidence_sha256"
            ),
            "attested_by": require_identifier(attested_by, "author_attribution.attested_by"),
            "attested_at": require_utc_timestamp(attested_at, "author_attribution.attested_at"),
        }
        return cls(
            proposal_digest=body["proposal_digest"],
            proposal_artifact_sha256=body["proposal_artifact_sha256"],
            author_id=body["author_id"],
            evidence_sha256=body["evidence_sha256"],
            attested_by=body["attested_by"],
            attested_at=body["attested_at"],
            attribution_digest=canonical_digest(body),
        )

    def to_dict(self) -> dict[str, str]:
        """Serialize the exact attribution and its integrity digest.

        Returns
        -------
        dict[str, str]
            Closed attribution wire; reparsing is required before trusting direct construction.
        """
        return {
            "schema_version": AUTHOR_ATTRIBUTION_SCHEMA,
            "proposal_digest": self.proposal_digest,
            "proposal_artifact_sha256": self.proposal_artifact_sha256,
            "author_id": self.author_id,
            "evidence_sha256": self.evidence_sha256,
            "attested_by": self.attested_by,
            "attested_at": self.attested_at,
            "attribution_digest": self.attribution_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> ProposalAuthorAttribution:
        """Rebuild the attribution and reject changed or extra fields.

        Parameters
        ----------
        value : object
            Exact closed attribution wire including its digest.

        Returns
        -------
        ProposalAuthorAttribution
            Validated canonical attribution.

        Raises
        ------
        ValueError
            Schema, fields, identity, time or recomputed digest differs.
        """
        data = require_mapping(value, "author attribution")
        require_exact_fields(data, _ATTRIBUTION_FIELDS, "author attribution")
        if data.get("schema_version") != AUTHOR_ATTRIBUTION_SCHEMA:
            raise ValueError("unsupported author-attribution schema")
        record = cls.build(
            proposal_digest=require_digest(
                data.get("proposal_digest"), "author_attribution.proposal_digest"
            ),
            proposal_artifact_sha256=require_digest(
                data.get("proposal_artifact_sha256"),
                "author_attribution.proposal_artifact_sha256",
            ),
            author_id=require_identifier(data.get("author_id"), "author_attribution.author_id"),
            evidence_sha256=require_digest(
                data.get("evidence_sha256"), "author_attribution.evidence_sha256"
            ),
            attested_by=require_identifier(
                data.get("attested_by"), "author_attribution.attested_by"
            ),
            attested_at=require_utc_timestamp(
                data.get("attested_at"), "author_attribution.attested_at"
            ),
        )
        if data.get("attribution_digest") != record.attribution_digest:
            raise ValueError("author-attribution digest differs")
        return record


@dataclass(frozen=True)
class ReviewerIdentityBinding:
    """Associate one public key ID with one selected reviewer identity.

    Attributes
    ----------
    key_id : str
        Exact public reviewer key identifier.
    reviewer_id : str
        Declared reviewer identity awaiting policy and enrollment checks.
    """

    key_id: str
    reviewer_id: str

    @classmethod
    def from_dict(cls, value: object) -> ReviewerIdentityBinding:
        """Parse only the exact key-to-reviewer binding fields.

        Parameters
        ----------
        value : object
            Closed key_id and reviewer_id object.

        Returns
        -------
        ReviewerIdentityBinding
            Structurally valid binding without enrollment authority.

        Raises
        ------
        ValueError
            Fields or identifiers are invalid.
        """
        data = require_mapping(value, "reviewer identity binding")
        require_exact_fields(
            data, frozenset({"key_id", "reviewer_id"}), "reviewer identity binding"
        )
        return cls(
            key_id=require_identifier(data.get("key_id"), "reviewer_binding.key_id"),
            reviewer_id=require_identifier(
                data.get("reviewer_id"), "reviewer_binding.reviewer_id"
            ),
        )

    def to_dict(self) -> dict[str, str]:
        """Serialize the exact key-to-reviewer mapping.

        Returns
        -------
        dict[str, str]
            Fresh two-field mapping with no private key material.
        """
        return {"key_id": self.key_id, "reviewer_id": self.reviewer_id}


@dataclass(frozen=True)
class ReviewerIdentityPolicy:
    """Integrity-bind a reviewer trust policy to every admitted key identity.

    Attributes
    ----------
    trust_policy : OfflineTrustPolicy
        Exact key lifecycle and enrollment records selected by the host.
    bindings : tuple[ReviewerIdentityBinding, ...]
        One binding per trusted key, sorted by key ID. Reviewer identities
        are unique under the same casefold relation used for enrollment.
    policy_digest : str
        Digest of the complete canonical policy and identity bindings.

    Notes
    -----
    This data record establishes integrity, not enrollment authority. An
    identity-bearing key must match its declared reviewer. Legacy v1 keys
    retain explicit mappings, but protected v2 consumers impose their own
    identity-bearing role requirements.
    """

    trust_policy: OfflineTrustPolicy
    bindings: tuple[ReviewerIdentityBinding, ...]
    policy_digest: str

    @classmethod
    def build(
        cls,
        *,
        trust_policy: OfflineTrustPolicy,
        bindings: tuple[ReviewerIdentityBinding, ...],
    ) -> ReviewerIdentityPolicy:
        """Require exactly one identity for every reviewer key.

        Parameters
        ----------
        trust_policy : OfflineTrustPolicy
            Host-selected public keys and lifecycle records.
        bindings : tuple[ReviewerIdentityBinding, ...]
            Complete unique key-to-reviewer mappings; input order may vary.
            A declared identity must match any key enrollment by casefold.

        Returns
        -------
        ReviewerIdentityPolicy
            Revalidated trust data and sorted, digest-bound bindings.

        Raises
        ------
        ValueError
            If trust data is invalid, bindings are missing or duplicated,
            reviewer identities alias each other, or an enrollment differs.
        """
        trusted = OfflineTrustPolicy.from_dict(trust_policy.to_dict())
        if not isinstance(bindings, tuple):
            raise ValueError("reviewer identity bindings must be a tuple")
        checked = tuple(ReviewerIdentityBinding.from_dict(item.to_dict()) for item in bindings)
        key_ids = tuple(item.key_id for item in checked)
        if len(set(key_ids)) != len(key_ids) or set(key_ids) != {
            item.key.key_id for item in trusted.keys
        }:
            raise ValueError("reviewer identity policy must bind each key once")
        if len({item.reviewer_id.casefold() for item in checked}) != len(checked):
            raise ValueError("reviewer identities must be unique")
        enrolled = {item.key.key_id: item.enrolled_identity for item in trusted.keys}
        for item in checked:
            identity = enrolled[item.key_id]
            if identity is not None and identity.casefold() != item.reviewer_id.casefold():
                raise ValueError("reviewer binding differs from key enrolled identity")
        ordered = tuple(sorted(checked, key=lambda item: item.key_id))
        body: dict[str, object] = {
            "schema_version": REVIEWER_IDENTITY_POLICY_SCHEMA,
            "trust_policy": trusted.to_dict(),
            "bindings": [item.to_dict() for item in ordered],
        }
        return cls(trusted, ordered, canonical_digest(body))

    def reviewer_for(self, key_id: str) -> str | None:
        """Return the protected identity for a trusted key, if selected.

        Parameters
        ----------
        key_id : str
            Valid public key identifier to look up in this selected policy.

        Returns
        -------
        str or None
            Identity for exactly one matching binding, or None if unavailable.

        Raises
        ------
        ValueError
            If the requested key identifier is malformed.

        Notes
        -----
        This lookup does not verify a signature or key lifecycle. Consumers
        first reparse the complete policy and then verify the actual signature.
        """
        identity = require_identifier(key_id, "reviewer_policy.key_id")
        matches = tuple(item.reviewer_id for item in self.bindings if item.key_id == identity)
        return matches[0] if len(matches) == 1 else None

    def to_dict(self) -> dict[str, object]:
        """Serialise the complete policy without any private key material.

        Returns
        -------
        dict[str, object]
            Closed policy wire including public lifecycle data and its digest.
            Directly constructed objects require reparsing before trust.
        """
        return {
            "schema_version": REVIEWER_IDENTITY_POLICY_SCHEMA,
            "trust_policy": self.trust_policy.to_dict(),
            "bindings": [item.to_dict() for item in self.bindings],
            "policy_digest": self.policy_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> ReviewerIdentityPolicy:
        """Reject forged mappings, unordered keys or changed policy digests.

        Parameters
        ----------
        value : object
            Closed wire object containing trust policy, bindings and digest.

        Returns
        -------
        ReviewerIdentityPolicy
            Rebuilt policy whose input bindings and digest were canonical.

        Raises
        ------
        ValueError
            For malformed wire, invalid trust data or enrollment, aliases,
            noncanonical binding order, or a changed policy digest.
        """
        data = require_mapping(value, "reviewer identity policy")
        require_exact_fields(
            data,
            frozenset({"schema_version", "trust_policy", "bindings", "policy_digest"}),
            "reviewer identity policy",
        )
        if data.get("schema_version") != REVIEWER_IDENTITY_POLICY_SCHEMA:
            raise ValueError("unsupported reviewer identity policy schema")
        raw_bindings = data.get("bindings")
        if not isinstance(raw_bindings, list):
            raise ValueError("reviewer identity bindings must be an array")
        bindings = tuple(ReviewerIdentityBinding.from_dict(item) for item in raw_bindings)
        policy = cls.build(
            trust_policy=OfflineTrustPolicy.from_dict(data.get("trust_policy")),
            bindings=bindings,
        )
        if (
            bindings != policy.bindings
            or require_string(data.get("policy_digest"), "reviewer_policy.policy_digest")
            != policy.policy_digest
        ):
            raise ValueError("reviewer identity policy differs from its canonical content")
        return policy
