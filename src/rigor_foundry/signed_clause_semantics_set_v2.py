# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — dual-signed clause semantics set
"""Authenticate exact clause semantics bytes with separate author and reviewer keys."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .clause_semantics_set_v2 import ClauseSemanticsSetV2
from .model_primitives import parse_utc_timestamp
from .signed_rule_chain_v2 import RuleChainV2Signature, RuleChainV2TrustRoles
from .verification_policy import OfflineTrustPolicy


def _enrolled_identity(policy: OfflineTrustPolicy, key_id: str) -> str | None:
    """Find one identity from an exact protected trust-policy key record."""
    matches = tuple(key for key in policy.keys if key.key.key_id == key_id)
    return matches[0].enrolled_identity if len(matches) == 1 else None


@dataclass(frozen=True)
class SignedClauseSemanticsSetV2:
    """Keep one canonical body and its two typed detached signatures together."""

    body: ClauseSemanticsSetV2
    author: RuleChainV2Signature
    reviewer: RuleChainV2Signature

    @classmethod
    def from_bytes(
        cls, *, body_bytes: bytes, author_signature: object, reviewer_signature: object
    ) -> SignedClauseSemanticsSetV2:
        """Parse the exact body and both complete signature envelopes.

        Parameters
        ----------
        body_bytes : bytes
            Canonical clause-semantics JSON bytes retained without rewriting.
        author_signature, reviewer_signature : object
            Detached signature mappings with author and reviewer object kinds.

        Returns
        -------
        SignedClauseSemanticsSetV2
            Parsed body and two envelopes bound to its exact digest.

        Raises
        ------
        ValueError
            If the body, envelopes, object kinds or body digests disagree.
        """
        body = ClauseSemanticsSetV2.from_bytes(body_bytes)
        author = RuleChainV2Signature.from_dict(author_signature)
        reviewer = RuleChainV2Signature.from_dict(reviewer_signature)
        if (
            author.object_kind != "clause-semantics-set-author"
            or reviewer.object_kind != "clause-semantics-set"
            or author.body_digest != body.body_digest
            or reviewer.body_digest != body.body_digest
        ):
            raise ValueError("semantics signatures do not name the exact typed body")
        return cls(body, author, reviewer)

    def verify(self, *, roles: RuleChainV2TrustRoles, now: datetime) -> bool:
        """Recheck both signatures, key lifecycles, order and identity separation.

        Parameters
        ----------
        roles : RuleChainV2TrustRoles
            Caller-selected, independently enrolled signing-role policies.
        now : datetime
            Explicit UTC verification time; signing times cannot be later.

        Returns
        -------
        bool
            True only for the exact body with current author and reviewer keys
            from different identities, and a declared review time no earlier
            than the declared author time. These declarations do not prove event
            order. The review does not bind a particular author key or signature.
            This result grants no effect or policy-adoption authority.
        """
        try:
            if self != SignedClauseSemanticsSetV2.from_bytes(
                body_bytes=self.body.body_bytes,
                author_signature=self.author.to_dict(),
                reviewer_signature=self.reviewer.to_dict(),
            ):
                return False
            checked_roles = RuleChainV2TrustRoles.build(
                pack_issuers=roles.pack_issuers,
                project_selectors=roles.project_selectors,
                lock_resolvers=roles.lock_resolvers,
                semantic_authors=roles.semantic_authors,
                semantic_reviewers=roles.semantic_reviewers,
            )
            if checked_roles != roles or parse_utc_timestamp(
                self.author.signed_at, "semantics author signed_at"
            ) > parse_utc_timestamp(self.reviewer.signed_at, "semantics reviewer signed_at"):
                return False
            author_identity = _enrolled_identity(roles.semantic_authors, self.author.key_id)
            reviewer_identity = _enrolled_identity(roles.semantic_reviewers, self.reviewer.key_id)
            return bool(
                author_identity
                and reviewer_identity
                and author_identity.casefold() != reviewer_identity.casefold()
                and self.author.verify(body_digest=self.body.body_digest, roles=roles, now=now)
                and self.reviewer.verify(body_digest=self.body.body_digest, roles=roles, now=now)
            )
        except (TypeError, ValueError):
            return False
