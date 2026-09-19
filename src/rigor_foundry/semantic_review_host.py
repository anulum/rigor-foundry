# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — host-selected semantic review admission
"""Derive transition acceptance only from selected source and signed CLEAR."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256

from .discovery_source_schema import parse_json
from .model_primitives import require_digest, require_identifier
from .models import canonical_digest
from .semantic_source_host import HostSemanticSourceVerifier
from .semantic_transition import SemanticTransitionProposal
from .semantic_transition_review import SemanticTransitionReview
from .signed_rule_chain_v2 import RuleChainV2TrustRoles

MAX_PROPOSAL_ARTIFACT_BYTES = 1_048_576
HOST_SEMANTIC_REVIEW_SELECTION_SCHEMA_VERSION = "host-semantic-review-selection.v1"
HOST_SEMANTIC_REVIEW_VERIFICATION_SCHEMA_VERSION = "host-semantic-review-verification.v1"


@dataclass(frozen=True)
class HostSemanticReviewSelection:
    """One exact proposal, source selection, reviewer and signed review."""

    proposal_digest: str
    proposal_artifact_digest: str
    source_selection_digest: str
    review_digest: str
    author_id: str
    reviewer_id: str
    reviewer_key_id: str
    reviewer_policy_digest: str
    selection_digest: str

    @classmethod
    def build(
        cls,
        *,
        proposal_digest: str,
        proposal_artifact_digest: str,
        source_selection_digest: str,
        review_digest: str,
        author_id: str,
        reviewer_id: str,
        reviewer_key_id: str,
        reviewer_policy_digest: str,
    ) -> HostSemanticReviewSelection:
        """Digest the host's complete reviewer and source choice."""
        body: dict[str, str] = {
            "schema_version": HOST_SEMANTIC_REVIEW_SELECTION_SCHEMA_VERSION,
            "proposal_digest": require_digest(proposal_digest, "review host.proposal_digest"),
            "proposal_artifact_digest": require_digest(
                proposal_artifact_digest, "review host.proposal_artifact_digest"
            ),
            "source_selection_digest": require_digest(
                source_selection_digest, "review host.source_selection_digest"
            ),
            "review_digest": require_digest(review_digest, "review host.review_digest"),
            "author_id": require_identifier(author_id, "review host.author_id"),
            "reviewer_id": require_identifier(reviewer_id, "review host.reviewer_id"),
            "reviewer_key_id": require_identifier(reviewer_key_id, "review host.reviewer_key_id"),
            "reviewer_policy_digest": require_digest(
                reviewer_policy_digest, "review host.reviewer_policy_digest"
            ),
        }
        return cls(
            proposal_digest=body["proposal_digest"],
            proposal_artifact_digest=body["proposal_artifact_digest"],
            source_selection_digest=body["source_selection_digest"],
            review_digest=body["review_digest"],
            author_id=body["author_id"],
            reviewer_id=body["reviewer_id"],
            reviewer_key_id=body["reviewer_key_id"],
            reviewer_policy_digest=body["reviewer_policy_digest"],
            selection_digest=canonical_digest(body),
        )


@dataclass(frozen=True)
class HostSemanticReviewState:
    """Stable host lease over the exact signed review and source provider."""

    selected: HostSemanticReviewSelection
    expected_selection_digest: str
    revoked_selection_digests: frozenset[str]
    source_verifier: HostSemanticSourceVerifier
    review: SemanticTransitionReview
    roles: RuleChainV2TrustRoles


@dataclass(frozen=True)
class HostSemanticReviewVerifier:
    """Require a trusted host selection; synthetic test hosts grant no authority.

    A production provider must protect selection, reviewer policy and
    revocations across the nested source reads. The clock is host-owned.
    This does not choose a pack/profile/lock or grant a Guard effect.
    """

    state: Callable[[], AbstractContextManager[HostSemanticReviewState]]
    clock: Callable[[], datetime]

    def verify(
        self,
        proposal: SemanticTransitionProposal,
        *,
        proposal_artifact: bytes,
        proposal_source: bytes,
        owner_question: bytes,
        owner_reply: bytes,
    ) -> dict[str, object]:
        """Return a reviewed dependency only after exact host-selected CLEAR."""
        parsed = SemanticTransitionProposal.from_dict(proposal.to_dict())
        if (
            not isinstance(proposal_artifact, bytes)
            or not 0 < len(proposal_artifact) <= MAX_PROPOSAL_ARTIFACT_BYTES
            or SemanticTransitionProposal.from_dict(parse_json(proposal_artifact)) != parsed
        ):
            raise ValueError("reviewed proposal artifact differs")
        artifact_digest = sha256(proposal_artifact).hexdigest()
        proof: dict[str, object] | None = None
        with self.state() as current:
            if not isinstance(current, HostSemanticReviewState):
                raise PermissionError("semantic review host state is unavailable")
            selected = current.selected
            checked = HostSemanticReviewSelection.build(
                proposal_digest=selected.proposal_digest,
                proposal_artifact_digest=selected.proposal_artifact_digest,
                source_selection_digest=selected.source_selection_digest,
                review_digest=selected.review_digest,
                author_id=selected.author_id,
                reviewer_id=selected.reviewer_id,
                reviewer_key_id=selected.reviewer_key_id,
                reviewer_policy_digest=selected.reviewer_policy_digest,
            )
            expected = require_digest(
                current.expected_selection_digest, "review host.expected_selection_digest"
            )
            revoked = frozenset(
                require_digest(value, "review host.revoked_selection_digest")
                for value in current.revoked_selection_digests
            )
            if (
                checked != selected
                or checked.selection_digest != expected
                or expected in revoked
                or parsed.proposal_digest != checked.proposal_digest
                or artifact_digest != checked.proposal_artifact_digest
                or not isinstance(current.source_verifier, HostSemanticSourceVerifier)
                or not isinstance(current.review, SemanticTransitionReview)
                or not isinstance(current.roles, RuleChainV2TrustRoles)
            ):
                raise PermissionError("review differs from host selection")
            source = current.source_verifier.verify(
                parsed,
                proposal_source=proposal_source,
                owner_question=owner_question,
                owner_reply=owner_reply,
            )
            if (
                source.get("selection_digest") != checked.source_selection_digest
                or source.get("assertion_class") != "selected-semantic-source-integrity-only"
                or source.get("promotable") is not False
            ):
                raise ValueError("review source proof differs from host selection")
            review = SemanticTransitionReview.from_dict(current.review.to_dict())
            if (
                review != current.review
                or review.review_digest != checked.review_digest
                or current.roles.semantic_reviewers.policy_digest != checked.reviewer_policy_digest
            ):
                raise PermissionError("review bytes or reviewer policy differs")
            source_digest = require_digest(
                source.get("source_verification_digest"), "review host.source_verification_digest"
            )
            accepted = review.verified_acceptance_digest(
                roles=current.roles,
                expected_policy_digest=checked.reviewer_policy_digest,
                expected_proposal_digest=checked.proposal_digest,
                expected_proposal_artifact_digest=checked.proposal_artifact_digest,
                expected_source_verification_digest=source_digest,
                expected_parent_replay_digest=parsed.parent_replay_digest,
                expected_author_id=checked.author_id,
                expected_reviewer_id=checked.reviewer_id,
                expected_reviewer_key_id=checked.reviewer_key_id,
                now=self.clock(),
            )
            if accepted is None:
                raise PermissionError("independent semantic CLEAR is absent or inactive")
            proof = {
                "schema_version": HOST_SEMANTIC_REVIEW_VERIFICATION_SCHEMA_VERSION,
                "assertion_class": "reviewed-transition-dependency-only",
                "guard_admissible": False,
                "selection_digest": expected,
                "proposal_digest": checked.proposal_digest,
                "proposal_artifact_digest": checked.proposal_artifact_digest,
                "source_verification_digest": source_digest,
                "review_digest": checked.review_digest,
                "reviewer_policy_digest": checked.reviewer_policy_digest,
                "acceptance_digest": accepted,
            }
        if proof is None:
            raise PermissionError("semantic review host state suppressed verification failure")
        return proof
