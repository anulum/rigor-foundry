# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — semantic transition review tests
"""Exercise detached review signatures without asserting a real approval."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import cast

import pytest
from signing_fixtures import public_key_hex, sign_message

from rigor_foundry.models import canonical_digest
from rigor_foundry.semantic_transition_review import (
    SEMANTIC_REVIEW_DOMAIN,
    ReviewVerdict,
    SemanticTransitionReview,
)
from rigor_foundry.signed_rule_chain_v2 import RuleChainV2TrustRoles
from rigor_foundry.trust import TrustedPublicKey
from rigor_foundry.verification_policy import OfflineTrustPolicy, VerificationKeyPolicy

_KEY_ID = "synthetic-independent-reviewer"
_AUTHOR = "RIGOR-FOUNDRY/author-fixture"
_REVIEWER = "RIGOR-FOUNDRY/reviewer-fixture"
_PROPOSAL = "a" * 64
_ARTIFACT = "b" * 64
_SOURCE = "c" * 64
_PARENT = "d" * 64
_FINDINGS = "e" * 64
_SIGNED_AT = "2026-09-18T00:00:00Z"
_NOW = datetime(2026, 9, 19, tzinfo=UTC)


def _policy(*, key_id: str = _KEY_ID, revoked_at: str = "") -> OfflineTrustPolicy:
    key = TrustedPublicKey.build(key_id=key_id, public_key_hex=public_key_hex(key_id))
    return OfflineTrustPolicy.build(
        (
            VerificationKeyPolicy.build(
                key=key,
                valid_from="2026-09-01T00:00:00Z",
                valid_until="2026-10-01T00:00:00Z",
                revoked_at=revoked_at,
            ),
        )
    )


def _roles(reviewer_policy: OfflineTrustPolicy) -> RuleChainV2TrustRoles:
    """Assign an independently keyed reviewer beside all rule-chain signers."""
    return RuleChainV2TrustRoles.build(
        pack_issuers=_policy(key_id="review-test-pack"),
        project_selectors=_policy(key_id="review-test-selector"),
        lock_resolvers=_policy(key_id="review-test-resolver"),
        semantic_reviewers=reviewer_policy,
    )


def _review(
    *, verdict: ReviewVerdict = "clear", reviewed_at: str = _SIGNED_AT
) -> SemanticTransitionReview:
    payload = SemanticTransitionReview.payload(
        proposal_digest=_PROPOSAL,
        proposal_artifact_digest=_ARTIFACT,
        source_verification_digest=_SOURCE,
        parent_replay_digest=_PARENT,
        author_id=_AUTHOR,
        reviewer_id=_REVIEWER,
        reviewer_key_id=_KEY_ID,
        verdict=verdict,
        findings_digest=_FINDINGS,
        reviewed_at=reviewed_at,
    )
    signature = sign_message(_KEY_ID, SEMANTIC_REVIEW_DOMAIN, canonical_digest(payload))
    return SemanticTransitionReview.build(
        proposal_digest=_PROPOSAL,
        proposal_artifact_digest=_ARTIFACT,
        source_verification_digest=_SOURCE,
        parent_replay_digest=_PARENT,
        author_id=_AUTHOR,
        reviewer_id=_REVIEWER,
        reviewer_key_id=_KEY_ID,
        verdict=verdict,
        findings_digest=_FINDINGS,
        reviewed_at=reviewed_at,
        signature_hex=signature,
    )


def _acceptance(
    review: SemanticTransitionReview,
    *,
    policy: OfflineTrustPolicy | None = None,
    now: datetime = _NOW,
    **expected: str,
) -> str | None:
    chosen = _policy() if policy is None else policy
    arguments = {
        "expected_policy_digest": chosen.policy_digest,
        "expected_proposal_digest": _PROPOSAL,
        "expected_proposal_artifact_digest": _ARTIFACT,
        "expected_source_verification_digest": _SOURCE,
        "expected_parent_replay_digest": _PARENT,
        "expected_author_id": _AUTHOR,
        "expected_reviewer_id": _REVIEWER,
        "expected_reviewer_key_id": _KEY_ID,
        **expected,
    }
    return review.verified_acceptance_digest(
        roles=_roles(chosen),
        now=now,
        **arguments,
    )


def test_synthetic_signature_round_trip_and_exact_acceptance_digest() -> None:
    """Verify the signing path with a test key and no live review claim."""
    review = _review()
    assert SemanticTransitionReview.from_dict(review.to_dict()) == review
    expected = canonical_digest(
        {
            "schema_version": "accepted-semantic-transition.v1",
            "proposal_digest": _PROPOSAL,
            "review_digest": review.review_digest,
            "source_verification_digest": _SOURCE,
        }
    )
    assert _acceptance(review) == expected


def test_reviewer_role_alias_refuses_even_with_valid_review_signature() -> None:
    """A cryptographic CLEAR cannot borrow a pack-issuer key as reviewer."""
    review = _review()
    roles = replace(_roles(_policy()), pack_issuers=_policy())
    assert (
        review.verified_acceptance_digest(
            roles=roles,
            expected_policy_digest=roles.semantic_reviewers.policy_digest,
            expected_proposal_digest=_PROPOSAL,
            expected_proposal_artifact_digest=_ARTIFACT,
            expected_source_verification_digest=_SOURCE,
            expected_parent_replay_digest=_PARENT,
            expected_author_id=_AUTHOR,
            expected_reviewer_id=_REVIEWER,
            expected_reviewer_key_id=_KEY_ID,
            now=_NOW,
        )
        is None
    )


@pytest.mark.parametrize("verdict", ["changes-requested", "blocked"])
def test_non_clear_verdict_never_yields_acceptance(verdict: str) -> None:
    """A correctly signed objection cannot turn into an accepted transition."""
    review = _review(verdict=cast(ReviewVerdict, verdict))
    assert SemanticTransitionReview.from_dict(review.to_dict()) == review
    assert _acceptance(review) is None


@pytest.mark.parametrize(
    "fault",
    [
        "wrong-policy-digest",
        "wrong-proposal",
        "wrong-artifact",
        "wrong-source-proof",
        "wrong-parent",
        "wrong-author",
        "wrong-reviewer",
        "wrong-key-id",
        "wrong-key-material",
        "revoked-key",
        "expired-key",
        "future-review",
        "naive-clock",
        "altered-signature",
        "altered-review-digest",
        "wrong-signature-domain",
        "revoked-before-review",
    ],
)
def test_untrusted_or_changed_review_cannot_yield_acceptance(fault: str) -> None:
    """Deny altered source, identity, trust, time and cryptographic inputs."""
    review = _review()
    expected: dict[str, str] = {}
    policy = _policy()
    now = _NOW
    if fault == "wrong-policy-digest":
        expected["expected_policy_digest"] = "0" * 64
    elif fault == "wrong-proposal":
        expected["expected_proposal_digest"] = "0" * 64
    elif fault == "wrong-artifact":
        expected["expected_proposal_artifact_digest"] = "0" * 64
    elif fault == "wrong-source-proof":
        expected["expected_source_verification_digest"] = "0" * 64
    elif fault == "wrong-parent":
        expected["expected_parent_replay_digest"] = "0" * 64
    elif fault == "wrong-author":
        expected["expected_author_id"] = "different-author"
    elif fault == "wrong-reviewer":
        expected["expected_reviewer_id"] = "different-reviewer"
    elif fault == "wrong-key-id":
        expected["expected_reviewer_key_id"] = "different-key"
    elif fault == "wrong-key-material":
        policy = _policy(key_id="other-test-key")
    elif fault == "revoked-key":
        policy = _policy(revoked_at="2026-09-18T12:00:00Z")
    elif fault == "revoked-before-review":
        policy = _policy(revoked_at="2026-09-17T12:00:00Z")
    elif fault == "expired-key":
        now = datetime(2026, 10, 1, tzinfo=UTC)
    elif fault == "future-review":
        now = datetime(2026, 9, 17, tzinfo=UTC)
    elif fault == "naive-clock":
        now = datetime(2026, 9, 19)
    elif fault == "altered-signature":
        review = replace(review, signature_hex="0" * 128)
    elif fault == "wrong-signature-domain":
        review = SemanticTransitionReview.build(
            proposal_digest=review.proposal_digest,
            proposal_artifact_digest=review.proposal_artifact_digest,
            source_verification_digest=review.source_verification_digest,
            parent_replay_digest=review.parent_replay_digest,
            author_id=review.author_id,
            reviewer_id=review.reviewer_id,
            reviewer_key_id=review.reviewer_key_id,
            verdict=review.verdict,
            findings_digest=review.findings_digest,
            reviewed_at=review.reviewed_at,
            signature_hex=sign_message(
                _KEY_ID, "rigor-foundry.standard-pack.v2", review.payload_digest
            ),
        )
    else:
        review = replace(review, review_digest="0" * 64)
    assert _acceptance(review, policy=policy, now=now, **expected) is None


@pytest.mark.parametrize(
    "field",
    [
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
    ],
)
def test_changed_wire_field_refuses_parse(field: str) -> None:
    """No signed or derived review field may be rewritten in transit."""
    wire = _review().to_dict()
    wire[field] = "0" * 64
    with pytest.raises(ValueError):
        SemanticTransitionReview.from_dict(wire)


def test_unknown_missing_and_self_review_fields_refuse() -> None:
    """Deny extensions, omissions, unsupported decisions and author aliases."""
    wire = _review().to_dict()
    with pytest.raises(ValueError):
        SemanticTransitionReview.from_dict({**wire, "grant": True})
    wire.pop("findings_digest")
    with pytest.raises(ValueError):
        SemanticTransitionReview.from_dict(wire)
    with pytest.raises(ValueError, match="own proposal"):
        SemanticTransitionReview.payload(
            proposal_digest=_PROPOSAL,
            proposal_artifact_digest=_ARTIFACT,
            source_verification_digest=_SOURCE,
            parent_replay_digest=_PARENT,
            author_id=_REVIEWER,
            reviewer_id=_REVIEWER,
            reviewer_key_id=_KEY_ID,
            verdict="clear",
            findings_digest=_FINDINGS,
            reviewed_at=_SIGNED_AT,
        )
    with pytest.raises(ValueError, match="unsupported"):
        SemanticTransitionReview.payload(
            proposal_digest=_PROPOSAL,
            proposal_artifact_digest=_ARTIFACT,
            source_verification_digest=_SOURCE,
            parent_replay_digest=_PARENT,
            author_id=_AUTHOR,
            reviewer_id=_REVIEWER,
            reviewer_key_id=_KEY_ID,
            verdict=cast(ReviewVerdict, "accepted"),
            findings_digest=_FINDINGS,
            reviewed_at=_SIGNED_AT,
        )
