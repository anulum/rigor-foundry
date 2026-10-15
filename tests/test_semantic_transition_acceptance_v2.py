# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — signed semantic acceptance tests
"""Exercise exact v2 review signatures and refusal with real Ed25519 fixtures."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from signing_fixtures import public_key_hex, sign_message

from rigor_foundry.models import canonical_digest
from rigor_foundry.semantic_acceptance_policy import (
    REVIEWER_IDENTITY_POLICY_SCHEMA,
    ProposalAuthorAttribution,
    ReviewerIdentityBinding,
    ReviewerIdentityPolicy,
)
from rigor_foundry.semantic_transition_acceptance_v2 import (
    ACCEPTANCE_DOMAIN,
    SemanticAcceptanceBodyV2,
    SignedSemanticAcceptanceV2,
)
from rigor_foundry.trust import TrustedPublicKey
from rigor_foundry.verification_policy import OfflineTrustPolicy, VerificationKeyPolicy

_KEY = "fixture-ceo-reviewer-key"
_AUTHOR = "RIGOR-FOUNDRY/fixture-author@12345678-1234-4234-8234-123456789abc"
_REVIEWER = "REVIEW/fixture-reviewer"
_NOW = datetime(2026, 9, 23, 0, 30, tzinfo=UTC)


def _author() -> ProposalAuthorAttribution:
    """Build a synthetic protected-host author attestation for one wire."""
    return ProposalAuthorAttribution.build(
        proposal_digest="a" * 64,
        proposal_artifact_sha256="b" * 64,
        author_id=_AUTHOR,
        evidence_sha256="c" * 64,
        attested_by="owner",
        attested_at="2026-09-23T00:00:00Z",
    )


def _policy(*, revoked_at: str = "", reviewer_id: str = _REVIEWER) -> ReviewerIdentityPolicy:
    """Bind a real public key and lifecycle to one synthetic CEO identity."""
    key = TrustedPublicKey.build(key_id=_KEY, public_key_hex=public_key_hex(_KEY))
    trust = OfflineTrustPolicy.build(
        (
            VerificationKeyPolicy.build(
                key=key,
                valid_from="2026-09-22T00:00:00Z",
                valid_until="2026-10-22T00:00:00Z",
                revoked_at=revoked_at,
                enrolled_identity=reviewer_id,
            ),
        )
    )
    return ReviewerIdentityPolicy.build(
        trust_policy=trust,
        bindings=(ReviewerIdentityBinding(_KEY, reviewer_id),),
    )


def _body() -> dict[str, object]:
    """Declare one exact four-link acceptance with explicit receipt budgets."""
    statements = [character * 64 for character in "1234"]
    return {
        "schema_version": "accepted-semantic-transition.v2",
        "object_kind": "semantic-transition-acceptance",
        "signature_domain": ACCEPTANCE_DOMAIN,
        "algorithm": "ed25519",
        "signer_role": "semantic-reviewer",
        "proposal_digest": "a" * 64,
        "proposal_artifact_sha256": "b" * 64,
        "parent_replay_digest": "d" * 64,
        "source_verification_digest": "e" * 64,
        "discovery_source_selection_digest": "f" * 64,
        "source_limits": {
            "total_bytes": 20000,
            "file_bytes": 8000,
            "sources": 3,
            "shards": 1,
            "candidates": 4,
            "spans": 12,
        },
        "normative_source_sha256": "0" * 64,
        "statement_sha256": statements,
        "author_attribution_digest": _author().attribution_digest,
        "owner_ratification_manifest_sha256": "5" * 64,
        "owner_question_sha256": "6" * 64,
        "owner_reply_sha256": "7" * 64,
        "replacements": [
            {
                "predecessor_id": f"old-{index}",
                "successor_id": f"new-{index}",
                "statement_sha256": statements[index],
            }
            for index in range(4)
        ],
        "author_id": _AUTHOR,
        "reviewer_id": _REVIEWER,
        "reviewer_key_id": _KEY,
        "verdict": "clear",
        "findings_sha256": "8" * 64,
        "reviewed_at": "2026-09-23T00:05:00Z",
    }


def _signed() -> SignedSemanticAcceptanceV2:
    """Sign the v2 body with a real deterministic test private key."""
    body = SemanticAcceptanceBodyV2.from_dict(_body())
    return SignedSemanticAcceptanceV2.build(
        body=body,
        signature_hex=sign_message(_KEY, ACCEPTANCE_DOMAIN, body.payload_digest),
    )


def test_real_ed25519_acceptance_round_trip_is_dependency_only() -> None:
    """Exact signed bytes verify only with selected identity and author data."""
    signed = _signed()
    assert SignedSemanticAcceptanceV2.from_dict(signed.to_dict()) == signed
    assert signed.verify_signature(policy=_policy(), author=_author(), now=_NOW)
    assert signed.body.to_dict()["source_limits"] == _body()["source_limits"]


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("signature_domain", "rigor-foundry.standard-pack.v2"),
        ("signer_role", "pack-issuer"),
        ("verdict", "changes-requested"),
        ("author_id", _REVIEWER),
        ("source_limits", {"total_bytes": 20000}),
        ("statement_sha256", []),
        ("statement_sha256", ["1" * 64] * 4),
        ("replacements", []),
    ],
)
def test_wrong_signed_body_refuses_before_any_host_admission(
    field: str, replacement: object
) -> None:
    """Wrong domain, grant class, source limit or replacement cannot parse."""
    body = {**_body(), field: replacement}
    with pytest.raises(ValueError):
        SemanticAcceptanceBodyV2.from_dict(body)


def test_changed_signature_or_envelope_cannot_verify() -> None:
    """A digest edit or another domain signature cannot borrow reviewer trust."""
    signed = _signed()
    altered = {**signed.to_dict(), "signature_hex": "0" * 128}
    with pytest.raises(ValueError, match="envelope digest differs"):
        SignedSemanticAcceptanceV2.from_dict(altered)
    wrong_domain = SignedSemanticAcceptanceV2.build(
        body=signed.body,
        signature_hex=sign_message(
            _KEY, "rigor-foundry.standard-pack.v2", signed.body.payload_digest
        ),
    )
    assert not wrong_domain.verify_signature(policy=_policy(), author=_author(), now=_NOW)


@pytest.mark.parametrize(
    "fault",
    [
        "wrong-reviewer",
        "revoked",
        "expired",
        "future",
        "naive",
        "wrong-author",
        "late-author",
        "wrong-proposal",
    ],
)
def test_host_identity_lifecycle_and_time_hold_acceptance(fault: str) -> None:
    """A real signature cannot override author/reviewer or lifecycle mismatch."""
    signed = _signed()
    policy = _policy()
    author = _author()
    now = _NOW
    if fault == "wrong-reviewer":
        policy = _policy(reviewer_id="CEO/another-reviewer")
    elif fault == "revoked":
        policy = _policy(revoked_at="2026-09-23T00:10:00Z")
    elif fault == "expired":
        now = datetime(2026, 10, 22, tzinfo=UTC)
    elif fault == "future":
        now = datetime(2026, 9, 23, 0, 1, tzinfo=UTC)
    elif fault == "naive":
        now = datetime(2026, 9, 23)
    elif fault == "wrong-proposal":
        body = SemanticAcceptanceBodyV2.from_dict({**_body(), "proposal_digest": "9" * 64})
        signed = SignedSemanticAcceptanceV2.build(
            body=body,
            signature_hex=sign_message(_KEY, ACCEPTANCE_DOMAIN, body.payload_digest),
        )
    elif fault == "wrong-author":
        author = ProposalAuthorAttribution.build(
            proposal_digest="9" * 64,
            proposal_artifact_sha256=author.proposal_artifact_sha256,
            author_id=author.author_id,
            evidence_sha256=author.evidence_sha256,
            attested_by=author.attested_by,
            attested_at=author.attested_at,
        )
    else:
        author = ProposalAuthorAttribution.build(
            proposal_digest=author.proposal_digest,
            proposal_artifact_sha256=author.proposal_artifact_sha256,
            author_id=author.author_id,
            evidence_sha256=author.evidence_sha256,
            attested_by=author.attested_by,
            attested_at="2026-09-23T00:20:00Z",
        )
    assert not signed.verify_signature(policy=policy, author=author, now=now)


def test_direct_dataclass_tamper_refuses_on_reparse() -> None:
    """Caller reconstruction cannot change a signed body after signing."""
    signed = _signed()
    forged = replace(signed, signature_digest="0" * 64)
    assert not forged.verify_signature(policy=_policy(), author=_author(), now=_NOW)
    with pytest.raises(ValueError, match="body digest differs"):
        replace(signed.body, payload_digest="0" * 64).to_dict()


def test_crossed_successor_link_refuses_even_with_valid_statement_hashes() -> None:
    """Reordering successor identities cannot retain the signed mapping."""
    body = _body()
    links = body["replacements"]
    assert isinstance(links, list)
    crossed = [dict(item) for item in links]
    crossed[0]["successor_id"] = crossed[1]["successor_id"]
    with pytest.raises(ValueError, match="replacement mapping differs"):
        SemanticAcceptanceBodyV2.from_dict({**body, "replacements": crossed})


@pytest.mark.parametrize(
    "author_id", [_AUTHOR.upper(), "RIGOR-FOUNDRY/fixture-author@invalid-uuid"]
)
def test_acceptance_author_session_must_use_canonical_uuid(author_id: str) -> None:
    """A malformed or alternate UUID spelling refuses before signature admission."""
    with pytest.raises(ValueError, match="canonical UUID"):
        SemanticAcceptanceBodyV2.from_dict({**_body(), "author_id": author_id})


def test_author_seat_cannot_review_its_own_qualified_session() -> None:
    """The exact author seat and reviewer seat pair refuses at both APIs."""
    self_reviewer = _AUTHOR.rpartition("@")[0]
    unsafe = {**_body(), "reviewer_id": self_reviewer}
    with pytest.raises(ValueError, match="author and reviewer must differ"):
        SemanticAcceptanceBodyV2.from_dict(unsafe)
    with pytest.raises(ValueError, match="author and reviewer must differ"):
        SemanticAcceptanceBodyV2.from_dict({**_body(), "reviewer_id": _AUTHOR})
    signed = SignedSemanticAcceptanceV2(
        body=SemanticAcceptanceBodyV2(canonical_json=json.dumps(unsafe), payload_digest="0" * 64),
        signature_hex="0" * 128,
        signature_digest="0" * 64,
        acceptance_digest="0" * 64,
    )
    assert not signed.verify_signature(
        policy=_policy(reviewer_id=self_reviewer), author=_author(), now=_NOW
    )


def test_valid_signature_cannot_relabel_the_authors_enrolled_key() -> None:
    """Cryptographic validity cannot override the selected key's actor binding."""
    selected = _policy()
    key = selected.trust_policy.keys[0]
    author_key = VerificationKeyPolicy.build(
        key=key.key,
        valid_from=key.valid_from,
        valid_until=key.valid_until,
        enrolled_identity=_AUTHOR.rpartition("@")[0],
    )
    trust = OfflineTrustPolicy.build((author_key,))
    body = {
        "schema_version": REVIEWER_IDENTITY_POLICY_SCHEMA,
        "trust_policy": trust.to_dict(),
        "bindings": [item.to_dict() for item in selected.bindings],
    }
    forged = ReviewerIdentityPolicy(trust, selected.bindings, canonical_digest(body))
    assert not _signed().verify_signature(policy=forged, author=_author(), now=_NOW)


@pytest.mark.parametrize(
    ("author_id", "reviewer_id"),
    [
        (_AUTHOR.replace("@", "@x@"), _AUTHOR.rpartition("@")[0]),
        (_AUTHOR, _AUTHOR.rpartition("@")[0].casefold()),
    ],
)
def test_malformed_or_case_variant_author_seat_refuses(author_id: str, reviewer_id: str) -> None:
    """Extra separators and case variants cannot turn self-review into CLEAR."""
    with pytest.raises(ValueError):
        SemanticAcceptanceBodyV2.from_dict(
            {**_body(), "author_id": author_id, "reviewer_id": reviewer_id}
        )
