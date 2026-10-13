# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — semantic acceptance identity policy tests
"""Exercise exact author and reviewer identity records with real public keys."""

from __future__ import annotations

from typing import cast

import pytest
from signing_fixtures import public_key_hex

from rigor_foundry.semantic_acceptance_policy import (
    ProposalAuthorAttribution,
    ReviewerIdentityBinding,
    ReviewerIdentityPolicy,
)
from rigor_foundry.trust import TrustedPublicKey
from rigor_foundry.verification_policy import OfflineTrustPolicy, VerificationKeyPolicy

_AUTHOR = "RIGOR-FOUNDRY/codex-7184@01a09839-f7e6-76b0-9d2f-69c19a1fadda"
_REVIEWER = "CEO/claude"


def _policy() -> OfflineTrustPolicy:
    """Build a lifecycle-bound policy for a real deterministic test key."""
    key = TrustedPublicKey.build(
        key_id="fixture-semantic-reviewer",
        public_key_hex=public_key_hex("fixture-semantic-reviewer"),
    )
    return OfflineTrustPolicy.build(
        (
            VerificationKeyPolicy.build(
                key=key,
                valid_from="2026-09-22T00:00:00Z",
                valid_until="2026-10-22T00:00:00Z",
                enrolled_identity=_REVIEWER,
            ),
        )
    )


def test_owner_author_attribution_requires_exact_wire_and_session() -> None:
    """A selected author assertion keeps the source wire and session distinct."""
    record = ProposalAuthorAttribution.build(
        proposal_digest="a" * 64,
        proposal_artifact_sha256="b" * 64,
        author_id=_AUTHOR,
        evidence_sha256="c" * 64,
        attested_by="owner",
        attested_at="2026-09-23T00:00:00Z",
    )
    assert ProposalAuthorAttribution.from_dict(record.to_dict()) == record
    assert record.author_id != _REVIEWER
    altered = {**record.to_dict(), "proposal_artifact_sha256": "d" * 64}
    with pytest.raises(ValueError, match="digest differs"):
        ProposalAuthorAttribution.from_dict(altered)
    altered = {**record.to_dict(), "author_id": "RIGOR-FOUNDRY/codex-7184"}
    with pytest.raises(ValueError, match="qualified session"):
        ProposalAuthorAttribution.from_dict(altered)
    with pytest.raises(ValueError, match="session must be a UUID"):
        ProposalAuthorAttribution.build(
            proposal_digest="a" * 64,
            proposal_artifact_sha256="b" * 64,
            author_id="RIGOR-FOUNDRY/codex-7184@invalid-session",
            evidence_sha256="c" * 64,
            attested_by="owner",
            attested_at="2026-09-23T00:00:00Z",
        )
    with pytest.raises(ValueError, match="qualified session"):
        ProposalAuthorAttribution.build(
            proposal_digest="a" * 64,
            proposal_artifact_sha256="b" * 64,
            author_id=_AUTHOR.replace("@", "@x@"),
            evidence_sha256="c" * 64,
            attested_by="owner",
            attested_at="2026-09-23T00:00:00Z",
        )
    with pytest.raises(ValueError, match="canonical UUID"):
        ProposalAuthorAttribution.build(
            proposal_digest="a" * 64,
            proposal_artifact_sha256="b" * 64,
            author_id=_AUTHOR.upper(),
            evidence_sha256="c" * 64,
            attested_by="owner",
            attested_at="2026-09-23T00:00:00Z",
        )
    with pytest.raises(ValueError, match="unsupported author-attribution schema"):
        ProposalAuthorAttribution.from_dict({**record.to_dict(), "schema_version": "v0"})


def test_reviewer_identity_is_bound_to_policy_key_not_review_claim() -> None:
    """A caller cannot change reviewer identity while retaining policy digest."""
    policy = ReviewerIdentityPolicy.build(
        trust_policy=_policy(),
        bindings=(ReviewerIdentityBinding("fixture-semantic-reviewer", _REVIEWER),),
    )
    assert ReviewerIdentityPolicy.from_dict(policy.to_dict()) == policy
    assert policy.reviewer_for("fixture-semantic-reviewer") == _REVIEWER
    assert policy.reviewer_for("unknown-reviewer-key") is None
    with pytest.raises(ValueError, match="canonical content"):
        ReviewerIdentityPolicy.from_dict({**policy.to_dict(), "policy_digest": "0" * 64})
    altered = policy.to_dict()
    altered["bindings"] = [{"key_id": "fixture-semantic-reviewer", "reviewer_id": _AUTHOR}]
    with pytest.raises(ValueError, match="enrolled identity"):
        ReviewerIdentityPolicy.from_dict(altered)


def test_reviewer_policy_rejects_unbound_or_duplicate_keys() -> None:
    """Every trusted key has one and only one protected reviewer identity."""
    with pytest.raises(ValueError, match="bind each key once"):
        ReviewerIdentityPolicy.build(trust_policy=_policy(), bindings=())
    binding = ReviewerIdentityBinding("fixture-semantic-reviewer", _REVIEWER)
    with pytest.raises(ValueError, match="bind each key once"):
        ReviewerIdentityPolicy.build(trust_policy=_policy(), bindings=(binding, binding))
    with pytest.raises(ValueError, match="bindings must be a tuple"):
        ReviewerIdentityPolicy.build(
            trust_policy=_policy(), bindings=cast(tuple[ReviewerIdentityBinding, ...], [binding])
        )


def test_reviewer_identity_case_alias_cannot_occupy_two_key_bindings() -> None:
    """Identity uniqueness uses the same casefold relation as enrollment checks."""
    keys = tuple(
        VerificationKeyPolicy.build(
            key=TrustedPublicKey.build(key_id=name, public_key_hex=public_key_hex(name)),
            valid_from="2026-09-22T00:00:00Z",
            valid_until="2026-10-22T00:00:00Z",
            enrolled_identity=identity,
        )
        for name, identity in (
            ("reviewer-key-a", _REVIEWER),
            ("reviewer-key-b", _REVIEWER.upper()),
        )
    )
    with pytest.raises(ValueError, match="identities must be unique"):
        ReviewerIdentityPolicy.build(
            trust_policy=OfflineTrustPolicy.build(keys),
            bindings=(
                ReviewerIdentityBinding("reviewer-key-a", _REVIEWER),
                ReviewerIdentityBinding("reviewer-key-b", _REVIEWER.upper()),
            ),
        )


def test_reviewer_binding_cannot_relabel_an_identity_bearing_key() -> None:
    """A mapping must preserve the enrolled actor, including an author-held key."""
    trusted = _policy().keys[0]
    changed_key = VerificationKeyPolicy.build(
        key=trusted.key,
        valid_from=trusted.valid_from,
        valid_until=trusted.valid_until,
        enrolled_identity=_AUTHOR.rpartition("@")[0],
    )
    with pytest.raises(ValueError, match="enrolled identity"):
        ReviewerIdentityPolicy.build(
            trust_policy=OfflineTrustPolicy.build((changed_key,)),
            bindings=(ReviewerIdentityBinding(changed_key.key.key_id, _REVIEWER),),
        )


def test_reviewer_binding_accepts_the_same_enrolled_identity_ignoring_case() -> None:
    """Case changes preserve an enrolled actor while the explicit label stays bound."""
    policy = ReviewerIdentityPolicy.build(
        trust_policy=_policy(),
        bindings=(ReviewerIdentityBinding("fixture-semantic-reviewer", _REVIEWER.upper()),),
    )
    assert ReviewerIdentityPolicy.from_dict(policy.to_dict()) == policy
    assert policy.reviewer_for("fixture-semantic-reviewer") == _REVIEWER.upper()


def test_legacy_key_keeps_its_explicit_identity_mapping_as_data() -> None:
    """A v1 key has no intrinsic actor; the selected policy mapping is explicit."""
    trusted = _policy().keys[0]
    legacy = VerificationKeyPolicy.build(
        key=trusted.key,
        valid_from=trusted.valid_from,
        valid_until=trusted.valid_until,
    )
    policy = ReviewerIdentityPolicy.build(
        trust_policy=OfflineTrustPolicy.build((legacy,)),
        bindings=(ReviewerIdentityBinding(legacy.key.key_id, _REVIEWER),),
    )
    assert ReviewerIdentityPolicy.from_dict(policy.to_dict()) == policy
    assert policy.reviewer_for(legacy.key.key_id) == _REVIEWER


def test_reviewer_policy_rejects_shared_person_and_changed_wire_shape() -> None:
    """Two keys cannot alias one reviewer, and policy parsing is exact."""
    keys = tuple(
        VerificationKeyPolicy.build(
            key=TrustedPublicKey.build(key_id=name, public_key_hex=public_key_hex(name)),
            valid_from="2026-09-22T00:00:00Z",
            valid_until="2026-10-22T00:00:00Z",
        )
        for name in ("reviewer-key-a", "reviewer-key-b")
    )
    with pytest.raises(ValueError, match="identities must be unique"):
        ReviewerIdentityPolicy.build(
            trust_policy=OfflineTrustPolicy.build(keys),
            bindings=(
                ReviewerIdentityBinding("reviewer-key-a", _REVIEWER),
                ReviewerIdentityBinding("reviewer-key-b", _REVIEWER),
            ),
        )
    policy = ReviewerIdentityPolicy.build(
        trust_policy=_policy(),
        bindings=(ReviewerIdentityBinding("fixture-semantic-reviewer", _REVIEWER),),
    )
    with pytest.raises(ValueError, match="unsupported reviewer identity policy schema"):
        ReviewerIdentityPolicy.from_dict({**policy.to_dict(), "schema_version": "v0"})
    with pytest.raises(ValueError, match="bindings must be an array"):
        ReviewerIdentityPolicy.from_dict({**policy.to_dict(), "bindings": ()})
    with pytest.raises(ValueError, match="reviewer identity binding fields"):
        ReviewerIdentityBinding.from_dict(
            {"key_id": "fixture-semantic-reviewer", "reviewer_id": _REVIEWER, "extra": 1}
        )
