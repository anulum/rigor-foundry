# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — typed rule-chain signature tests
"""Exercise real Ed25519 role and domain boundaries for candidate v2 wire."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import cast

import pytest
from signing_fixtures import public_key_hex, sign_message

from rigor_foundry.signed_rule_chain_v2 import (
    RuleChainV2Signature,
    RuleChainV2TrustRoles,
    RuleObjectKind,
    rule_chain_v2_payload_digest,
)
from rigor_foundry.trust import STANDARD_PACK_SIGNATURE_DOMAIN, TrustedPublicKey
from rigor_foundry.verification_policy import OfflineTrustPolicy, VerificationKeyPolicy

_BODY = "a" * 64
_SIGNED_AT = "2026-09-12T00:00:00Z"
_DOMAINS = {
    "standard-pack": "rigor-foundry.standard-pack.v2",
    "project-profile": "rigor-foundry.project-profile-selection.v2",
    "effective-profile-lock": "rigor-foundry.effective-profile-lock.v2",
    "clause-semantics-set-author": "rigor-foundry.clause-semantics-set-author.v2",
    "clause-semantics-set": "rigor-foundry.clause-semantics-set.v2",
}
_KEYS = {
    "standard-pack": "v2-pack-issuer",
    "project-profile": "v2-project-selector",
    "effective-profile-lock": "v2-lock-resolver",
    "clause-semantics-set-author": "v2-semantic-author",
    "clause-semantics-set": "v2-semantic-reviewer",
}


def _policy(
    key_id: str, *, revoked_at: str = "", enrolled_identity: str | None = None
) -> OfflineTrustPolicy:
    """Create one real public-key policy with an explicit lifecycle."""
    key = TrustedPublicKey.build(key_id=key_id, public_key_hex=public_key_hex(key_id))
    return OfflineTrustPolicy.build(
        (
            VerificationKeyPolicy.build(
                key=key,
                valid_from="2026-09-01T00:00:00Z",
                valid_until="2026-10-01T00:00:00Z",
                revoked_at=revoked_at,
                enrolled_identity=enrolled_identity,
            ),
        )
    )


def _roles(*, revoked_pack_at: str = "") -> RuleChainV2TrustRoles:
    """Keep five signer roles on distinct actual Ed25519 keys."""
    return RuleChainV2TrustRoles.build(
        pack_issuers=_policy(_KEYS["standard-pack"], revoked_at=revoked_pack_at),
        project_selectors=_policy(_KEYS["project-profile"]),
        lock_resolvers=_policy(_KEYS["effective-profile-lock"]),
        semantic_authors=_policy(
            _KEYS["clause-semantics-set-author"],
            enrolled_identity="RIGOR-FOUNDRY/author-1",
        ),
        semantic_reviewers=_policy(
            _KEYS["clause-semantics-set"],
            enrolled_identity="RIGOR-FOUNDRY/reviewer-1",
        ),
    )


def _signature(kind: RuleObjectKind) -> RuleChainV2Signature:
    """Sign one typed canonical payload with its corresponding test key."""
    digest = rule_chain_v2_payload_digest(
        object_kind=kind, body_digest=_BODY, signed_at=_SIGNED_AT
    )
    return RuleChainV2Signature.build(
        object_kind=kind,
        key_id=_KEYS[kind],
        body_digest=_BODY,
        signed_at=_SIGNED_AT,
        signature_hex=sign_message(_KEYS[kind], _DOMAINS[kind], digest),
    )


@pytest.mark.parametrize("kind", tuple(_DOMAINS))
def test_each_typed_object_verifies_only_its_own_role(kind: str) -> None:
    """Every object kind uses its own real signature and key domain.

    Parameters
    ----------
    kind : str
        Supported object kind paired with its selected signing-role policy.
    """
    signature = _signature(cast(RuleObjectKind, kind))
    parsed = RuleChainV2Signature.from_dict(signature.to_dict())
    assert parsed == signature
    assert parsed.verify(body_digest=_BODY, roles=_roles(), now=datetime(2026, 9, 19, tzinfo=UTC))


@pytest.mark.parametrize(
    "fault",
    [
        "body",
        "signature",
        "domain",
        "role",
        "kind",
        "v1-signature",
        "future",
        "expired",
        "naive-now",
        "signed-before-validity",
        "revoked-key",
        "unknown-key",
    ],
)
def test_pack_signature_failures_never_authenticate(fault: str) -> None:
    """Changing type, time, role, body or key material always refuses."""
    signature = _signature("standard-pack")
    body = _BODY
    roles = _roles()
    now = datetime(2026, 9, 19, tzinfo=UTC)
    if fault == "body":
        body = "b" * 64
    elif fault == "signature":
        signature = replace(signature, signature_hex="0" * 128)
    elif fault == "domain":
        signature = replace(signature, signature_domain=_DOMAINS["project-profile"])
    elif fault == "role":
        signature = replace(signature, signer_role="project-selector")
    elif fault == "kind":
        signature = replace(signature, object_kind="project-profile")
    elif fault == "v1-signature":
        signature = replace(
            signature,
            signature_hex=sign_message(
                _KEYS["standard-pack"],
                STANDARD_PACK_SIGNATURE_DOMAIN,
                signature.payload_digest,
            ),
        )
        signature = replace(
            signature,
            signature_digest=RuleChainV2Signature.build(
                object_kind="standard-pack",
                key_id=_KEYS["standard-pack"],
                body_digest=_BODY,
                signed_at=_SIGNED_AT,
                signature_hex=signature.signature_hex,
            ).signature_digest,
        )
    elif fault == "future":
        now = datetime(2026, 9, 11, tzinfo=UTC)
    elif fault == "expired":
        now = datetime(2026, 10, 1, tzinfo=UTC)
    elif fault == "naive-now":
        now = datetime(2026, 9, 19)
    elif fault == "signed-before-validity":
        old = "2026-08-31T00:00:00Z"
        digest = rule_chain_v2_payload_digest(
            object_kind="standard-pack", body_digest=_BODY, signed_at=old
        )
        signature = RuleChainV2Signature.build(
            object_kind="standard-pack",
            key_id=_KEYS["standard-pack"],
            body_digest=_BODY,
            signed_at=old,
            signature_hex=sign_message(_KEYS["standard-pack"], _DOMAINS["standard-pack"], digest),
        )
    elif fault == "revoked-key":
        roles = _roles(revoked_pack_at="2026-09-18T00:00:00Z")
    else:
        signature = replace(signature, key_id="unknown")
    assert not signature.verify(body_digest=body, roles=roles, now=now)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("schema_version", "1.0"),
        ("algorithm", "ed448"),
        ("signature_domain", _DOMAINS["effective-profile-lock"]),
        ("signer_role", "lock-resolver"),
        ("payload_digest", "b" * 64),
        ("signature_digest", "b" * 64),
        ("body_digest", "b" * 64),
        ("signed_at", "2026-09-13T00:00:00Z"),
        ("signature_hex", "A" * 128),
    ],
)
def test_v2_wire_parser_refuses_tampered_metadata(field: str, replacement: str) -> None:
    """A digest recomputation cannot silently change typed signature fields."""
    wire = _signature("standard-pack").to_dict()
    wire[field] = replacement
    with pytest.raises(ValueError):
        RuleChainV2Signature.from_dict(wire)


def test_v2_wire_parser_refuses_unknown_or_missing_fields() -> None:
    """The signature parser has no permissive default for a new or old field."""
    wire = _signature("standard-pack").to_dict()
    with pytest.raises(ValueError):
        RuleChainV2Signature.from_dict({**wire, "extra": "ignored"})
    del wire["signer_role"]
    with pytest.raises(ValueError):
        RuleChainV2Signature.from_dict(wire)


def test_v2_wire_parser_refuses_unknown_object_kind() -> None:
    """An unsupported kind cannot borrow another kind's domain or role."""
    wire = _signature("standard-pack").to_dict()
    wire["object_kind"] = "audit-receipt"
    with pytest.raises(ValueError, match="unsupported rule-chain v2 object kind"):
        RuleChainV2Signature.from_dict(wire)
    with pytest.raises(ValueError, match="unsupported rule-chain v2 object kind"):
        _roles().policy_for(cast(RuleObjectKind, "audit-receipt"))


def test_role_store_refuses_key_aliases() -> None:
    """A single key cannot issue the pack, select the profile and seal the lock."""
    policy = _policy(_KEYS["standard-pack"])
    with pytest.raises(ValueError, match="key ids"):
        RuleChainV2TrustRoles.build(
            pack_issuers=policy,
            project_selectors=policy,
            lock_resolvers=_policy(_KEYS["effective-profile-lock"]),
            semantic_authors=_roles().semantic_authors,
            semantic_reviewers=_roles().semantic_reviewers,
        )
    reused_material = TrustedPublicKey.build(
        key_id="other-id",
        public_key_hex=public_key_hex(_KEYS["standard-pack"]),
    )
    alias = OfflineTrustPolicy.build(
        (
            VerificationKeyPolicy.build(
                key=reused_material,
                valid_from="2026-09-01T00:00:00Z",
                valid_until="2026-10-01T00:00:00Z",
            ),
        )
    )
    with pytest.raises(ValueError, match="public keys"):
        RuleChainV2TrustRoles.build(
            pack_issuers=policy,
            project_selectors=alias,
            lock_resolvers=_policy(_KEYS["effective-profile-lock"]),
            semantic_authors=_roles().semantic_authors,
            semantic_reviewers=_roles().semantic_reviewers,
        )


def test_semantic_reviewer_cannot_reuse_pack_signer_key() -> None:
    """A reviewer title cannot make a pack-signing key independent."""
    pack = _policy(_KEYS["standard-pack"])
    with pytest.raises(ValueError, match="key ids"):
        RuleChainV2TrustRoles.build(
            pack_issuers=pack,
            project_selectors=_policy(_KEYS["project-profile"]),
            lock_resolvers=_policy(_KEYS["effective-profile-lock"]),
            semantic_authors=_roles().semantic_authors,
            semantic_reviewers=pack,
        )
    alias = OfflineTrustPolicy.build(
        (
            VerificationKeyPolicy.build(
                key=TrustedPublicKey.build(
                    key_id="reviewer-key-alias",
                    public_key_hex=public_key_hex(_KEYS["standard-pack"]),
                ),
                valid_from="2026-09-01T00:00:00Z",
                valid_until="2026-10-01T00:00:00Z",
            ),
        )
    )
    with pytest.raises(ValueError, match="public keys"):
        RuleChainV2TrustRoles.build(
            pack_issuers=pack,
            project_selectors=_policy(_KEYS["project-profile"]),
            lock_resolvers=_policy(_KEYS["effective-profile-lock"]),
            semantic_authors=_roles().semantic_authors,
            semantic_reviewers=alias,
        )


@pytest.mark.parametrize("kind", tuple(_DOMAINS))
@pytest.mark.parametrize("signing_kind", tuple(_DOMAINS))
def test_five_role_matrix_rejects_cross_role_signatures(kind: str, signing_kind: str) -> None:
    """Only one of the five selected roles can sign each typed object kind.

    Parameters
    ----------
    kind : str
        Object kind whose domain and body digest are signed.
    signing_kind : str
        Role supplying the real Ed25519 signing key.
    """
    object_kind = cast(RuleObjectKind, kind)
    digest = rule_chain_v2_payload_digest(
        object_kind=object_kind, body_digest=_BODY, signed_at=_SIGNED_AT
    )
    signer = _KEYS[signing_kind]
    signature = RuleChainV2Signature.build(
        object_kind=object_kind,
        key_id=signer,
        body_digest=_BODY,
        signed_at=_SIGNED_AT,
        signature_hex=sign_message(signer, _DOMAINS[kind], digest),
    )
    assert signature.verify(
        body_digest=_BODY, roles=_roles(), now=datetime(2026, 9, 19, tzinfo=UTC)
    ) is (kind == signing_kind)


def test_role_store_rejects_wrong_key_versions_and_shared_identity() -> None:
    """Semantic roles need v2 seats; other roles retain the closed v1 wire."""
    roles = _roles()
    with pytest.raises(ValueError, match="semantic roles require v2"):
        RuleChainV2TrustRoles.build(
            pack_issuers=roles.pack_issuers,
            project_selectors=roles.project_selectors,
            lock_resolvers=roles.lock_resolvers,
            semantic_authors=roles.semantic_authors,
            semantic_reviewers=_policy("old-reviewer"),
        )
    with pytest.raises(ValueError, match="non-semantic roles require v1"):
        RuleChainV2TrustRoles.build(
            pack_issuers=_policy("new-pack", enrolled_identity="RIGOR-FOUNDRY/pack-seat"),
            project_selectors=roles.project_selectors,
            lock_resolvers=roles.lock_resolvers,
            semantic_authors=roles.semantic_authors,
            semantic_reviewers=roles.semantic_reviewers,
        )
    with pytest.raises(ValueError, match="identities must differ"):
        RuleChainV2TrustRoles.build(
            pack_issuers=roles.pack_issuers,
            project_selectors=roles.project_selectors,
            lock_resolvers=roles.lock_resolvers,
            semantic_authors=roles.semantic_authors,
            semantic_reviewers=_policy(
                "same-seat-reviewer", enrolled_identity="rigor-foundry/AUTHOR-1"
            ),
        )
