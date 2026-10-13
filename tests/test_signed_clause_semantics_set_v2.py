# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — dual-signed clause semantics set tests
"""Exercise the exact public body and two real Ed25519 signing boundaries."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone

import pytest
from signing_fixtures import sign_message
from test_clause_semantics_set_v2 import _body
from test_signed_rule_chain_v2 import _DOMAINS, _KEYS, _policy, _roles

from rigor_foundry.clause_semantics_set_v2 import ClauseSemanticsSetV2
from rigor_foundry.effect_journal_records_v2 import canonical_journal_json_v2
from rigor_foundry.signed_clause_semantics_set_v2 import SignedClauseSemanticsSetV2
from rigor_foundry.signed_rule_chain_v2 import (
    RuleChainV2Signature,
    RuleObjectKind,
    rule_chain_v2_payload_digest,
)
from rigor_foundry.verification_policy import OfflineTrustPolicy, VerificationKeyPolicy

_NOW = datetime(2026, 9, 19, tzinfo=UTC)


def _signature(kind: RuleObjectKind, body_digest: str, signed_at: str) -> RuleChainV2Signature:
    """Sign one exact body with its enrolled author or reviewer key."""
    signer = _KEYS[kind]
    payload = rule_chain_v2_payload_digest(
        object_kind=kind, body_digest=body_digest, signed_at=signed_at
    )
    return RuleChainV2Signature.build(
        object_kind=kind,
        key_id=signer,
        body_digest=body_digest,
        signed_at=signed_at,
        signature_hex=sign_message(signer, _DOMAINS[kind], payload),
    )


def _set(
    *, author_at: str = "2026-09-12T00:00:00Z", reviewer_at: str = "2026-09-12T01:00:00Z"
) -> SignedClauseSemanticsSetV2:
    """Build one real dual-signed canonical body through the bytes parser."""
    body_bytes = canonical_journal_json_v2(_body())
    digest = ClauseSemanticsSetV2.from_bytes(body_bytes).body_digest
    return SignedClauseSemanticsSetV2.from_bytes(
        body_bytes=body_bytes,
        author_signature=_signature("clause-semantics-set-author", digest, author_at).to_dict(),
        reviewer_signature=_signature("clause-semantics-set", digest, reviewer_at).to_dict(),
    )


def test_dual_signature_verifies_exact_body_and_distinct_seats() -> None:
    """One real author signature followed by one independent review verifies."""
    signed = _set()
    assert signed.verify(roles=_roles(), now=_NOW)
    assert signed.author.body_digest == signed.reviewer.body_digest == signed.body.body_digest


def test_wrong_kind_or_body_refuses_at_parse() -> None:
    """An author cannot borrow the reviewer's object kind or another body."""
    signed = _set()
    with pytest.raises(ValueError, match="exact typed body"):
        SignedClauseSemanticsSetV2.from_bytes(
            body_bytes=signed.body.body_bytes,
            author_signature=signed.reviewer.to_dict(),
            reviewer_signature=signed.reviewer.to_dict(),
        )
    changed = _body()
    changed["scope_digest"] = "f" * 64
    with pytest.raises(ValueError, match="exact typed body"):
        SignedClauseSemanticsSetV2.from_bytes(
            body_bytes=canonical_journal_json_v2(changed),
            author_signature=signed.author.to_dict(),
            reviewer_signature=signed.reviewer.to_dict(),
        )


def test_signing_order_and_key_revocation_refuse() -> None:
    """A review before authorship or a key revoked before recheck fails closed."""
    assert not _set(author_at="2026-09-12T02:00:00Z", reviewer_at="2026-09-12T01:00:00Z").verify(
        roles=_roles(), now=_NOW
    )
    roles = _roles()
    changed = replace(
        roles,
        semantic_authors=_policy(
            _KEYS["clause-semantics-set-author"],
            revoked_at="2026-09-18T00:00:00Z",
            enrolled_identity="RIGOR-FOUNDRY/author-1",
        ),
    )
    assert not _set().verify(roles=changed, now=_NOW)


def test_changed_signature_or_inconsistent_body_refuses() -> None:
    """Forged cryptographic bytes or a forged in-memory body never verify."""
    signed = _set()
    forged = replace(signed, reviewer=replace(signed.reviewer, signature_hex="0" * 128))
    assert not forged.verify(roles=_roles(), now=_NOW)
    changed_body = replace(signed, body=ClauseSemanticsSetV2(signed.body.body_bytes, "0" * 64))
    assert not changed_body.verify(roles=_roles(), now=_NOW)


def test_role_policy_change_or_unknown_key_refuses() -> None:
    """A caller cannot replace selected role policy or key identity after signing."""
    signed = _set()
    roles = _roles()
    bad_roles = replace(
        roles,
        semantic_reviewers=_policy("other-reviewer", enrolled_identity="RIGOR-FOUNDRY/reviewer-1"),
    )
    assert not signed.verify(roles=bad_roles, now=_NOW)
    wrong = replace(signed, author=replace(signed.author, key_id="unknown"))
    assert not wrong.verify(roles=roles, now=_NOW)


def test_unparseable_signature_envelope_refuses() -> None:
    """A partial detached signature cannot stand in for one signed set."""
    signed = _set()
    wire = signed.author.to_dict()
    del wire["signature_hex"]
    with pytest.raises(ValueError):
        SignedClauseSemanticsSetV2.from_bytes(
            body_bytes=signed.body.body_bytes,
            author_signature=wire,
            reviewer_signature=signed.reviewer.to_dict(),
        )


@pytest.mark.parametrize("role", ("semantic_authors", "semantic_reviewers"))
@pytest.mark.parametrize("fault", ("expired", "revoked", "not-yet-valid"))
def test_each_signer_lifecycle_is_checked_independently(role: str, fault: str) -> None:
    """Refuse one ineligible semantic key while all other roles remain valid.

    Parameters
    ----------
    role : str
        Author or reviewer policy changed independently of the other policies.
    fault : str
        Lifecycle condition preventing signing or current verification.
    """
    roles = _roles()
    original = roles.semantic_authors if role == "semantic_authors" else roles.semantic_reviewers
    key = original.keys[0]
    changed_key = VerificationKeyPolicy.build(
        key=key.key,
        valid_from="2026-09-13T00:00:00Z" if fault == "not-yet-valid" else key.valid_from,
        valid_until="2026-09-18T00:00:00Z" if fault == "expired" else key.valid_until,
        revoked_at="2026-09-18T00:00:00Z" if fault == "revoked" else "",
        enrolled_identity=key.enrolled_identity,
    )
    changed_policy = OfflineTrustPolicy.build((changed_key,))
    changed = (
        replace(roles, semantic_authors=changed_policy)
        if role == "semantic_authors"
        else replace(roles, semantic_reviewers=changed_policy)
    )
    assert _set().verify(roles=roles, now=_NOW)
    assert not _set().verify(roles=changed, now=_NOW)


@pytest.mark.parametrize(
    "now",
    (
        datetime(2026, 9, 19),
        datetime(2026, 9, 19, tzinfo=timezone(timedelta(hours=1))),
        datetime(2026, 9, 11, tzinfo=UTC),
    ),
)
def test_verification_requires_utc_and_no_future_signature(now: datetime) -> None:
    """Fail closed for ambiguous verification time or signatures from its future.

    Parameters
    ----------
    now : datetime
        Naive, non-UTC or earlier-than-signing verification instant.
    """
    assert not _set().verify(roles=_roles(), now=now)
