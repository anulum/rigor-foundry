# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — dispatch permit role separation
"""Exercise six-role separation with actual Ed25519 policies and signatures."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from signing_fixtures import public_key_hex, sign_message
from test_instruction_dispatch_permit_v2 import _NOW, _body, _roles, _signed
from test_rule_chain_pack_v2 import _roles as chain_roles

from rigor_foundry.instruction_dispatch_permit_v2 import (
    PERMIT_V2_DECISION_FIELDS,
    PERMIT_V2_DOMAIN,
    DispatchPermitBodyV2,
    RuleChainV2PermitTrustRoles,
    SignedDispatchPermitV2,
)
from rigor_foundry.trust import TrustedPublicKey
from rigor_foundry.verification_policy import OfflineTrustPolicy, VerificationKeyPolicy


def _reused_policy(source_key: str, *, alias: bool) -> OfflineTrustPolicy:
    """Enroll a chain key under its own ID or a different permit ID."""
    return OfflineTrustPolicy.build(
        (
            VerificationKeyPolicy.build(
                key=TrustedPublicKey.build(
                    key_id="permit-material-alias" if alias else source_key,
                    public_key_hex=public_key_hex(source_key),
                ),
                valid_from="2026-09-01T00:00:00Z",
                valid_until="2026-10-01T00:00:00Z",
            ),
        )
    )


@pytest.mark.parametrize(
    "source_key",
    [
        "v2-pack-issuer",
        "v2-project-selector",
        "v2-lock-resolver",
        "v2-semantic-author",
        "v2-semantic-reviewer",
    ],
)
@pytest.mark.parametrize("alias", [False, True], ids=["same-id", "same-material"])
def test_every_chain_role_is_distinct_from_permit_issuer(source_key: str, alias: bool) -> None:
    """Neither an existing role ID nor aliased key bytes can issue permits."""
    with pytest.raises(ValueError, match="distinct from chain roles"):
        RuleChainV2PermitTrustRoles.build(
            chain=chain_roles(), permit_issuers=_reused_policy(source_key, alias=alias)
        )


@pytest.mark.parametrize("alias", [False, True], ids=["same-id", "same-material"])
def test_semantic_author_signature_cannot_bypass_role_builder(alias: bool) -> None:
    """Verification rebuilds directly constructed roles before trusting a signature."""
    key_id = "permit-material-alias" if alias else "v2-semantic-author"
    body = DispatchPermitBodyV2.from_dict({**_body(), "key_id": key_id})
    signed = SignedDispatchPermitV2.build(
        body=body,
        signature_hex=sign_message("v2-semantic-author", PERMIT_V2_DOMAIN, body.payload_digest),
    )
    direct_roles = RuleChainV2PermitTrustRoles(
        chain_roles(), _reused_policy("v2-semantic-author", alias=alias)
    )
    assert not signed.verify_signature(roles=direct_roles, now=_NOW)


def test_dedicated_sixth_role_remains_valid() -> None:
    """Separating the permit issuer preserves actual valid candidate verification."""
    assert _signed().verify_signature(roles=_roles(), now=_NOW)


@pytest.mark.parametrize("field", sorted(PERMIT_V2_DECISION_FIELDS))
def test_signature_binds_every_decision_digest(field: str) -> None:
    """Rebuilding coherent digests cannot transfer a signature to another decision."""
    signed = _signed()
    changed_body = DispatchPermitBodyV2.from_dict({**signed.body.to_dict(), field: "b" * 64})
    changed = SignedDispatchPermitV2.build(body=changed_body, signature_hex=signed.signature_hex)
    assert changed.body.payload_digest != signed.body.payload_digest
    assert SignedDispatchPermitV2.from_dict(changed.to_dict()) == changed
    assert not changed.verify_signature(roles=_roles(), now=_NOW)


def test_non_utc_caller_time_refuses_even_for_the_same_instant() -> None:
    """The caller must supply UTC, including when an offset represents a valid instant."""
    offset_time = _NOW.astimezone(timezone(timedelta(hours=1)))
    assert offset_time == _NOW
    assert not _signed().verify_signature(roles=_roles(), now=offset_time)


@pytest.mark.parametrize("skew_seconds", [0, 5])
def test_inclusive_start_and_maximum_window_verify(skew_seconds: int) -> None:
    """Both legal issuance skew endpoints permit a full 300-second window."""
    start = datetime(2026, 9, 23, 0, 10, tzinfo=UTC) + timedelta(seconds=skew_seconds)
    end = start + timedelta(seconds=300)
    body = DispatchPermitBodyV2.from_dict(
        {
            **_body(),
            "not_before": start.isoformat().replace("+00:00", "Z"),
            "expires_at": end.isoformat().replace("+00:00", "Z"),
        }
    )
    signed = SignedDispatchPermitV2.build(
        body=body,
        signature_hex=sign_message(
            "fixture-v2-permit-issuer", PERMIT_V2_DOMAIN, body.payload_digest
        ),
    )
    assert signed.verify_signature(roles=_roles(), now=start)
    assert signed.verify_signature(roles=_roles(), now=end - timedelta(microseconds=1))
    assert not signed.verify_signature(roles=_roles(), now=end)
