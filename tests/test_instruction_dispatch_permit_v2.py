# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — v2 dispatch permit wire tests
"""Exercise exact bound permit signatures before any host effect admission."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest
from signing_fixtures import public_key_hex, sign_message
from test_rule_chain_pack_v2 import _roles as chain_roles

from rigor_foundry.instruction_dispatch_permit_v2 import (
    PERMIT_V2_DOMAIN,
    DispatchPermitBodyV2,
    RuleChainV2PermitTrustRoles,
    SignedDispatchPermitV2,
)
from rigor_foundry.trust import TrustedPublicKey
from rigor_foundry.verification_policy import OfflineTrustPolicy, VerificationKeyPolicy

_KEY = "fixture-v2-permit-issuer"
_NOW = datetime(2026, 9, 23, 0, 12, tzinfo=UTC)
_PERMIT_ID = "01a09a66-7b5c-7a2e-93f0-b726808737d4"


def _body() -> dict[str, object]:
    """Return one exact five-minute synthetic decision-bound permit body."""
    return {
        "schema_version": "instruction-dispatch-permit.v2.1",
        "object_kind": "instruction-dispatch-permit",
        "signature_domain": PERMIT_V2_DOMAIN,
        "algorithm": "ed25519",
        "signer_role": "permit-issuer",
        "permit_id": _PERMIT_ID,
        "key_id": _KEY,
        "lock_digest": "1" * 64,
        "rule_projection_digest": "2" * 64,
        "request_digest": "3" * 64,
        "grant_snapshot_digest": "4" * 64,
        "current_state_proof_digest": "5" * 64,
        "adapter_custody_digest": "6" * 64,
        "route_digest": "7" * 64,
        "effect_target_digest": "8" * 64,
        "effect_operations_digest": "9" * 64,
        "operations_digest": "a" * 64,
        "issued_at": "2026-09-23T00:10:00Z",
        "not_before": "2026-09-23T00:10:00Z",
        "expires_at": "2026-09-23T00:15:00Z",
    }


def _signed() -> SignedDispatchPermitV2:
    """Sign a v2 candidate with a deterministic test-only Ed25519 key."""
    body = DispatchPermitBodyV2.from_dict(_body())
    return SignedDispatchPermitV2.build(
        body=body, signature_hex=sign_message(_KEY, PERMIT_V2_DOMAIN, body.payload_digest)
    )


def _policy(*, revoked_at: str = "", key_id: str = _KEY) -> OfflineTrustPolicy:
    """Choose one dedicated test issuer key and its lifecycle."""
    return OfflineTrustPolicy.build(
        (
            VerificationKeyPolicy.build(
                key=TrustedPublicKey.build(key_id=key_id, public_key_hex=public_key_hex(key_id)),
                valid_from="2026-09-23T00:00:00Z",
                valid_until="2026-10-01T00:00:00Z",
                revoked_at=revoked_at,
            ),
        )
    )


def _roles(*, revoked_at: str = "") -> RuleChainV2PermitTrustRoles:
    """Compose all six distinct test signing roles."""
    return RuleChainV2PermitTrustRoles.build(
        chain=chain_roles(), permit_issuers=_policy(revoked_at=revoked_at)
    )


def test_exact_v2_signature_round_trip_still_cannot_admit_an_effect() -> None:
    """A five-minute signed body verifies but exposes no dispatch authority."""
    signed = _signed()
    assert SignedDispatchPermitV2.from_dict(signed.to_dict()) == signed
    assert signed.verify_signature(roles=_roles(), now=_NOW)
    assert not hasattr(signed, "admit")
    assert not hasattr(signed, "consume")


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("schema_version", "1.0"),
        ("schema_version", "instruction-dispatch-permit.v2"),
        ("signature_domain", "rigor-foundry.instruction-dispatch-permit.v1"),
        ("signature_domain", "rigor-foundry.instruction-dispatch-permit.v2"),
        ("signer_role", "lock-resolver"),
        ("permit_id", "not-a-uuid"),
        ("permit_id", _PERMIT_ID.upper()),
        ("permit_id", "00000000-0000-0000-0000-000000000000"),
        ("permit_id", "ffffffff-ffff-ffff-ffff-ffffffffffff"),
        ("lock_digest", "invalid"),
        ("effect_operations_digest", "invalid"),
        ("operations_digest", "invalid"),
        ("not_before", "2026-09-23T00:15:00Z"),
        ("expires_at", "2026-09-23T00:10:00Z"),
        ("expires_at", "2026-09-23T00:15:01Z"),
        ("issued_at", "2026-09-23T00:10:01Z"),
        ("not_before", "2026-09-23T00:10:06Z"),
    ],
)
def test_wrong_domain_identity_digest_or_window_refuses(field: str, replacement: object) -> None:
    """A v1 domain, malformed nonce and over-long window cannot parse."""
    with pytest.raises(ValueError):
        DispatchPermitBodyV2.from_dict({**_body(), field: replacement})


def test_extra_and_missing_fields_refuse_without_defaults() -> None:
    """The signed body and envelope use exact v2 field sets."""
    with pytest.raises(ValueError):
        DispatchPermitBodyV2.from_dict({**_body(), "unknown": True})
    body = _body()
    del body["route_digest"]
    with pytest.raises(ValueError):
        DispatchPermitBodyV2.from_dict(body)
    for field in ("effect_operations_digest", "operations_digest"):
        body = _body()
        del body[field]
        with pytest.raises(ValueError):
            DispatchPermitBodyV2.from_dict(body)
    envelope = _signed().to_dict()
    envelope["policy_digest"] = "0" * 64
    with pytest.raises(ValueError):
        SignedDispatchPermitV2.from_dict(envelope)


def test_envelope_and_signature_tamper_refuse() -> None:
    """A valid body cannot borrow another signature or recomputed field."""
    signed = _signed()
    wire = signed.to_dict()
    wire["signature_hex"] = "0" * 128
    with pytest.raises(ValueError, match="envelope digest"):
        SignedDispatchPermitV2.from_dict(wire)
    forged = SignedDispatchPermitV2.build(
        body=signed.body,
        signature_hex=sign_message(
            _KEY, "rigor-foundry.instruction-dispatch-permit.v1", signed.body.payload_digest
        ),
    )
    assert not forged.verify_signature(roles=_roles(), now=_NOW)
    old_domain = SignedDispatchPermitV2.build(
        body=signed.body,
        signature_hex=sign_message(
            _KEY, "rigor-foundry.instruction-dispatch-permit.v2", signed.body.payload_digest
        ),
    )
    assert not old_domain.verify_signature(roles=_roles(), now=_NOW)
    assert not replace(signed, permit_digest="0" * 64).verify_signature(roles=_roles(), now=_NOW)
    with pytest.raises(ValueError, match="body digest"):
        replace(signed.body, payload_digest="0" * 64).to_dict()


@pytest.mark.parametrize(
    ("now", "revoked"),
    [
        (datetime(2026, 9, 23, 0, 9, tzinfo=UTC), ""),
        (datetime(2026, 9, 23, 0, 15, tzinfo=UTC), ""),
        (datetime(2026, 10, 1, tzinfo=UTC), ""),
        (datetime(2026, 9, 23, 0, 12), ""),
        (_NOW, "2026-09-23T00:11:00Z"),
        (_NOW, "2026-09-23T00:09:00Z"),
    ],
)
def test_host_selected_time_and_issuer_lifecycle_hold(now: datetime, revoked: str) -> None:
    """A signature outside the exact window or active key lifecycle refuses."""
    assert not _signed().verify_signature(roles=_roles(revoked_at=revoked), now=now)


def test_permit_issuer_key_cannot_be_a_lock_resolver_key() -> None:
    """Six-role composition refuses reused custody and signatures."""
    with pytest.raises(ValueError, match="distinct from chain roles"):
        RuleChainV2PermitTrustRoles.build(
            chain=chain_roles(), permit_issuers=_policy(key_id="v2-lock-resolver")
        )
    body = DispatchPermitBodyV2.from_dict({**_body(), "key_id": "v2-lock-resolver"})
    signed = SignedDispatchPermitV2.build(
        body=body,
        signature_hex=sign_message("v2-lock-resolver", PERMIT_V2_DOMAIN, body.payload_digest),
    )
    assert not signed.verify_signature(roles=_roles(), now=_NOW)


def test_forward_dated_issuance_cannot_become_stored_future_authority() -> None:
    """A signed future minting instant stays invalid at the current host time."""
    body = DispatchPermitBodyV2.from_dict(
        {
            **_body(),
            "issued_at": "2026-09-24T00:10:00Z",
            "not_before": "2026-09-24T00:10:00Z",
            "expires_at": "2026-09-24T00:15:00Z",
        }
    )
    signed = SignedDispatchPermitV2.build(
        body=body, signature_hex=sign_message(_KEY, PERMIT_V2_DOMAIN, body.payload_digest)
    )
    assert not signed.verify_signature(roles=_roles(), now=_NOW)
