# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — offline trust-policy tests
"""Prove lifecycle, revocation, alias, and policy-integrity boundaries."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from offline_verification_fixtures import trust_policy
from signing_fixtures import public_key_hex

from rigor_foundry.trust import TrustedPublicKey
from rigor_foundry.verification_policy import OfflineTrustPolicy, VerificationKeyPolicy


def key_policy(
    key_id: str = "key-a",
    *,
    valid_from: str = "2026-07-01T00:00:00Z",
    valid_until: str = "2026-08-01T00:00:00Z",
    revoked_at: str = "",
) -> VerificationKeyPolicy:
    """Return one deterministic lifecycle-bound key."""
    return VerificationKeyPolicy.build(
        key=TrustedPublicKey.build(key_id=key_id, public_key_hex=public_key_hex(key_id)),
        valid_from=valid_from,
        valid_until=valid_until,
        revoked_at=revoked_at,
    )


def test_key_lifecycle_round_trip_and_all_states() -> None:
    """Lifecycle evaluation distinguishes future, active, revoked, and expired keys."""
    active = key_policy()
    assert VerificationKeyPolicy.from_dict(active.to_dict()) == active
    assert active.status_at(datetime(2026, 6, 30, tzinfo=UTC)) == "not-yet-valid"
    assert active.status_at(datetime(2026, 7, 20, tzinfo=UTC)) == "active"
    assert active.status_at(datetime(2026, 8, 1, tzinfo=UTC)) == "expired"

    revoked = key_policy(revoked_at="2026-07-15T00:00:00Z")
    assert revoked.status_at(datetime(2026, 7, 15, tzinfo=UTC)) == "revoked"
    with pytest.raises(ValueError, match="timezone-aware"):
        active.status_at(datetime(2026, 7, 20))


@pytest.mark.parametrize(
    ("start", "end", "revoked", "message"),
    [
        ("2026-07-01T00:00:00Z", "2026-07-01T00:00:00Z", "", "follow"),
        ("2026-07-02T00:00:00Z", "2026-07-01T00:00:00Z", "", "follow"),
        (
            "2026-07-01T00:00:00Z",
            "2026-08-01T00:00:00Z",
            "2026-06-30T00:00:00Z",
            "within",
        ),
        (
            "2026-07-01T00:00:00Z",
            "2026-08-01T00:00:00Z",
            "2026-08-01T00:00:00Z",
            "within",
        ),
    ],
)
def test_key_lifecycle_rejects_inverted_or_outside_intervals(
    start: str,
    end: str,
    revoked: str,
    message: str,
) -> None:
    """Invalid validity and revocation intervals never enter a policy."""
    with pytest.raises(ValueError, match=message):
        key_policy(valid_from=start, valid_until=end, revoked_at=revoked)


def test_policy_round_trip_key_lookup_and_internal_consistency() -> None:
    """A policy rebuilds its cryptographic store and returns exact key states."""
    policy = OfflineTrustPolicy.build((key_policy("key-b"), key_policy("key-a")))
    assert tuple(item.key.key_id for item in policy.keys) == ("key-a", "key-b")
    assert OfflineTrustPolicy.from_dict(policy.to_dict()) == policy
    assert policy.key_status("missing", datetime(2026, 7, 20, tzinfo=UTC)) == "unknown"
    assert policy.key_status("key-a", datetime(2026, 7, 20, tzinfo=UTC)) == "active"
    assert tuple(item.key_id for item in policy.trust_store().keys) == ("key-a", "key-b")

    inconsistent = replace(policy, policy_digest="0" * 64)
    with pytest.raises(ValueError, match="internally inconsistent"):
        inconsistent.trust_store()


def test_policy_rejects_empty_duplicate_and_key_material_aliases() -> None:
    """Names cannot multiply or alias one cryptographic identity."""
    first = key_policy("key-a")
    with pytest.raises(ValueError, match="at least one"):
        OfflineTrustPolicy.build(())
    with pytest.raises(ValueError, match="unique"):
        OfflineTrustPolicy.build((first, first))
    alias = VerificationKeyPolicy.build(
        key=TrustedPublicKey.build(
            key_id="key-alias",
            public_key_hex=first.key.public_key_hex,
        ),
        valid_from=first.valid_from,
        valid_until=first.valid_until,
    )
    with pytest.raises(ValueError, match="public keys must be unique"):
        OfflineTrustPolicy.build((first, alias))


def test_policy_parsers_reject_schema_shape_array_and_digest_tampering() -> None:
    """Every policy envelope is strict and content-addressed."""
    key = key_policy()
    for mutation, message in (
        ({**key.to_dict(), "extra": True}, "fields"),
        ({**key.to_dict(), "schema_version": "2.0"}, "schema"),
        ({**key.to_dict(), "key_policy_digest": "0" * 64}, "digest"),
    ):
        with pytest.raises(ValueError, match=message):
            VerificationKeyPolicy.from_dict(mutation)

    policy = trust_policy()
    for mutation, message in (
        ({**policy.to_dict(), "extra": True}, "fields"),
        ({**policy.to_dict(), "schema_version": "2.0"}, "schema"),
        ({**policy.to_dict(), "keys": {}}, "array"),
        ({**policy.to_dict(), "policy_digest": "0" * 64}, "digest"),
    ):
        with pytest.raises(ValueError, match=message):
            OfflineTrustPolicy.from_dict(mutation)

    unsorted = policy.to_dict()
    assert isinstance(unsorted["keys"], list)
    unsorted["keys"].reverse()
    with pytest.raises(ValueError, match="sorted by key_id"):
        OfflineTrustPolicy.from_dict(unsorted)

    tampered_key = deepcopy(key.to_dict())
    tampered_key["revoked_at"] = "2026-07-20T00:00:00Z"
    with pytest.raises(ValueError, match="digest"):
        VerificationKeyPolicy.from_dict(tampered_key)
