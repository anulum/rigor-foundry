# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — cryptographic trust-store tests
"""Prove real Ed25519 verification and fail-closed trust-store parsing."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest
from signing_fixtures import public_key_hex, sign_digest, trust_store

from rigor_foundry.trust import TrustedPublicKey, VerificationTrustStore


def test_trust_store_round_trip_and_real_signature_verification() -> None:
    """Only the trusted key's real signature verifies for exact digest bytes."""
    store = trust_store("release-key")
    payload = "a" * 64
    signature = sign_digest("release-key", payload)
    assert store.verify(
        key_id="release-key",
        algorithm="ed25519",
        payload_digest=payload,
        signature_hex=signature,
    )
    assert VerificationTrustStore.from_dict(store.to_dict()) == store
    assert TrustedPublicKey.from_dict(store.keys[0].to_dict()) == store.keys[0]


@pytest.mark.parametrize(
    ("key_id", "algorithm", "payload", "signature"),
    [
        ("unknown-key", "ed25519", "a" * 64, sign_digest("release-key", "a" * 64)),
        ("release-key", "rsa", "a" * 64, sign_digest("release-key", "a" * 64)),
        ("release-key", "ed25519", "b" * 64, sign_digest("release-key", "a" * 64)),
        ("release-key", "ed25519", "a" * 64, "0" * 128),
        ("release-key", "ed25519", "not-a-digest", "0" * 128),
    ],
)
def test_unknown_key_tampering_and_fabricated_signature_never_verify(
    key_id: str,
    algorithm: str,
    payload: str,
    signature: str,
) -> None:
    """Names, labels, malformed data, and invented bytes cannot establish trust."""
    assert not trust_store("release-key").verify(
        key_id=key_id,
        algorithm=algorithm,
        payload_digest=payload,
        signature_hex=signature,
    )


def test_trust_store_rejects_duplicate_ids_tampering_and_unsupported_keys() -> None:
    """The trust boundary rejects duplicate identities and key-material aliases."""
    key = TrustedPublicKey.build(
        key_id="release-key",
        public_key_hex=public_key_hex("release-key"),
    )
    alias = TrustedPublicKey.build(
        key_id="release-key-alias",
        public_key_hex=key.public_key_hex,
    )
    with pytest.raises(ValueError, match="at least one"):
        VerificationTrustStore.build(())
    with pytest.raises(ValueError, match="unique"):
        VerificationTrustStore.build((key, key))
    with pytest.raises(ValueError, match="public keys must be unique"):
        VerificationTrustStore.build((key, alias))
    alias_payload = {
        "schema_version": "1.0",
        "keys": [key.to_dict(), alias.to_dict()],
        "trust_store_digest": "0" * 64,
    }
    with pytest.raises(ValueError, match="public keys must be unique"):
        VerificationTrustStore.from_dict(alias_payload)
    with pytest.raises(ValueError, match="ed25519"):
        TrustedPublicKey.build(
            key_id="release-key",
            algorithm="rsa",
            public_key_hex=public_key_hex("release-key"),
        )
    tampered = deepcopy(trust_store("release-key").to_dict())
    tampered["trust_store_digest"] = "0" * 64
    with pytest.raises(ValueError, match="trust-store digest"):
        VerificationTrustStore.from_dict(tampered)
    forged_store = replace(trust_store("release-key"), trust_store_digest="0" * 64)
    assert not forged_store.verify(
        key_id="release-key",
        algorithm="ed25519",
        payload_digest="a" * 64,
        signature_hex=sign_digest("release-key", "a" * 64),
    )
