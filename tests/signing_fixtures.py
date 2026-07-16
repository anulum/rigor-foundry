# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — deterministic test-only signing helpers
"""Create deterministic Ed25519 fixtures without shipping private production keys."""

from __future__ import annotations

from hashlib import sha256

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from rigor_foundry.standard_pack import PackSignature
from rigor_foundry.trust import (
    STANDARD_PACK_SIGNATURE_DOMAIN,
    TrustedPublicKey,
    VerificationTrustStore,
    ed25519_signature_message,
)


def private_key(key_id: str) -> Ed25519PrivateKey:
    """Derive one deterministic test-only private key from its fixture identity."""
    seed = sha256(f"rigor-foundry-test-key:{key_id}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_hex(key_id: str) -> str:
    """Return the raw public key for one deterministic fixture identity."""
    raw = (
        private_key(key_id)
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    return raw.hex()


def trust_store(*key_ids: str) -> VerificationTrustStore:
    """Return an explicit trust store for deterministic fixture keys."""
    return VerificationTrustStore.build(
        tuple(
            TrustedPublicKey.build(key_id=key_id, public_key_hex=public_key_hex(key_id))
            for key_id in key_ids
        )
    )


def sign_message(key_id: str, signature_domain: str, payload_digest: str) -> str:
    """Sign one domain-separated fixture message with a deterministic key."""
    message = ed25519_signature_message(
        signature_domain=signature_domain,
        payload_digest=payload_digest,
    )
    return private_key(key_id).sign(message).hex()


def pack_signature(payload_digest: str, key_id: str = "trusted-key") -> PackSignature:
    """Return an actual detached pack signature for one fixture payload."""
    return PackSignature.build(
        key_id=key_id,
        payload_digest=payload_digest,
        signature_hex=sign_message(key_id, STANDARD_PACK_SIGNATURE_DOMAIN, payload_digest),
    )
