# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — explicit cryptographic trust stores
"""Verify detached Ed25519 signatures against integrity-bound public keys."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .model_primitives import require_digest, require_identifier
from .models import canonical_digest, require_mapping, require_string

ED25519_ALGORITHM = "ed25519"
ED25519_PUBLIC_KEY_HEX_LENGTH = 64
ED25519_SIGNATURE_HEX_LENGTH = 128
TRUST_STORE_SCHEMA_VERSION = "1.0"
ED25519_SIGNATURE_MESSAGE_VERSION: Final = "1.0"
ED25519_SIGNATURE_MESSAGE_PREFIX: Final = b"RIGOR-FOUNDRY-ED25519\x00v1\x00"
STANDARD_PACK_SIGNATURE_DOMAIN: Final = "rigor-foundry.standard-pack.v1"
REVIEW_ATTESTATION_SIGNATURE_DOMAIN: Final = "rigor-foundry.reviewer-attestation.v1"
_SIGNATURE_DOMAIN = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,126}[a-z0-9])?\Z")


def require_lower_hex(value: object, field: str, *, length: int) -> str:
    """Return exact-length lowercase hexadecimal text."""
    text = require_string(value, field)
    if len(text) != length or any(character not in "0123456789abcdef" for character in text):
        raise ValueError(f"{field} must be {length} lowercase hexadecimal characters")
    return text


def ed25519_signature_message(*, signature_domain: str, payload_digest: str) -> bytes:
    """Encode one versioned, domain-separated Ed25519 signing message."""
    domain = require_string(signature_domain, "signature.signature_domain")
    if _SIGNATURE_DOMAIN.fullmatch(domain) is None:
        raise ValueError("signature.signature_domain must be a canonical protocol domain")
    digest = require_digest(payload_digest, "signature.payload_digest")
    encoded_domain = domain.encode("ascii")
    return (
        ED25519_SIGNATURE_MESSAGE_PREFIX
        + len(encoded_domain).to_bytes(2, "big")
        + encoded_domain
        + bytes.fromhex(digest)
    )


@dataclass(frozen=True)
class TrustedPublicKey:
    """One explicitly trusted Ed25519 public key."""

    key_id: str
    algorithm: str
    public_key_hex: str
    key_digest: str

    @classmethod
    def build(
        cls,
        *,
        key_id: str,
        public_key_hex: str,
        algorithm: str = ED25519_ALGORITHM,
    ) -> TrustedPublicKey:
        """Build and integrity-bind a supported public key."""
        if algorithm != ED25519_ALGORITHM:
            raise ValueError("trusted key algorithm must be ed25519")
        fields = {
            "algorithm": algorithm,
            "key_id": require_identifier(key_id, "trusted_key.key_id"),
            "public_key_hex": require_lower_hex(
                public_key_hex,
                "trusted_key.public_key_hex",
                length=ED25519_PUBLIC_KEY_HEX_LENGTH,
            ),
        }
        return cls(
            key_id=fields["key_id"],
            algorithm=algorithm,
            public_key_hex=fields["public_key_hex"],
            key_digest=canonical_digest(fields),
        )

    def to_dict(self) -> dict[str, str]:
        """Serialise one trusted key without private material."""
        return {
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "public_key_hex": self.public_key_hex,
            "key_digest": self.key_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> TrustedPublicKey:
        """Parse and integrity-check one trusted key."""
        data = require_mapping(value, "trusted_key")
        key = cls.build(
            key_id=require_identifier(data.get("key_id"), "trusted_key.key_id"),
            algorithm=require_string(data.get("algorithm"), "trusted_key.algorithm"),
            public_key_hex=require_string(
                data.get("public_key_hex"),
                "trusted_key.public_key_hex",
            ),
        )
        if data.get("key_digest") != key.key_digest:
            raise ValueError("trusted-key digest does not match its content")
        return key


@dataclass(frozen=True)
class VerificationTrustStore:
    """Explicit set of public keys accepted for one verification boundary."""

    keys: tuple[TrustedPublicKey, ...]
    trust_store_digest: str

    @classmethod
    def build(cls, keys: tuple[TrustedPublicKey, ...]) -> VerificationTrustStore:
        """Build a non-empty, deterministic trust store with unique identities."""
        if not keys:
            raise ValueError("trust store must contain at least one public key")
        if any(
            TrustedPublicKey.build(
                key_id=item.key_id,
                algorithm=item.algorithm,
                public_key_hex=item.public_key_hex,
            )
            != item
            for item in keys
        ):
            raise ValueError("trust store contains an inconsistent public-key record")
        key_ids = tuple(item.key_id for item in keys)
        if len(key_ids) != len(set(key_ids)):
            raise ValueError("trust store key ids must be unique")
        public_keys = tuple(item.public_key_hex for item in keys)
        if len(public_keys) != len(set(public_keys)):
            raise ValueError("trust store public keys must be unique")
        ordered = tuple(sorted(keys, key=lambda item: item.key_id))
        fields: dict[str, object] = {
            "schema_version": TRUST_STORE_SCHEMA_VERSION,
            "keys": [item.to_dict() for item in ordered],
        }
        return cls(keys=ordered, trust_store_digest=canonical_digest(fields))

    def verify(
        self,
        *,
        key_id: str,
        algorithm: str,
        signature_domain: str,
        payload_digest: str,
        signature_hex: str,
    ) -> bool:
        """Return whether a trusted key signed the exact domain and payload digest."""
        try:
            if VerificationTrustStore.build(self.keys) != self:
                return False
        except ValueError:
            return False
        if algorithm != ED25519_ALGORITHM:
            return False
        try:
            message = ed25519_signature_message(
                signature_domain=signature_domain,
                payload_digest=payload_digest,
            )
            signature = require_lower_hex(
                signature_hex,
                "signature.signature_hex",
                length=ED25519_SIGNATURE_HEX_LENGTH,
            )
        except ValueError:
            return False
        matches = tuple(item for item in self.keys if item.key_id == key_id)
        if len(matches) != 1 or matches[0].algorithm != algorithm:
            return False
        try:
            public_key = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(matches[0].public_key_hex)
            )
            public_key.verify(bytes.fromhex(signature), message)
        except (InvalidSignature, ValueError):
            return False
        return True

    def to_dict(self) -> dict[str, object]:
        """Serialise the exact trusted public-key set."""
        return {
            "schema_version": TRUST_STORE_SCHEMA_VERSION,
            "keys": [item.to_dict() for item in self.keys],
            "trust_store_digest": self.trust_store_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> VerificationTrustStore:
        """Parse and integrity-check one trust store."""
        data = require_mapping(value, "trust_store")
        if data.get("schema_version") != TRUST_STORE_SCHEMA_VERSION:
            raise ValueError("unsupported trust-store schema version")
        raw_keys = data.get("keys")
        if not isinstance(raw_keys, list):
            raise ValueError("trust_store.keys must be an array")
        store = cls.build(tuple(TrustedPublicKey.from_dict(item) for item in raw_keys))
        if data.get("trust_store_digest") != store.trust_store_digest:
            raise ValueError("trust-store digest does not match its content")
        return store
