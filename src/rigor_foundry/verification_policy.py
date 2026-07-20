# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — offline verification key lifecycle policy
"""Bind trusted public keys to explicit validity and revocation intervals."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from .model_primitives import parse_utc_timestamp, require_digest, require_utc_timestamp
from .models import canonical_digest, require_mapping, require_string
from .trust import TrustedPublicKey, VerificationTrustStore

OFFLINE_TRUST_POLICY_SCHEMA_VERSION = "1.0"
VERIFICATION_KEY_POLICY_SCHEMA_VERSION = "1.0"

KeyStatus = Literal["active", "unknown", "not-yet-valid", "expired", "revoked"]


@dataclass(frozen=True)
class VerificationKeyPolicy:
    """One trusted public key with an offline-verifiable lifecycle."""

    key: TrustedPublicKey
    valid_from: str
    valid_until: str
    revoked_at: str
    key_policy_digest: str

    @classmethod
    def build(
        cls,
        *,
        key: TrustedPublicKey,
        valid_from: str,
        valid_until: str,
        revoked_at: str = "",
    ) -> VerificationKeyPolicy:
        """Build one integrity-bound key lifecycle record."""
        rebuilt_key = TrustedPublicKey.from_dict(key.to_dict())
        start = require_utc_timestamp(valid_from, "verification key.valid_from")
        end = require_utc_timestamp(valid_until, "verification key.valid_until")
        start_time = parse_utc_timestamp(start, "verification key.valid_from")
        end_time = parse_utc_timestamp(end, "verification key.valid_until")
        if end_time <= start_time:
            raise ValueError("verification key.valid_until must follow valid_from")
        revoked = ""
        if revoked_at:
            revoked = require_utc_timestamp(revoked_at, "verification key.revoked_at")
            revoked_time = parse_utc_timestamp(revoked, "verification key.revoked_at")
            if not start_time <= revoked_time < end_time:
                raise ValueError("verification key.revoked_at must fall within its validity")
        fields: dict[str, object] = {
            "schema_version": VERIFICATION_KEY_POLICY_SCHEMA_VERSION,
            "key": rebuilt_key.to_dict(),
            "valid_from": start,
            "valid_until": end,
            "revoked_at": revoked,
        }
        return cls(
            key=rebuilt_key,
            valid_from=start,
            valid_until=end,
            revoked_at=revoked,
            key_policy_digest=canonical_digest(fields),
        )

    def status_at(self, instant: datetime) -> KeyStatus:
        """Return the key's lifecycle state at one timezone-aware instant."""
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise ValueError("verification time must be timezone-aware")
        start = parse_utc_timestamp(self.valid_from, "verification key.valid_from")
        end = parse_utc_timestamp(self.valid_until, "verification key.valid_until")
        if instant < start:
            return "not-yet-valid"
        if self.revoked_at and instant >= parse_utc_timestamp(
            self.revoked_at,
            "verification key.revoked_at",
        ):
            return "revoked"
        if instant >= end:
            return "expired"
        return "active"

    def to_dict(self) -> dict[str, object]:
        """Serialise one key lifecycle without private material."""
        return {
            "schema_version": VERIFICATION_KEY_POLICY_SCHEMA_VERSION,
            "key": self.key.to_dict(),
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "revoked_at": self.revoked_at,
            "key_policy_digest": self.key_policy_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> VerificationKeyPolicy:
        """Parse and integrity-check one key lifecycle record."""
        data = require_mapping(value, "verification key")
        expected = {
            "schema_version",
            "key",
            "valid_from",
            "valid_until",
            "revoked_at",
            "key_policy_digest",
        }
        if set(data) != expected:
            raise ValueError("verification key fields do not match the schema")
        if data.get("schema_version") != VERIFICATION_KEY_POLICY_SCHEMA_VERSION:
            raise ValueError("unsupported verification-key schema version")
        key_policy = cls.build(
            key=TrustedPublicKey.from_dict(data.get("key")),
            valid_from=require_string(data.get("valid_from"), "verification key.valid_from"),
            valid_until=require_string(data.get("valid_until"), "verification key.valid_until"),
            revoked_at=require_string(
                data.get("revoked_at"),
                "verification key.revoked_at",
                allow_empty=True,
            ),
        )
        if (
            require_digest(
                data.get("key_policy_digest"),
                "verification key.key_policy_digest",
            )
            != key_policy.key_policy_digest
        ):
            raise ValueError("verification-key policy digest does not match its content")
        return key_policy


@dataclass(frozen=True)
class OfflineTrustPolicy:
    """Caller-selected public keys and lifecycle state for offline verification."""

    keys: tuple[VerificationKeyPolicy, ...]
    policy_digest: str

    @classmethod
    def build(cls, keys: tuple[VerificationKeyPolicy, ...]) -> OfflineTrustPolicy:
        """Build a non-empty deterministic policy with unaliased key material."""
        if not keys:
            raise ValueError("offline trust policy must contain at least one key")
        rebuilt = tuple(VerificationKeyPolicy.from_dict(item.to_dict()) for item in keys)
        VerificationTrustStore.build(tuple(item.key for item in rebuilt))
        ordered = tuple(sorted(rebuilt, key=lambda item: item.key.key_id))
        fields: dict[str, object] = {
            "schema_version": OFFLINE_TRUST_POLICY_SCHEMA_VERSION,
            "keys": [item.to_dict() for item in ordered],
        }
        return cls(keys=ordered, policy_digest=canonical_digest(fields))

    def key_status(self, key_id: str, instant: datetime) -> KeyStatus:
        """Return one exact key identity's state without names-only trust."""
        matches = tuple(item for item in self.keys if item.key.key_id == key_id)
        if len(matches) != 1:
            return "unknown"
        return matches[0].status_at(instant)

    def trust_store(self) -> VerificationTrustStore:
        """Return the integrity-checked cryptographic store for this policy."""
        rebuilt = OfflineTrustPolicy.build(self.keys)
        if rebuilt != self:
            raise ValueError("offline trust policy is internally inconsistent")
        return VerificationTrustStore.build(tuple(item.key for item in self.keys))

    def to_dict(self) -> dict[str, object]:
        """Serialise the complete caller-selected offline trust policy."""
        return {
            "schema_version": OFFLINE_TRUST_POLICY_SCHEMA_VERSION,
            "keys": [item.to_dict() for item in self.keys],
            "policy_digest": self.policy_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> OfflineTrustPolicy:
        """Parse and integrity-check one offline trust policy."""
        data = require_mapping(value, "offline trust policy")
        if set(data) != {"schema_version", "keys", "policy_digest"}:
            raise ValueError("offline trust policy fields do not match the schema")
        if data.get("schema_version") != OFFLINE_TRUST_POLICY_SCHEMA_VERSION:
            raise ValueError("unsupported offline trust-policy schema version")
        raw_keys = data.get("keys")
        if not isinstance(raw_keys, list):
            raise ValueError("offline trust policy.keys must be an array")
        keys = tuple(VerificationKeyPolicy.from_dict(item) for item in raw_keys)
        if tuple(item.key.key_id for item in keys) != tuple(
            sorted(item.key.key_id for item in keys)
        ):
            raise ValueError("offline trust policy keys must be sorted by key_id")
        policy = cls.build(keys)
        recorded = require_digest(data.get("policy_digest"), "offline trust policy.policy_digest")
        if recorded != policy.policy_digest:
            raise ValueError("offline trust-policy digest does not match its content")
        return policy
