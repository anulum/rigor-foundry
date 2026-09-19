# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — typed rule-chain signature boundaries
"""Authenticate typed v2 rule-chain payload digests without granting effects."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Final, Literal, cast

from .audit_primitives import require_exact_fields
from .model_primitives import (
    parse_utc_timestamp,
    require_digest,
    require_identifier,
    require_utc_timestamp,
)
from .models import canonical_digest, require_mapping, require_string
from .trust import (
    ED25519_ALGORITHM,
    ED25519_SIGNATURE_HEX_LENGTH,
    require_lower_hex,
)
from .verification_policy import OfflineTrustPolicy

RULE_CHAIN_V2_SCHEMA_VERSION: Final = "2.0"
RuleObjectKind = Literal["standard-pack", "project-profile", "effective-profile-lock"]
SignerRole = Literal["pack-issuer", "project-selector", "lock-resolver"]

_KIND_BOUNDARIES: Final[dict[str, tuple[SignerRole, str]]] = {
    "standard-pack": ("pack-issuer", "rigor-foundry.standard-pack.v2"),
    "project-profile": ("project-selector", "rigor-foundry.project-profile-selection.v2"),
    "effective-profile-lock": ("lock-resolver", "rigor-foundry.effective-profile-lock.v2"),
}
_SIGNATURE_FIELDS: Final = frozenset(
    {
        "schema_version",
        "object_kind",
        "algorithm",
        "signer_role",
        "signature_domain",
        "key_id",
        "body_digest",
        "signed_at",
        "payload_digest",
        "signature_hex",
        "signature_digest",
    }
)


def _boundary(kind: object) -> tuple[RuleObjectKind, SignerRole, str]:
    """Resolve exactly one supported object type, signer role and domain."""
    name = require_string(kind, "rule_signature.object_kind")
    if name not in _KIND_BOUNDARIES:
        raise ValueError("unsupported rule-chain v2 object kind")
    role, domain = _KIND_BOUNDARIES[name]
    return cast(RuleObjectKind, name), role, domain


def rule_chain_v2_payload_digest(
    *, object_kind: RuleObjectKind, body_digest: str, signed_at: str
) -> str:
    """Bind a typed v2 body digest and signing time before Ed25519 signing.

    The body must first pass its own exact versioned parser. This function
    cannot admit a rule, select a profile, create a lock or grant dispatch.
    """
    kind, _, domain = _boundary(object_kind)
    return canonical_digest(
        {
            "schema_version": RULE_CHAIN_V2_SCHEMA_VERSION,
            "object_kind": kind,
            "signature_domain": domain,
            "body_digest": require_digest(body_digest, "rule_signature.body_digest"),
            "signed_at": require_utc_timestamp(signed_at, "rule_signature.signed_at"),
        }
    )


@dataclass(frozen=True)
class RuleChainV2TrustRoles:
    """Separate lifecycle-aware verification policies for four signing roles."""

    pack_issuers: OfflineTrustPolicy
    project_selectors: OfflineTrustPolicy
    lock_resolvers: OfflineTrustPolicy
    semantic_reviewers: OfflineTrustPolicy

    @classmethod
    def build(
        cls,
        *,
        pack_issuers: OfflineTrustPolicy,
        project_selectors: OfflineTrustPolicy,
        lock_resolvers: OfflineTrustPolicy,
        semantic_reviewers: OfflineTrustPolicy,
    ) -> RuleChainV2TrustRoles:
        """Refuse key-id or public-key reuse across signing roles."""
        policies = tuple(
            OfflineTrustPolicy.from_dict(item.to_dict())
            for item in (pack_issuers, project_selectors, lock_resolvers, semantic_reviewers)
        )
        keys = tuple(key.key for policy in policies for key in policy.keys)
        if len({key.key_id for key in keys}) != len(keys):
            raise ValueError("rule-chain signer key ids must be distinct across roles")
        if len({key.public_key_hex for key in keys}) != len(keys):
            raise ValueError("rule-chain signer public keys must be distinct across roles")
        return cls(*policies)

    def policy_for(self, object_kind: RuleObjectKind) -> OfflineTrustPolicy:
        """Return only the policy assigned to the exact signed object type."""
        kind, _, _ = _boundary(object_kind)
        if kind == "standard-pack":
            return self.pack_issuers
        if kind == "project-profile":
            return self.project_selectors
        return self.lock_resolvers


@dataclass(frozen=True)
class RuleChainV2Signature:
    """Detached signature over one typed body, not a policy admission receipt."""

    object_kind: RuleObjectKind
    algorithm: str
    signer_role: SignerRole
    signature_domain: str
    key_id: str
    body_digest: str
    signed_at: str
    payload_digest: str
    signature_hex: str
    signature_digest: str

    @classmethod
    def build(
        cls,
        *,
        object_kind: RuleObjectKind,
        key_id: str,
        body_digest: str,
        signed_at: str,
        signature_hex: str,
    ) -> RuleChainV2Signature:
        """Validate metadata for actual detached Ed25519 signature bytes."""
        kind, role, domain = _boundary(object_kind)
        body = require_digest(body_digest, "rule_signature.body_digest")
        instant = require_utc_timestamp(signed_at, "rule_signature.signed_at")
        signature = require_lower_hex(
            signature_hex,
            "rule_signature.signature_hex",
            length=ED25519_SIGNATURE_HEX_LENGTH,
        )
        return cls(
            object_kind=kind,
            algorithm=ED25519_ALGORITHM,
            signer_role=role,
            signature_domain=domain,
            key_id=require_identifier(key_id, "rule_signature.key_id"),
            body_digest=body,
            signed_at=instant,
            payload_digest=rule_chain_v2_payload_digest(
                object_kind=kind, body_digest=body, signed_at=instant
            ),
            signature_hex=signature,
            signature_digest=sha256(bytes.fromhex(signature)).hexdigest(),
        )

    def to_dict(self) -> dict[str, str]:
        """Serialise the exact v2 signature metadata."""
        return {
            "schema_version": RULE_CHAIN_V2_SCHEMA_VERSION,
            "object_kind": self.object_kind,
            "algorithm": self.algorithm,
            "signer_role": self.signer_role,
            "signature_domain": self.signature_domain,
            "key_id": self.key_id,
            "body_digest": self.body_digest,
            "signed_at": self.signed_at,
            "payload_digest": self.payload_digest,
            "signature_hex": self.signature_hex,
            "signature_digest": self.signature_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> RuleChainV2Signature:
        """Reject unknown fields, wrong versions and recomputed-digest aliases."""
        data = require_mapping(value, "rule signature")
        require_exact_fields(data, _SIGNATURE_FIELDS, "rule-chain v2 signature")
        if data.get("schema_version") != RULE_CHAIN_V2_SCHEMA_VERSION:
            raise ValueError("unsupported rule-chain signature schema version")
        kind, role, domain = _boundary(data.get("object_kind"))
        if data.get("algorithm") != ED25519_ALGORITHM:
            raise ValueError("rule-chain signature algorithm must be ed25519")
        if data.get("signer_role") != role or data.get("signature_domain") != domain:
            raise ValueError("rule-chain signer role or domain does not match object kind")
        signature = cls.build(
            object_kind=kind,
            key_id=require_identifier(data.get("key_id"), "rule_signature.key_id"),
            body_digest=require_digest(data.get("body_digest"), "rule_signature.body_digest"),
            signed_at=require_utc_timestamp(data.get("signed_at"), "rule_signature.signed_at"),
            signature_hex=require_string(
                data.get("signature_hex"), "rule_signature.signature_hex"
            ),
        )
        if data.get("payload_digest") != signature.payload_digest:
            raise ValueError("rule-chain payload digest does not match typed body")
        if data.get("signature_digest") != signature.signature_digest:
            raise ValueError("rule-chain signature digest does not match signature bytes")
        return signature

    def verify(
        self,
        *,
        body_digest: str,
        roles: RuleChainV2TrustRoles,
        now: datetime,
    ) -> bool:
        """Verify exact bytes, role, domain and current signing-key lifecycle.

        A true result proves only authenticity of the caller-validated body
        digest. It does not resolve semantics or authorize an effect.
        """
        try:
            signature = RuleChainV2Signature.from_dict(self.to_dict())
            if signature != self or body_digest != signature.body_digest:
                return False
            validated_roles = RuleChainV2TrustRoles.build(
                pack_issuers=roles.pack_issuers,
                project_selectors=roles.project_selectors,
                lock_resolvers=roles.lock_resolvers,
                semantic_reviewers=roles.semantic_reviewers,
            )
            if (
                validated_roles != roles
                or now.tzinfo is None
                or now.utcoffset() != UTC.utcoffset(now)
            ):
                return False
            policy = roles.policy_for(signature.object_kind)
            signed_at = parse_utc_timestamp(signature.signed_at, "rule_signature.signed_at")
            if (
                signed_at > now
                or policy.key_status(signature.key_id, signed_at) != "active"
                or policy.key_status(signature.key_id, now) != "active"
            ):
                return False
            return policy.trust_store().verify(
                key_id=signature.key_id,
                algorithm=ED25519_ALGORITHM,
                signature_domain=signature.signature_domain,
                payload_digest=signature.payload_digest,
                signature_hex=signature.signature_hex,
            )
        except (TypeError, ValueError):
            return False
