# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — typed v3 rule-chain signature primitive
"""Authenticate typed body digests under exact selected v3 role policies."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256

from .audit_primitives import require_exact_fields
from .model_primitives import (
    parse_utc_timestamp,
    require_digest,
    require_identifier,
    require_utc_timestamp,
)
from .models import canonical_digest, require_mapping, require_string
from .policy_model_inputs import policy_wire_size
from .policy_read_budget import PolicyReadBudget1
from .rule_chain_trust_v3 import (
    RuleObjectKindV3,
    SignerRoleV3,
    TrustRolesV3,
    rule_chain_v3_signature_boundary,
)
from .trust import ED25519_ALGORITHM, ED25519_SIGNATURE_HEX_LENGTH, require_lower_hex

RULE_CHAIN_V3_SCHEMA_VERSION = "3.0"
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "body_schema_version",
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


def rule_chain_v3_payload_digest(
    *,
    object_kind: RuleObjectKindV3,
    body_schema_version: str,
    body_digest: str,
    signed_at: str,
) -> str:
    """Bind the exact supported type, body version, domain, digest and UTC time.

    Parameters
    ----------
    object_kind : RuleObjectKindV3
        Signature kind from the closed five-role table.
    body_schema_version : str
        Exact owning body version: 3.0 for parents, 1.0 for corpus acceptance.
    body_digest : str
        Canonical digest already checked by the owning body parser.
    signed_at : str
        Exact UTC timestamp included in the signed payload.

    Returns
    -------
    str
        Canonical payload digest for domain-separated Ed25519 signing.

    Raises
    ------
    ValueError
        The kind, version, digest or timestamp is unsupported or malformed.
    """
    kind, version, _, domain = rule_chain_v3_signature_boundary(object_kind)
    if body_schema_version != version:
        raise ValueError("v3 signature body schema differs from its object kind")
    return canonical_digest(
        {
            "schema_version": RULE_CHAIN_V3_SCHEMA_VERSION,
            "object_kind": kind,
            "body_schema_version": version,
            "signature_domain": domain,
            "body_digest": require_digest(body_digest, "v3 signature body digest"),
            "signed_at": require_utc_timestamp(signed_at, "v3 signature signed_at"),
        }
    )


@dataclass(frozen=True)
class RuleChainV3Signature:
    """A bounded detached signature primitive, separate from body admission.

    Owning pack/profile/lock/corpus consumers must first reparse their actual
    complete body and independently select its expected kind and policy digest.
    This primitive proves authenticity of that typed digest only; it supplies
    no competent semantic acceptance, host selection or permission.
    """

    object_kind: RuleObjectKindV3
    body_schema_version: str
    algorithm: str
    signer_role: SignerRoleV3
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
        object_kind: RuleObjectKindV3,
        body_schema_version: str,
        key_id: str,
        body_digest: str,
        signed_at: str,
        signature_hex: str,
        budget: PolicyReadBudget1,
    ) -> RuleChainV3Signature:
        """Construct exact metadata for supplied actual Ed25519 signature bytes.

        Parameters
        ----------
        object_kind : RuleObjectKindV3
            Exact signature kind from the five-role table.
        body_schema_version, key_id, body_digest, signed_at, signature_hex : str
            Owning body version, key identity, canonical body digest, UTC time
            and 128 lowercase hexadecimal signature characters.
        budget : PolicyReadBudget1
            Explicit original document byte/depth limits.

        Returns
        -------
        RuleChainV3Signature
            Integrity-checked metadata. Construction does not verify the key.

        Raises
        ------
        ValueError
            Metadata is malformed, unsupported or exceeds the explicit budget.
        """
        kind, _, role, domain = rule_chain_v3_signature_boundary(object_kind)
        instant = require_utc_timestamp(signed_at, "v3 signature signed_at")
        payload = rule_chain_v3_payload_digest(
            object_kind=kind,
            body_schema_version=body_schema_version,
            body_digest=body_digest,
            signed_at=instant,
        )
        raw = require_lower_hex(
            signature_hex, "v3 signature bytes", length=ED25519_SIGNATURE_HEX_LENGTH
        )
        result = cls(
            kind,
            body_schema_version,
            ED25519_ALGORITHM,
            role,
            domain,
            require_identifier(key_id, "v3 signature key id"),
            body_digest,
            instant,
            payload,
            raw,
            sha256(bytes.fromhex(raw)).hexdigest(),
        )
        result.to_dict(budget=budget)
        return result

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, str]:
        """Serialize and revalidate all fields, including directly constructed data.

        Parameters
        ----------
        budget : PolicyReadBudget1
            Explicit byte/depth limits applied to the complete wire record.

        Returns
        -------
        dict[str, str]
            The exact twelve fields, with signature schema 3.0.

        Raises
        ------
        ValueError
            A role, version, domain, algorithm or recorded digest is inconsistent.
        """
        _, _, role, domain = rule_chain_v3_signature_boundary(self.object_kind)
        instant = require_utc_timestamp(self.signed_at, "v3 signature signed_at")
        if self.signed_at != instant:
            raise ValueError("v3 signature direct timestamp must use canonical UTC")
        payload = rule_chain_v3_payload_digest(
            object_kind=self.object_kind,
            body_schema_version=self.body_schema_version,
            body_digest=self.body_digest,
            signed_at=instant,
        )
        raw = require_lower_hex(
            self.signature_hex, "v3 signature bytes", length=ED25519_SIGNATURE_HEX_LENGTH
        )
        if (
            self.algorithm != ED25519_ALGORITHM
            or self.signer_role != role
            or self.signature_domain != domain
        ):
            raise ValueError("v3 signature algorithm, role or domain differs")
        if (
            self.payload_digest != payload
            or self.signature_digest != sha256(bytes.fromhex(raw)).hexdigest()
        ):
            raise ValueError("v3 signature recorded digest differs")
        result = {
            "schema_version": RULE_CHAIN_V3_SCHEMA_VERSION,
            "object_kind": self.object_kind,
            "body_schema_version": self.body_schema_version,
            "algorithm": self.algorithm,
            "signer_role": self.signer_role,
            "signature_domain": self.signature_domain,
            "key_id": require_identifier(self.key_id, "v3 signature key id"),
            "body_digest": self.body_digest,
            "signed_at": instant,
            "payload_digest": self.payload_digest,
            "signature_hex": raw,
            "signature_digest": self.signature_digest,
        }
        policy_wire_size(result, budget=budget)
        return result

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> RuleChainV3Signature:
        """Parse only the bounded complete v3 signature wire record.

        Parameters
        ----------
        value : object
            Decoded inert JSON with exactly the twelve declared fields.
        budget : PolicyReadBudget1
            Original explicit document byte/depth limits.

        Returns
        -------
        RuleChainV3Signature
            Reparsed metadata with all content digests checked.

        Raises
        ------
        ValueError
            Fields, versions, roles, domains, bytes or digests are inconsistent.
        """
        policy_wire_size(value, budget=budget)
        data = require_mapping(value, "v3 rule signature")
        require_exact_fields(data, _FIELDS, "v3 rule signature")
        if data["schema_version"] != RULE_CHAIN_V3_SCHEMA_VERSION:
            raise ValueError("unsupported rule-chain v3 signature schema")
        kind, _, _, _ = rule_chain_v3_signature_boundary(data["object_kind"])
        result = cls(
            kind,
            require_string(data["body_schema_version"], "v3 body schema"),
            require_string(data["algorithm"], "v3 algorithm"),
            rule_chain_v3_signature_boundary(kind)[2],
            require_string(data["signature_domain"], "v3 signature domain"),
            require_identifier(data["key_id"], "v3 key id"),
            require_digest(data["body_digest"], "v3 body digest"),
            require_utc_timestamp(data["signed_at"], "v3 signed_at"),
            require_digest(data["payload_digest"], "v3 payload digest"),
            require_string(data["signature_hex"], "v3 signature bytes"),
            require_digest(data["signature_digest"], "v3 signature digest"),
        )
        if result.to_dict(budget=budget) != data:
            raise ValueError("v3 signature fields differ from their owning contract")
        return result

    def verify(
        self,
        *,
        object_kind: RuleObjectKindV3,
        body_schema_version: str,
        body_digest: str,
        roles: TrustRolesV3,
        trust_roles_digest: str,
        now: datetime,
        budget: PolicyReadBudget1,
    ) -> bool:
        """Verify exact expected type/digest/policies and both key lifecycle instants.

        Parameters
        ----------
        object_kind : RuleObjectKindV3
            Independently expected kind selected by the consuming body owner.
        body_schema_version, body_digest, trust_roles_digest : str
            Actual validated body version/digest and selected whole-policy digest.
        roles : TrustRolesV3
            Exact five original policy objects; no caller-created enrollment.
        now : datetime
            Current UTC instant, also required to be at or after signing.
        budget : PolicyReadBudget1
            Explicit metadata allocation limits.

        Returns
        -------
        bool
            Authentic typed digest under the exact selected policy. False on
            malformed metadata, changed roles, replay, bad signature or lifecycle.
        """
        try:
            if type(self) is not RuleChainV3Signature or type(roles) is not TrustRolesV3:
                return False
            parsed = RuleChainV3Signature.from_dict(self.to_dict(budget=budget), budget=budget)
            expected_payload = rule_chain_v3_payload_digest(
                object_kind=object_kind,
                body_schema_version=body_schema_version,
                body_digest=body_digest,
                signed_at=parsed.signed_at,
            )
            checked = TrustRolesV3.build(
                pack_issuers=roles.pack_issuers,
                project_selectors=roles.project_selectors,
                lock_resolvers=roles.lock_resolvers,
                semantic_authors=roles.semantic_authors,
                semantic_reviewers=roles.semantic_reviewers,
            )
            if parsed != self or parsed.payload_digest != expected_payload or checked != roles:
                return False
            if (
                require_digest(trust_roles_digest, "selected v3 trust roles digest")
                != checked.trust_roles_digest
            ):
                return False
            if (
                not isinstance(now, datetime)
                or now.tzinfo is None
                or now.utcoffset() != UTC.utcoffset(now)
            ):
                return False
            instant = parse_utc_timestamp(parsed.signed_at, "v3 signature signed_at")
            policy = checked.policy_for(object_kind)
            if (
                instant > now
                or policy.key_status(parsed.key_id, instant) != "active"
                or policy.key_status(parsed.key_id, now) != "active"
            ):
                return False
            return policy.trust_store().verify(
                key_id=parsed.key_id,
                algorithm=parsed.algorithm,
                signature_domain=parsed.signature_domain,
                payload_digest=parsed.payload_digest,
                signature_hex=parsed.signature_hex,
            )
        except (TypeError, ValueError):
            return False
