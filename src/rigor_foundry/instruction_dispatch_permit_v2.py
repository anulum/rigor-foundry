# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — typed v2 dispatch permit candidate
"""Bind one bounded dispatch decision without consuming or admitting a permit."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Final
from uuid import UUID

from .audit_primitives import require_exact_fields
from .model_primitives import (
    parse_utc_timestamp,
    require_digest,
    require_identifier,
    require_utc_timestamp,
)
from .models import canonical_digest, require_mapping, require_string
from .signed_rule_chain_v2 import RuleChainV2TrustRoles
from .trust import ED25519_ALGORITHM, ED25519_SIGNATURE_HEX_LENGTH, require_lower_hex
from .verification_policy import OfflineTrustPolicy

PERMIT_V2_SCHEMA_VERSION: Final = "instruction-dispatch-permit.v2.1"
PERMIT_V2_SCHEMA: Final = PERMIT_V2_SCHEMA_VERSION
PERMIT_V2_KIND: Final = "instruction-dispatch-permit"
PERMIT_V2_DOMAIN: Final = "rigor-foundry.instruction-dispatch-permit.v2.1"
PERMIT_V2_ROLE: Final = "permit-issuer"
PERMIT_V2_MAX_WINDOW: Final = timedelta(seconds=300)
PERMIT_V2_ISSUE_SKEW: Final = timedelta(seconds=5)
_DIGEST_FIELDS: Final = frozenset(
    {
        "lock_digest",
        "rule_projection_digest",
        "request_digest",
        "grant_snapshot_digest",
        "current_state_proof_digest",
        "adapter_custody_digest",
        "route_digest",
        "effect_target_digest",
        "effect_operations_digest",
        "operations_digest",
    }
)
PERMIT_V2_DECISION_FIELDS: Final = _DIGEST_FIELDS
_BODY_FIELDS: Final = _DIGEST_FIELDS | frozenset(
    {
        "schema_version",
        "object_kind",
        "signature_domain",
        "algorithm",
        "signer_role",
        "permit_id",
        "key_id",
        "issued_at",
        "not_before",
        "expires_at",
    }
)
_WIRE_FIELDS: Final = _BODY_FIELDS | frozenset(
    {"payload_digest", "signature_hex", "signature_digest", "permit_digest"}
)


def _body(value: object) -> dict[str, str]:
    """Require the complete signed decision and a validity window at most 300 s."""
    data = require_mapping(value, "v2 dispatch permit body")
    require_exact_fields(data, _BODY_FIELDS, "v2 dispatch permit body")
    constants = {
        "schema_version": PERMIT_V2_SCHEMA,
        "object_kind": PERMIT_V2_KIND,
        "signature_domain": PERMIT_V2_DOMAIN,
        "algorithm": ED25519_ALGORITHM,
        "signer_role": PERMIT_V2_ROLE,
    }
    if any(data.get(field) != expected for field, expected in constants.items()):
        raise ValueError("v2 dispatch permit type, role or domain differs")
    permit_id = require_identifier(data.get("permit_id"), "permit.permit_id")
    try:
        parsed_id = UUID(permit_id)
        if str(parsed_id) != permit_id or parsed_id.int in (0, (1 << 128) - 1):
            raise ValueError("v2 dispatch permit ID must be non-reserved canonical UUID text")
    except ValueError as exc:
        raise ValueError("v2 dispatch permit ID must be canonical UUID text") from exc
    issued_at = require_utc_timestamp(data.get("issued_at"), "permit.issued_at")
    not_before = require_utc_timestamp(data.get("not_before"), "permit.not_before")
    expires_at = require_utc_timestamp(data.get("expires_at"), "permit.expires_at")
    issued = parse_utc_timestamp(issued_at, "permit.issued_at")
    start = parse_utc_timestamp(not_before, "permit.not_before")
    end = parse_utc_timestamp(expires_at, "permit.expires_at")
    if not issued <= start <= issued + PERMIT_V2_ISSUE_SKEW:
        raise ValueError("v2 dispatch permit start differs from issuance time")
    if not start < end <= start + PERMIT_V2_MAX_WINDOW:
        raise ValueError("v2 dispatch permit window must be positive and at most 300 seconds")
    return {
        **constants,
        **{field: require_digest(data.get(field), f"permit.{field}") for field in _DIGEST_FIELDS},
        "permit_id": permit_id,
        "key_id": require_identifier(data.get("key_id"), "permit.key_id"),
        "issued_at": issued_at,
        "not_before": not_before,
        "expires_at": expires_at,
    }


@dataclass(frozen=True)
class RuleChainV2PermitTrustRoles:
    """Keep the permit issuer separate from all five signed-chain roles.

    Attributes
    ----------
    chain : RuleChainV2TrustRoles
        Caller-selected pack, project, lock, semantic author and reviewer policies.
    permit_issuers : OfflineTrustPolicy
        Dedicated issuer policy with key identifiers and public bytes disjoint
        from every chain policy. Construction alone does not select host trust.
    """

    chain: RuleChainV2TrustRoles
    permit_issuers: OfflineTrustPolicy

    @classmethod
    def build(
        cls,
        *,
        chain: RuleChainV2TrustRoles,
        permit_issuers: OfflineTrustPolicy,
    ) -> RuleChainV2PermitTrustRoles:
        """Validate six disjoint signing roles without selecting host authority.

        Parameters
        ----------
        chain : RuleChainV2TrustRoles
            Five chain policies, rebuilt to validate their existing separation.
        permit_issuers : OfflineTrustPolicy
            Issuer policy, rebuilt before comparing identifiers and public bytes.

        Returns
        -------
        RuleChainV2PermitTrustRoles
            Validated policy composition for candidate signature verification.

        Raises
        ------
        ValueError
            A policy is invalid or any two roles reuse a key ID or public key.
        """
        checked_chain = RuleChainV2TrustRoles.build(
            pack_issuers=chain.pack_issuers,
            project_selectors=chain.project_selectors,
            lock_resolvers=chain.lock_resolvers,
            semantic_authors=chain.semantic_authors,
            semantic_reviewers=chain.semantic_reviewers,
        )
        checked_permits = OfflineTrustPolicy.from_dict(permit_issuers.to_dict())
        keys = tuple(
            key.key
            for policy in (
                checked_chain.pack_issuers,
                checked_chain.project_selectors,
                checked_chain.lock_resolvers,
                checked_chain.semantic_authors,
                checked_chain.semantic_reviewers,
                checked_permits,
            )
            for key in policy.keys
        )
        if len({key.key_id for key in keys}) != len(keys) or len(
            {key.public_key_hex for key in keys}
        ) != len(keys):
            raise ValueError("v2 permit-issuer key must be distinct from chain roles")
        return cls(checked_chain, checked_permits)


@dataclass(frozen=True)
class DispatchPermitBodyV2:
    """Retain a canonical provisional body for an external issuer signature.

    Attributes
    ----------
    canonical_json : str
        Exact validated body in sorted, compact JSON form.
    payload_digest : str
        SHA-256 of the canonical body bytes, including all ten decision digests.
    """

    canonical_json: str
    payload_digest: str

    @classmethod
    def from_dict(cls, value: object) -> DispatchPermitBodyV2:
        """Parse exact fields and retain their canonical bytes and digest.

        Parameters
        ----------
        value : object
            Body mapping with canonical UUID, UTC timestamps and decision digests.

        Returns
        -------
        DispatchPermitBodyV2
            Canonical body with a positive window of at most 300 seconds.

        Raises
        ------
        ValueError
            Fields, identities, digests or the bounded validity window are invalid.
        """
        body = _body(value)
        canonical = json.dumps(
            body, allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        return cls(canonical, canonical_digest(body))

    def to_dict(self) -> dict[str, str]:
        """Recheck directly constructed instances before exporting fields.

        Returns
        -------
        dict[str, str]
            Exact body fields with their validated wire representations.

        Raises
        ------
        ValueError
            Canonical JSON, body fields or the retained digest are invalid.
        """
        body = _body(json.loads(self.canonical_json))
        if canonical_digest(body) != self.payload_digest:
            raise ValueError("v2 dispatch permit body digest differs")
        return body


@dataclass(frozen=True)
class SignedDispatchPermitV2:
    """Bind one candidate body to an externally produced Ed25519 signature.

    Attributes
    ----------
    body : DispatchPermitBodyV2
        Exact canonical signed decision and bounded validity window.
    signature_hex : str
        Lowercase hexadecimal Ed25519 signature bytes.
    signature_digest : str
        SHA-256 of those signature bytes.
    permit_digest : str
        Canonical digest of the body, payload digest and signature envelope.

    Notes
    -----
    The candidate carries no host selection or single-use consumption authority.
    """

    body: DispatchPermitBodyV2
    signature_hex: str
    signature_digest: str
    permit_digest: str

    @classmethod
    def build(cls, *, body: DispatchPermitBodyV2, signature_hex: str) -> SignedDispatchPermitV2:
        """Attach externally produced Ed25519 bytes to a rechecked v2 body.

        Parameters
        ----------
        body : DispatchPermitBodyV2
            Canonical body, revalidated before envelope construction.
        signature_hex : str
            External 64-byte signature encoded as 128 lowercase hex characters.

        Returns
        -------
        SignedDispatchPermitV2
            Digest-bound envelope; cryptographic validity is checked separately.

        Raises
        ------
        ValueError
            The body or signature representation is invalid.
        """
        checked = DispatchPermitBodyV2.from_dict(body.to_dict())
        signature = require_lower_hex(
            signature_hex, "permit.signature_hex", length=ED25519_SIGNATURE_HEX_LENGTH
        )
        signature_digest = sha256(bytes.fromhex(signature)).hexdigest()
        envelope = {
            **checked.to_dict(),
            "payload_digest": checked.payload_digest,
            "signature_hex": signature,
            "signature_digest": signature_digest,
        }
        return cls(checked, signature, signature_digest, canonical_digest(envelope))

    def to_dict(self) -> dict[str, str]:
        """Export a signed envelope for later parsing and protected-host checks.

        Returns
        -------
        dict[str, str]
            Body and retained signature/digest fields. The body is rechecked;
            use ``from_dict`` to validate the complete envelope after direct
            construction, and ``verify_signature`` for cryptographic validity.

        Raises
        ------
        ValueError
            The retained body is invalid.
        """
        return {
            **self.body.to_dict(),
            "payload_digest": self.body.payload_digest,
            "signature_hex": self.signature_hex,
            "signature_digest": self.signature_digest,
            "permit_digest": self.permit_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> SignedDispatchPermitV2:
        """Reject missing fields, unknown fields and altered envelope digests.

        Parameters
        ----------
        value : object
            Complete candidate wire mapping with all body and signature fields.

        Returns
        -------
        SignedDispatchPermitV2
            Rebuilt exact envelope, still requiring signature verification.

        Raises
        ------
        ValueError
            Field sets, body, signature encoding or any envelope digest differ.
        """
        data = require_mapping(value, "signed v2 dispatch permit")
        require_exact_fields(data, _WIRE_FIELDS, "signed v2 dispatch permit")
        body = DispatchPermitBodyV2.from_dict({field: data[field] for field in _BODY_FIELDS})
        signed = cls.build(
            body=body,
            signature_hex=require_string(data.get("signature_hex"), "permit.signature_hex"),
        )
        if (
            data.get("payload_digest") != signed.body.payload_digest
            or data.get("signature_digest") != signed.signature_digest
            or data.get("permit_digest") != signed.permit_digest
        ):
            raise ValueError("signed v2 dispatch permit envelope digest differs")
        return signed

    def verify_signature(self, *, roles: RuleChainV2PermitTrustRoles, now: datetime) -> bool:
        """Check issuer signature and lifecycle with a caller-supplied time.

        Parameters
        ----------
        roles : RuleChainV2PermitTrustRoles
            Caller-selected six-role composition, rebuilt before verification.
        now : datetime
            Caller-supplied UTC verification time; no host clock is authenticated.

        Returns
        -------
        bool
            Whether the exact envelope, dedicated key signature, issuer lifecycle
            at issuance/start/current time and half-open permit window all pass.
            Invalid candidate values or role compositions return ``False``.

        Notes
        -----
        This is structural verification only. A protected host must supply its
        own clock, selected policy, lock and state, then atomically consume the
        permit ID before a registered effect. This method cannot admit one.
        """
        try:
            parsed = SignedDispatchPermitV2.from_dict(self.to_dict())
            selected_roles = RuleChainV2PermitTrustRoles.build(
                chain=roles.chain, permit_issuers=roles.permit_issuers
            )
            selected_policy = selected_roles.permit_issuers
            if now.tzinfo is None or now.utcoffset() != UTC.utcoffset(now):
                return False
            body = parsed.body.to_dict()
            issued = parse_utc_timestamp(body["issued_at"], "permit.issued_at")
            start = parse_utc_timestamp(body["not_before"], "permit.not_before")
            end = parse_utc_timestamp(body["expires_at"], "permit.expires_at")
            key_id = body["key_id"]
            if (
                not issued <= start <= now < end
                or selected_policy.key_status(key_id, issued) != "active"
                or selected_policy.key_status(key_id, start) != "active"
                or selected_policy.key_status(key_id, now) != "active"
            ):
                return False
            return selected_policy.trust_store().verify(
                key_id=key_id,
                algorithm=ED25519_ALGORITHM,
                signature_domain=PERMIT_V2_DOMAIN,
                payload_digest=parsed.body.payload_digest,
                signature_hex=parsed.signature_hex,
            )
        except (TypeError, ValueError):
            return False
