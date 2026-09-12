# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — authenticated instruction dispatch
"""Bind an issuer's exact signed request and policy to registered dispatch."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import asdict, dataclass, replace
from datetime import datetime

from .instruction_dispatch import (
    DispatchLease,
    DispatchRequest,
    DispatchResult,
    dispatch_instruction_action,
)
from .instruction_resolution import InstructionPolicy
from .model_primitives import parse_utc_timestamp, require_digest, require_identifier
from .models import canonical_digest
from .verification_policy import OfflineTrustPolicy

DISPATCH_SIGNATURE_DOMAIN = "rigor-foundry.instruction-dispatch-permit.v1"


def dispatch_request_digest(request: DispatchRequest) -> str:
    """Bind exact actions, adapter, route and payload without probing the target."""
    return canonical_digest(
        {
            "actions": [asdict(action) for action in request.actions],
            "adapter": request.adapter.to_dict(),
            "route": request.route,
            "payload_digest": hashlib.sha256(request.payload).hexdigest(),
        }
    )


def instruction_policy_digest(policy: InstructionPolicy) -> str:
    """Bind every source/selector/override and the semantically ordered issuers."""
    return canonical_digest(
        {
            "instructions": [
                asdict(item)
                for item in sorted(policy.instructions, key=lambda item: item.source_id)
            ],
            "issuer_order": policy.issuer_order,
            "grantors": sorted(policy.grantors),
        }
    )


@dataclass(frozen=True)
class SignedDispatchPermit:
    """Exact in-process approval; dedicated issuer keys are selected by the host."""

    request_digest: str
    policy_digest: str
    key_id: str
    issued_at: str
    expires_at: str
    signature_hex: str

    @property
    def payload_digest(self) -> str:
        """Validate and hash signed fields without including the detached signature."""
        start = parse_utc_timestamp(self.issued_at, "dispatch.issued_at")
        end = parse_utc_timestamp(self.expires_at, "dispatch.expires_at")
        if end <= start:
            raise ValueError("dispatch permit expiry must follow issuance")
        return canonical_digest(
            {
                "request_digest": require_digest(self.request_digest, "dispatch.request_digest"),
                "policy_digest": require_digest(self.policy_digest, "dispatch.policy_digest"),
                "key_id": require_identifier(self.key_id, "dispatch.key_id"),
                "issued_at": self.issued_at,
                "expires_at": self.expires_at,
            }
        )


@dataclass(frozen=True)
class SignedDispatchState:
    """Fresh host lease with a dedicated issuer policy and current revocations.

    The host authenticates its trust configuration and adapter registration and
    serialises state updates through the lease. A permit signs exact policy
    content, not independent authenticity of every referenced policy source.
    """

    lease: DispatchLease
    permit: SignedDispatchPermit
    issuer_policy: OfflineTrustPolicy
    revoked_permits: frozenset[str]


def dispatch_signed_instruction_action(
    request: DispatchRequest,
    *,
    state: Callable[[DispatchRequest], AbstractContextManager[SignedDispatchState]],
    clock: Callable[[], datetime],
) -> DispatchResult:
    """Authenticate current exact permission immediately before the real handler.

    Host custody validation precedes the final signature/time check. The clock,
    issuer policy, state factory and handler registration are trusted composition,
    never request-controlled inputs. No callback or evidence advertisement becomes
    permission on its own. Keep existing adapter confinement and resource checks.
    This API does not install a wire parser, provider or post-admission cancellation.
    """

    @contextmanager
    def authenticated(received: DispatchRequest) -> Iterator[DispatchLease]:
        """Retain the original host lease while replacing its final admission check."""
        with state(received) as current:

            def revalidate(exact: DispatchRequest) -> None:
                """Recheck host custody, then exact signature and live validity."""
                current.lease.revalidate(exact)
                permit = current.permit
                digest = permit.payload_digest
                if permit.request_digest != dispatch_request_digest(
                    exact
                ) or permit.policy_digest != instruction_policy_digest(current.lease.policy):
                    raise PermissionError("dispatch permit does not bind request and policy")
                trust = current.issuer_policy.trust_store()
                if not trust.verify(
                    key_id=permit.key_id,
                    algorithm="ed25519",
                    signature_domain=DISPATCH_SIGNATURE_DOMAIN,
                    payload_digest=digest,
                    signature_hex=permit.signature_hex,
                ):
                    raise PermissionError("dispatch permit signature is invalid")
                now = clock()
                issued = parse_utc_timestamp(permit.issued_at, "dispatch.issued_at")
                expires = parse_utc_timestamp(permit.expires_at, "dispatch.expires_at")
                if (
                    current.issuer_policy.key_status(permit.key_id, now) != "active"
                    or current.issuer_policy.key_status(permit.key_id, issued) != "active"
                    or not issued <= now < expires
                    or digest in current.revoked_permits
                ):
                    raise PermissionError("dispatch permit is inactive or revoked")

            yield replace(current.lease, revalidate=revalidate)

    return dispatch_instruction_action(request, state=authenticated)
