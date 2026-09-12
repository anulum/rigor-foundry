# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — signed campaign creation admission
"""Authenticate exact campaign permits using fresh, trusted host state leases."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from datetime import datetime

from .campaign_admission import CampaignCreation
from .model_primitives import parse_utc_timestamp, require_digest, require_identifier
from .models import canonical_digest
from .verification_policy import OfflineTrustPolicy

CAMPAIGN_PERMIT_SIGNATURE_DOMAIN = "rigor-foundry.campaign-create-permit.v1"


def campaign_request_digest(request: CampaignCreation) -> str:
    """Hash every declared creation argument without inspecting target files."""
    return canonical_digest(
        {
            "repository_root": request.repository_root.as_posix(),
            "policy_path": request.policy_path.as_posix(),
            "audit_root": request.audit_root.as_posix(),
            "project": request.project,
            "campaign_id": request.campaign_id,
            "actor": request.actor,
            "expected_runs": request.expected_runs,
            "purpose": request.purpose,
            "required_model_witnesses": request.required_model_witnesses,
            "git_trust_policy": (
                None if request.git_trust_policy is None else request.git_trust_policy.to_dict()
            ),
        }
    )


@dataclass(frozen=True)
class SignedCampaignPermit:
    """One in-process exact-request permit, not a serialized policy or self-grant."""

    request_digest: str
    key_id: str
    issued_at: str
    expires_at: str
    signature_hex: str

    @property
    def payload_digest(self) -> str:
        """Validate signed fields and derive the payload independent of signature."""
        start = parse_utc_timestamp(self.issued_at, "permit.issued_at")
        end = parse_utc_timestamp(self.expires_at, "permit.expires_at")
        if end <= start:
            raise ValueError("permit expiry must follow issuance")
        return canonical_digest(
            {
                "request_digest": require_digest(self.request_digest, "permit.request_digest"),
                "key_id": require_identifier(self.key_id, "permit.key_id"),
                "issued_at": self.issued_at,
                "expires_at": self.expires_at,
            }
        )


@dataclass(frozen=True)
class CampaignAdmissionState:
    """Host-selected dedicated issuer policy, current permit and revoked payloads.

    Only trusted host composition may supply this state. A caller-provided
    trust policy would allow the caller to authorise itself.
    """

    permit: SignedCampaignPermit
    issuer_policy: OfflineTrustPolicy
    revoked_permits: frozenset[str]


@dataclass(frozen=True)
class SignedCampaignAdmission:
    """Acquire fresh host state and authenticate before yielding to creation.

    The host context must synchronize current policy/permit reads and hold any
    required lease through execution. The clock and context are trusted host
    dependencies. This does not establish runtime adapter evidence, filesystem
    identity custody, or cancellation after an operation has been admitted.
    """

    state: Callable[[], AbstractContextManager[CampaignAdmissionState]]
    clock: Callable[[], datetime]

    @contextmanager
    def __call__(self, request: CampaignCreation) -> Iterator[None]:
        """Check an exact signed permit and current revocation on every entry."""
        entered = False
        with self.state() as current:
            permit = current.permit
            digest = permit.payload_digest
            if permit.request_digest != campaign_request_digest(request):
                raise PermissionError("permit does not bind this campaign request")
            store = current.issuer_policy.trust_store()
            if not store.verify(
                key_id=permit.key_id,
                algorithm="ed25519",
                signature_domain=CAMPAIGN_PERMIT_SIGNATURE_DOMAIN,
                payload_digest=digest,
                signature_hex=permit.signature_hex,
            ):
                raise PermissionError("campaign permit signature is invalid")
            now = self.clock()
            issued = parse_utc_timestamp(permit.issued_at, "permit.issued_at")
            expires = parse_utc_timestamp(permit.expires_at, "permit.expires_at")
            if (
                current.issuer_policy.key_status(permit.key_id, now) != "active"
                or current.issuer_policy.key_status(permit.key_id, issued) != "active"
                or not issued <= now < expires
                or digest in current.revoked_permits
            ):
                raise PermissionError("campaign permit is inactive or revoked")
            entered = True
            yield
        if not entered:
            raise PermissionError("host state provider suppressed admission failure")
