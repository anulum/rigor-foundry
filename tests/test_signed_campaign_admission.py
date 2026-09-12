# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — signed campaign public boundary tests
"""Observe actual campaign effects behind real cryptographic admission."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository
from signing_fixtures import public_key_hex, sign_message

from rigor_foundry.campaign_admission import CampaignCreation, create_admitted_campaign
from rigor_foundry.campaign_store import load_campaign
from rigor_foundry.git_provenance import GitTrustPolicy
from rigor_foundry.signed_campaign_admission import (
    CAMPAIGN_PERMIT_SIGNATURE_DOMAIN,
    CampaignAdmissionState,
    SignedCampaignAdmission,
    SignedCampaignPermit,
    campaign_request_digest,
)
from rigor_foundry.trust import TrustedPublicKey
from rigor_foundry.verification_policy import OfflineTrustPolicy, VerificationKeyPolicy


def _request(root: Path) -> CampaignCreation:
    """Declare one exact diagnostic request with no provider execution."""
    return CampaignCreation(
        root,
        Path("rigor-foundry-policy.json"),
        Path(".rigor/audits"),
        "TEST-PROJECT",
        "signed-campaign",
        "test-owner",
        1,
    )


def _now() -> datetime:
    """Supply a deterministic trusted-host instant inside the fixture validity."""
    return datetime(2026, 9, 12, tzinfo=UTC)


def _state(request: CampaignCreation) -> CampaignAdmissionState:
    """Sign the exact request using a dedicated real test-only issuer key."""
    key = TrustedPublicKey.build(key_id="issuer", public_key_hex=public_key_hex("issuer"))
    policy = OfflineTrustPolicy.build(
        (
            VerificationKeyPolicy.build(
                key=key,
                valid_from="2026-09-01T00:00:00Z",
                valid_until="2026-10-01T00:00:00Z",
            ),
        )
    )
    unsigned = SignedCampaignPermit(
        campaign_request_digest(request),
        "issuer",
        "2026-09-10T00:00:00Z",
        "2026-09-20T00:00:00Z",
        "",
    )
    permit = replace(
        unsigned,
        signature_hex=sign_message(
            "issuer",
            CAMPAIGN_PERMIT_SIGNATURE_DOMAIN,
            unsigned.payload_digest,
        ),
    )
    return CampaignAdmissionState(permit, policy, frozenset())


def test_valid_signed_request_creates_real_campaign(tmp_path: Path) -> None:
    """A genuine active permit reaches durable creation with existing Git checks."""
    repo = GitRepository.create(tmp_path / "repository")
    repo.write_policy()
    repo.commit()
    request = _request(repo.root)
    current = _state(request)
    provider = SignedCampaignAdmission(lambda: nullcontext(current), _now)
    path, campaign = create_admitted_campaign(request, admission=provider)
    assert load_campaign(path) == campaign


@pytest.mark.parametrize(
    "fault",
    [
        "request",
        "signature",
        "domain",
        "key",
        "expired",
        "future",
        "revoked",
        "key-revoked",
        "key-issued-late",
    ],
)
def test_invalid_signed_request_has_no_filesystem_effect(tmp_path: Path, fault: str) -> None:
    """Real signature and lifecycle refusals occur before missing-root access."""
    request = _request(tmp_path / "absent")
    current = _state(request)
    instant = _now()
    if fault == "request":
        request = replace(request, actor="different-actor")
    elif fault == "signature":
        current = replace(current, permit=replace(current.permit, signature_hex="0" * 128))
    elif fault == "domain":
        signature = sign_message(
            "issuer", "rigor-foundry.standard-pack.v1", current.permit.payload_digest
        )
        current = replace(current, permit=replace(current.permit, signature_hex=signature))
    elif fault == "key":
        permit = replace(current.permit, key_id="unknown")
        current = replace(
            current,
            permit=replace(
                permit,
                signature_hex=sign_message(
                    "unknown", CAMPAIGN_PERMIT_SIGNATURE_DOMAIN, permit.payload_digest
                ),
            ),
        )
    elif fault == "expired":
        instant = datetime(2026, 9, 20, tzinfo=UTC)
    elif fault == "future":
        instant = datetime(2026, 9, 9, tzinfo=UTC)
    elif fault == "revoked":
        current = replace(current, revoked_permits=frozenset({current.permit.payload_digest}))
    else:
        key = current.issuer_policy.keys[0].key
        policy = VerificationKeyPolicy.build(
            key=key,
            valid_from="2026-09-11T00:00:00Z"
            if fault == "key-issued-late"
            else "2026-09-01T00:00:00Z",
            valid_until="2026-10-01T00:00:00Z",
            revoked_at="2026-09-12T00:00:00Z" if fault == "key-revoked" else "",
        )
        current = replace(current, issuer_policy=OfflineTrustPolicy.build((policy,)))
    provider = SignedCampaignAdmission(lambda: nullcontext(current), lambda: instant)
    with pytest.raises(PermissionError):
        create_admitted_campaign(request, admission=provider)
    assert not request.repository_root.exists()


def test_revocation_is_loaded_at_entry_not_provider_construction(tmp_path: Path) -> None:
    """A permit revoked after constructing the provider never reaches creation."""
    request = _request(tmp_path / "absent")
    current = _state(request)
    provider = SignedCampaignAdmission(lambda: nullcontext(current), _now)
    current = replace(current, revoked_permits=frozenset({current.permit.payload_digest}))
    with pytest.raises(PermissionError, match="revoked"):
        create_admitted_campaign(request, admission=provider)
    assert not request.repository_root.exists()


def test_invalid_interval_is_refused_before_storage(tmp_path: Path) -> None:
    """Even a structurally constructible record cannot invert its signed lifetime."""
    request = _request(tmp_path / "absent")
    current = _state(request)
    current = replace(current, permit=replace(current.permit, expires_at=current.permit.issued_at))
    with pytest.raises(ValueError, match="expiry"):
        create_admitted_campaign(
            request, admission=SignedCampaignAdmission(lambda: nullcontext(current), _now)
        )
    assert not request.repository_root.exists()


def test_host_cannot_suppress_signature_refusal(tmp_path: Path) -> None:
    """An incorrectly suppressing host lease still cannot yield permission."""
    request = _request(tmp_path / "absent")
    current = _state(request)
    current = replace(current, permit=replace(current.permit, signature_hex="0" * 128))

    @contextmanager
    def state() -> Iterator[CampaignAdmissionState]:
        """Deliberately suppress validation to exercise the provider's refusal."""
        try:
            yield current
        except PermissionError:
            return

    with pytest.raises(PermissionError, match="suppressed"):
        create_admitted_campaign(request, admission=SignedCampaignAdmission(state, _now))
    assert not request.repository_root.exists()


def test_request_identity_includes_explicit_git_trust(tmp_path: Path) -> None:
    """An otherwise identical request cannot inherit a different Git trust scope."""
    request = _request(tmp_path)
    assert campaign_request_digest(request) != campaign_request_digest(
        replace(request, git_trust_policy=GitTrustPolicy(trusted_roots=("/usr/bin",)))
    )


def test_every_changed_creation_argument_invalidates_permit(tmp_path: Path) -> None:
    """Every request argument participates in the authenticated operation identity."""
    original = _request(tmp_path / "absent")
    current = _state(original)
    changes = (
        replace(original, repository_root=Path("/different-project")),
        replace(original, policy_path=Path("other-policy.json")),
        replace(original, audit_root=Path("other-output")),
        replace(original, project="OTHER-PROJECT"),
        replace(original, campaign_id="different-campaign"),
        replace(original, actor="other-actor"),
        replace(original, expected_runs=2),
        replace(original, purpose="promotion"),
        replace(original, required_model_witnesses=3),
        replace(original, git_trust_policy=GitTrustPolicy(trusted_roots=("/usr/bin",))),
    )
    for changed in changes:
        with pytest.raises(PermissionError, match="does not bind"):
            create_admitted_campaign(
                changed, admission=SignedCampaignAdmission(lambda: nullcontext(current), _now)
            )
    assert not original.repository_root.exists()
