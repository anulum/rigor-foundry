# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — signed dispatch real-effect contracts
"""Require actual issuer signatures before registered local file operations."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from instruction_dispatch_support import (
    file_lease,
    instruction_rule,
    policy_for_rules,
    request_for_file,
)
from signing_fixtures import public_key_hex, sign_message

from rigor_foundry.instruction_dispatch import DispatchRequest
from rigor_foundry.instruction_scope import InstructionScope
from rigor_foundry.signed_instruction_dispatch import (
    DISPATCH_SIGNATURE_DOMAIN,
    SignedDispatchPermit,
    SignedDispatchState,
    dispatch_request_digest,
    dispatch_signed_instruction_action,
    instruction_policy_digest,
)
from rigor_foundry.trust import TrustedPublicKey
from rigor_foundry.verification_policy import OfflineTrustPolicy, VerificationKeyPolicy


def _now() -> datetime:
    """Choose an explicit host instant inside the fixture permit interval."""
    return datetime(2026, 9, 12, tzinfo=UTC)


def _state(request: DispatchRequest) -> SignedDispatchState:
    """Issue a real signature for the complete operation and host policy."""
    policy = policy_for_rules(
        instruction_rule(scope=InstructionScope(target=request.actions[0].target))
    )
    key = TrustedPublicKey.build(
        key_id="dispatch-issuer", public_key_hex=public_key_hex("dispatch-issuer")
    )
    trust = OfflineTrustPolicy.build(
        (
            VerificationKeyPolicy.build(
                key=key, valid_from="2026-09-01T00:00:00Z", valid_until="2026-10-01T00:00:00Z"
            ),
        )
    )
    unsigned = SignedDispatchPermit(
        dispatch_request_digest(request),
        instruction_policy_digest(policy),
        "dispatch-issuer",
        "2026-09-10T00:00:00Z",
        "2026-09-20T00:00:00Z",
        "",
    )
    permit = replace(
        unsigned,
        signature_hex=sign_message(
            "dispatch-issuer", DISPATCH_SIGNATURE_DOMAIN, unsigned.payload_digest
        ),
    )
    return SignedDispatchState(
        file_lease(request, Path(request.actions[0].target), policy), permit, trust, frozenset()
    )


def test_real_signature_reaches_registered_writer(tmp_path: Path) -> None:
    """Only the signed payload reaches the registered host-owned destination."""
    destination = tmp_path / "document"
    request = request_for_file(destination)
    current = _state(request)
    result = dispatch_signed_instruction_action(
        request, state=lambda _: nullcontext(current), clock=_now
    )
    assert result.output == destination.read_bytes() == request.payload


@pytest.mark.parametrize(
    "fault",
    [
        "payload",
        "policy",
        "issuer-order",
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
def test_invalid_signed_dispatch_preserves_owner_bytes(tmp_path: Path, fault: str) -> None:
    """Signature and lifecycle failures cannot reach an otherwise permitted writer."""
    destination = tmp_path / "document"
    destination.write_bytes(b"retained owner data")
    request = request_for_file(destination)
    current = _state(request)
    instant = _now()
    if fault == "payload":
        request = replace(request, payload=b"not the signed bytes")
        current = replace(current, lease=file_lease(request, destination, current.lease.policy))
    elif fault == "policy":
        policy = replace(
            current.lease.policy,
            instructions=(
                *current.lease.policy.instructions,
                instruction_rule("unrelated", scope=InstructionScope(project="OTHER")),
            ),
        )
        current = replace(current, lease=replace(current.lease, policy=policy))
    elif fault == "issuer-order":
        policy = replace(current.lease.policy, issuer_order=("platform", "vendor", "owner"))
        current = replace(current, lease=replace(current.lease, policy=policy))
    elif fault == "signature":
        current = replace(current, permit=replace(current.permit, signature_hex="0" * 128))
    elif fault == "domain":
        signature = sign_message(
            "dispatch-issuer",
            "rigor-foundry.campaign-create-permit.v1",
            current.permit.payload_digest,
        )
        current = replace(current, permit=replace(current.permit, signature_hex=signature))
    elif fault == "key":
        permit = replace(current.permit, key_id="unknown")
        current = replace(
            current,
            permit=replace(
                permit,
                signature_hex=sign_message(
                    "unknown", DISPATCH_SIGNATURE_DOMAIN, permit.payload_digest
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
        key_policy = VerificationKeyPolicy.build(
            key=current.issuer_policy.keys[0].key,
            valid_from="2026-09-11T00:00:00Z"
            if fault == "key-issued-late"
            else "2026-09-01T00:00:00Z",
            valid_until="2026-10-01T00:00:00Z",
            revoked_at="2026-09-12T00:00:00Z" if fault == "key-revoked" else "",
        )
        current = replace(current, issuer_policy=OfflineTrustPolicy.build((key_policy,)))
    with pytest.raises(PermissionError):
        dispatch_signed_instruction_action(
            request, state=lambda _: nullcontext(current), clock=lambda: instant
        )
    assert destination.read_bytes() == b"retained owner data"


def test_expiry_during_host_preparation_is_not_cached(tmp_path: Path) -> None:
    """Time is checked after the host's final custody check, not at preparation."""
    destination = tmp_path / "document"
    request = request_for_file(destination)
    current = _state(request)
    instant = _now()

    def revalidate(received: DispatchRequest) -> None:
        """Complete host preparation at the exact signed expiry boundary."""
        nonlocal instant
        assert received == request
        instant = datetime(2026, 9, 20, tzinfo=UTC)

    current = replace(current, lease=replace(current.lease, revalidate=revalidate))
    with pytest.raises(PermissionError, match="inactive"):
        dispatch_signed_instruction_action(
            request, state=lambda _: nullcontext(current), clock=lambda: instant
        )
    assert not destination.exists()


def test_invalid_interval_and_suppression_cannot_admit(tmp_path: Path) -> None:
    """A malformed interval stays a refusal even when a host wrongly suppresses it."""
    destination = tmp_path / "document"
    request = request_for_file(destination)
    current = _state(request)
    current = replace(current, permit=replace(current.permit, expires_at=current.permit.issued_at))
    with pytest.raises(ValueError, match="expiry"):
        dispatch_signed_instruction_action(
            request, state=lambda _: nullcontext(current), clock=_now
        )

    @contextmanager
    def suppressing(received: DispatchRequest) -> Iterator[SignedDispatchState]:
        """Deliberately swallow validation to test the enclosing dispatch refusal."""
        assert received == request
        try:
            yield current
        except ValueError:
            return

    with pytest.raises(RuntimeError, match="suppressed"):
        dispatch_signed_instruction_action(request, state=suppressing, clock=_now)
    assert not destination.exists()


def test_actual_handler_failure_releases_signed_host_lease(tmp_path: Path) -> None:
    """A real filesystem error propagates while the signed host releases custody."""
    destination = tmp_path / "directory"
    destination.mkdir()
    request = request_for_file(destination)
    current = _state(request)
    released: list[bool] = []

    @contextmanager
    def state(received: DispatchRequest) -> Iterator[SignedDispatchState]:
        """Retain observable host custody through the failing real operation."""
        assert received == request
        try:
            yield current
        finally:
            released.append(True)

    with pytest.raises(IsADirectoryError):
        dispatch_signed_instruction_action(request, state=state, clock=_now)
    assert released == [True] and destination.is_dir()
