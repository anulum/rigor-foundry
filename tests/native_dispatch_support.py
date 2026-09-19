# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native dispatch source and signing fixtures
"""Construct real tracked audit inputs and separately issued test-only host permits."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from instruction_dispatch_support import instruction_rule, policy_for_rules
from repository_audit_git_repository import GitRepository
from signing_fixtures import public_key_hex, sign_message

from rigor_foundry.instruction_dispatch import DispatchLease, DispatchRequest
from rigor_foundry.models import AdapterSpec
from rigor_foundry.signed_instruction_dispatch import (
    DISPATCH_SIGNATURE_DOMAIN,
    SignedDispatchPermit,
    SignedDispatchState,
    dispatch_request_digest,
    instruction_policy_digest,
)
from rigor_foundry.trust import TrustedPublicKey
from rigor_foundry.verification_policy import OfflineTrustPolicy, VerificationKeyPolicy


def repository_and_spec(root: Path) -> tuple[GitRepository, AdapterSpec]:
    """Create a real tracked Semgrep input and preserve private source sentinels."""
    repository = GitRepository.create(root)
    repository.write_text(".gitignore", "private/\n")
    repository.write_text(
        "config.yml",
        "rules:\n  - id: no-eval\n    languages: [python]\n"
        "    message: reject dynamic evaluation\n    severity: ERROR\n"
        "    pattern: eval(...)\n",
    )
    repository.write_text("src/module.py", "VALUE = 1\n")
    repository.commit()
    repository.write_text("private/note.txt", "private sentinel\n")
    repository.write_text("untracked.txt", "untracked sentinel\n")
    return repository, AdapterSpec.from_dict(
        {
            "name": "semgrep-security",
            "profile": "semgrep-local-json-v1",
            "configuration_path": "config.yml",
            "target_paths": ["src"],
            "timeout_seconds": 30,
            "scope": "full",
            "working_directory": ".",
            "required": True,
        },
        0,
    )


def instant() -> datetime:
    """Return a controlled test host time inside the fixture approval interval."""
    return datetime(2026, 9, 12, tzinfo=UTC)


def issued_state(
    request: DispatchRequest, revalidate: Callable[[DispatchRequest], None]
) -> SignedDispatchState:
    """Sign the complete native operation under a separately registered fixture host."""
    policy = policy_for_rules(instruction_rule())
    issuer = "native-dispatch-test"
    key = TrustedPublicKey.build(key_id=issuer, public_key_hex=public_key_hex(issuer))
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
        issuer,
        "2026-09-11T00:00:00Z",
        "2026-09-13T00:00:00Z",
        "",
    )
    permit = replace(
        unsigned,
        signature_hex=sign_message(issuer, DISPATCH_SIGNATURE_DOMAIN, unsigned.payload_digest),
    )

    def not_the_native_handler(payload: bytes) -> bytes:
        """Refuse any accidental invocation of the host fixture's generic callback."""
        raise AssertionError(payload)

    lease = DispatchLease(
        policy,
        request.adapter,
        request.adapter,
        request.actions,
        request.route,
        True,
        revalidate,
        not_the_native_handler,
    )
    return SignedDispatchState(lease, permit, trust, frozenset())
