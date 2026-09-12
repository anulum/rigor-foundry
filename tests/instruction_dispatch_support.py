# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — instruction dispatch host fixtures
"""Provide real file-operation host fixtures for unsigned and signed dispatch."""

from __future__ import annotations

import hashlib
import sys
from dataclasses import replace
from pathlib import Path

from rigor_foundry.effective_profile import AdapterLock
from rigor_foundry.instruction_dispatch import DispatchLease, DispatchRequest
from rigor_foundry.instruction_resolution import InstructionPolicy
from rigor_foundry.instruction_scope import ActionScope, InstructionScope, ScopedInstruction
from rigor_foundry.models import canonical_digest


def request_for_file(destination: Path) -> DispatchRequest:
    """Bind one local file replacement to explicit identity and route dimensions."""
    adapter = AdapterLock.build(
        adapter_id="local-file",
        version="1.0.0",
        executable_digest=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        config_digest=canonical_digest({"destination": str(destination)}),
        command_digest=canonical_digest(
            {"entry": "instruction_dispatch_support.file_lease.execute"}
        ),
        environment_digest=canonical_digest({"python": sys.version, "prefix": sys.prefix}),
        domains=("data-and-privacy",),
    )
    action = ActionScope(
        "writer",
        "test-runtime",
        "TEST-PROJECT",
        "edit-file",
        "write",
        str(destination),
        "local",
        "test-account",
        "no-billing",
        "local-only",
    )
    return DispatchRequest(
        (action,), adapter, "local", "test-account", "no-billing", "local-only", b"replacement"
    )


def instruction_rule(
    source: str = "owner-grant",
    *,
    issuer: str = "owner",
    subject: str = "permission",
    allow: bool = True,
    scope: InstructionScope | None = None,
    supersedes: tuple[str, ...] = (),
) -> ScopedInstruction:
    """Construct an explicitly host-authenticated test instruction, not a signature."""
    return ScopedInstruction(
        source, issuer, subject, scope or InstructionScope(), allow, supersedes
    )


def policy_for_rules(*rules: ScopedInstruction) -> InstructionPolicy:
    """Keep platform above owner, and vendor as a constraint-only issuer."""
    return InstructionPolicy(
        rules, ("platform", "owner", "vendor"), frozenset({"owner", "platform"})
    )


def file_lease(
    request: DispatchRequest, destination: Path, policy: InstructionPolicy
) -> DispatchLease:
    """Register a real local writer with host-owned target and effect classification."""

    def execute(payload: bytes) -> bytes:
        """Write exactly the host-owned destination and return its observed bytes."""
        destination.write_bytes(payload)
        return destination.read_bytes()

    def revalidate(received: DispatchRequest) -> None:
        """Assert the immutable request still matches this host registration."""
        assert received == request

    verified = (replace(request.actions[0], target=str(destination), effect="write"),)
    return DispatchLease(
        policy,
        request.adapter,
        request.adapter,
        verified,
        request.route,
        True,
        revalidate,
        execute,
    )
