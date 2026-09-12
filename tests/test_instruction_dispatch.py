# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — instruction dispatch filesystem contracts
"""Observe real file effects under scoped host policy and adapter evidence."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from instruction_dispatch_support import (
    file_lease,
    instruction_rule,
    policy_for_rules,
    request_for_file,
)

from rigor_foundry.instruction_dispatch import (
    DispatchLease,
    DispatchRequest,
    dispatch_instruction_action,
)
from rigor_foundry.instruction_scope import ActionScope, InstructionScope, ScopedInstruction


def test_higher_scope_and_standing_grant_reach_real_writer(tmp_path: Path) -> None:
    """Higher placement permission and standing grant survive lower scoped bans."""
    destination = tmp_path / "document"
    request = request_for_file(destination)
    rules = (
        instruction_rule(scope=InstructionScope(target=str(destination))),
        instruction_rule("placement-exception", subject="placement"),
        instruction_rule("old-placement", issuer="vendor", subject="placement", allow=False),
        instruction_rule(
            "unrelated-runtime",
            issuer="vendor",
            allow=False,
            scope=InstructionScope(runtime="other-runtime"),
        ),
    )
    lease = file_lease(request, destination, policy_for_rules(*rules))
    for _ in range(2):
        result = dispatch_instruction_action(request, state=lambda _: nullcontext(lease))
        assert result.output == destination.read_bytes() == b"replacement"
        assert result.decisions[0].excluded == ("unrelated-runtime",)
        assert "old-placement" in result.decisions[0].overridden


@pytest.mark.parametrize(
    "fault",
    [
        "role-only",
        "missing-grant",
        "independent-deny",
        "equal-conflict",
        "unknown-issuer",
        "unknown-override",
        "lower-override",
        "cross-subject",
        "cycle",
        "unknown-target-issuer",
    ],
)
def test_instruction_refusal_preserves_actual_target(tmp_path: Path, fault: str) -> None:
    """Ambiguous, untrusted or non-granting policy never invokes the local writer."""
    destination = tmp_path / "document"
    destination.write_bytes(b"owner original")
    request = request_for_file(destination)
    rules: tuple[ScopedInstruction, ...] = (instruction_rule(),)
    if fault == "role-only":
        rules = (instruction_rule(issuer="vendor"),)
    elif fault == "missing-grant":
        rules = ()
    elif fault == "independent-deny":
        rules += (
            instruction_rule("platform-limit", issuer="platform", subject="platform", allow=False),
        )
    elif fault == "equal-conflict":
        rules += (instruction_rule("conflict", allow=False),)
    elif fault == "unknown-issuer":
        rules += (instruction_rule("unverified", issuer="unknown"),)
    elif fault == "unknown-override":
        rules = (instruction_rule(supersedes=("absent",)),)
    elif fault == "lower-override":
        rules += (
            instruction_rule("vendor-override", issuer="vendor", supersedes=("owner-grant",)),
        )
    elif fault == "cross-subject":
        rules += (
            instruction_rule(
                "different-subject", subject="placement", supersedes=("owner-grant",)
            ),
        )
    elif fault == "cycle":
        rules = (
            instruction_rule(supersedes=("other",)),
            instruction_rule("other", supersedes=("owner-grant",)),
        )
    else:
        rules = (
            instruction_rule(supersedes=("unverified",)),
            instruction_rule("unverified", issuer="unknown"),
        )
    lease = file_lease(request, destination, policy_for_rules(*rules))
    with pytest.raises(PermissionError, match="resolution"):
        dispatch_instruction_action(request, state=lambda _: nullcontext(lease))
    assert destination.read_bytes() == b"owner original"


@pytest.mark.parametrize(
    "fault",
    [
        "unavailable",
        "adapter",
        "unknown-effects",
        "extra-effect",
        "provider",
        "account",
        "cost",
        "privacy",
        "os",
    ],
)
def test_runtime_evidence_refuses_before_real_effect(tmp_path: Path, fault: str) -> None:
    """Unavailable or mismatched runtime facts cannot borrow an action grant."""
    destination = tmp_path / "document"
    request = request_for_file(destination)
    lease = file_lease(request, destination, policy_for_rules(instruction_rule()))
    if fault == "unavailable":
        lease = replace(lease, advertised_adapter=None)
    elif fault == "adapter":
        lease = replace(lease, verified_adapter=replace(request.adapter, version="2.0.0"))
    elif fault == "unknown-effects":
        lease = replace(lease, verified_actions=None)
    elif fault == "extra-effect":
        lease = replace(
            lease,
            verified_actions=(*request.actions, replace(request.actions[0], effect="create-pr")),
        )
    elif fault == "os":
        lease = replace(lease, os_capable=False)
    else:
        index = {"provider": 0, "account": 1, "cost": 2, "privacy": 3}[fault]
        route = list(request.route)
        route[index] = "different"
        lease = replace(lease, route=(route[0], route[1], route[2], route[3]))
    with pytest.raises(PermissionError):
        dispatch_instruction_action(request, state=lambda _: nullcontext(lease))
    assert not destination.exists()


def test_revocation_after_policy_preparation_prevents_effect(tmp_path: Path) -> None:
    """The final host check observes revocation before invoking the real writer."""
    destination = tmp_path / "document"
    request = request_for_file(destination)
    revoked = False

    def current(received: DispatchRequest) -> None:
        """Consult live host revocation state rather than a preparation snapshot."""
        assert received == request
        if revoked:
            raise PermissionError("revoked")

    lease = replace(
        file_lease(request, destination, policy_for_rules(instruction_rule())), revalidate=current
    )
    revoked = True
    with pytest.raises(PermissionError, match="revoked"):
        dispatch_instruction_action(request, state=lambda _: nullcontext(lease))
    assert not destination.exists()


def test_suppression_cannot_turn_failure_into_success(tmp_path: Path) -> None:
    """A broken host context cannot swallow denial into an empty successful call."""
    destination = tmp_path / "document"
    request = request_for_file(destination)
    lease = file_lease(request, destination, policy_for_rules())

    @contextmanager
    def state(received: DispatchRequest) -> Iterator[DispatchLease]:
        """Deliberately suppress admission failure to exercise the outer boundary."""
        assert received == request
        try:
            yield lease
        except PermissionError:
            return

    with pytest.raises(RuntimeError, match="suppressed"):
        dispatch_instruction_action(request, state=state)
    assert not destination.exists()


def test_equal_authority_explicit_override_reaches_writer(tmp_path: Path) -> None:
    """An explicit same-authority replacement resolves its predecessor locally."""
    destination = tmp_path / "document"
    request = request_for_file(destination)
    policy = policy_for_rules(
        instruction_rule("old", allow=False),
        instruction_rule(supersedes=("old", "out-of-scope")),
        instruction_rule("out-of-scope", allow=False, scope=InstructionScope(project="other")),
    )
    result = dispatch_instruction_action(
        request, state=lambda _: nullcontext(file_lease(request, destination, policy))
    )
    assert result.output == destination.read_bytes() == request.payload
    assert result.decisions[0].overridden == ("old",)


@pytest.mark.parametrize(
    "fault",
    ["no-effects", "duplicate-effects", "mutable-effects", "mutable-payload", "route", "lock"],
)
def test_malformed_dispatch_never_reaches_host(tmp_path: Path, fault: str) -> None:
    """Malformed requests fail before acquiring a host or touching its target."""
    destination = tmp_path / "document"
    request = request_for_file(destination)
    lease = file_lease(request, destination, policy_for_rules(instruction_rule()))
    if fault == "no-effects":
        request = replace(request, actions=())
    elif fault == "duplicate-effects":
        request = replace(request, actions=request.actions * 2)
    elif fault == "mutable-effects":
        request = replace(request, actions=cast(tuple[ActionScope, ...], list(request.actions)))
    elif fault == "mutable-payload":
        request = replace(request, payload=cast(bytes, bytearray(b"mutable")))
    elif fault == "route":
        request = replace(request, provider="different")
    else:
        request = replace(request, adapter=replace(request.adapter, adapter_digest="0" * 64))
    acquired: list[DispatchRequest] = []

    @contextmanager
    def state(received: DispatchRequest) -> Iterator[DispatchLease]:
        """Record any host acquisition independently of target-side effects."""
        acquired.append(received)
        yield lease

    with pytest.raises(ValueError):
        dispatch_instruction_action(request, state=state)
    assert not acquired and not destination.exists()


def test_denied_write_leaves_authorised_read_operational(tmp_path: Path) -> None:
    """A per-effect write conflict does not block a separate real file read."""
    destination = tmp_path / "document"
    destination.write_bytes(b"preserved original")
    write = request_for_file(destination)
    policy = policy_for_rules(
        instruction_rule(),
        instruction_rule("write-conflict", allow=False, scope=InstructionScope(effect="write")),
    )
    writer = file_lease(write, destination, policy)
    with pytest.raises(PermissionError):
        dispatch_instruction_action(write, state=lambda _: nullcontext(writer))
    read = replace(write, actions=(replace(write.actions[0], effect="read"),), payload=b"")
    reader = replace(
        file_lease(read, destination, policy),
        verified_actions=read.actions,
        execute=lambda _: destination.read_bytes(),
    )
    result = dispatch_instruction_action(read, state=lambda _: nullcontext(reader))
    assert result.output == destination.read_bytes() == b"preserved original"
