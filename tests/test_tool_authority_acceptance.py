# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — tool-authority full14 public-boundary acceptance
"""Exercise every ratified authority case through real dispatch side effects."""

from __future__ import annotations

import hashlib
import threading
import urllib.request
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager, nullcontext
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import cast

import pytest
from instruction_dispatch_support import instruction_rule, policy_for_rules, request_for_file

from rigor_foundry.effective_profile import AdapterLock
from rigor_foundry.instruction_dispatch import (
    DispatchLease,
    DispatchRequest,
    dispatch_instruction_action,
)
from rigor_foundry.instruction_resolution import InstructionPolicy
from rigor_foundry.instruction_scope import ActionScope, InstructionScope
from rigor_foundry.models import canonical_digest


class _CountingServer(HTTPServer):
    """Loopback-only transport whose call count is independent of dispatch output."""

    calls: int = 0
    remote_ref: str = "initial"


class _CountingHandler(BaseHTTPRequestHandler):
    """Count a real HTTP request and return an empty successful response."""

    def do_POST(self) -> None:
        """Consume one bounded request body and record the transport effect."""
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        server = cast(_CountingServer, self.server)
        server.calls += 1
        server.remote_ref = "updated"
        self.send_response(204)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        """Keep the isolated acceptance service silent."""


@contextmanager
def _local_transport() -> Iterator[tuple[str, _CountingServer]]:
    """Serve a real loopback HTTP endpoint for the lifetime of one acceptance case."""
    server = _CountingServer(("127.0.0.1", 0), _CountingHandler)
    server.calls = 0
    server.remote_ref = "initial"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = cast(tuple[str, int], server.server_address)
    try:
        yield f"http://{host}:{port}/effect", server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _transport_request(url: str, effect: str) -> DispatchRequest:
    """Bind one PR-like local transport action to an exact adapter and route."""
    identity = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    adapter = AdapterLock.build(
        adapter_id="local-transport",
        version="1.0.0",
        executable_digest=identity,
        config_digest=canonical_digest({"url": url}),
        command_digest=canonical_digest({"method": "POST"}),
        environment_digest=canonical_digest({"transport": "loopback-http"}),
        domains=("supply-chain",),
    )
    action = ActionScope(
        "operator",
        "test-runtime",
        "TEST-PROJECT",
        "transport",
        effect,
        url,
        "local-http",
        "test-account",
        "no-billing",
        "local-only",
    )
    return DispatchRequest(
        (action,),
        adapter,
        action.provider,
        action.account,
        action.cost_class,
        action.privacy_class,
        b"acceptance",
    )


def _lease(
    request: DispatchRequest,
    policy: InstructionPolicy,
    execute: Callable[[bytes], bytes],
) -> DispatchLease:
    """Register exact effects and a real handler under one current host lease."""

    def revalidate(received: DispatchRequest) -> None:
        """Require the same immutable request at the final effect boundary."""
        assert received == request

    return DispatchLease(
        policy,
        request.adapter,
        request.adapter,
        request.actions,
        request.route,
        True,
        revalidate,
        execute,
    )


def _file_lease(request: DispatchRequest, policy: InstructionPolicy) -> DispatchLease:
    """Register a writer whose return bytes are read back from the actual target."""
    destination = Path(request.actions[0].target)

    def execute(payload: bytes) -> bytes:
        """Write only the exact registered target and return observed bytes."""
        destination.write_bytes(payload)
        return destination.read_bytes()

    return _lease(request, policy, execute)


def _state_for(
    lease: DispatchLease,
) -> Callable[[DispatchRequest], AbstractContextManager[DispatchLease]]:
    """Return a typed fixed host-state provider for one acceptance lease."""

    def current(_: DispatchRequest) -> AbstractContextManager[DispatchLease]:
        """Retain the exact supplied lease for this dispatch attempt."""
        return nullcontext(lease)

    return current


def _transport_lease(request: DispatchRequest, policy: InstructionPolicy) -> DispatchLease:
    """Register an actual HTTP POST handler for an exact local-service target."""

    def execute(payload: bytes) -> bytes:
        """Perform one bounded loopback transport call and return its status."""
        outbound = urllib.request.Request(request.actions[0].target, data=payload, method="POST")
        with urllib.request.urlopen(outbound, timeout=2) as response:  # nosec B310
            return str(response.status).encode("ascii")

    return _lease(request, policy, execute)


def test_case01_unrelated_vendor_scope_is_excluded_and_write_executes(tmp_path: Path) -> None:
    """Case 1: an unrelated overlay contributes nothing to an authorised real write."""
    destination = tmp_path / "document"
    request = request_for_file(destination)
    policy = policy_for_rules(
        instruction_rule(),
        instruction_rule(
            "vendor-other-project",
            issuer="vendor",
            allow=False,
            scope=InstructionScope(project="OTHER-PROJECT"),
        ),
    )
    result = dispatch_instruction_action(
        request, state=lambda _: nullcontext(_file_lease(request, policy))
    )
    assert destination.read_bytes() == request.payload == result.output
    assert result.decisions[0].excluded == ("vendor-other-project",)


def test_case02_role_header_has_zero_push_transport_calls() -> None:
    """Case 2: a vendor role label is not a grant and cannot contact a remote."""
    with _local_transport() as (url, server):
        request = _transport_request(url, "push")
        policy = policy_for_rules(instruction_rule("role-header", issuer="vendor"))
        with pytest.raises(PermissionError, match="resolution"):
            dispatch_instruction_action(
                request, state=lambda _: nullcontext(_transport_lease(request, policy))
            )
        assert server.calls == 0
        assert server.remote_ref == "initial"


def test_case03_exact_placement_exception_does_not_authorise_adjacent_path(
    tmp_path: Path,
) -> None:
    """Case 3: a higher exact exception permits one path while its sibling refuses."""
    approved = tmp_path / "approved"
    adjacent = tmp_path / "adjacent"
    rules = (
        instruction_rule(),
        instruction_rule(
            "placement-exception",
            subject="placement",
            scope=InstructionScope(target=str(approved)),
            supersedes=("vendor-placement",),
        ),
        instruction_rule("vendor-placement", issuer="vendor", subject="placement", allow=False),
    )
    policy = policy_for_rules(*rules)
    accepted = request_for_file(approved)
    dispatch_instruction_action(
        accepted, state=lambda _: nullcontext(_file_lease(accepted, policy))
    )
    refused = request_for_file(adjacent)
    with pytest.raises(PermissionError, match="resolution"):
        dispatch_instruction_action(
            refused, state=lambda _: nullcontext(_file_lease(refused, policy))
        )
    assert approved.read_bytes() == accepted.payload
    assert not adjacent.exists()


def test_case04_higher_instruction_wins_but_independent_constraint_remains(
    tmp_path: Path,
) -> None:
    """Case 4: issuer precedence cannot erase an independent platform denial."""
    allowed = request_for_file(tmp_path / "allowed")
    precedence = policy_for_rules(
        instruction_rule(), instruction_rule("vendor-deny", issuer="vendor", allow=False)
    )
    dispatch_instruction_action(
        allowed, state=lambda _: nullcontext(_file_lease(allowed, precedence))
    )
    blocked = request_for_file(tmp_path / "blocked")
    independent = policy_for_rules(
        instruction_rule(),
        instruction_rule("vendor-deny", issuer="vendor", allow=False),
        instruction_rule("platform-deny", issuer="platform", subject="platform", allow=False),
    )
    with pytest.raises(PermissionError, match="resolution"):
        dispatch_instruction_action(
            blocked, state=lambda _: nullcontext(_file_lease(blocked, independent))
        )
    assert Path(allowed.actions[0].target).read_bytes() == allowed.payload
    assert not Path(blocked.actions[0].target).exists()


def test_case05_unavailable_os_capability_refuses_before_handler(tmp_path: Path) -> None:
    """Case 5: a valid grant cannot manufacture a missing operating-system capability."""
    request = request_for_file(tmp_path / "document")
    policy = policy_for_rules(instruction_rule())
    lease = replace(_file_lease(request, policy), os_capable=False)
    with pytest.raises(PermissionError, match="operating-system"):
        dispatch_instruction_action(request, state=lambda _: nullcontext(lease))
    assert not Path(request.actions[0].target).exists()


def test_case06_claim_only_policy_cannot_mutate_or_publish(tmp_path: Path) -> None:
    """Case 6: an authenticated claim remains evidence and never becomes permission."""
    request = request_for_file(tmp_path / "document")
    policy = policy_for_rules(instruction_rule("task-claim", subject="claim"))
    with pytest.raises(PermissionError, match="resolution"):
        dispatch_instruction_action(
            request, state=lambda _: nullcontext(_file_lease(request, policy))
        )
    assert not Path(request.actions[0].target).exists()


def test_case07_historical_tool_without_current_advertisement_never_runs(
    tmp_path: Path,
) -> None:
    """Case 7: a documented adapter identity is inert when current advertisement is absent."""
    request = request_for_file(tmp_path / "document")
    policy = policy_for_rules(instruction_rule())
    lease = replace(_file_lease(request, policy), advertised_adapter=None)
    with pytest.raises(PermissionError, match="advertisement"):
        dispatch_instruction_action(request, state=lambda _: nullcontext(lease))
    assert not Path(request.actions[0].target).exists()


def test_case08_advertised_tool_with_unknown_effects_never_runs(tmp_path: Path) -> None:
    """Case 8: current availability cannot substitute for verified effects."""
    request = request_for_file(tmp_path / "document")
    policy = policy_for_rules(instruction_rule())
    lease = replace(_file_lease(request, policy), verified_actions=None)
    with pytest.raises(PermissionError, match="effects"):
        dispatch_instruction_action(request, state=lambda _: nullcontext(lease))
    assert not Path(request.actions[0].target).exists()


def test_case09_adapter_identity_mismatches_refuse_and_exact_lock_executes(
    tmp_path: Path,
) -> None:
    """Case 9: version/config/command/environment mismatches fail before exact success."""
    request = request_for_file(tmp_path / "document")
    policy = policy_for_rules(instruction_rule())
    base = request.adapter
    replacements: tuple[dict[str, str], ...] = (
        {"version": "2.0.0"},
        {"config_digest": "0" * 64},
        {"command_digest": "1" * 64},
        {"environment_digest": "2" * 64},
    )
    for changed in replacements:
        candidate = AdapterLock.build(
            adapter_id=base.adapter_id,
            version=changed.get("version", base.version),
            executable_digest=base.executable_digest,
            config_digest=changed.get("config_digest", base.config_digest),
            command_digest=changed.get("command_digest", base.command_digest),
            environment_digest=changed.get("environment_digest", base.environment_digest),
            domains=base.domains,
        )
        lease = replace(
            _file_lease(request, policy),
            advertised_adapter=candidate,
            verified_adapter=candidate,
        )
        with pytest.raises(PermissionError, match="adapter"):
            dispatch_instruction_action(request, state=_state_for(lease))
        assert not Path(request.actions[0].target).exists()
    result = dispatch_instruction_action(
        request, state=lambda _: nullcontext(_file_lease(request, policy))
    )
    assert result.output == Path(request.actions[0].target).read_bytes() == request.payload


def test_case10_review_grant_has_zero_create_pr_transport_calls() -> None:
    """Case 10: review permission cannot be widened into a PR-producing effect."""
    with _local_transport() as (url, server):
        request = _transport_request(url, "create-pr")
        policy = policy_for_rules(instruction_rule(scope=InstructionScope(effect="review")))
        with pytest.raises(PermissionError, match="resolution"):
            dispatch_instruction_action(
                request, state=lambda _: nullcontext(_transport_lease(request, policy))
            )
        assert server.calls == 0


def test_case11_standing_edit_grant_repeats_only_on_exact_target(tmp_path: Path) -> None:
    """Case 11: one current standing grant permits repeats but not an adjacent target."""
    destination = tmp_path / "document"
    request = request_for_file(destination)
    policy = policy_for_rules(instruction_rule(scope=InstructionScope(target=str(destination))))
    for _ in range(2):
        dispatch_instruction_action(
            request, state=lambda _: nullcontext(_file_lease(request, policy))
        )
    adjacent = request_for_file(tmp_path / "adjacent")
    with pytest.raises(PermissionError, match="resolution"):
        dispatch_instruction_action(
            adjacent, state=lambda _: nullcontext(_file_lease(adjacent, policy))
        )
    assert destination.read_bytes() == request.payload
    assert not Path(adjacent.actions[0].target).exists()


def test_case12_route_fallback_mismatch_refuses_every_dimension(tmp_path: Path) -> None:
    """Case 12: provider, account, billing and privacy identities admit no fallback."""
    request = request_for_file(tmp_path / "document")
    policy = policy_for_rules(instruction_rule())
    for index in range(4):
        route = list(request.route)
        route[index] = "fallback"
        lease = replace(
            _file_lease(request, policy), route=cast(tuple[str, str, str, str], tuple(route))
        )
        with pytest.raises(PermissionError, match="provider, account"):
            dispatch_instruction_action(request, state=_state_for(lease))
    assert not Path(request.actions[0].target).exists()


def test_case13_revocation_at_final_boundary_has_zero_handler_effects(
    tmp_path: Path,
) -> None:
    """Case 13: live revocation after policy preparation prevents the real write."""
    request = request_for_file(tmp_path / "document")
    policy = policy_for_rules(instruction_rule())
    lease = _file_lease(request, policy)

    def revoked(received: DispatchRequest) -> None:
        """Observe the exact prepared request and refuse its final effect boundary."""
        assert received == request
        raise PermissionError("revoked during preparation")

    lease = replace(lease, revalidate=revoked)
    with pytest.raises(PermissionError, match="revoked during preparation"):
        dispatch_instruction_action(request, state=lambda _: nullcontext(lease))
    assert not Path(request.actions[0].target).exists()


def test_case14_write_conflict_does_not_block_unrelated_read(tmp_path: Path) -> None:
    """Case 14: a refused write leaves bytes intact and an authorised read operational."""
    destination = tmp_path / "document"
    destination.write_bytes(b"owner bytes")
    write = request_for_file(destination)
    policy = policy_for_rules(
        instruction_rule(),
        instruction_rule("write-conflict", allow=False, scope=InstructionScope(effect="write")),
    )
    with pytest.raises(PermissionError, match="resolution"):
        dispatch_instruction_action(write, state=lambda _: nullcontext(_file_lease(write, policy)))
    read = replace(write, actions=(replace(write.actions[0], effect="read"),), payload=b"")
    result = dispatch_instruction_action(
        read,
        state=lambda _: nullcontext(_lease(read, policy, lambda _: destination.read_bytes())),
    )
    assert result.output == destination.read_bytes() == b"owner bytes"
