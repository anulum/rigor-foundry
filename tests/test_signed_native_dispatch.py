# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — signed native preparation and invocation contracts
"""Exercise actual Semgrep preparation, signed admission and repeated boundary refusal."""

from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext, suppress
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from native_dispatch_support import instant, issued_state, repository_and_spec

from rigor_foundry.adapters import AdapterInvocation, AdapterResult, run_adapter
from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.git_provenance import GitTrustPolicy
from rigor_foundry.instruction_dispatch import DispatchRequest
from rigor_foundry.instruction_scope import ActionScope, InstructionScope
from rigor_foundry.native_dispatch import NativeAuditOperation, dispatch_native_audit
from rigor_foundry.signed_instruction_dispatch import (
    SignedDispatchState,
    dispatch_request_digest,
    instruction_policy_digest,
)


@pytest.fixture(scope="module")
def registered_native(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[NativeAuditOperation, ActionScope]:
    """Obtain real registration evidence from an explicitly consented fixture scan."""
    root = tmp_path_factory.mktemp("registered-native")
    repository, spec = repository_and_spec(root / "repository")
    allocation = root / "allocation"
    allocation.mkdir()
    git = GitTrustPolicy(executable="/usr/bin/git")
    observations: list[AdapterInvocation] = []
    result = run_adapter(
        repository.root,
        spec,
        trusted=True,
        git_trust_policy=git,
        workspace_parent=allocation,
        invocation_guard=observations.append,
    )
    assert result.passed
    operation = NativeAuditOperation(
        repository.root,
        allocation,
        spec,
        load_git_inventory(repository.root, git_trust_policy=git).tracked_content_digest,
        "native-runtime-generation-1",
        git,
        observations[0],
        observations[1],
    )
    context = ActionScope(
        "operator",
        operation.runtime_generation,
        "TEST-PROJECT",
        "scan",
        "read",
        str(repository.root),
        "local",
        "test-account",
        "no-billing",
        "local-only",
    )
    return operation, context


@contextmanager
def process_events() -> Iterator[list[str]]:
    """Observe actual subprocess audit events without replacing process execution."""
    recorded: list[str] = []
    active = True

    def observe(event: str, arguments: tuple[object, ...]) -> None:
        """Record process launches only while this observer is active."""
        if active and event == "subprocess.Popen":
            recorded.append(repr(arguments))

    sys.addaudithook(observe)
    try:
        yield recorded
    finally:
        active = False


def test_signed_native_scan_binds_actual_receipt_and_all_effects(
    registered_native: tuple[NativeAuditOperation, ActionScope],
) -> None:
    """Real signed dispatch validates preparation/version/audit and returns matching evidence."""
    operation, context = registered_native
    request = operation.request(context)
    validated: list[DispatchRequest] = []
    current = issued_state(request, validated.append)
    result = dispatch_native_audit(
        operation, request, state=lambda _: nullcontext(current), clock=instant
    )
    receipt = json.loads(result.output)
    assert receipt["cleanup"] == "owned-workspace-removed"
    assert receipt["policy_digest"] == instruction_policy_digest(current.lease.policy)
    assert receipt["request_digest"] == dispatch_request_digest(request)
    assert receipt["runtime_generation"] == operation.runtime_generation
    native = AdapterResult.from_dict(receipt["result"])
    assert native.passed
    assert native.executable_digest == request.adapter.executable_digest
    assert native.command_digest == request.adapter.command_digest
    assert validated == [request, request, request]
    assert all(decision.allowed for decision in result.decisions)
    assert {action.effect for action in request.actions} == {
        "read",
        "write",
        "delete-owned-workspace",
        "execute",
    }
    assert list(operation.workspace_parent.iterdir()) == []
    assert (operation.repository / "untracked.txt").read_text() == "untracked sentinel\n"
    assert (operation.repository / "private/note.txt").read_text() == "private sentinel\n"


def test_tracked_source_change_after_admission_refuses_before_adapter_process(
    registered_native: tuple[NativeAuditOperation, ActionScope],
) -> None:
    """A real post-admission source mutation cannot reach version or audit execution."""
    operation, context = registered_native
    request = operation.request(context)
    calls = 0

    def mutate_after_admission(received: DispatchRequest) -> None:
        """Change a tracked byte at the admitted boundary before workspace preparation."""
        nonlocal calls
        assert received == request
        calls += 1
        if calls == 1:
            (operation.repository / "src/module.py").write_text("VALUE = 2\n")

    current = issued_state(request, mutate_after_admission)
    try:
        with process_events() as events, pytest.raises(RuntimeError, match="clean tracked"):
            dispatch_native_audit(
                operation, request, state=lambda _: nullcontext(current), clock=instant
            )
        assert not any("/run/rigor-adapter-tool" in event for event in events)
        assert list(operation.workspace_parent.iterdir()) == []
    finally:
        (operation.repository / "src/module.py").write_text("VALUE = 1\n")


@pytest.mark.parametrize("fault", ["signature", "read-only", "incomplete-effects", "runtime"])
def test_native_initial_refusal_precedes_all_preparation(
    registered_native: tuple[NativeAuditOperation, ActionScope],
    fault: str,
) -> None:
    """No Git, version, sandbox or workspace effect occurs for an invalid initial request."""
    operation, context = registered_native
    request = operation.request(context)
    validated: list[DispatchRequest] = []
    current = issued_state(request, validated.append)
    if fault == "signature":
        current = replace(current, permit=replace(current.permit, signature_hex="0" * 128))
    elif fault == "read-only":
        original = current.lease.policy.instructions[0]
        policy = replace(
            current.lease.policy,
            instructions=(replace(original, scope=InstructionScope(effect="read")),),
        )
        current = replace(current, lease=replace(current.lease, policy=policy))
    elif fault == "incomplete-effects":
        request = replace(request, actions=request.actions[:1])
    else:
        operation = replace(operation, runtime_generation="native-runtime-generation-2")
    with process_events() as events, pytest.raises((PermissionError, ValueError)):
        dispatch_native_audit(
            operation, request, state=lambda _: nullcontext(current), clock=instant
        )
    assert events == []
    assert list(operation.workspace_parent.iterdir()) == []


@pytest.mark.parametrize("boundary", [2, 3])
def test_expiry_during_preparation_or_version_refuses_audit(
    registered_native: tuple[NativeAuditOperation, ActionScope],
    boundary: int,
) -> None:
    """Fresh signature time checks prevent native audit after an admitted preparation step."""
    operation, context = registered_native
    request = operation.request(context)
    validated: list[DispatchRequest] = []
    current = issued_state(request, validated.append)

    def clock() -> datetime:
        """Expire at the selected real revalidation boundary without sleeping."""
        return datetime(2026, 9, 13, tzinfo=UTC) if len(validated) >= boundary else instant()

    with process_events() as events, pytest.raises(PermissionError, match="inactive or revoked"):
        dispatch_native_audit(
            operation, request, state=lambda _: nullcontext(current), clock=clock
        )
    assert len(validated) == boundary
    assert not any("/run/rigor-adapter-tool" in event for event in events)
    assert list(operation.workspace_parent.iterdir()) == []


@pytest.mark.parametrize("stage", ["version", "audit"])
def test_signed_but_incorrect_invocation_expectation_is_refused(
    registered_native: tuple[NativeAuditOperation, ActionScope],
    stage: str,
) -> None:
    """An authentic signature cannot make a mismatching actual invocation acceptable."""
    operation, context = registered_native
    if stage == "version":
        operation = replace(
            operation,
            version_invocation=replace(operation.version_invocation, command_digest="0" * 64),
        )
    else:
        operation = replace(
            operation,
            audit_invocation=replace(operation.audit_invocation, sandbox_digest="0" * 64),
        )
    request = operation.request(context)
    validated: list[DispatchRequest] = []
    current = issued_state(request, validated.append)
    with (
        process_events() as events,
        pytest.raises(PermissionError, match="differs from signed expectation"),
    ):
        dispatch_native_audit(
            operation, request, state=lambda _: nullcontext(current), clock=instant
        )
    assert not any("/run/rigor-adapter-tool" in event for event in events)
    assert list(operation.workspace_parent.iterdir()) == []


def test_native_host_suppression_cannot_manufacture_receipt(
    registered_native: tuple[NativeAuditOperation, ActionScope],
) -> None:
    """A state provider suppressing failed admission cannot return a successful result."""
    operation, context = registered_native
    request = operation.request(context)
    current = issued_state(request, lambda _: None)
    current = replace(current, permit=replace(current.permit, signature_hex="0" * 128))

    @contextmanager
    def suppressing(received: DispatchRequest) -> Iterator[SignedDispatchState]:
        """Deliberately suppress an actual invalid-signature refusal at host exit."""
        assert received == request
        with suppress(PermissionError):
            yield current

    with pytest.raises(RuntimeError, match="suppressed a failure"):
        dispatch_native_audit(operation, request, state=suppressing, clock=instant)
    assert list(operation.workspace_parent.iterdir()) == []


@pytest.mark.parametrize(
    "fault",
    [
        "relative-root",
        "inside-allocation",
        "generic",
        "stage",
        "missing-version",
        "bad-digest",
        "missing-sandbox",
    ],
)
def test_inconsistent_registration_is_rejected_without_io(
    registered_native: tuple[NativeAuditOperation, ActionScope],
    fault: str,
) -> None:
    """Operation construction rejects unusable registration before any process or snapshot."""
    operation, _ = registered_native
    with process_events() as events, pytest.raises(ValueError):
        if fault == "relative-root":
            replace(operation, repository=Path("relative"))
        elif fault == "inside-allocation":
            replace(operation, workspace_parent=operation.repository / "scratch")
        elif fault == "generic":
            replace(operation, spec=replace(operation.spec, profile=None))
        elif fault == "stage":
            replace(operation, version_invocation=operation.audit_invocation)
        elif fault == "missing-version":
            replace(operation, audit_invocation=replace(operation.audit_invocation, version=None))
        elif fault == "bad-digest":
            replace(
                operation,
                version_invocation=replace(operation.version_invocation, input_digest="unknown"),
            )
        else:
            replace(
                operation,
                audit_invocation=replace(operation.audit_invocation, sandbox_digest=None),
            )
    assert events == []


def test_signed_repository_alias_is_refused_before_preparation(
    registered_native: tuple[NativeAuditOperation, ActionScope],
    tmp_path: Path,
) -> None:
    """A signed lexical alias cannot select another canonical source repository."""
    operation, context = registered_native
    alias = tmp_path / "repository-alias"
    alias.symlink_to(operation.repository, target_is_directory=True)
    operation = replace(operation, repository=alias)
    request = operation.request(context)
    current = issued_state(request, lambda _: None)
    with process_events() as events, pytest.raises(ValueError, match="path alias"):
        dispatch_native_audit(
            operation, request, state=lambda _: nullcontext(current), clock=instant
        )
    assert events == []
    assert list(operation.workspace_parent.iterdir()) == []
