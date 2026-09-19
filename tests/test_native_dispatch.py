# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native dispatch invocation boundaries
"""Exercise real native invocation guards, allocation and refusal without syscall mocks."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from native_dispatch_support import repository_and_spec

from rigor_foundry.adapters import AdapterInvocation, run_adapter
from rigor_foundry.models import AdapterSpec


def test_native_guard_observes_actual_version_and_audit_identity(tmp_path: Path) -> None:
    """Both guarded stages match the successful real scan and clean only owned scratch."""
    repository, spec = repository_and_spec(tmp_path / "repository")
    allocation = tmp_path / "allocation"
    allocation.mkdir()
    observations: list[AdapterInvocation] = []
    result = run_adapter(
        repository.root,
        spec,
        trusted=True,
        workspace_parent=allocation,
        invocation_guard=observations.append,
    )
    assert result.passed
    assert [item.stage for item in observations] == ["version", "audit"]
    version, audit = observations
    assert version.version is None and version.sandbox_digest is None
    assert audit.executable_digest == version.executable_digest == result.executable_digest
    assert audit.command_digest == result.command_digest
    assert audit.environment_digest == result.environment_digest
    assert audit.sandbox_digest == result.sandbox_digest
    assert result.profile_evidence is not None
    assert audit.version == result.profile_evidence.tool_version
    assert audit.configuration_digest == result.profile_evidence.configuration_digest
    assert audit.input_digest == result.profile_evidence.input_digest
    assert list(allocation.iterdir()) == []
    assert (repository.root / "private/note.txt").read_text() == "private sentinel\n"
    assert (repository.root / "untracked.txt").read_text() == "untracked sentinel\n"


def test_generic_adapter_cannot_ignore_guard_or_allocation(tmp_path: Path) -> None:
    """Unsupported generic execution refuses the guarded contract without invoking it."""
    repository, _ = repository_and_spec(tmp_path / "repository")
    spec = AdapterSpec.from_dict({"name": "metadata", "command": ["{python}", "--version"]}, 0)

    def forbidden(observation: AdapterInvocation) -> None:
        """Report any attempted invocation of an unsupported guard contract."""
        raise AssertionError(observation)

    with pytest.raises(ValueError, match="explicit trusted consent"):
        run_adapter(repository.root, spec, invocation_guard=forbidden)
    with pytest.raises(ValueError, match="built-in adapter profile"):
        run_adapter(repository.root, spec, trusted=True, invocation_guard=forbidden)
    with pytest.raises(ValueError, match="built-in adapter profile"):
        run_adapter(repository.root, spec, trusted=True, workspace_parent=tmp_path)


@pytest.mark.parametrize("stage", ["version", "audit"])
def test_native_refusal_starts_no_subsequent_process(tmp_path: Path, stage: str) -> None:
    """Observe real Popen audit events and prove a refused stage launches no process."""
    repository, spec = repository_and_spec(tmp_path / "repository")
    allocation = tmp_path / "allocation"
    allocation.mkdir()
    events: list[str] = []
    active = True
    boundary: int | None = None

    def observe(event: str, arguments: tuple[object, ...]) -> None:
        """Record native process starts without altering the actual subprocess operation."""
        if active and event == "subprocess.Popen":
            events.append(repr(arguments))

    def refuse(observation: AdapterInvocation) -> None:
        """Refuse the selected stage and retain the process-event boundary."""
        nonlocal boundary
        if observation.stage == stage:
            boundary = len(events)
            raise PermissionError("host invocation refused")

    sys.addaudithook(observe)
    try:
        with pytest.raises(PermissionError, match="host invocation refused"):
            run_adapter(
                repository.root,
                spec,
                trusted=True,
                workspace_parent=allocation,
                invocation_guard=refuse,
            )
    finally:
        active = False
    assert boundary is not None
    assert len(events) == boundary
    assert list(allocation.iterdir()) == []
    assert (repository.root / "private/note.txt").read_text() == "private sentinel\n"
    assert (repository.root / "untracked.txt").read_text() == "untracked sentinel\n"
