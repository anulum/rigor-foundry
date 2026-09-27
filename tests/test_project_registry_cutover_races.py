# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — public registry read races
"""Mutate actual files during descriptor-held public registry reads."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from project_registry_syscall_scheduler import SyscallStop, run_traced, write_trace
from test_project_registry_cutover import REGISTRY_PATH, filesystem, plan
from test_project_registry_models import registry

from rigor_foundry.project_registry_cutover import apply_project_registry_cutover
from rigor_foundry.project_registry_models import PROJECT_REGISTRY_MAX_BYTES, ProjectRegistry


def worker_command(
    operation: str, root: Path, transactions: Path, candidate: ProjectRegistry
) -> list[str]:
    """Bind one real worker to explicit root, transaction and registry bytes."""
    candidate_path = root.parent / "worker-candidate.json"
    candidate_path.write_bytes(candidate.to_bytes())
    candidate_path.chmod(0o600)
    return [
        sys.executable,
        str(Path(__file__).with_name("project_registry_race_worker.py")),
        operation,
        str(root),
        str(transactions),
        str(candidate_path),
    ]


@pytest.mark.parametrize("mutation", ["none", "growth", "replacement"])
def test_public_registry_read_schedules_real_mutation(tmp_path: Path, mutation: str) -> None:
    """Reject post-fstat growth and inode substitution; accept the control read."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    apply_project_registry_cutover(root, REGISTRY_PATH, transactions, plan(candidate))
    target = root / REGISTRY_PATH
    original = target.read_bytes()
    original_inode = target.stat().st_ino
    sentinel = root / "owner-data.bin"
    sentinel.write_bytes(b"retain unrelated owner data")
    scheduled: list[SyscallStop] = []

    def mutate(stop: SyscallStop) -> bool:
        """Change the real entry only at its first actual retained-FD read."""
        if not scheduled and stop.entering and stop.number == 0 and stop.path == str(target):
            scheduled.append(stop)
            if mutation == "growth":
                with target.open("ab") as stream:
                    stream.write(b"x" * (PROJECT_REGISTRY_MAX_BYTES + 1))
            elif mutation == "replacement":
                replacement = target.with_name("replacement.json")
                replacement.write_bytes(original)
                replacement.chmod(0o600)
                os.replace(replacement, target)
        return False

    result = run_traced(worker_command("load", root, transactions, candidate), mutate)
    write_trace(tmp_path / "native-load.json", result)
    with pytest.raises(ChildProcessError):
        os.waitpid(result.pid, os.WNOHANG)
    assert result.returncode == 0, result.stderr
    assert len(scheduled) == 1
    outcome = json.loads(result.stdout)
    if mutation == "none":
        assert outcome == {"accepted": True, "outcome": candidate.registry_sha256}
        assert target.read_bytes() == original
    else:
        expected = (
            "current registry exceeds its byte bound"
            if mutation == "growth"
            else "current registry changed while being read"
        )
        assert outcome == {"accepted": False, "error": expected}
        if mutation == "replacement":
            assert target.read_bytes() == original
            assert target.stat().st_ino != original_inode
        else:
            assert target.stat().st_size == len(original) + PROJECT_REGISTRY_MAX_BYTES + 1
    assert sentinel.read_bytes() == b"retain unrelated owner data"


def test_scheduler_reaps_worker_when_observer_fails(tmp_path: Path) -> None:
    """An actual parent failure cannot leave its traced registry child stopped."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    apply_project_registry_cutover(root, REGISTRY_PATH, transactions, plan(candidate))
    target = root / REGISTRY_PATH
    observed: list[int] = []
    before = set(os.listdir("/proc/self/fd"))

    def fail(stop: SyscallStop) -> bool:
        """Raise in the real supervisor at the child's actual target read."""
        if stop.entering and stop.number == 0 and stop.path == str(target):
            observed.append(stop.pid)
            raise RuntimeError("observer failed")
        return False

    with pytest.raises(RuntimeError, match="observer failed"):
        run_traced(worker_command("load", root, transactions, candidate), fail)
    assert len(observed) == 1
    with pytest.raises(ChildProcessError):
        os.waitpid(observed[0], os.WNOHANG)
    assert set(os.listdir("/proc/self/fd")) == before
    assert target.read_bytes() == candidate.to_bytes()
