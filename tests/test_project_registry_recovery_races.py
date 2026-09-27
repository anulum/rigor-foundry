# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — public registry recovery races
"""Schedule real process death and filesystem changes during public recovery."""

from __future__ import annotations

import json
import os
import signal
from pathlib import Path

import pytest
from project_registry_syscall_scheduler import SyscallStop, run_traced, write_trace
from test_project_registry_cutover import REGISTRY_PATH, filesystem, plan
from test_project_registry_cutover_races import worker_command
from test_project_registry_models import registry
from test_project_registry_recovery import successor

from rigor_foundry.project_registry_cutover import apply_project_registry_cutover
from rigor_foundry.project_registry_models import ProjectRegistry


def interrupted_transaction(
    tmp_path: Path, *, prior: bool, committed: bool
) -> tuple[Path, Path, ProjectRegistry, Path]:
    """Kill real cutover after a rename on either side of the registry commit."""
    first = registry()
    root, transactions = filesystem(tmp_path, first)
    candidate = first
    if prior:
        apply_project_registry_cutover(root, REGISTRY_PATH, transactions, plan(first))
        candidate = successor(first)
    target = root / (REGISTRY_PATH if committed else candidate.consumers[0].path)
    reached: list[SyscallStop] = []

    def interrupt(stop: SyscallStop) -> bool:
        """Kill after the actual successful target rename syscall returns."""
        if not stop.entering and stop.number in {82, 264, 316} and stop.path == str(target):
            assert stop.result == 0
            reached.append(stop)
            return True
        return False

    result = run_traced(worker_command("apply", root, transactions, candidate), interrupt)
    write_trace(tmp_path / "native-cutover.json", result)
    with pytest.raises(ChildProcessError):
        os.waitpid(result.pid, os.WNOHANG)
    assert result.returncode == -signal.SIGKILL, result.stderr
    assert len(reached) == 1
    transaction = transactions / f"{candidate.generation_id}_{candidate.registry_sha256}"
    assert json.loads((transaction / "journal.json").read_bytes())["state"] == "applying"
    assert not (transaction / "receipt.json").exists()
    return root, transactions, candidate, transaction


@pytest.mark.parametrize("committed", [False, True])
@pytest.mark.parametrize("target_kind", ["registry", "consumer"])
def test_recovery_rejects_real_final_verification_change(
    tmp_path: Path, committed: bool, target_kind: str
) -> None:
    """Reject actual bytes changed after commit-point selection or restoration."""
    root, transactions, candidate, transaction = interrupted_transaction(
        tmp_path, prior=True, committed=committed
    )
    target = root / (REGISTRY_PATH if target_kind == "registry" else candidate.consumers[0].path)
    reads = 0
    reached: list[SyscallStop] = []
    required = (2 if committed else 3) if target_kind == "registry" else (1 if committed else 2)

    def mutate(stop: SyscallStop) -> bool:
        """Replace real bytes before the final independently repeated read."""
        nonlocal reads
        if stop.entering and stop.number == 257 and stop.path == str(target):
            reads += 1
            if reads == required:
                target.write_bytes(b"{}")
                reached.append(stop)
        return False

    result = run_traced(worker_command("recover", root, transactions, candidate), mutate)
    write_trace(tmp_path / "native-recovery.json", result)
    with pytest.raises(ChildProcessError):
        os.waitpid(result.pid, os.WNOHANG)
    assert result.returncode == 0, result.stderr
    assert len(reached) == 1
    prefix = "committed" if committed else "recovered"
    suffix = "candidate" if committed else "prior state"
    assert json.loads(result.stdout) == {
        "accepted": False,
        "error": f"{prefix} {target_kind} does not match {suffix}",
    }
    assert target.read_bytes() == b"{}"
    assert not (transaction / "receipt.json").exists()


@pytest.mark.parametrize("committed", [False, True])
@pytest.mark.parametrize("prior", [False, True])
def test_native_interruption_recovers_without_mutation(
    tmp_path: Path, committed: bool, prior: bool
) -> None:
    """Actual process death leaves a recoverable transaction on either side."""
    root, transactions, candidate, transaction = interrupted_transaction(
        tmp_path, prior=prior, committed=committed
    )

    def observe(stop: SyscallStop) -> bool:
        """Leave actual syscall results and all fixture files unchanged."""
        return False

    result = run_traced(worker_command("recover", root, transactions, candidate), observe)
    write_trace(tmp_path / "native-recovery.json", result)
    with pytest.raises(ChildProcessError):
        os.waitpid(result.pid, os.WNOHANG)
    assert result.returncode == 0, result.stderr
    outcome = "committed" if committed else "rolled-back"
    assert json.loads(result.stdout) == {"accepted": True, "outcome": outcome}
    assert json.loads((transaction / "receipt.json").read_bytes())["outcome"] == outcome


@pytest.mark.parametrize("disappearance", [False, True])
def test_recovery_rejects_real_snapshot_set_change(tmp_path: Path, disappearance: bool) -> None:
    """Reject real snapshot creation/removal after its closed directory listing."""
    root, transactions, candidate, transaction = interrupted_transaction(
        tmp_path, prior=disappearance, committed=False
    )
    prior_root = transaction / "prior"
    snapshot = prior_root / f"0000_{candidate.consumers[0].consumer_id}.json"
    reached: list[SyscallStop] = []

    def mutate(stop: SyscallStop) -> bool:
        """Change the directory only after the kernel's final listing response."""
        if (
            not reached
            and not stop.entering
            and stop.number == 217
            and stop.path == str(prior_root)
            and stop.result == 0
        ):
            if disappearance:
                snapshot.unlink()
            else:
                snapshot.write_bytes(b"{}")
                snapshot.chmod(0o600)
            reached.append(stop)
        return False

    result = run_traced(worker_command("recover", root, transactions, candidate), mutate)
    write_trace(tmp_path / "native-recovery.json", result)
    with pytest.raises(ChildProcessError):
        os.waitpid(result.pid, os.WNOHANG)
    assert result.returncode == 0, result.stderr
    assert len(reached) == 1
    expected = (
        "required prior consumer snapshot is absent"
        if disappearance
        else "unexpected prior consumer snapshot is present"
    )
    assert json.loads(result.stdout) == {"accepted": False, "error": expected}
    assert snapshot.exists() != disappearance
    assert not (transaction / "receipt.json").exists()
