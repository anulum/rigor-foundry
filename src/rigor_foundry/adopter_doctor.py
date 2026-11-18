# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Adopter preflight diagnostics
"""Observe installed and repository prerequisites before an adopter audit."""

from __future__ import annotations

from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from typing import Literal

from .adapter_runtime import resolved_executable, working_directory
from .adapter_workspace import verify_profile_inputs
from .adapters import run_adapter
from .git_inventory import GitInventory, load_git_inventory
from .git_provenance import GitRunner, GitTrustPolicy
from .policy_models import AdapterSpec
from .scanner import resolve_policy
from .version import __version__

# Bound the no-op probe so namespace setup cannot stall the preflight.
_SANDBOX_PROBE_TIMEOUT_SECONDS = 5


@dataclass(frozen=True)
class Prerequisite:
    """One bounded observation and the action needed if it is unavailable."""

    check: str
    status: Literal["ready", "unavailable", "not-assessed"]
    required: bool
    detail: str


def _package() -> Prerequisite:
    """Check the actual installed version and console entry-point metadata."""
    try:
        installed = distribution("rigor-foundry")
    except PackageNotFoundError:
        return Prerequisite("package", "unavailable", True, "Install the verified wheel.")
    if installed.version != __version__ or not installed.entry_points.select(
        group="console_scripts", name="rigor", value="rigor_foundry.cli:main"
    ):
        return Prerequisite(
            "package", "unavailable", True, "Reinstall the wheel matching the running source."
        )
    return Prerequisite("package", "ready", True, f"RigorFoundry {installed.version}")


def _sandbox(root: Path, required: bool) -> Prerequisite:
    """Exercise the standard sandbox with its fixed system no-op."""
    probe = AdapterSpec(
        name="doctor-sandbox",
        command=("/usr/bin/true",),
        timeout_seconds=_SANDBOX_PROBE_TIMEOUT_SECONDS,
        scope="both",
        working_directory=".",
        required=required,
        domains=(),
    )
    try:
        result = run_adapter(root, probe, trusted=True)
    except (OSError, RuntimeError, ValueError):
        pass
    else:
        if result.returncode == 0 and not result.timed_out:
            return Prerequisite("sandbox", "ready", required, "Bubblewrap ran the isolated probe.")
    return Prerequisite(
        "sandbox",
        "unavailable",
        required,
        "Check the supported Bubblewrap package and host namespace configuration.",
    )


def _adapter(inventory: GitInventory, spec: AdapterSpec, index: int) -> Prerequisite:
    """Resolve the descriptor using the same roots and inputs as native audit."""
    check = f"native_audits[{index}]"
    try:
        working_directory(inventory.root, spec.working_directory)
        if spec.configuration_path is not None:
            if inventory.dirty_paths:
                raise RuntimeError("built-in adapter profiles require a clean tracked worktree")
            verify_profile_inputs(inventory, spec.configuration_path, spec.target_paths)
        resolved_executable(inventory.root, spec.command[0])
    except (OSError, RuntimeError, ValueError):
        return Prerequisite(
            check,
            "unavailable",
            spec.required,
            "Check the executable, working directory and tracked profile inputs.",
        )
    return Prerequisite(check, "ready", spec.required, "Adapter descriptor resolves.")


def diagnose_adopter(
    root: Path, policy_path: Path | None, git_trust_policy: GitTrustPolicy
) -> tuple[Prerequisite, ...]:
    """Inspect actual adopter prerequisites without changing repository state.

    Parameters
    ----------
    root
        Audit checkout or a path inside its worktree.
    policy_path
        Optional explicit tracked policy path relative to the repository.
    git_trust_policy
        The same executable trust constraints used by the audit CLI.

    Returns
    -------
    tuple of Prerequisite
        Ordered observations for the installation, Git, policy, sandbox and
        each declared native adapter.
    """
    package = _package()
    try:
        runner = GitRunner(git_trust_policy)
        inventory = load_git_inventory(root, git_runner=runner)
    except (OSError, RuntimeError, ValueError):
        return (
            package,
            Prerequisite(
                "git", "unavailable", True, "Check the trusted Git version and worktree path."
            ),
            Prerequisite("policy", "not-assessed", True, "Resolve Git inventory first."),
            Prerequisite("sandbox", "not-assessed", False, "Resolve Git inventory first."),
        )
    git = Prerequisite("git", "ready", True, f"Git {runner.provenance.version}")
    try:
        policy, _, governance = resolve_policy(inventory, policy_path)
    except (OSError, RuntimeError, ValueError):
        return (
            package,
            git,
            Prerequisite(
                "policy", "unavailable", True, "Fix the tracked policy path or its schema."
            ),
            _sandbox(inventory.root, required=False),
        )
    policy_result = (
        Prerequisite("policy", "unavailable", True, "Bootstrap and track a repository policy.")
        if governance
        else Prerequisite("policy", "ready", True, "Tracked policy conforms to its schema.")
    )
    return (
        package,
        git,
        policy_result,
        _sandbox(inventory.root, required=any(spec.required for spec in policy.native_audits)),
        *(_adapter(inventory, spec, index) for index, spec in enumerate(policy.native_audits)),
    )
