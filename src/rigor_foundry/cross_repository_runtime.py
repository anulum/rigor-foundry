# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — temporary runtime for historical campaign scans
"""Materialise captured commits without changing their source checkouts."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Event

from .campaign_evidence import ToolchainIdentity
from .cross_repository_campaign import RepositorySnapshot
from .cross_repository_capture import CrossRepositoryCapture, RepositoryCaptureRequest
from .cross_repository_execution import (
    CrossRepositoryExecution,
    CrossRepositoryExecutionPlan,
    HistoricalRepositoryExecution,
    validate_historical_report,
)
from .git_provenance import GitRunner, GitTrustPolicy
from .models import AuditReport
from .scanner import scan_repository


def _now() -> str:
    """Return the current UTC time in the protocol timestamp form."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class CampaignCancellation:
    """Thread-safe cooperative cancellation for repository boundaries."""

    def __init__(self) -> None:
        """Create an active cancellation signal."""
        self._event = Event()

    def cancel(self) -> None:
        """Request cancellation before the next repository boundary."""
        self._event.set()

    @property
    def requested(self) -> bool:
        """Return whether cancellation has been requested."""
        return self._event.is_set()


@dataclass(frozen=True)
class _SourceState:
    """Point-in-time source checkout identity used for non-mutation proof."""

    head: bytes
    tree: bytes
    status: bytes
    identity: tuple[int, int, int, int, int]


def _run_git(runner: GitRunner, root: Path, *arguments: str, check: bool = True) -> bytes:
    """Run a fixed Git command with an explicit safe-directory binding."""
    return runner.run(
        root,
        "-c",
        f"safe.directory={root}",
        *arguments,
        check=check,
    ).stdout


def _source_state(request: RepositoryCaptureRequest, runner: GitRunner) -> _SourceState:
    """Read source checkout state without following or modifying its contents."""
    root = request.repository_root
    metadata = root.stat(follow_symlinks=False)
    return _SourceState(
        head=_run_git(runner, root, "rev-parse", "--verify", "HEAD"),
        tree=_run_git(runner, root, "rev-parse", "--verify", "HEAD^{tree}"),
        status=_run_git(
            runner,
            root,
            "status",
            "--porcelain=v2",
            "--branch",
            "-z",
            "--untracked-files=all",
        ),
        identity=(
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ),
    )


def _object_available(request: RepositoryCaptureRequest, runner: GitRunner) -> bool:
    """Return whether the exact captured commit remains in the source object database."""
    completed = runner.run(
        request.repository_root,
        "-c",
        f"safe.directory={request.repository_root}",
        "rev-parse",
        "--verify",
        "--quiet",
        "--end-of-options",
        f"{request.requested_commit}^{{commit}}",
        check=False,
    )
    if completed.returncode not in {0, 1}:
        raise RuntimeError("Git could not inspect the historical commit object")
    return completed.returncode == 0


def _workspace_parent(
    path: Path | None,
    requests: tuple[RepositoryCaptureRequest, ...],
) -> Path | None:
    """Validate an optional temporary parent outside every source repository."""
    if path is None:
        return None
    if not path.is_absolute():
        raise ValueError("temporary workspace parent must be absolute")
    lexical = Path(os.path.abspath(path))
    resolved = lexical.resolve(strict=True)
    if lexical != resolved or lexical.is_symlink() or not resolved.is_dir():
        raise ValueError("temporary workspace parent must be a real canonical directory")
    for request in requests:
        if resolved == request.repository_root or resolved.is_relative_to(request.repository_root):
            raise ValueError("temporary workspace parent must be outside source repositories")
        if request.repository_root.is_relative_to(resolved):
            raise ValueError("temporary workspace parent must not contain source repositories")
    return resolved


def _materialise(
    request: RepositoryCaptureRequest,
    worktree: Path,
    runner: GitRunner,
) -> None:
    """Fetch one exact commit into an isolated repository and detach its checkout."""
    object_format = "sha1" if len(request.requested_commit) == 40 else "sha256"
    runner.run(worktree, "init", "--quiet", f"--object-format={object_format}")
    _run_git(
        runner,
        worktree,
        "fetch",
        "--quiet",
        "--no-tags",
        "--depth=1",
        "--no-write-fetch-head",
        request.repository_root.as_uri(),
        request.requested_commit,
    )
    _run_git(
        runner,
        worktree,
        "checkout",
        "--quiet",
        "--detach",
        request.requested_commit,
    )


def _diverges_from_runtime(
    *,
    snapshot: RepositorySnapshot,
    report: AuditReport,
    capture: CrossRepositoryCapture,
    toolchain: ToolchainIdentity,
) -> bool:
    """Return whether runtime, Git, or report identity differs from the freeze."""
    try:
        validate_historical_report(snapshot, report)
    except ValueError:
        return True
    return (
        snapshot.toolchain_digest != toolchain.identity_digest
        or report.git_provenance.identity_digest != capture.git_provenance.identity_digest
    )


def execute_cross_repository_campaign(
    *,
    plan: CrossRepositoryExecutionPlan,
    capture: CrossRepositoryCapture,
    requests: tuple[RepositoryCaptureRequest, ...],
    cancellation: CampaignCancellation | None = None,
    git_trust_policy: GitTrustPolicy | None = None,
    temporary_parent: Path | None = None,
) -> CrossRepositoryExecution:
    """Execute one frozen campaign through isolated historical static scans.

    Source repositories are read only. Every historical commit is fetched into
    a fresh temporary repository, checked out detached, scanned through the
    production scanner, and removed before the function returns. Native
    adapters and remediation procedures are never run by this surface.
    """
    policy_paths = tuple(target.policy_path for target in plan.targets)
    try:
        current_plan = CrossRepositoryExecutionPlan.build(
            capture=capture,
            requests=requests,
            policy_paths=policy_paths,
        )
    except ValueError as exc:
        raise ValueError("historical execution plan is stale or substituted") from exc
    if current_plan != plan:
        raise ValueError("historical execution plan is stale or substituted")
    parent = _workspace_parent(temporary_parent, requests)
    runner = GitRunner(git_trust_policy)
    if runner.provenance.identity_digest != capture.git_provenance.identity_digest:
        raise ValueError("historical execution Git provenance differs from capture")
    state_before = tuple(_source_state(request, runner) for request in requests)
    started_at = _now()
    toolchain = ToolchainIdentity.current()
    request_by_id = {request.repository_id: request for request in requests}
    snapshot_by_id = {snapshot.repository_id: snapshot for snapshot in capture.campaign.snapshots}
    target_by_id = {target.repository_id: target for target in plan.targets}
    results: list[HistoricalRepositoryExecution] = []
    unavailable: set[str] = set()
    workspaces_removed = False
    try:
        with tempfile.TemporaryDirectory(prefix="rigor-historical-", dir=parent) as directory:
            workspace = Path(directory)
            for repository_id in plan.execution_order:
                snapshot = snapshot_by_id[repository_id]
                request = request_by_id[repository_id]
                target = target_by_id[repository_id]
                dependency_ids = {
                    edge.to_repository
                    for edge in capture.campaign.edges
                    if edge.from_repository == repository_id
                }
                if cancellation is not None and cancellation.requested:
                    result = HistoricalRepositoryExecution.build(
                        snapshot=snapshot,
                        status="cancelled",
                        reason="cancelled",
                    )
                elif dependency_ids & unavailable:
                    result = HistoricalRepositoryExecution.build(
                        snapshot=snapshot,
                        status="unavailable",
                        reason="dependency-unavailable",
                    )
                elif not snapshot.is_available:
                    result = HistoricalRepositoryExecution.build(
                        snapshot=snapshot,
                        status="unavailable",
                        reason="capture-unavailable",
                    )
                elif not _object_available(request, runner):
                    result = HistoricalRepositoryExecution.build(
                        snapshot=snapshot,
                        status="unavailable",
                        reason="historical-object-unavailable",
                    )
                else:
                    result = _execute_repository(
                        request=request,
                        snapshot=snapshot,
                        target_policy_path=target.policy_path,
                        workspace=workspace,
                        runner=runner,
                        capture=capture,
                        toolchain=toolchain,
                        cancellation=cancellation,
                        git_trust_policy=git_trust_policy,
                    )
                results.append(result)
                if result.status in {"unavailable", "failed", "cancelled"}:
                    unavailable.add(repository_id)
        workspaces_removed = True
    finally:
        state_after = tuple(_source_state(request, runner) for request in requests)
        if state_after != state_before:
            raise RuntimeError("source repository state changed during historical execution")
    return CrossRepositoryExecution.build(
        plan=plan,
        capture=capture,
        toolchain=toolchain,
        started_at=started_at,
        finished_at=_now(),
        results=tuple(results),
        temporary_workspaces_removed=workspaces_removed,
    )


def _execute_repository(
    *,
    request: RepositoryCaptureRequest,
    snapshot: RepositorySnapshot,
    target_policy_path: str,
    workspace: Path,
    runner: GitRunner,
    capture: CrossRepositoryCapture,
    toolchain: ToolchainIdentity,
    cancellation: CampaignCancellation | None,
    git_trust_policy: GitTrustPolicy | None,
) -> HistoricalRepositoryExecution:
    """Materialise and scan one available repository inside the temporary root."""
    worktree = workspace / request.repository_id
    worktree.mkdir(mode=0o700)
    try:
        _materialise(request, worktree, runner)
    except (OSError, RuntimeError):
        return HistoricalRepositoryExecution.build(
            snapshot=snapshot,
            status="failed",
            reason="materialisation-failed",
        )
    if cancellation is not None and cancellation.requested:
        return HistoricalRepositoryExecution.build(
            snapshot=snapshot,
            status="cancelled",
            reason="cancelled",
        )
    try:
        report = scan_repository(
            worktree,
            Path(target_policy_path),
            git_trust_policy=git_trust_policy,
        )
    except (OSError, RuntimeError, ValueError):
        return HistoricalRepositoryExecution.build(
            snapshot=snapshot,
            status="failed",
            reason="scan-failed",
        )
    if _diverges_from_runtime(
        snapshot=snapshot,
        report=report,
        capture=capture,
        toolchain=toolchain,
    ):
        return HistoricalRepositoryExecution.build(
            snapshot=snapshot,
            status="failed",
            reason="frozen-input-divergence",
        )
    return HistoricalRepositoryExecution.build(
        snapshot=snapshot,
        status="succeeded",
        report=report,
    )
