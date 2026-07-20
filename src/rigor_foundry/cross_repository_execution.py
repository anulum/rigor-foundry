# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — isolated historical cross-repository campaign execution
"""Scan captured Git objects in temporary detached repositories."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final, Literal

from .campaign_evidence import ToolchainIdentity
from .cross_repository_campaign import CrossRepositoryCampaign, RepositorySnapshot
from .cross_repository_capture import (
    CrossRepositoryCapture,
    RepositoryCaptureRequest,
)
from .git_provenance import GitExecutableProvenance
from .model_primitives import (
    parse_utc_timestamp,
    require_digest,
    require_identifier,
    require_utc_timestamp,
)
from .models import AuditPolicy, AuditReport, canonical_digest

HISTORICAL_EXECUTION_SCHEMA_VERSION: Final = "1.0"

RepositoryExecutionStatus = Literal["succeeded", "unavailable", "failed", "cancelled"]
ExecutionResolution = Literal["succeeded", "partial", "unavailable", "failed", "cancelled"]
FailureReason = Literal[
    "capture-unavailable",
    "dependency-unavailable",
    "historical-object-unavailable",
    "materialisation-failed",
    "scan-failed",
    "frozen-input-divergence",
    "cancelled",
]

_STATUSES: Final = frozenset({"succeeded", "unavailable", "failed", "cancelled"})
_STATUS_REASONS: Final = {
    "unavailable": frozenset(
        {
            "capture-unavailable",
            "dependency-unavailable",
            "historical-object-unavailable",
        }
    ),
    "failed": frozenset(
        {
            "materialisation-failed",
            "scan-failed",
            "frozen-input-divergence",
        }
    ),
    "cancelled": frozenset({"cancelled"}),
}


def _validate_request(request: RepositoryCaptureRequest) -> None:
    """Reject a capture request whose stored digest masks substituted fields."""
    rebuilt = RepositoryCaptureRequest.build(
        repository_id=request.repository_id,
        repository_root=request.repository_root,
        requested_commit=request.requested_commit,
        policy_digest=request.policy_digest,
        rule_pack_version=request.rule_pack_version,
        rule_pack_digest=request.rule_pack_digest,
        adapter_lock_digest=request.adapter_lock_digest,
        toolchain_digest=request.toolchain_digest,
    )
    if request != rebuilt:
        raise ValueError("historical capture request digest does not match its content")


def _validate_capture(capture: CrossRepositoryCapture) -> None:
    """Reject a forged campaign, Git provenance, or capture envelope."""
    campaign = CrossRepositoryCampaign.from_dict(capture.campaign.to_dict())
    git_provenance = GitExecutableProvenance.from_dict(capture.git_provenance.to_dict())
    rebuilt = CrossRepositoryCapture.build(
        campaign=campaign,
        request_digests=capture.request_digests,
        git_provenance=git_provenance,
    )
    if capture != rebuilt:
        raise ValueError("historical capture digest does not match its content")


def adapter_lock_digest(policy: AuditPolicy) -> str:
    """Return the frozen identity of a policy's complete native-adapter list."""
    return canonical_digest(
        {"native_audits": [adapter.to_dict() for adapter in policy.native_audits]}
    )


def _relative_policy_path(value: str) -> str:
    """Return one canonical repository-relative policy path."""
    path = PurePosixPath(value)
    if (
        not value
        or value == "."
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in value
        or "\x00" in value
        or path.as_posix() != value
    ):
        raise ValueError("historical policy path must be canonical and repository-relative")
    return value


@dataclass(frozen=True)
class HistoricalExecutionTarget:
    """Bind one captured request to its historical policy path.

    Parameters
    ----------
    repository_id:
        Repository identifier present in the captured campaign.
    request_digest:
        Exact capture-request identity, including the source root and commit.
    policy_path:
        Repository-relative policy path inside the historical tree.
    target_digest:
        Content identity of this execution target.
    """

    repository_id: str
    request_digest: str
    policy_path: str
    target_digest: str

    @classmethod
    def build(
        cls,
        *,
        repository_id: str,
        request_digest: str,
        policy_path: str,
    ) -> HistoricalExecutionTarget:
        """Build one validated historical execution target."""
        body = {
            "repository_id": require_identifier(repository_id, "target.repository_id"),
            "request_digest": require_digest(request_digest, "target.request_digest"),
            "policy_path": _relative_policy_path(policy_path),
        }
        return cls(**body, target_digest=canonical_digest(body))

    def to_dict(self) -> dict[str, str]:
        """Serialise one historical execution target."""
        return {
            "repository_id": self.repository_id,
            "request_digest": self.request_digest,
            "policy_path": self.policy_path,
            "target_digest": self.target_digest,
        }


def _validate_target(target: HistoricalExecutionTarget) -> None:
    """Reject a forged execution target or target digest."""
    rebuilt = HistoricalExecutionTarget.build(
        repository_id=target.repository_id,
        request_digest=target.request_digest,
        policy_path=target.policy_path,
    )
    if target != rebuilt:
        raise ValueError("historical execution target digest does not match its content")


@dataclass(frozen=True)
class CrossRepositoryExecutionPlan:
    """Immutable plan for dependency-ordered execution of one exact capture.

    Parameters
    ----------
    capture_digest, campaign_digest:
        Exact frozen capture and campaign identities.
    targets:
        One target per captured repository.
    execution_order:
        Dependency-first stable repository order.
    plan_digest:
        Content identity used to reject stale-plan substitution.
    """

    capture_digest: str
    campaign_digest: str
    targets: tuple[HistoricalExecutionTarget, ...]
    execution_order: tuple[str, ...]
    plan_digest: str

    @classmethod
    def build(
        cls,
        *,
        capture: CrossRepositoryCapture,
        requests: tuple[RepositoryCaptureRequest, ...],
        policy_paths: tuple[str, ...],
    ) -> CrossRepositoryExecutionPlan:
        """Build a plan only when capture, requests, and policies bind exactly."""
        _validate_capture(capture)
        for request in requests:
            _validate_request(request)
        if len(requests) != len(policy_paths):
            raise ValueError("historical requests and policy paths must have equal length")
        if tuple(item.request_digest for item in requests) != capture.request_digests:
            raise ValueError("historical requests do not match the exact capture")
        snapshot_ids = tuple(item.repository_id for item in capture.campaign.snapshots)
        request_ids = tuple(item.repository_id for item in requests)
        if request_ids != snapshot_ids:
            raise ValueError("historical request order does not match campaign snapshots")
        targets = tuple(
            HistoricalExecutionTarget.build(
                repository_id=request.repository_id,
                request_digest=request.request_digest,
                policy_path=policy_path,
            )
            for request, policy_path in zip(requests, policy_paths, strict=True)
        )
        order = _dependency_order(capture.campaign)
        body: dict[str, object] = {
            "schema_version": HISTORICAL_EXECUTION_SCHEMA_VERSION,
            "capture_digest": capture.capture_digest,
            "campaign_digest": capture.campaign.campaign_digest,
            "targets": [item.to_dict() for item in targets],
            "execution_order": list(order),
        }
        plan = cls(
            capture_digest=capture.capture_digest,
            campaign_digest=capture.campaign.campaign_digest,
            targets=targets,
            execution_order=order,
            plan_digest=canonical_digest(body),
        )
        plan.validate()
        return plan

    def to_dict(self) -> dict[str, object]:
        """Serialise one historical execution plan."""
        return {
            "schema_version": HISTORICAL_EXECUTION_SCHEMA_VERSION,
            "capture_digest": self.capture_digest,
            "campaign_digest": self.campaign_digest,
            "targets": [item.to_dict() for item in self.targets],
            "execution_order": list(self.execution_order),
            "plan_digest": self.plan_digest,
        }

    def validate(self) -> None:
        """Verify the complete plan body and its content identity."""
        for target in self.targets:
            _validate_target(target)
        target_ids = tuple(item.repository_id for item in self.targets)
        request_digests = tuple(item.request_digest for item in self.targets)
        if not target_ids:
            raise ValueError("historical execution targets must not be empty")
        for index, repository_id in enumerate(self.execution_order):
            require_identifier(repository_id, f"plan.execution_order[{index}]")
        if len(target_ids) != len(set(target_ids)):
            raise ValueError("historical execution target repositories must be unique")
        if len(request_digests) != len(set(request_digests)):
            raise ValueError("historical execution target requests must be unique")
        if len(self.execution_order) != len(set(self.execution_order)):
            raise ValueError("historical execution order must be unique")
        if set(self.execution_order) != set(target_ids):
            raise ValueError("historical execution order must cover every target")
        body: dict[str, object] = {
            "schema_version": HISTORICAL_EXECUTION_SCHEMA_VERSION,
            "capture_digest": require_digest(self.capture_digest, "plan.capture_digest"),
            "campaign_digest": require_digest(self.campaign_digest, "plan.campaign_digest"),
            "targets": [item.to_dict() for item in self.targets],
            "execution_order": list(self.execution_order),
        }
        if canonical_digest(body) != self.plan_digest:
            raise ValueError("historical execution plan digest does not match its content")


def _dependency_order(campaign: CrossRepositoryCampaign) -> tuple[str, ...]:
    """Return a deterministic order with every dependency before its dependant."""
    remaining = {snapshot.repository_id for snapshot in campaign.snapshots}
    dependencies: dict[str, set[str]] = {repository_id: set() for repository_id in remaining}
    for edge in campaign.edges:
        dependencies[edge.from_repository].add(edge.to_repository)
    order: list[str] = []
    while remaining:
        ready = sorted(
            repository_id
            for repository_id in remaining
            if dependencies[repository_id].isdisjoint(remaining)
        )
        if not ready:
            raise ValueError("campaign dependency order contains a cycle")
        order.extend(ready)
        remaining.difference_update(ready)
    return tuple(order)


@dataclass(frozen=True)
class HistoricalRepositoryExecution:
    """One historical repository scan outcome without a verdict claim.

    Parameters
    ----------
    repository_id, snapshot_digest:
        Exact repository and frozen snapshot identities.
    status:
        Execution state; ``succeeded`` means only that scanning completed.
    reason:
        Stable reason code for every non-success outcome.
    report:
        Exact report only for a completed scan.
    execution_digest:
        Content identity of this repository outcome.
    """

    repository_id: str
    snapshot_digest: str
    status: RepositoryExecutionStatus
    reason: str
    report: AuditReport | None
    execution_digest: str

    @classmethod
    def build(
        cls,
        *,
        snapshot: RepositorySnapshot,
        status: RepositoryExecutionStatus,
        reason: FailureReason | str = "",
        report: AuditReport | None = None,
    ) -> HistoricalRepositoryExecution:
        """Build one self-consistent historical repository outcome."""
        if status not in _STATUSES:
            raise ValueError("historical execution status is unsupported")
        if status == "succeeded":
            if reason or report is None:
                raise ValueError("successful historical execution requires only a report")
            validate_historical_report(snapshot, report)
        elif report is not None or reason not in _STATUS_REASONS[status]:
            raise ValueError("non-success historical execution requires one stable reason")
        body: dict[str, object] = {
            "schema_version": HISTORICAL_EXECUTION_SCHEMA_VERSION,
            "repository_id": snapshot.repository_id,
            "snapshot_digest": snapshot.snapshot_digest,
            "status": status,
            "reason": reason,
            "report_digest": "" if report is None else report.report_digest,
        }
        return cls(
            repository_id=snapshot.repository_id,
            snapshot_digest=snapshot.snapshot_digest,
            status=status,
            reason=reason,
            report=report,
            execution_digest=canonical_digest(body),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one historical repository outcome and its report."""
        return {
            "schema_version": HISTORICAL_EXECUTION_SCHEMA_VERSION,
            "repository_id": self.repository_id,
            "snapshot_digest": self.snapshot_digest,
            "status": self.status,
            "reason": self.reason,
            "report": None if self.report is None else self.report.to_dict(),
            "execution_digest": self.execution_digest,
        }


def validate_historical_report(snapshot: RepositorySnapshot, report: AuditReport) -> None:
    """Reject a report that diverges from any frozen snapshot input."""
    observed = (
        report.head,
        report.head_tree,
        report.policy_digest,
        report.rule_pack_version,
        report.rule_pack_digest,
        adapter_lock_digest(report.policy),
    )
    expected = (
        snapshot.head_commit,
        snapshot.head_tree,
        snapshot.policy_digest,
        snapshot.rule_pack_version,
        snapshot.rule_pack_digest,
        snapshot.adapter_lock_digest,
    )
    if observed != expected:
        raise ValueError("historical report diverges from the frozen snapshot")
    if report.branch != "HEAD" or report.dirty_paths:
        raise ValueError("historical report must come from a clean detached repository")
    AuditReport.from_dict(report.to_dict())


@dataclass(frozen=True)
class CrossRepositoryExecution:
    """Content-addressed execution record for one frozen campaign plan."""

    plan_digest: str
    capture_digest: str
    campaign_digest: str
    toolchain: ToolchainIdentity
    git_provenance: GitExecutableProvenance
    started_at: str
    finished_at: str
    results: tuple[HistoricalRepositoryExecution, ...]
    resolution: ExecutionResolution
    temporary_workspaces_removed: bool
    execution_digest: str

    @classmethod
    def build(
        cls,
        *,
        plan: CrossRepositoryExecutionPlan,
        capture: CrossRepositoryCapture,
        toolchain: ToolchainIdentity,
        started_at: str,
        finished_at: str,
        results: tuple[HistoricalRepositoryExecution, ...],
        temporary_workspaces_removed: bool,
    ) -> CrossRepositoryExecution:
        """Build and validate one complete campaign execution record."""
        _validate_capture(capture)
        plan.validate()
        ToolchainIdentity.from_dict(toolchain.to_dict())
        if plan.capture_digest != capture.capture_digest:
            raise ValueError("historical execution plan does not match the capture")
        if plan.campaign_digest != capture.campaign.campaign_digest:
            raise ValueError("historical execution plan does not match the campaign")
        snapshot_ids = tuple(snapshot.repository_id for snapshot in capture.campaign.snapshots)
        if tuple(item.repository_id for item in plan.targets) != snapshot_ids:
            raise ValueError("historical execution targets do not match the campaign")
        if tuple(item.request_digest for item in plan.targets) != capture.request_digests:
            raise ValueError("historical execution targets do not match the capture requests")
        if plan.execution_order != _dependency_order(capture.campaign):
            raise ValueError("historical execution order does not match campaign dependencies")
        if not temporary_workspaces_removed:
            raise ValueError("historical execution requires successful temporary rollback")
        if tuple(item.repository_id for item in results) != plan.execution_order:
            raise ValueError("historical execution results do not match plan order")
        snapshots = {snapshot.repository_id: snapshot for snapshot in capture.campaign.snapshots}
        for result in results:
            snapshot = snapshots[result.repository_id]
            rebuilt = HistoricalRepositoryExecution.build(
                snapshot=snapshot,
                status=result.status,
                reason=result.reason,
                report=result.report,
            )
            if result != rebuilt:
                raise ValueError(
                    "historical repository execution digest does not match its content"
                )
            if result.report is not None:
                if snapshot.toolchain_digest != toolchain.identity_digest:
                    raise ValueError("historical report toolchain differs from the snapshot")
                if (
                    result.report.git_provenance.identity_digest
                    != capture.git_provenance.identity_digest
                ):
                    raise ValueError("historical report Git provenance differs from capture")
        started = require_utc_timestamp(started_at, "execution.started_at")
        finished = require_utc_timestamp(finished_at, "execution.finished_at")
        if parse_utc_timestamp(finished, "execution.finished_at") < parse_utc_timestamp(
            started, "execution.started_at"
        ):
            raise ValueError("execution.finished_at must not precede started_at")
        resolution = _resolution(results)
        body: dict[str, object] = {
            "schema_version": HISTORICAL_EXECUTION_SCHEMA_VERSION,
            "plan_digest": plan.plan_digest,
            "capture_digest": capture.capture_digest,
            "campaign_digest": capture.campaign.campaign_digest,
            "toolchain_identity": toolchain.identity_digest,
            "git_provenance_identity": capture.git_provenance.identity_digest,
            "started_at": started,
            "finished_at": finished,
            "results": [item.to_dict() for item in results],
            "resolution": resolution,
            "temporary_workspaces_removed": True,
        }
        return cls(
            plan_digest=plan.plan_digest,
            capture_digest=capture.capture_digest,
            campaign_digest=capture.campaign.campaign_digest,
            toolchain=toolchain,
            git_provenance=capture.git_provenance,
            started_at=started,
            finished_at=finished,
            results=results,
            resolution=resolution,
            temporary_workspaces_removed=True,
            execution_digest=canonical_digest(body),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the complete historical execution record."""
        return {
            "schema_version": HISTORICAL_EXECUTION_SCHEMA_VERSION,
            "plan_digest": self.plan_digest,
            "capture_digest": self.capture_digest,
            "campaign_digest": self.campaign_digest,
            "toolchain": self.toolchain.to_dict(),
            "git_provenance": self.git_provenance.to_dict(),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "results": [item.to_dict() for item in self.results],
            "resolution": self.resolution,
            "temporary_workspaces_removed": self.temporary_workspaces_removed,
            "execution_digest": self.execution_digest,
        }


def _resolution(results: tuple[HistoricalRepositoryExecution, ...]) -> ExecutionResolution:
    """Derive an execution resolution without treating missing evidence as success."""
    statuses = tuple(item.status for item in results)
    if any(status == "cancelled" for status in statuses):
        return "cancelled"
    succeeded = statuses.count("succeeded")
    if succeeded == len(statuses):
        return "succeeded"
    if succeeded:
        return "partial"
    if all(status == "unavailable" for status in statuses):
        return "unavailable"
    return "failed"
