# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — historical cross-repository execution contracts
"""Verify immutable planning and outcome records against real scan reports."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.campaign_evidence import ToolchainIdentity
from rigor_foundry.cross_repository_campaign import InterRepositoryEdge
from rigor_foundry.cross_repository_capture import (
    CrossRepositoryCapture,
    RepositoryCaptureRequest,
    capture_cross_repository_campaign,
)
from rigor_foundry.cross_repository_execution import (
    CrossRepositoryExecution,
    CrossRepositoryExecutionPlan,
    HistoricalExecutionTarget,
    HistoricalRepositoryExecution,
    RepositoryExecutionStatus,
    adapter_lock_digest,
    validate_historical_report,
)
from rigor_foundry.git_provenance import GitTrustPolicy
from rigor_foundry.models import AuditReport, canonical_digest
from rigor_foundry.scanner import scan_repository

FROZEN_AT = "2026-07-20T14:40:00Z"
POLICY_PATH = Path("rigor-foundry-policy.json")


def _repository(path: Path, name: str) -> tuple[GitRepository, RepositoryCaptureRequest]:
    """Create one detached, scannable repository and its exact replay request."""
    repository = GitRepository.create(path)
    repository.write_text(f"src/{name}.py", f'NAME = "{name}"\n')
    repository.write_policy()
    repository.commit(f"test: create {name}")
    repository.git_command("checkout", "--detach")
    report = scan_repository(repository.root, POLICY_PATH)
    request = RepositoryCaptureRequest.build(
        repository_id=name,
        repository_root=repository.root,
        requested_commit=report.head,
        policy_digest=report.policy_digest,
        rule_pack_version=report.rule_pack_version,
        rule_pack_digest=report.rule_pack_digest,
        adapter_lock_digest=adapter_lock_digest(report.policy),
        toolchain_digest=ToolchainIdentity.current().identity_digest,
    )
    return repository, request


def _capture(
    tmp_path: Path,
) -> tuple[
    CrossRepositoryCapture,
    tuple[RepositoryCaptureRequest, ...],
    CrossRepositoryExecutionPlan,
]:
    """Build a two-repository capture and dependency-first execution plan."""
    _app, app_request = _repository(tmp_path / "app", "app")
    _library, library_request = _repository(tmp_path / "library", "library")
    requests = (app_request, library_request)
    edge = InterRepositoryEdge.build(
        from_repository="app",
        to_repository="library",
        relationship="depends-on",
        rationale="the app imports the library",
    )
    capture = capture_cross_repository_campaign(
        campaign_id="execution-contract",
        frozen_at=FROZEN_AT,
        requests=requests,
        edges=(edge,),
    )
    plan = CrossRepositoryExecutionPlan.build(
        capture=capture,
        requests=requests,
        policy_paths=(POLICY_PATH.as_posix(), POLICY_PATH.as_posix()),
    )
    return capture, requests, plan


def _detached_reports(
    requests: tuple[RepositoryCaptureRequest, ...],
) -> dict[str, AuditReport]:
    """Scan the already-detached real fixture repositories."""
    return {
        request.repository_id: scan_repository(request.repository_root, POLICY_PATH)
        for request in requests
    }


def _execution_record(
    *,
    plan: CrossRepositoryExecutionPlan,
    capture: CrossRepositoryCapture,
    results: tuple[HistoricalRepositoryExecution, ...],
    finished_at: str = "2026-07-20T14:40:02Z",
    removed: bool = True,
) -> CrossRepositoryExecution:
    """Build one aggregate with stable test timestamps."""
    return CrossRepositoryExecution.build(
        plan=plan,
        capture=capture,
        toolchain=ToolchainIdentity.current(),
        started_at="2026-07-20T14:40:01Z",
        finished_at=finished_at,
        results=results,
        temporary_workspaces_removed=removed,
    )


def _redigest_plan(
    plan: CrossRepositoryExecutionPlan,
    *,
    capture_digest: str | None = None,
    campaign_digest: str | None = None,
    targets: tuple[HistoricalExecutionTarget, ...] | None = None,
    execution_order: tuple[str, ...] | None = None,
) -> CrossRepositoryExecutionPlan:
    """Replace selected plan fields and recompute its exact content identity."""
    changed = replace(
        plan,
        capture_digest=plan.capture_digest if capture_digest is None else capture_digest,
        campaign_digest=plan.campaign_digest if campaign_digest is None else campaign_digest,
        targets=plan.targets if targets is None else targets,
        execution_order=plan.execution_order if execution_order is None else execution_order,
    )
    body = changed.to_dict()
    body.pop("plan_digest")
    return replace(changed, plan_digest=canonical_digest(body))


def test_plan_binds_exact_requests_and_orders_dependencies_first(tmp_path: Path) -> None:
    """Targets preserve capture order while execution follows dependency order."""
    capture, requests, plan = _capture(tmp_path)

    assert tuple(item.repository_id for item in plan.targets) == ("app", "library")
    assert tuple(item.request_digest for item in plan.targets) == capture.request_digests
    assert plan.execution_order == ("library", "app")
    assert len(plan.plan_digest) == 64
    assert plan.to_dict()["plan_digest"] == plan.plan_digest
    plan.validate()

    with pytest.raises(ValueError, match="equal length"):
        CrossRepositoryExecutionPlan.build(
            capture=capture,
            requests=requests,
            policy_paths=(POLICY_PATH.as_posix(),),
        )
    with pytest.raises(ValueError, match="exact capture"):
        CrossRepositoryExecutionPlan.build(
            capture=capture,
            requests=tuple(reversed(requests)),
            policy_paths=(POLICY_PATH.as_posix(), POLICY_PATH.as_posix()),
        )

    reordered_capture = CrossRepositoryCapture.build(
        campaign=capture.campaign,
        request_digests=tuple(reversed(capture.request_digests)),
        git_provenance=capture.git_provenance,
    )
    with pytest.raises(ValueError, match="order does not match"):
        CrossRepositoryExecutionPlan.build(
            capture=reordered_capture,
            requests=tuple(reversed(requests)),
            policy_paths=(POLICY_PATH.as_posix(), POLICY_PATH.as_posix()),
        )

    reverse_edge = InterRepositoryEdge.build(
        from_repository="library",
        to_repository="app",
        relationship="depends-on",
        rationale="forged cycle",
    )
    cyclic_campaign = replace(
        capture.campaign,
        edges=(*capture.campaign.edges, reverse_edge),
    )
    cyclic_capture = replace(capture, campaign=cyclic_campaign)
    with pytest.raises(ValueError, match="contains a cycle"):
        CrossRepositoryExecutionPlan.build(
            capture=cyclic_capture,
            requests=requests,
            policy_paths=(POLICY_PATH.as_posix(), POLICY_PATH.as_posix()),
        )


@pytest.mark.parametrize(
    "value",
    ("", ".", "/tmp/policy.json", "../policy.json", "a/../policy.json", "a\\b", "a\0b"),
)
def test_target_rejects_noncanonical_policy_paths(value: str) -> None:
    """Historical policy selection never escapes or aliases the detached tree."""
    with pytest.raises(ValueError, match="canonical and repository-relative"):
        HistoricalExecutionTarget.build(
            repository_id="repository",
            request_digest="a" * 64,
            policy_path=value,
        )


def test_plan_validation_rejects_every_substituted_identity(tmp_path: Path) -> None:
    """Target, coverage, order, digest, and frozen identities fail closed."""
    _capture_record, _requests, plan = _capture(tmp_path)
    target = plan.targets[0]
    forged_target = replace(target, target_digest="0" * 64)
    duplicate_request = HistoricalExecutionTarget.build(
        repository_id=plan.targets[1].repository_id,
        request_digest=target.request_digest,
        policy_path=plan.targets[1].policy_path,
    )
    mutations = (
        replace(plan, targets=(forged_target, *plan.targets[1:])),
        replace(plan, targets=(plan.targets[0], plan.targets[0])),
        replace(plan, targets=(plan.targets[0], duplicate_request)),
        replace(plan, execution_order=("library", "library")),
        replace(plan, execution_order=("library", "absent")),
        replace(plan, plan_digest="0" * 64),
        replace(plan, capture_digest="bad"),
    )
    for mutation in mutations:
        with pytest.raises(ValueError):
            mutation.validate()


def test_repository_outcome_validates_real_detached_report(tmp_path: Path) -> None:
    """Only a clean detached report matching every frozen input can succeed."""
    capture, requests, _plan = _capture(tmp_path)
    report = _detached_reports(requests)["app"]
    app_snapshot = capture.campaign.snapshots[0]
    outcome = HistoricalRepositoryExecution.build(
        snapshot=app_snapshot,
        status="succeeded",
        report=report,
    )

    assert outcome.status == "succeeded"
    assert outcome.reason == ""
    assert outcome.report is report
    assert len(outcome.execution_digest) == 64
    validate_historical_report(app_snapshot, report)
    with pytest.raises(ValueError, match="clean detached"):
        validate_historical_report(app_snapshot, replace(report, branch="main"))
    with pytest.raises(ValueError, match="report digest"):
        validate_historical_report(app_snapshot, replace(report, report_digest="0" * 64))

    with pytest.raises(ValueError, match="requires only a report"):
        HistoricalRepositoryExecution.build(snapshot=app_snapshot, status="succeeded")
    with pytest.raises(ValueError, match="stable reason"):
        HistoricalRepositoryExecution.build(snapshot=app_snapshot, status="failed")
    with pytest.raises(ValueError, match="unsupported"):
        HistoricalRepositoryExecution.build(
            snapshot=app_snapshot,
            status=cast(RepositoryExecutionStatus, "unknown"),
            reason="scan-failed",
        )
    with pytest.raises(ValueError, match="stable reason"):
        HistoricalRepositoryExecution.build(
            snapshot=app_snapshot,
            status="failed",
            reason="scan-failed",
            report=report,
        )


def test_execution_record_derives_resolution_and_rejects_tampering(tmp_path: Path) -> None:
    """The aggregate binds plan, capture, results, timestamps, and rollback proof."""
    capture, requests, plan = _capture(tmp_path)
    reports = _detached_reports(requests)
    snapshots = {item.repository_id: item for item in capture.campaign.snapshots}
    results = tuple(
        HistoricalRepositoryExecution.build(
            snapshot=snapshots[repository_id],
            status="succeeded",
            report=reports[repository_id],
        )
        for repository_id in plan.execution_order
    )
    toolchain = ToolchainIdentity.current()
    execution = CrossRepositoryExecution.build(
        plan=plan,
        capture=capture,
        toolchain=toolchain,
        started_at="2026-07-20T14:40:01Z",
        finished_at="2026-07-20T14:40:02Z",
        results=results,
        temporary_workspaces_removed=True,
    )

    assert execution.resolution == "succeeded"
    assert execution.git_provenance == capture.git_provenance
    assert execution.to_dict()["execution_digest"] == execution.execution_digest

    unavailable = tuple(
        HistoricalRepositoryExecution.build(
            snapshot=snapshots[repository_id],
            status="unavailable",
            reason="historical-object-unavailable",
        )
        for repository_id in plan.execution_order
    )
    assert (
        CrossRepositoryExecution.build(
            plan=plan,
            capture=capture,
            toolchain=toolchain,
            started_at="2026-07-20T14:40:01Z",
            finished_at="2026-07-20T14:40:02Z",
            results=unavailable,
            temporary_workspaces_removed=True,
        ).resolution
        == "unavailable"
    )
    partial = (results[0], unavailable[1])
    assert (
        CrossRepositoryExecution.build(
            plan=plan,
            capture=capture,
            toolchain=toolchain,
            started_at="2026-07-20T14:40:01Z",
            finished_at="2026-07-20T14:40:02Z",
            results=partial,
            temporary_workspaces_removed=True,
        ).resolution
        == "partial"
    )
    failed = tuple(
        HistoricalRepositoryExecution.build(
            snapshot=snapshots[repository_id],
            status="failed",
            reason="scan-failed",
        )
        for repository_id in plan.execution_order
    )
    assert (
        CrossRepositoryExecution.build(
            plan=plan,
            capture=capture,
            toolchain=toolchain,
            started_at="2026-07-20T14:40:01Z",
            finished_at="2026-07-20T14:40:02Z",
            results=failed,
            temporary_workspaces_removed=True,
        ).resolution
        == "failed"
    )
    cancelled = (
        HistoricalRepositoryExecution.build(
            snapshot=snapshots["library"], status="cancelled", reason="cancelled"
        ),
        failed[1],
    )
    assert (
        CrossRepositoryExecution.build(
            plan=plan,
            capture=capture,
            toolchain=toolchain,
            started_at="2026-07-20T14:40:01Z",
            finished_at="2026-07-20T14:40:02Z",
            results=cancelled,
            temporary_workspaces_removed=True,
        ).resolution
        == "cancelled"
    )

    invalid_results = (
        tuple(reversed(results)),
        results[:1],
        (replace(results[0], execution_digest="0" * 64), results[1]),
    )
    for changed_results in invalid_results:
        with pytest.raises(ValueError):
            _execution_record(plan=plan, capture=capture, results=changed_results)
    with pytest.raises(ValueError, match="temporary rollback"):
        _execution_record(plan=plan, capture=capture, results=results, removed=False)
    with pytest.raises(ValueError, match="must not precede"):
        _execution_record(
            plan=plan,
            capture=capture,
            results=results,
            finished_at="2026-07-20T14:40:00Z",
        )


def test_execution_record_rejects_plan_capture_and_campaign_substitution(
    tmp_path: Path,
) -> None:
    """An internally valid plan cannot be reused with a different frozen campaign."""
    capture, requests, plan = _capture(tmp_path / "first")
    other_capture, _other_requests, _other_plan = _capture(tmp_path / "second")
    reports = _detached_reports(requests)
    snapshots = {item.repository_id: item for item in capture.campaign.snapshots}
    results = tuple(
        HistoricalRepositoryExecution.build(
            snapshot=snapshots[repository_id],
            status="succeeded",
            report=reports[repository_id],
        )
        for repository_id in plan.execution_order
    )
    with pytest.raises(ValueError, match="does not match the capture"):
        _execution_record(plan=plan, capture=other_capture, results=results)

    wrong_campaign = _redigest_plan(plan, campaign_digest="0" * 64)
    with pytest.raises(ValueError, match="does not match the campaign"):
        _execution_record(plan=wrong_campaign, capture=capture, results=results)

    wrong_repository_target = HistoricalExecutionTarget.build(
        repository_id="other",
        request_digest=plan.targets[0].request_digest,
        policy_path=plan.targets[0].policy_path,
    )
    wrong_targets = _redigest_plan(
        plan,
        targets=(wrong_repository_target, plan.targets[1]),
        execution_order=("library", "other"),
    )
    with pytest.raises(ValueError, match="targets do not match the campaign"):
        _execution_record(plan=wrong_targets, capture=capture, results=results)

    wrong_request_target = HistoricalExecutionTarget.build(
        repository_id=plan.targets[0].repository_id,
        request_digest="e" * 64,
        policy_path=plan.targets[0].policy_path,
    )
    wrong_requests = _redigest_plan(
        plan,
        targets=(wrong_request_target, plan.targets[1]),
    )
    with pytest.raises(ValueError, match="targets do not match the capture requests"):
        _execution_record(plan=wrong_requests, capture=capture, results=results)

    wrong_order = _redigest_plan(plan, execution_order=("app", "library"))
    with pytest.raises(ValueError, match="order does not match"):
        _execution_record(plan=wrong_order, capture=capture, results=results)

    forged_campaign_plan = _redigest_plan(
        plan,
        capture_digest=other_capture.capture_digest,
        campaign_digest=other_capture.campaign.campaign_digest,
    )
    with pytest.raises(ValueError, match="targets do not match the capture requests"):
        _execution_record(
            plan=forged_campaign_plan,
            capture=other_capture,
            results=results,
        )


def test_execution_record_rejects_runtime_identity_divergence(tmp_path: Path) -> None:
    """A success record binds valid toolchain and Git identities to the snapshot."""
    capture, requests, plan = _capture(tmp_path)
    reports = _detached_reports(requests)
    snapshots = {item.repository_id: item for item in capture.campaign.snapshots}
    results = tuple(
        HistoricalRepositoryExecution.build(
            snapshot=snapshots[repository_id],
            status="succeeded",
            report=reports[repository_id],
        )
        for repository_id in plan.execution_order
    )
    current = ToolchainIdentity.current()
    altered_fields = current.to_dict()
    altered_fields["platform"] = f"{current.platform}-different"
    altered_fields["identity_digest"] = canonical_digest(
        {key: value for key, value in altered_fields.items() if key != "identity_digest"}
    )
    altered_toolchain = ToolchainIdentity.from_dict(altered_fields)
    with pytest.raises(ValueError, match="toolchain differs"):
        CrossRepositoryExecution.build(
            plan=plan,
            capture=capture,
            toolchain=altered_toolchain,
            started_at="2026-07-20T14:40:01Z",
            finished_at="2026-07-20T14:40:02Z",
            results=results,
            temporary_workspaces_removed=True,
        )

    different_git_reports = {
        request.repository_id: scan_repository(
            request.repository_root,
            POLICY_PATH,
            git_trust_policy=GitTrustPolicy(maximum_version_exclusive="99.0.0"),
        )
        for request in requests
    }
    different_git_results = tuple(
        HistoricalRepositoryExecution.build(
            snapshot=snapshots[repository_id],
            status="succeeded",
            report=different_git_reports[repository_id],
        )
        for repository_id in plan.execution_order
    )
    with pytest.raises(ValueError, match="Git provenance differs"):
        _execution_record(
            plan=plan,
            capture=capture,
            results=different_git_results,
        )
