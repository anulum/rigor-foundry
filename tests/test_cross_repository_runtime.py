# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real historical campaign execution tests
"""Exercise isolated detached scans without changing source repositories."""

from __future__ import annotations

import os
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

import rigor_foundry.cross_repository_runtime as runtime
from rigor_foundry.campaign_evidence import ToolchainIdentity
from rigor_foundry.cross_repository_campaign import InterRepositoryEdge
from rigor_foundry.cross_repository_capture import (
    CrossRepositoryCapture,
    RepositoryCaptureRequest,
    capture_cross_repository_campaign,
)
from rigor_foundry.cross_repository_execution import (
    CrossRepositoryExecutionPlan,
    adapter_lock_digest,
)
from rigor_foundry.cross_repository_runtime import (
    CampaignCancellation,
    execute_cross_repository_campaign,
)
from rigor_foundry.git_provenance import GitTrustPolicy
from rigor_foundry.rules import RULE_PACK_VERSION, rule_pack_digest
from rigor_foundry.scanner import scan_repository

FROZEN_AT = "2026-07-20T14:50:00Z"
POLICY_PATH = Path("rigor-foundry-policy.json")


@dataclass(frozen=True)
class PreparedRepository:
    """Real source repository plus its historical request."""

    repository: GitRepository
    request: RepositoryCaptureRequest
    historical_head: str


class CancelAfterMaterialisation(CampaignCancellation):
    """Request cancellation on the second repository-boundary observation."""

    def __init__(self) -> None:
        super().__init__()
        self.observations = 0

    @property
    def requested(self) -> bool:
        """Remain active once, then cancel after detached materialisation."""
        self.observations += 1
        return self.observations >= 2


class MutatingCancellation(CampaignCancellation):
    """Change source root metadata after the runtime captures its before-state."""

    def __init__(self, root: Path) -> None:
        super().__init__()
        self.root = root

    @property
    def requested(self) -> bool:
        """Perform one real concurrent source-state mutation and cancel."""
        metadata = self.root.stat(follow_symlinks=False)
        os.utime(
            self.root,
            ns=(metadata.st_atime_ns, metadata.st_mtime_ns - 1_000_000_000),
            follow_symlinks=False,
        )
        return True


def _prepare(path: Path, repository_id: str) -> PreparedRepository:
    """Create one historical commit with a complete policy and frozen request."""
    repository = GitRepository.create(path)
    repository.write_text(f"src/{repository_id}.py", "VALUE = 1\n")
    repository.write_policy()
    historical_head = repository.commit(f"test: create {repository_id}")
    report = scan_repository(repository.root, POLICY_PATH)
    request = RepositoryCaptureRequest.build(
        repository_id=repository_id,
        repository_root=repository.root,
        requested_commit=historical_head,
        policy_digest=report.policy_digest,
        rule_pack_version=report.rule_pack_version,
        rule_pack_digest=report.rule_pack_digest,
        adapter_lock_digest=adapter_lock_digest(report.policy),
        toolchain_digest=ToolchainIdentity.current().identity_digest,
    )
    return PreparedRepository(repository, request, historical_head)


def _edge(source: str, dependency: str) -> InterRepositoryEdge:
    """Build one explicit dependency edge."""
    return InterRepositoryEdge.build(
        from_repository=source,
        to_repository=dependency,
        relationship="depends-on",
        rationale="runtime test dependency",
    )


def _freeze(
    requests: tuple[RepositoryCaptureRequest, ...],
    *,
    edges: tuple[InterRepositoryEdge, ...] = (),
) -> tuple[CrossRepositoryCapture, CrossRepositoryExecutionPlan]:
    """Capture exact requests and build their execution plan."""
    capture = capture_cross_repository_campaign(
        campaign_id="runtime-campaign",
        frozen_at=FROZEN_AT,
        requests=requests,
        edges=edges,
    )
    plan = CrossRepositoryExecutionPlan.build(
        capture=capture,
        requests=requests,
        policy_paths=tuple(POLICY_PATH.as_posix() for _item in requests),
    )
    return capture, plan


def _source_state(repository: GitRepository) -> tuple[str, str, str]:
    """Return the checkout state protected by the execution contract."""
    return (
        repository.git_command("rev-parse", "HEAD").stdout,
        repository.git_command("rev-parse", "HEAD^{tree}").stdout,
        repository.git_command(
            "status",
            "--porcelain=v2",
            "--branch",
            "-z",
            "--untracked-files=all",
        ).stdout,
    )


def _advance_and_dirty(prepared: PreparedRepository) -> None:
    """Move a source beyond the capture and leave tracked and untracked dirt."""
    repository_id = prepared.request.repository_id
    prepared.repository.write_text(f"src/{repository_id}.py", "VALUE = 2\n")
    prepared.repository.commit(f"test: advance {repository_id}")
    prepared.repository.write_text(f"src/{repository_id}.py", "VALUE = 3\n")
    prepared.repository.write_text("scratch.txt", "untracked\n")


def test_runtime_scans_dependency_first_historical_trees_without_source_mutation(
    tmp_path: Path,
) -> None:
    """Old commits execute detached while newer dirty source checkouts remain exact."""
    app = _prepare(tmp_path / "sources" / "app", "app")
    library = _prepare(tmp_path / "sources" / "library", "library")
    requests = (app.request, library.request)
    capture, plan = _freeze(requests, edges=(_edge("app", "library"),))
    _advance_and_dirty(app)
    _advance_and_dirty(library)
    before = (_source_state(app.repository), _source_state(library.repository))
    temporary_parent = tmp_path / "temporary"
    temporary_parent.mkdir()

    execution = execute_cross_repository_campaign(
        plan=plan,
        capture=capture,
        requests=requests,
        temporary_parent=temporary_parent,
    )

    assert execution.resolution == "succeeded"
    assert tuple(item.repository_id for item in execution.results) == ("library", "app")
    assert tuple(item.report.head for item in execution.results if item.report) == (
        library.historical_head,
        app.historical_head,
    )
    assert all(item.report and item.report.branch == "HEAD" for item in execution.results)
    assert all(item.report and not item.report.dirty_paths for item in execution.results)
    assert (_source_state(app.repository), _source_state(library.repository)) == before
    assert tuple(temporary_parent.iterdir()) == ()
    assert execution.temporary_workspaces_removed is True


def test_pre_requested_cancellation_records_every_repository_and_rolls_back(
    tmp_path: Path,
) -> None:
    """Cancellation at the first boundary remains explicit for the whole plan."""
    app = _prepare(tmp_path / "sources" / "app", "app")
    library = _prepare(tmp_path / "sources" / "library", "library")
    requests = (app.request, library.request)
    capture, plan = _freeze(requests, edges=(_edge("app", "library"),))
    temporary_parent = tmp_path / "temporary"
    temporary_parent.mkdir()
    cancellation = CampaignCancellation()
    cancellation.cancel()
    assert cancellation.requested is True

    execution = execute_cross_repository_campaign(
        plan=plan,
        capture=capture,
        requests=requests,
        cancellation=cancellation,
        temporary_parent=temporary_parent,
    )

    assert execution.resolution == "cancelled"
    assert tuple(item.status for item in execution.results) == ("cancelled", "cancelled")
    assert tuple(item.reason for item in execution.results) == ("cancelled", "cancelled")
    assert tuple(temporary_parent.iterdir()) == ()


def test_cancellation_after_materialisation_removes_detached_workspace(
    tmp_path: Path,
) -> None:
    """A boundary cancellation after fetch never scans or retains the checkout."""
    prepared = _prepare(tmp_path / "source", "repository")
    capture, plan = _freeze((prepared.request,))
    temporary_parent = tmp_path / "temporary"
    temporary_parent.mkdir()
    cancellation = CancelAfterMaterialisation()

    execution = execute_cross_repository_campaign(
        plan=plan,
        capture=capture,
        requests=(prepared.request,),
        cancellation=cancellation,
        temporary_parent=temporary_parent,
    )

    assert cancellation.observations == 2
    assert execution.resolution == "cancelled"
    assert execution.results[0].reason == "cancelled"
    assert tuple(temporary_parent.iterdir()) == ()


def test_unavailable_dependency_blocks_dependant_without_laundering_evidence(
    tmp_path: Path,
) -> None:
    """A capture-time missing object makes its dependant explicitly unavailable."""
    app = _prepare(tmp_path / "sources" / "app", "app")
    library = _prepare(tmp_path / "sources" / "library", "library")
    missing_library = RepositoryCaptureRequest.build(
        repository_id="library",
        repository_root=library.repository.root,
        requested_commit="f" * 40,
        policy_digest=library.request.policy_digest,
        rule_pack_version=library.request.rule_pack_version,
        rule_pack_digest=library.request.rule_pack_digest,
        adapter_lock_digest=library.request.adapter_lock_digest,
        toolchain_digest=library.request.toolchain_digest,
    )
    requests = (app.request, missing_library)
    capture, plan = _freeze(requests, edges=(_edge("app", "library"),))

    execution = execute_cross_repository_campaign(
        plan=plan,
        capture=capture,
        requests=requests,
    )

    assert execution.resolution == "unavailable"
    assert tuple(item.repository_id for item in execution.results) == ("library", "app")
    assert tuple(item.reason for item in execution.results) == (
        "capture-unavailable",
        "dependency-unavailable",
    )
    assert all(item.report is None for item in execution.results)


def test_independent_frozen_input_divergence_is_partial_not_success(
    tmp_path: Path,
) -> None:
    """One mismatched frozen policy cannot erase another repository's real scan."""
    good = _prepare(tmp_path / "sources" / "good", "good")
    bad = _prepare(tmp_path / "sources" / "bad", "bad")
    divergent_request = RepositoryCaptureRequest.build(
        repository_id="bad",
        repository_root=bad.repository.root,
        requested_commit=bad.historical_head,
        policy_digest="0" * 64,
        rule_pack_version=bad.request.rule_pack_version,
        rule_pack_digest=bad.request.rule_pack_digest,
        adapter_lock_digest=bad.request.adapter_lock_digest,
        toolchain_digest=bad.request.toolchain_digest,
    )
    requests = (good.request, divergent_request)
    capture, plan = _freeze(requests)

    execution = execute_cross_repository_campaign(
        plan=plan,
        capture=capture,
        requests=requests,
    )

    assert execution.resolution == "partial"
    outcomes = {item.repository_id: item for item in execution.results}
    assert outcomes["good"].status == "succeeded"
    assert outcomes["bad"].status == "failed"
    assert outcomes["bad"].reason == "frozen-input-divergence"


def test_pruned_historical_object_becomes_runtime_unavailable(tmp_path: Path) -> None:
    """An object removed after capture is unavailable rather than failed or passed."""
    old = _prepare(tmp_path / "source", "old")
    capture, plan = _freeze((old.request,))
    _advance_and_dirty(old)
    object_path = (
        old.repository.root
        / ".git"
        / "objects"
        / old.historical_head[:2]
        / old.historical_head[2:]
    )
    object_path.unlink()
    before = _source_state(old.repository)

    execution = execute_cross_repository_campaign(
        plan=plan,
        capture=capture,
        requests=(old.request,),
    )

    assert execution.resolution == "unavailable"
    assert execution.results[0].reason == "historical-object-unavailable"
    assert _source_state(old.repository) == before


def test_corrupt_historical_object_aborts_git_inspection(tmp_path: Path) -> None:
    """Git operational corruption is not downgraded to ordinary unavailability."""
    old = _prepare(tmp_path / "source", "old")
    capture, plan = _freeze((old.request,))
    _advance_and_dirty(old)
    object_path = (
        old.repository.root
        / ".git"
        / "objects"
        / old.historical_head[:2]
        / old.historical_head[2:]
    )
    object_path.chmod(0o600)
    object_path.write_bytes(b"corrupt-object")

    with pytest.raises(RuntimeError, match="could not inspect"):
        execute_cross_repository_campaign(
            plan=plan,
            capture=capture,
            requests=(old.request,),
        )


def test_controlled_fetch_failure_is_materialisation_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A post-availability fetch failure produces one bounded failed outcome."""
    prepared = _prepare(tmp_path / "source", "repository")
    capture, plan = _freeze((prepared.request,))

    def fail_materialisation(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("controlled fetch boundary failure")

    monkeypatch.setattr(runtime, "_materialise", fail_materialisation)

    execution = execute_cross_repository_campaign(
        plan=plan,
        capture=capture,
        requests=(prepared.request,),
    )

    assert execution.resolution == "failed"
    assert execution.results[0].reason == "materialisation-failed"


def test_historical_policy_symlink_escape_fails_without_reading_outside(
    tmp_path: Path,
) -> None:
    """A tracked historical policy symlink cannot import external policy bytes."""
    outside = tmp_path / "outside-policy.json"
    outside.write_text('{"secret":"unchanged"}\n', encoding="utf-8")
    repository = GitRepository.create(tmp_path / "source")
    repository.write_text("src/module.py", "VALUE = 1\n")
    repository.symlink(POLICY_PATH.as_posix(), str(outside))
    head = repository.commit()
    request = RepositoryCaptureRequest.build(
        repository_id="linked",
        repository_root=repository.root,
        requested_commit=head,
        policy_digest="a" * 64,
        rule_pack_version=RULE_PACK_VERSION,
        rule_pack_digest=rule_pack_digest(),
        adapter_lock_digest="b" * 64,
        toolchain_digest=ToolchainIdentity.current().identity_digest,
    )
    capture, plan = _freeze((request,))
    before = (_source_state(repository), outside.read_bytes())

    execution = execute_cross_repository_campaign(
        plan=plan,
        capture=capture,
        requests=(request,),
    )

    assert execution.resolution == "failed"
    assert execution.results[0].reason == "scan-failed"
    assert (_source_state(repository), outside.read_bytes()) == before


def test_stale_or_substituted_plan_is_rejected_before_materialisation(
    tmp_path: Path,
) -> None:
    """Changed order, policy, or digest cannot reuse a frozen plan identity."""
    app = _prepare(tmp_path / "sources" / "app", "app")
    library = _prepare(tmp_path / "sources" / "library", "library")
    requests = (app.request, library.request)
    capture, plan = _freeze(requests, edges=(_edge("app", "library"),))
    changed_target = replace(plan.targets[0], policy_path="other-policy.json")
    invalid_target = replace(plan.targets[0], policy_path="../outside-policy.json")
    mutations = (
        replace(plan, execution_order=tuple(reversed(plan.execution_order))),
        replace(plan, targets=(changed_target, plan.targets[1])),
        replace(plan, targets=(invalid_target, plan.targets[1])),
        replace(plan, plan_digest="0" * 64),
    )

    for mutation in mutations:
        with pytest.raises(ValueError, match="stale or substituted"):
            execute_cross_repository_campaign(
                plan=mutation,
                capture=capture,
                requests=requests,
            )

    forged_request = replace(
        requests[0],
        repository_root=requests[1].repository_root,
    )
    with pytest.raises(ValueError, match="stale or substituted"):
        execute_cross_repository_campaign(
            plan=plan,
            capture=capture,
            requests=(forged_request, requests[1]),
        )


def test_temporary_parent_must_be_canonical_and_disjoint_from_sources(
    tmp_path: Path,
) -> None:
    """Temporary materialisation cannot nest in, contain, or alias a source."""
    prepared = _prepare(tmp_path / "sources" / "repository", "repository")
    capture, plan = _freeze((prepared.request,))
    real_parent = tmp_path / "temporary"
    real_parent.mkdir()
    linked_parent = tmp_path / "temporary-link"
    os.symlink(real_parent, linked_parent)
    invalid = (
        Path("relative"),
        prepared.repository.root,
        tmp_path / "sources",
        linked_parent,
    )

    for candidate in invalid:
        with pytest.raises(ValueError, match="temporary workspace parent"):
            execute_cross_repository_campaign(
                plan=plan,
                capture=capture,
                requests=(prepared.request,),
                temporary_parent=candidate,
            )


def test_runtime_rejects_git_provenance_substitution(tmp_path: Path) -> None:
    """Execution cannot silently widen the Git trust interval used at capture."""
    prepared = _prepare(tmp_path / "source", "repository")
    capture, plan = _freeze((prepared.request,))
    changed_policy = GitTrustPolicy(maximum_version_exclusive="99.0.0")

    with pytest.raises(ValueError, match="Git provenance differs"):
        execute_cross_repository_campaign(
            plan=plan,
            capture=capture,
            requests=(prepared.request,),
            git_trust_policy=changed_policy,
        )


def test_concurrent_source_identity_change_aborts_after_rollback(tmp_path: Path) -> None:
    """A source mutation observed after execution overrides any outcome claim."""
    prepared = _prepare(tmp_path / "source", "repository")
    capture, plan = _freeze((prepared.request,))
    temporary_parent = tmp_path / "temporary"
    temporary_parent.mkdir()

    with pytest.raises(RuntimeError, match="source repository state changed"):
        execute_cross_repository_campaign(
            plan=plan,
            capture=capture,
            requests=(prepared.request,),
            cancellation=MutatingCancellation(prepared.repository.root),
            temporary_parent=temporary_parent,
        )
    assert tuple(temporary_parent.iterdir()) == ()
