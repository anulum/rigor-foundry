# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — normative digest-dependency tests
"""Prove declared identity propagation and unrelated-record stability."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from repository_audit_git_repository import sample_git_provenance, sample_tree_anchor
from signing_fixtures import trust_store
from test_effective_profile import profile as project_profile
from test_effective_profile import standard_pack
from test_work_models import lifecycle, source_records

import rigor_foundry
from rigor_foundry.campaign_compare import AuditComparison, compare_campaign
from rigor_foundry.campaign_models import AuditCampaign, ToolchainIdentity
from rigor_foundry.digest_dependencies import (
    DIGEST_DEPENDENCIES,
    DIGEST_DEPENDENCY_SCHEMA_VERSION,
    DIGEST_NODES,
    DigestDependency,
    DigestNode,
    DigestNodeSpec,
    digest_dependency_graph,
    digest_dependency_graph_digest,
    direct_dependents,
    transitive_dependents,
    validate_digest_dependency_graph,
)
from rigor_foundry.effective_profile import (
    AdapterLock,
    EffectiveControl,
    EffectiveProfileLock,
    PackVerification,
    ResolvedVariable,
)
from rigor_foundry.git_provenance import GitExecutableProvenance
from rigor_foundry.ignored_inventory import (
    IgnoredInventoryDeclaration,
    IgnoredInventoryEvidence,
)
from rigor_foundry.models import (
    AuditPolicy,
    AuditReport,
    Candidate,
    ReviewRecord,
    canonical_digest,
)
from rigor_foundry.rule_maturity import RuleMaturityPolicy, RuleMaturityReport
from rigor_foundry.standard_pack import StandardPack
from rigor_foundry.work_closure import WorkClosure
from rigor_foundry.work_models import WorkEvent, WorkRecord, WorkTask

DigestSnapshot = dict[DigestNode, str]


def _toolchain(*, executable_digest: str = "f" * 64) -> ToolchainIdentity:
    """Return one deterministic, parser-verified toolchain identity."""
    fields = {
        "python_implementation": "CPython",
        "python_version": "3.12.3",
        "platform": "linux-test-fixture",
        "executable_digest": executable_digest,
    }
    return ToolchainIdentity.from_dict({**fields, "identity_digest": canonical_digest(fields)})


def _report(
    root: Path,
    *,
    policy: AuditPolicy | None = None,
    tracked_content_digest: str = "3" * 64,
    candidates: tuple[Candidate, ...] | None = None,
    git_provenance: GitExecutableProvenance | None = None,
    ignored_inventory_evidence: tuple[IgnoredInventoryEvidence, ...] = (),
) -> AuditReport:
    """Build one report whose repository root exists for campaign construction."""
    source, _review_record = source_records()
    return AuditReport.build(
        repository_root=str(root),
        head=source.head,
        head_tree=source.head_tree,
        git_object_format=source.git_object_format,
        branch=source.branch,
        tracked_content_digest=tracked_content_digest,
        dirty_paths=source.dirty_paths,
        tracked_file_count=source.tracked_file_count,
        git_provenance=git_provenance or sample_git_provenance(),
        policy=source.policy if policy is None else policy,
        ignored_inventory_evidence=ignored_inventory_evidence,
        candidates=source.candidates if candidates is None else candidates,
    )


def _review(
    report: AuditReport, *, rationale: str = "reproduced on the exact tree"
) -> ReviewRecord:
    """Return one valid review bound to ``report``."""
    candidate = report.candidates[0]
    return ReviewRecord(
        report_digest=report.report_digest,
        candidate_id=candidate.candidate_id,
        decision="valid",
        reviewer="audit-reviewer",
        reviewed_at="2026-07-15T10:00:00Z",
        rationale=rationale,
        evidence=("sha256:review-evidence",),
        severity="P1",
        owner="implementation-owner",
        dependencies=(),
        acceptance_gates=("focused-import-test",),
        title="Remove first-party import cycle",
        boundary_justification="not an accepted architecture boundary",
        expires_at="",
        reopen_triggers=("import-graph-change",),
    )


def _task(
    report: AuditReport,
    review: ReviewRecord,
    *,
    created_at: str = "2026-07-15T10:05:00Z",
) -> WorkTask:
    """Build one task compatible with the real closed-event fixture."""
    return WorkTask.build(
        report,
        review,
        task_id="architecture-import-cycle",
        production_impact="cycle can create partial module initialisation",
        affected_surfaces=("src/rigor_foundry/a.py", "src/rigor_foundry/b.py"),
        prohibited_shortcuts=("no lazy-import masking", "no test deletion"),
        required_verifier="independent-verifier",
        created_by="planning-agent",
        created_at=created_at,
    )


def _campaign(
    report: AuditReport,
    *,
    created_at: str = "2026-07-15T12:00:00Z",
    toolchain: ToolchainIdentity | None = None,
) -> AuditCampaign:
    """Build one independent-audit contract from the report input projection."""
    return AuditCampaign.build(
        report,
        campaign_id="digest-campaign",
        project="rigor-foundry",
        policy_path="rigor-foundry-policy.json",
        toolchain=toolchain or _toolchain(),
        created_by="coordinator/one",
        created_at=created_at,
        expected_runs=1,
    )


def _comparison(campaign: AuditCampaign) -> AuditComparison:
    """Build one deterministic empty-run comparison for ``campaign``."""
    return compare_campaign(
        campaign,
        (),
        (),
        comparison_id="digest-comparison",
        created_by="coordinator/one",
        created_at="2026-07-15T12:05:00Z",
    )


def _events(task: WorkTask) -> tuple[WorkEvent, ...]:
    """Rebuild the real lifecycle fixture against ``task``'s exact source."""
    _fixture_task, templates = lifecycle()
    events: list[WorkEvent] = []
    for template in templates:
        previous = events[-1] if events else None
        source_state = template.sequence <= 4
        events.append(
            WorkEvent.build(
                sequence=template.sequence,
                task_id=task.task_id,
                previous_state=previous.state if previous is not None else None,
                state=template.state,
                actor=template.actor,
                occurred_at=template.occurred_at,
                head=task.baseline_head if source_state else template.head,
                head_tree=task.baseline_head_tree if source_state else template.head_tree,
                tracked_content_digest=(
                    task.baseline_tracked_content_digest
                    if source_state
                    else template.tracked_content_digest
                ),
                owner=template.owner,
                candidate_id=(
                    task.candidate.candidate_id
                    if template.state == "revalidated"
                    else template.candidate_id
                ),
                report_digest=(
                    task.source_report_digest
                    if template.state == "revalidated"
                    else template.report_digest
                ),
                commit_sha=template.commit_sha,
                commit_tree=template.commit_tree,
                verifier=template.verifier,
                reason=template.reason,
                evidence=template.evidence,
                limitations=template.limitations,
                previous_event_digest=(previous.event_digest if previous is not None else ""),
            )
        )
    return tuple(events)


def _closure(task: WorkTask) -> WorkClosure:
    """Bind ``task`` to the real independently verified closure chain."""
    events = _events(task)
    return WorkClosure.build(WorkRecord.build(task, events))


def _workflow_snapshot(
    report: AuditReport,
    review: ReviewRecord,
    task: WorkTask,
    campaign: AuditCampaign,
) -> DigestSnapshot:
    """Return production identities for the report/campaign/work subgraph."""
    return {
        "inventory": report.tracked_content_digest,
        "ignored-inventory": report.ignored_inventory_digest,
        "git-provenance": report.git_provenance.identity_digest,
        "policy": report.policy_digest,
        "rule-pack": report.rule_pack_digest,
        "toolchain": campaign.toolchain.identity_digest,
        "report": report.report_digest,
        "review": review.review_digest,
        "campaign": campaign.contract_digest,
        "comparison": _comparison(campaign).comparison_digest,
        "task": task.definition_digest,
        "closure": _closure(task).closure_digest,
    }


def _effective_records(
    *,
    pack_id: str = "core",
    adapter_config_digest: str = "6" * 64,
    toolchain_digest: str = "9" * 64,
) -> tuple[AdapterLock, StandardPack, EffectiveProfileLock]:
    """Build mutually valid standard, adapter, and effective-profile records."""
    pack = standard_pack(pack_id=pack_id)
    profile = project_profile(pack)
    verification = PackVerification.build(
        pack=pack,
        trust_store=trust_store("trusted-key"),
        verified_at="2026-07-15T11:55:00Z",
    )
    adapter = AdapterLock.build(
        adapter_id="loc-adapter",
        version="1.0.0",
        executable_digest="5" * 64,
        config_digest=adapter_config_digest,
        command_digest="7" * 64,
        environment_digest="8" * 64,
        domains=("godfile-responsibility",),
    )
    variable = ResolvedVariable.build(profile.variables[0], None)
    control = EffectiveControl.build(
        source_pack=pack,
        control=pack.controls[0],
        applicable=True,
        applicability_rationale="pack default and project maturity",
        target_level="enterprise",
        mode="require",
        active_waiver_ids=(),
        missing_adapter_ids=(),
    )
    lock = EffectiveProfileLock.build(
        profile=profile,
        packs=(pack,),
        verifications=(verification,),
        adapters=(adapter,),
        variables=(variable,),
        controls=(control,),
        warnings=(),
        trust_store=trust_store("trusted-key"),
        toolchain_digest=toolchain_digest,
        resolved_at="2026-07-15T12:00:00Z",
    )
    return adapter, pack, lock


def _profile_snapshot(
    adapter: AdapterLock,
    pack: StandardPack,
    lock: EffectiveProfileLock,
) -> DigestSnapshot:
    """Return production identities for the standard/effective-profile subgraph."""
    return {
        "adapter-lock": adapter.adapter_digest,
        "standard-pack": pack.pack_digest,
        "effective-profile": lock.lock_digest,
        **_maturity_snapshot(),
    }


def _maturity_policy(*, maximum_p90_effort_seconds: int = 90) -> RuleMaturityPolicy:
    """Return one explicit probation policy for digest propagation tests."""
    return RuleMaturityPolicy.build(
        minimum_adjudicated_reviews=2,
        minimum_distinct_repositories=2,
        minimum_distinct_reviewers=2,
        minimum_positive_reviews=1,
        maximum_false_positive_basis_points=1_000,
        maximum_median_effort_seconds=60,
        maximum_p90_effort_seconds=maximum_p90_effort_seconds,
    )


def _maturity_snapshot(
    policy: RuleMaturityPolicy | None = None,
) -> DigestSnapshot:
    """Return maturity policy and derived full-pack identities."""
    selected = policy or _maturity_policy()
    report = RuleMaturityReport.build(selected, ())
    return {
        "maturity-policy": selected.policy_digest,
        "rule-maturity": report.maturity_digest,
    }


def _assert_transition(
    mutated: DigestNode,
    before: DigestSnapshot,
    after: DigestSnapshot,
) -> None:
    """Assert complete dependent propagation and unrelated-node stability."""
    assert before.keys() == after.keys()
    changed = {node for node in before if before[node] != after[node]}
    expected = {mutated, *transitive_dependents(mutated)}.intersection(before)
    assert changed == expected


def test_graph_schema_is_complete_acyclic_and_content_addressed() -> None:
    """The public graph has one stable identity for every required record family."""
    assert DIGEST_DEPENDENCY_SCHEMA_VERSION == "1.3"
    assert tuple(node.name for node in DIGEST_NODES) == (
        "inventory",
        "ignored-inventory",
        "git-provenance",
        "policy",
        "rule-pack",
        "maturity-policy",
        "rule-maturity",
        "adapter-lock",
        "standard-pack",
        "toolchain",
        "effective-profile",
        "report",
        "review",
        "campaign",
        "comparison",
        "task",
        "closure",
    )
    assert len(DIGEST_DEPENDENCIES) == 24
    assert validate_digest_dependency_graph() == ()
    assert digest_dependency_graph()["schema_version"] == "1.3"
    assert rigor_foundry.digest_dependency_graph() == digest_dependency_graph()
    assert rigor_foundry.WorkClosure is WorkClosure
    assert direct_dependents("standard-pack") == ("effective-profile",)
    assert direct_dependents("maturity-policy") == ("rule-maturity",)
    assert transitive_dependents("review") == ("task", "closure")
    assert transitive_dependents("toolchain") == (
        "effective-profile",
        "campaign",
        "comparison",
    )
    assert transitive_dependents("inventory") == (
        "report",
        "review",
        "campaign",
        "comparison",
        "task",
        "closure",
    )
    assert (
        digest_dependency_graph_digest()
        == "7d050f9c2aa6ca636a71f18ccb89bf7a308c15eb5c586477f9ba24f6b138a8b8"
    )


@pytest.mark.parametrize(
    "nodes, dependencies, messages",
    [
        (
            (DIGEST_NODES[0], DIGEST_NODES[0]),
            (),
            ("node names", "identity fields"),
        ),
        (
            DIGEST_NODES,
            (DIGEST_DEPENDENCIES[0], DIGEST_DEPENDENCIES[0]),
            ("edges must be unique",),
        ),
        (
            DIGEST_NODES,
            (DigestDependency("inventory", "report", ""),),
            ("binding is empty",),
        ),
        (
            DIGEST_NODES,
            (DigestDependency("inventory", cast(DigestNode, "unknown"), "field"),),
            ("unknown node",),
        ),
        (
            DIGEST_NODES,
            (DigestDependency("inventory", "inventory", "field"),),
            ("self-cycle", "cycle reaches inventory"),
        ),
        (
            DIGEST_NODES,
            (
                DigestDependency("inventory", "report", "field"),
                DigestDependency("report", "inventory", "field"),
            ),
            ("cycle reaches inventory", "cycle reaches report"),
        ),
        (
            (
                DigestNodeSpec("inventory", "shared_digest", "one"),
                DigestNodeSpec("policy", "shared_digest", "one"),
            ),
            (),
            ("identity fields",),
        ),
    ],
)
def test_graph_validator_rejects_ambiguous_or_cyclic_schemas(
    nodes: tuple[DigestNodeSpec, ...],
    dependencies: tuple[DigestDependency, ...],
    messages: tuple[str, ...],
) -> None:
    """Malformed graph declarations fail with exact structural evidence."""
    errors = validate_digest_dependency_graph(nodes, dependencies)
    for message in messages:
        assert any(message in error for error in errors)


def test_inventory_policy_and_rule_mutations_propagate_to_every_dependent(
    tmp_path: Path,
) -> None:
    """Input identities change every report, campaign, task, and closure dependent."""
    baseline_report = _report(tmp_path)
    baseline_review = _review(baseline_report)
    baseline_task = _task(baseline_report, baseline_review)
    baseline_campaign = _campaign(baseline_report)
    baseline = _workflow_snapshot(
        baseline_report,
        baseline_review,
        baseline_task,
        baseline_campaign,
    )
    profile = _profile_snapshot(
        *_effective_records(toolchain_digest=baseline_campaign.toolchain.identity_digest)
    )
    baseline.update(profile)

    inventory_report = _report(tmp_path, tracked_content_digest="4" * 64)
    inventory_review = _review(inventory_report)
    inventory_task = _task(inventory_report, inventory_review)
    _assert_transition(
        "inventory",
        baseline,
        {
            **_workflow_snapshot(
                inventory_report,
                inventory_review,
                inventory_task,
                _campaign(inventory_report),
            ),
            **profile,
        },
    )

    changed_policy = replace(
        baseline_report.policy,
        source_line_threshold=baseline_report.policy.source_line_threshold + 1,
    )
    policy_report = _report(tmp_path, policy=changed_policy)
    policy_review = _review(policy_report)
    policy_task = _task(policy_report, policy_review)
    _assert_transition(
        "policy",
        baseline,
        {
            **_workflow_snapshot(
                policy_report,
                policy_review,
                policy_task,
                _campaign(policy_report),
            ),
            **profile,
        },
    )

    changed_rule_body = baseline_report.to_dict()
    changed_rule_body.pop("report_digest")
    changed_rule_body["rule_pack_digest"] = "e" * 64
    rule_report = replace(
        baseline_report,
        rule_pack_digest="e" * 64,
        report_digest=canonical_digest(changed_rule_body),
    )
    rule_review = _review(rule_report)
    rule_task = _task(rule_report, rule_review)
    _assert_transition(
        "rule-pack",
        baseline,
        {
            **_workflow_snapshot(
                rule_report,
                rule_review,
                rule_task,
                _campaign(rule_report),
            ),
            **profile,
            "rule-maturity": canonical_digest(
                {
                    "prior": profile["rule-maturity"],
                    "rule_pack_digest": rule_report.rule_pack_digest,
                }
            ),
        },
    )

    original_git = baseline_report.git_provenance
    changed_git = GitExecutableProvenance.build(
        resolved_path=original_git.resolved_path,
        trusted_root=original_git.trusted_root,
        version=original_git.version,
        executable_digest="a" * 64,
        trust_policy=original_git.trust_policy,
    )
    git_report = _report(tmp_path, git_provenance=changed_git)
    git_review = _review(git_report)
    git_task = _task(git_report, git_review)
    _assert_transition(
        "git-provenance",
        baseline,
        {
            **_workflow_snapshot(
                git_report,
                git_review,
                git_task,
                _campaign(git_report),
            ),
            **profile,
        },
    )


def test_report_review_campaign_and_task_mutations_respect_stable_nonedges(
    tmp_path: Path,
) -> None:
    """Output-only changes propagate exactly where a digest is directly bound."""
    baseline_report = _report(tmp_path)
    baseline_review = _review(baseline_report)
    baseline_task = _task(baseline_report, baseline_review)
    baseline_campaign = _campaign(baseline_report)
    baseline = _workflow_snapshot(
        baseline_report,
        baseline_review,
        baseline_task,
        baseline_campaign,
    )
    profile = _profile_snapshot(
        *_effective_records(toolchain_digest=baseline_campaign.toolchain.identity_digest)
    )
    baseline.update(profile)

    added = Candidate.build(
        category="architecture",
        rule_id="AR002-wildcard-import-boundary",
        anchor=sample_tree_anchor("src/rigor_foundry/public.py"),
        symbol="rigor_foundry.public",
        evidence="wildcard import crosses the public boundary",
        confidence="high",
        rationale="export ownership requires review",
        verification="import explicit public names in a clean process",
    )
    report_changed = _report(
        tmp_path,
        candidates=(*baseline_report.candidates, added),
    )
    report_review = _review(report_changed)
    report_task = _task(report_changed, report_review)
    _assert_transition(
        "report",
        baseline,
        {
            **_workflow_snapshot(
                report_changed,
                report_review,
                report_task,
                _campaign(report_changed),
            ),
            **profile,
        },
    )

    review_changed = replace(
        baseline_review,
        rationale="independently reproduced twice on the exact tree",
    )
    review_task = _task(baseline_report, review_changed)
    _assert_transition(
        "review",
        baseline,
        {
            **_workflow_snapshot(
                baseline_report,
                review_changed,
                review_task,
                baseline_campaign,
            ),
            **profile,
        },
    )

    campaign_changed = _campaign(
        baseline_report,
        created_at="2026-07-15T12:01:00Z",
    )
    _assert_transition(
        "campaign",
        baseline,
        {
            **_workflow_snapshot(
                baseline_report,
                baseline_review,
                baseline_task,
                campaign_changed,
            ),
            **profile,
        },
    )

    task_changed = _task(
        baseline_report,
        baseline_review,
        created_at="2026-07-15T10:06:00Z",
    )
    _assert_transition(
        "task",
        baseline,
        {
            **_workflow_snapshot(
                baseline_report,
                baseline_review,
                task_changed,
                baseline_campaign,
            ),
            **profile,
        },
    )


def test_ignored_inventory_mutation_rebinds_report_and_campaign_subgraphs(
    tmp_path: Path,
) -> None:
    """Ignored evidence changes every declared dependent and no unrelated identity."""
    declaration = IgnoredInventoryDeclaration(
        "runtime-state",
        ".rigor/runtime-state.json",
        "file-sha256",
    )
    policy = replace(_report(tmp_path).policy, ignored_inventory=(declaration,))
    missing = IgnoredInventoryEvidence(
        declaration.evidence_id,
        declaration.path,
        declaration.capture,
        "missing",
        None,
        None,
        None,
        "missing",
    )
    observed = IgnoredInventoryEvidence(
        declaration.evidence_id,
        declaration.path,
        declaration.capture,
        "observed",
        "regular-file",
        2,
        "a" * 64,
        "observed",
    )
    before_report = _report(
        tmp_path,
        policy=policy,
        ignored_inventory_evidence=(missing,),
    )
    before_review = _review(before_report)
    before_task = _task(before_report, before_review)
    before_campaign = _campaign(before_report)
    baseline = _workflow_snapshot(
        before_report,
        before_review,
        before_task,
        before_campaign,
    )
    profile = _profile_snapshot(
        *_effective_records(toolchain_digest=before_campaign.toolchain.identity_digest)
    )
    baseline.update(profile)

    after_report = _report(
        tmp_path,
        policy=policy,
        ignored_inventory_evidence=(observed,),
    )
    after_review = _review(after_report)
    after_task = _task(after_report, after_review)
    _assert_transition(
        "ignored-inventory",
        baseline,
        {
            **_workflow_snapshot(
                after_report,
                after_review,
                after_task,
                _campaign(after_report),
            ),
            **profile,
        },
    )


def test_adapter_pack_toolchain_and_effective_profile_bind_exact_dependencies(
    tmp_path: Path,
) -> None:
    """Adapter, pack, and toolchain mutations change only declared dependents."""
    report = _report(tmp_path)
    review = _review(report)
    task = _task(report, review)
    campaign = _campaign(report)
    adapter, pack, lock = _effective_records(toolchain_digest=campaign.toolchain.identity_digest)
    baseline = _profile_snapshot(adapter, pack, lock)
    workflow = _workflow_snapshot(report, review, task, campaign)
    baseline.update(workflow)

    changed_adapter, same_pack, adapter_lock = _effective_records(
        adapter_config_digest="a" * 64,
        toolchain_digest=campaign.toolchain.identity_digest,
    )
    _assert_transition(
        "adapter-lock",
        baseline,
        {
            **_profile_snapshot(changed_adapter, same_pack, adapter_lock),
            **workflow,
        },
    )

    same_adapter, changed_pack, pack_lock = _effective_records(
        pack_id="alternate",
        toolchain_digest=campaign.toolchain.identity_digest,
    )
    _assert_transition(
        "standard-pack",
        baseline,
        {
            **_profile_snapshot(same_adapter, changed_pack, pack_lock),
            **workflow,
        },
    )

    changed_toolchain = _toolchain(executable_digest="b" * 64)
    same_adapter, same_pack, changed_lock = _effective_records(
        toolchain_digest=changed_toolchain.identity_digest
    )
    changed_workflow = _workflow_snapshot(
        report,
        review,
        task,
        _campaign(report, toolchain=changed_toolchain),
    )
    _assert_transition(
        "toolchain",
        baseline,
        {
            **_profile_snapshot(same_adapter, same_pack, changed_lock),
            **changed_workflow,
        },
    )


def test_maturity_policy_mutation_rebinds_the_complete_rule_assessment() -> None:
    """A threshold change rebinds maturity without changing unrelated records."""
    before_policy = _maturity_policy()
    after_policy = _maturity_policy(maximum_p90_effort_seconds=120)
    adapter, pack, lock = _effective_records()
    stable: DigestSnapshot = {
        "adapter-lock": adapter.adapter_digest,
        "standard-pack": pack.pack_digest,
        "effective-profile": lock.lock_digest,
    }
    before: DigestSnapshot = dict(stable)
    before.update(_maturity_snapshot(before_policy))
    after: DigestSnapshot = dict(stable)
    after.update(_maturity_snapshot(after_policy))

    _assert_transition("maturity-policy", before, after)


def test_policy_and_review_identities_bind_complete_canonical_records() -> None:
    """First-class policy and review identities preserve canonical semantics."""
    definition, _events = lifecycle()
    assert definition.review_digest == source_records()[1].review_digest
    assert source_records()[0].policy_digest == source_records()[0].policy.policy_digest


def test_digest_query_rejects_an_unknown_runtime_node() -> None:
    """Runtime graph queries fail closed for values outside the declared schema."""
    with pytest.raises(ValueError, match="unsupported digest node"):
        direct_dependents(cast(DigestNode, "unknown"))
