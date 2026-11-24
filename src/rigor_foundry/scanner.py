# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — repository audit composition root
"""Compose portable scanners over one exact Git-tracked repository inventory."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Final

from .api_compatibility import scan_api_compatibility
from .application_security import scan_application_security
from .architecture import scan_architecture
from .candidate_anchor import (
    CandidateAnchor,
    RepositoryTreeAnchor,
    TrackedBlobAnchor,
    candidate_anchor_errors,
)
from .container import scan_container
from .cra_rules import scan_cra
from .data_privacy import scan_data_privacy
from .documentation import scan_documentation
from .domains import domain_governance_candidates
from .git_inventory import GitInventory, load_git_inventory, resolve_repository_root
from .git_provenance import GitRunner, GitTrustPolicy
from .github_actions import scan_github_actions
from .godfiles import scan_godfiles
from .historical_checkout import describe_historical_ignored_paths, historical_inventory
from .ignored_inventory import collect_ignored_inventory
from .language_capabilities import suffixes_with
from .models import AuditPolicy, AuditReport, Candidate
from .native_analysis import scan_native
from .notebook_analysis import NOTEBOOK_SUFFIXES, scan_notebooks
from .operations import scan_operations
from .performance import scan_performance
from .polyglot_architecture import scan_polyglot_architecture
from .reliability import scan_reliability
from .rule_guidance import RuleGuidance
from .scientific import scan_scientific
from .supply_chain import scan_supply_chain
from .test_authenticity import scan_test_authenticity

# Fixed rule guidance, the single source for the candidates below and the rule catalogue.
RULE_GUIDANCE: Final[Mapping[str, RuleGuidance]] = MappingProxyType(
    {
        "GV001-missing-repository-audit-policy": RuleGuidance(
            rationale="Repository-specific audit ownership is missing or ambiguous.",
            verification=(
                "Read the repository rules and canonical internal TODO, then define the "
                "exact roots, packages, GodFile registries, and enforcement state without "
                "copying another project's assumptions."
            ),
        ),
        "GV002-unscanned-tracked-code": RuleGuidance(
            rationale="A tracked code or test path was outside the scanner's parsed scope.",
            verification=(
                "Inspect the Git object and worktree path directly, establish whether it "
                "is an intentional symlink/submodule/binary/generated owner, and "
                "configure a specific auditor; a clean claim is forbidden while the path "
                "remains unexplained."
            ),
        ),
    }
)

_DEFAULT_POLICY_PATHS = (
    Path("rigor-foundry-policy.json"),
    Path("config/rigor-foundry/policy.json"),
)

_SCANNABLE_EXTENSIONS = suffixes_with("scope") | NOTEBOOK_SUFFIXES


def _governance_candidate(
    inventory: GitInventory,
    path: str,
    rule_id: str,
    evidence: str,
) -> Candidate:
    """Return one repository-governance review candidate."""
    return Candidate.build(
        category="governance",
        rule_id=rule_id,
        anchor=RepositoryTreeAnchor.build(inventory, path=path),
        symbol="",
        evidence=evidence,
        confidence="high",
        rationale=RULE_GUIDANCE[rule_id].rationale,
        verification=RULE_GUIDANCE[rule_id].verification,
    )


def resolve_policy(
    inventory: GitInventory,
    requested: Path | None,
) -> tuple[AuditPolicy, CandidateAnchor, tuple[Candidate, ...]]:
    """Resolve a repository policy and report fallback configuration."""
    if requested is not None:
        if requested.is_absolute() or ".." in requested.parts:
            raise ValueError("audit policy must be a tracked repository-relative path")
        matches = tuple(item for item in inventory.files if item.path == requested.as_posix())
        if len(matches) != 1 or matches[0].content_kind != "text" or matches[0].text is None:
            raise ValueError("audit policy must be one tracked non-symlink UTF-8 file")
        return (
            AuditPolicy.from_json(matches[0].text),
            TrackedBlobAnchor.build(matches[0], line_start=1),
            (),
        )
    for relative in _DEFAULT_POLICY_PATHS:
        matches = tuple(item for item in inventory.files if item.path == relative.as_posix())
        if not matches:
            continue
        if len(matches) != 1 or matches[0].content_kind != "text" or matches[0].text is None:
            raise ValueError("discovered audit policy must be tracked non-symlink UTF-8 text")
        return (
            AuditPolicy.from_json(matches[0].text),
            TrackedBlobAnchor.build(matches[0], line_start=1),
            (),
        )
    fallback_anchor = RepositoryTreeAnchor.build(
        inventory,
        path=_DEFAULT_POLICY_PATHS[0].as_posix(),
    )
    return (
        AuditPolicy(),
        fallback_anchor,
        (
            _governance_candidate(
                inventory,
                _DEFAULT_POLICY_PATHS[0].as_posix(),
                "GV001-missing-repository-audit-policy",
                "no RigorFoundry policy found; scanner used portable defaults",
            ),
        ),
    )


def _scope_candidates(inventory: GitInventory) -> tuple[Candidate, ...]:
    """Return candidates for tracked code that static scanners could not parse."""
    candidates: list[Candidate] = []
    for item in inventory.files:
        if item.text is not None:
            continue
        if (
            item.content_kind != "gitlink"
            and PurePosixPath(item.path).suffix.lower() not in _SCANNABLE_EXTENSIONS
        ):
            continue
        candidates.append(
            Candidate.build(
                category="governance",
                rule_id="GV002-unscanned-tracked-code",
                anchor=(
                    RepositoryTreeAnchor.build(inventory, path=item.path)
                    if item.scanned_blob_id is None
                    else TrackedBlobAnchor.build(item, line_start=1)
                ),
                symbol=item.content_kind,
                evidence=f"content_kind={item.content_kind}; byte_size={item.byte_size}",
                confidence="high",
                rationale=RULE_GUIDANCE["GV002-unscanned-tracked-code"].rationale,
                verification=RULE_GUIDANCE["GV002-unscanned-tracked-code"].verification,
            )
        )
    return tuple(candidates)


def scan_repository(
    root: Path,
    policy_path: Path | None = None,
    *,
    git_trust_policy: GitTrustPolicy | None = None,
    revision: str | None = None,
) -> AuditReport:
    """Read-only scan one Git repository and bind candidates to exact content.

    Parameters
    ----------
    root:
        Repository root or contained path used for worktree discovery.
    policy_path:
        Optional tracked repository-relative audit policy.
    git_trust_policy:
        Optional runtime Git executable trust contract.
    revision:
        Optional full commit object ID to scan in an isolated historical checkout.

    Returns
    -------
    AuditReport
        Content-addressed report including exact Git executable provenance.
    """
    runner = GitRunner(git_trust_policy)
    if revision is None:
        inventory = load_git_inventory(root, git_runner=runner)
        return _scan_inventory(inventory, policy_path, runner, inventory.root)
    source = resolve_repository_root(root, runner)
    with historical_inventory(source, revision, runner) as inventory:
        return _scan_inventory(inventory, policy_path, runner, source, historical=True)


def _scan_inventory(
    inventory: GitInventory,
    policy_path: Path | None,
    runner: GitRunner,
    report_root: Path,
    *,
    historical: bool = False,
) -> AuditReport:
    """Scan the selected filesystem and bind the report to its source repository."""
    policy, policy_anchor, governance = resolve_policy(inventory, policy_path)
    observe_ignored = (
        describe_historical_ignored_paths if historical else collect_ignored_inventory
    )
    ignored_evidence = observe_ignored(
        inventory,
        policy.ignored_inventory,
        git_runner=runner,
    )
    cra_candidates = scan_cra(inventory, policy, policy_anchor, ignored_evidence)
    if policy.cra is not None and policy.cra.applicability == "required":
        final_ignored_evidence = observe_ignored(
            inventory,
            policy.ignored_inventory,
            git_runner=runner,
        )
        if final_ignored_evidence != ignored_evidence:
            raise RuntimeError("CRA state changed during repository scan")
        if load_git_inventory(inventory.root, git_runner=runner) != inventory:
            raise RuntimeError("tracked repository state changed during CRA scan")
    candidates = (
        *governance,
        *domain_governance_candidates(policy, policy_anchor),
        *_scope_candidates(inventory),
        *scan_notebooks(inventory, policy),
        *scan_test_authenticity(inventory, policy),
        *scan_architecture(inventory, policy),
        *scan_polyglot_architecture(inventory, policy),
        *scan_godfiles(inventory, policy),
        *scan_application_security(inventory, policy),
        *scan_native(inventory, policy),
        *scan_reliability(inventory, policy),
        *scan_supply_chain(inventory, policy),
        *scan_container(inventory, policy),
        *scan_github_actions(inventory),
        *scan_data_privacy(inventory, policy),
        *scan_documentation(inventory, policy),
        *scan_scientific(inventory, policy),
        *scan_operations(inventory, policy),
        *scan_performance(inventory, policy),
        *scan_api_compatibility(inventory, policy),
        *cra_candidates,
    )
    anchor_errors = candidate_anchor_errors(inventory, candidates)
    if anchor_errors:
        raise RuntimeError("candidate anchor verification failed: " + "; ".join(anchor_errors))
    return AuditReport.build(
        repository_root=str(report_root),
        head=inventory.head,
        head_tree=inventory.head_tree,
        git_object_format=inventory.object_format,
        branch=inventory.branch,
        tracked_content_digest=inventory.tracked_content_digest,
        dirty_paths=inventory.dirty_paths,
        tracked_file_count=len(inventory.files),
        git_provenance=inventory.git_provenance,
        policy=policy,
        ignored_inventory_evidence=ignored_evidence,
        candidates=candidates,
    )
