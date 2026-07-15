# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — repository audit composition root
"""Compose portable scanners over one exact Git-tracked repository inventory."""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from .architecture import scan_architecture
from .domains import domain_governance_candidates
from .git_inventory import GitInventory, load_git_inventory
from .godfiles import scan_godfiles
from .models import AuditPolicy, AuditReport, Candidate
from .polyglot_architecture import scan_polyglot_architecture
from .test_authenticity import scan_test_authenticity

_DEFAULT_POLICY_PATHS = (
    Path("rigor-foundry-policy.json"),
    Path("config/rigor-foundry/policy.json"),
)

_SCANNABLE_EXTENSIONS = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".go",
        ".h",
        ".hpp",
        ".jl",
        ".js",
        ".jsx",
        ".lean",
        ".mojo",
        ".py",
        ".pyi",
        ".rs",
        ".sh",
        ".sv",
        ".ts",
        ".tsx",
        ".v",
        ".yaml",
        ".yml",
    }
)


def _governance_candidate(path: str, rule_id: str, evidence: str) -> Candidate:
    """Return one repository-governance review candidate."""
    return Candidate.build(
        category="governance",
        rule_id=rule_id,
        path=path,
        line=1,
        symbol="",
        evidence=evidence,
        confidence="high",
        rationale="Repository-specific audit ownership is missing or ambiguous.",
        verification=(
            "Read the repository rules and canonical internal TODO, then define the exact roots, "
            "packages, GodFile registries, and enforcement state without copying another project's "
            "assumptions."
        ),
    )


def resolve_policy(
    inventory: GitInventory,
    requested: Path | None,
) -> tuple[AuditPolicy, tuple[Candidate, ...]]:
    """Resolve a repository policy and report fallback configuration."""
    if requested is not None:
        if requested.is_absolute() or ".." in requested.parts:
            raise ValueError("audit policy must be a tracked repository-relative path")
        matches = tuple(item for item in inventory.files if item.path == requested.as_posix())
        if len(matches) != 1 or matches[0].content_kind != "text" or matches[0].text is None:
            raise ValueError("audit policy must be one tracked non-symlink UTF-8 file")
        return AuditPolicy.from_json(matches[0].text), ()
    for relative in _DEFAULT_POLICY_PATHS:
        matches = tuple(item for item in inventory.files if item.path == relative.as_posix())
        if not matches:
            continue
        if len(matches) != 1 or matches[0].content_kind != "text" or matches[0].text is None:
            raise ValueError("discovered audit policy must be tracked non-symlink UTF-8 text")
        return AuditPolicy.from_json(matches[0].text), ()
    return AuditPolicy(), (
        _governance_candidate(
            ".",
            "GV001-missing-repository-audit-policy",
            "no RigorFoundry policy found; scanner used portable defaults",
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
                path=item.path,
                line=1,
                symbol=item.content_kind,
                evidence=f"content_kind={item.content_kind}; byte_size={item.byte_size}",
                confidence="high",
                rationale="A tracked code or test path was outside the scanner's parsed scope.",
                verification=(
                    "Inspect the Git object and worktree path directly, establish whether it is an "
                    "intentional symlink/submodule/binary/generated owner, and configure a specific "
                    "auditor; a clean claim is forbidden while the path remains unexplained."
                ),
            )
        )
    return tuple(candidates)


def scan_repository(
    root: Path,
    policy_path: Path | None = None,
) -> AuditReport:
    """Read-only scan one Git repository and bind candidates to exact content."""
    inventory = load_git_inventory(root)
    policy, governance = resolve_policy(inventory, policy_path)
    candidates = (
        *governance,
        *domain_governance_candidates(policy),
        *_scope_candidates(inventory),
        *scan_test_authenticity(inventory, policy),
        *scan_architecture(inventory, policy),
        *scan_polyglot_architecture(inventory, policy),
        *scan_godfiles(inventory, policy),
    )
    return AuditReport.build(
        repository_root=str(inventory.root),
        head=inventory.head,
        head_tree=inventory.head_tree,
        branch=inventory.branch,
        tracked_content_digest=inventory.tracked_content_digest,
        dirty_paths=inventory.dirty_paths,
        tracked_file_count=len(inventory.files),
        policy=policy,
        candidates=candidates,
    )
