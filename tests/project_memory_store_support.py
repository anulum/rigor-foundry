# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project-memory store tests
"""Build real Git worktrees and immutable project-memory test records."""

from __future__ import annotations

import subprocess
from pathlib import Path

from rigor_foundry.project_memory_models import ProjectMemoryManifest, ProjectMemoryRecord
from rigor_foundry.project_memory_primitives import (
    PROJECT_MEMORY_PARENT_KINDS,
    ProjectMemoryActor,
    ProjectMemoryFreshness,
    ProjectMemoryParent,
    ProjectMemorySource,
)


def git(repository: Path, *arguments: str) -> None:
    """Run the system Git against one temporary worktree within ten seconds."""
    subprocess.run(
        ["/usr/bin/git", "-c", f"safe.directory={repository}", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )


def repository(tmp_path: Path) -> Path:
    """Create a real worktree with portable private-root protection."""
    root = tmp_path / "repository"
    root.mkdir(parents=True)
    git(root, "init", "--quiet")
    (root / ".gitignore").write_text("/agentic_project_memory/\n", encoding="utf-8")
    git(root, "add", ".gitignore")
    (root / "agentic_project_memory").mkdir(mode=0o700)
    return root


def parents() -> tuple[ProjectMemoryParent, ...]:
    """Return every selective parent layer in canonical order."""
    return tuple(
        ProjectMemoryParent(
            kind,
            {
                "ecosystem-boot": "../../../AGENTS.md",
                "ecosystem-rules": "../../../agentic-shared/SHARED_CONTEXT.md",
                "ecosystem-memory": "../../../agentic-shared/memory/INDEX.md",
                "group-memory": "../../agentic_group_memory/memory_index.md",
                "project-sessions": "../../../.coordination/sessions/PROJECT/",
                "project-handovers": "../../../.coordination/handovers/PROJECT/",
                "vendor-memory": "../../../agentic-shared/memory/vendors/",
            }[kind],
        )
        for kind in PROJECT_MEMORY_PARENT_KINDS
    )


def record(
    record_id: str,
    content: bytes,
    *,
    supersedes: tuple[str, ...] = (),
    freshness: ProjectMemoryFreshness | None = None,
) -> ProjectMemoryRecord:
    """Build one immutable identity-record fixture."""
    return ProjectMemoryRecord.for_content(
        record_id=record_id,
        category="identity",
        created_at="2026-09-04T12:00:00.000000Z",
        observed_at="2026-09-04T11:59:00.000000Z",
        freshness=freshness or ProjectMemoryFreshness("immutable", None),
        assertion_class="observation",
        sources=(ProjectMemorySource("source", "coordination/session.md", "a" * 64),),
        actor=ProjectMemoryActor("RIGOR-FOUNDRY/validator-1", "memory-write"),
        supersedes=supersedes,
        content=content,
    )


def manifest(
    generated_at: str,
    records: tuple[ProjectMemoryRecord, ...],
    previous: str | None = None,
) -> ProjectMemoryManifest:
    """Build one exact current-view fixture."""
    return ProjectMemoryManifest.build(
        project_id="PROJECT",
        generated_at=generated_at,
        previous_manifest_sha256=previous,
        parents=parents(),
        records=tuple(sorted(records, key=lambda item: item.record_id)),
    )
