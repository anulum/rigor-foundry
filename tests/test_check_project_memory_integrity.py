# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project-memory integrity CLI tests
"""Exercise the fixed-output checker through a real private generation."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from rigor_foundry.project_memory_models import ProjectMemoryManifest, ProjectMemoryRecord
from rigor_foundry.project_memory_primitives import (
    PROJECT_MEMORY_PARENT_KINDS,
    ProjectMemoryActor,
    ProjectMemoryFreshness,
    ProjectMemoryParent,
    ProjectMemorySource,
)
from rigor_foundry.project_memory_store import (
    commit_project_memory_generation,
    write_project_memory_record,
)
from tools.check_project_memory_integrity import main


def repository(tmp_path: Path) -> Path:
    """Create one real Git worktree with a committed-view private store."""
    root = tmp_path / "repository"
    root.mkdir()
    subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
    (root / ".gitignore").write_text("/agentic_project_memory/\n", encoding="utf-8")
    subprocess.run(["git", "add", ".gitignore"], cwd=root, check=True)
    (root / "agentic_project_memory").mkdir(mode=0o700)
    content = b"# Project identity\n"
    record = ProjectMemoryRecord.for_content(
        record_id="identity-0001",
        category="identity",
        created_at="2026-09-04T12:00:00.000000Z",
        observed_at="2026-09-04T11:59:00.000000Z",
        freshness=ProjectMemoryFreshness("immutable", None),
        assertion_class="observation",
        sources=(ProjectMemorySource("source", "coordination/session.md", "a" * 64),),
        actor=ProjectMemoryActor("RIGOR-FOUNDRY/validator-1", "memory-write"),
        supersedes=(),
        content=content,
    )
    write_project_memory_record(root, record, content)
    locators = {
        "ecosystem-boot": "../../../AGENTS.md",
        "ecosystem-rules": "../../../agentic-shared/SHARED_CONTEXT.md",
        "ecosystem-memory": "../../../agentic-shared/memory/INDEX.md",
        "group-memory": "../../agentic_group_memory/memory_index.md",
        "project-sessions": "../../../.coordination/sessions/PROJECT/",
        "project-handovers": "../../../.coordination/handovers/PROJECT/",
        "vendor-memory": "../../../agentic-shared/memory/vendors/",
    }
    manifest = ProjectMemoryManifest.build(
        project_id="PROJECT",
        generated_at="2026-09-04T12:01:00.000000Z",
        previous_manifest_sha256=None,
        parents=tuple(
            ProjectMemoryParent(kind, locators[kind]) for kind in PROJECT_MEMORY_PARENT_KINDS
        ),
        records=(record,),
    )
    commit_project_memory_generation(root, manifest)
    return root


@pytest.mark.parametrize("extra", [[], ["--history"]])
def test_cli_accepts_current_and_complete_history_with_fixed_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    extra: list[str],
) -> None:
    """Both supported verifier depths report only the fixed pass line."""
    root = repository(tmp_path)
    assert main([str(root), *extra]) == 0
    assert capsys.readouterr().out == "project-memory-integrity: PASS\n"


def test_cli_failure_redacts_private_record_details(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A changed private index returns only the fixed failure line."""
    root = repository(tmp_path)
    private_name = "identity-0001"
    (root / "agentic_project_memory/memory_index.md").write_text(
        f"private {private_name}\n",
        encoding="utf-8",
    )

    assert main([str(root), "--history"]) == 1
    output = capsys.readouterr().out
    assert output == "project-memory-integrity: FAIL\n"
    assert private_name not in output
