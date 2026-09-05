# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — group workspace allocation
"""Exercise the explicit allocation command in real subprocesses."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from test_group_workspace import workspace_tree

from tools.allocate_group_workspace import main


def test_callable_command_reports_the_real_allocation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Embedding the public command preserves the same explicit operator contract."""
    root, digest = workspace_tree(tmp_path)
    arguments = [
        str(root),
        "agentic-shared/memory/projects/registry/project_registry.json",
        "--project",
        "PROJECT-A",
        "--session",
        "embedded-session",
        "--registry-sha256",
        digest,
    ]
    assert main(arguments) == 0
    result = capsys.readouterr()
    assert result.err == ""
    destination = Path(result.out.strip())
    assert (
        destination == root / "03_CODE/GROUP-A/agentic_group_workspace/PROJECT-A/embedded-session"
    )
    assert {p.name for p in destination.iterdir()} == {"scratch", "tmp"}


def test_command_allocates_once_and_redacts_collision(tmp_path: Path) -> None:
    """The executable boundary reports success and preserves an existing allocation."""
    root, digest = workspace_tree(tmp_path)
    command = [
        sys.executable,
        "-m",
        "tools.allocate_group_workspace",
        str(root),
        "agentic-shared/memory/projects/registry/project_registry.json",
        "--project",
        "PROJECT-A",
        "--session",
        "cli-session",
        "--registry-sha256",
        digest,
    ]
    first = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
    assert first.returncode == 0 and first.stderr == ""
    destination = Path(first.stdout.strip())
    assert destination == root / "03_CODE/GROUP-A/agentic_group_workspace/PROJECT-A/cli-session"
    assert (destination / "scratch").is_dir() and (destination / "tmp").is_dir()
    evidence = destination / "scratch/unique.txt"
    evidence.write_text("keep", encoding="utf-8")
    second = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
    assert second.returncode == 1 and second.stderr == ""
    assert (
        second.stdout == "group-workspace: FAIL; preserve any partial allocation for inspection\n"
    )
    assert evidence.read_text() == "keep"
