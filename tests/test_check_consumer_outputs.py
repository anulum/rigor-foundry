# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — consumer Action output guard tests
"""Exercise output overwrite policy against real Git worktrees."""

from __future__ import annotations

import subprocess
from pathlib import Path

from tools.check_consumer_outputs import consumer_output_errors, main


def _git(root: Path, *arguments: str) -> None:
    """Run one required Git fixture command."""
    subprocess.run(  # nosec B603
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        shell=False,
        text=True,
        timeout=10,
    )


def _repository(tmp_path: Path) -> Path:
    """Create a real repository with tracked and ignored output surfaces."""
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "--initial-branch=main")
    _git(root, "config", "user.name", "Output Guard")
    _git(root, "config", "user.email", "output-guard@example.invalid")
    (root / ".gitignore").write_text("reports/\n", encoding="utf-8")
    (root / "tracked.json").write_text("{}\n", encoding="utf-8")
    (root / "reports").mkdir()
    _git(root, "add", ".gitignore", "tracked.json")
    _git(root, "commit", "-m", "test: seed output guard fixture")
    return root


def test_consumer_outputs_accept_new_ignored_or_external_files(tmp_path: Path) -> None:
    """Fresh ignored and external report paths preserve adopter content."""
    root = _repository(tmp_path)
    external = tmp_path / "external"
    external.mkdir()

    assert (
        consumer_output_errors(
            root,
            (root / "reports/report.json", external / "gate.json"),
        )
        == []
    )


def test_consumer_outputs_reject_overwrite_and_repository_policy_bypasses(
    tmp_path: Path,
) -> None:
    """Existing, tracked-deleted, unignored, duplicate, and symlink paths fail closed."""
    root = _repository(tmp_path)
    existing = root / "reports/existing.json"
    existing.write_text("preserve\n", encoding="utf-8")
    dangling = root / "reports/dangling.json"
    dangling.symlink_to(root / "missing-target")
    (root / "tracked.json").unlink()

    assert consumer_output_errors(
        root,
        (
            existing,
            dangling,
            root / "tracked.json",
            root / "unignored.json",
            root / "reports/new.json",
            root / "reports/new.json",
        ),
    ) == [
        f"output path already exists: {existing}",
        f"output path already exists: {dangling}",
        f"output path is tracked by Git: {root / 'tracked.json'}",
        f"in-repository output path must be ignored: {root / 'unignored.json'}",
        f"output paths must be distinct: {root / 'reports/new.json'}",
    ]


def test_consumer_output_cli_returns_policy_status(tmp_path: Path) -> None:
    """The Action-facing CLI accepts safe outputs and rejects existing ones."""
    root = _repository(tmp_path)
    output = root / "reports/action.json"
    assert main(["--repository-root", str(root), "--output", str(output)]) == 0
    output.write_text("preserve\n", encoding="utf-8")
    assert main(["--repository-root", str(root), "--output", str(output)]) == 2
