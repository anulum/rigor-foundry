# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — incremental changed-file scan tests
"""Verify the changed-since view resolves changed files and filters candidates."""

from __future__ import annotations

from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.cli import main
from rigor_foundry.git_provenance import GitRunner, GitTrustPolicy
from rigor_foundry.incremental_scan import (
    require_git_revision,
    resolve_changed_paths,
    select_changed_candidates,
)
from rigor_foundry.scanner import scan_repository

_VULNERABLE = "def handle(value):\n    eval(value)\n"


def _runner() -> GitRunner:
    return GitRunner(GitTrustPolicy(trusted_roots=("/usr/bin",)))


def test_require_git_revision_rejects_flag_and_path_injection() -> None:
    """A plain revision is accepted; leading-dash, empty, and spaced shapes fail."""
    assert require_git_revision("HEAD~2") == "HEAD~2"
    assert require_git_revision("origin/main") == "origin/main"
    assert require_git_revision("a1b2c3d") == "a1b2c3d"
    for bad in ("--output=x", "-rf", "", "a b", "a;b", "../etc"):
        with pytest.raises(ValueError, match="valid Git revision"):
            require_git_revision(bad)


def test_changed_since_resolves_and_filters_to_changed_files(tmp_path: Path) -> None:
    """The view keeps only candidates anchored in files changed since the base."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/base.py", _VULNERABLE)
    repository.write_text("src/pkg/keep.py", "VALUE = 1\n")
    repository.write_policy()
    base = repository.commit()
    # HEAD changes keep.py and adds new.py; base.py is unchanged.
    repository.write_text("src/pkg/keep.py", _VULNERABLE)
    repository.write_text("src/pkg/new.py", _VULNERABLE)
    repository.commit()

    report = scan_repository(repository.root)
    changed = resolve_changed_paths(_runner(), repository.root, base)
    assert changed == {"src/pkg/keep.py", "src/pkg/new.py"}

    filtered = select_changed_candidates(report.candidates, changed)
    filtered_paths = {candidate.path for candidate in filtered}
    assert {"src/pkg/keep.py", "src/pkg/new.py"} <= filtered_paths
    assert "src/pkg/base.py" not in filtered_paths
    assert all(candidate.path in changed for candidate in filtered)
    # The full report still carries the unchanged file's candidate.
    assert any(candidate.path == "src/pkg/base.py" for candidate in report.candidates)


def test_resolve_changed_paths_fails_closed_on_unknown_revision(tmp_path: Path) -> None:
    """A well-formed but non-existent revision surfaces a bounded failure."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/module.py", "VALUE = 1\n")
    repository.write_policy()
    repository.commit()
    with pytest.raises(RuntimeError, match="git diff"):
        resolve_changed_paths(_runner(), repository.root, "0" * 40)


def test_cli_changed_since_summarises_and_gates_only_changed_files(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The CLI prints a changed-files summary and gates only on the changed set."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/legacy.py", _VULNERABLE)
    repository.write_text("README.md", "# base\n")
    repository.write_policy()
    base = repository.commit()

    # HEAD changes only a non-code file; the vulnerable legacy module is unchanged.
    repository.write_text("README.md", "# updated\n")
    repository.commit()

    root = str(repository.root)
    # A full fail-on-candidates run fails, because legacy.py holds candidates.
    assert main(["scan", "--root", root, "--fail-on-candidates"]) == 1
    capsys.readouterr()
    # The changed-since run passes: no candidate is anchored in the changed file.
    exit_code = main(["scan", "--root", root, "--changed-since", base, "--fail-on-candidates"])
    summary = capsys.readouterr().out
    assert exit_code == 0
    assert f"changed-files view since {base}" in summary
    assert "in 1 changed file(s)" in summary
    assert "legacy.py" not in summary

    # Adding a vulnerable module makes the changed-since gate fail on the new code.
    repository.write_text("src/pkg/added.py", _VULNERABLE)
    head = repository.commit()
    assert main(["scan", "--root", root, "--changed-since", head + "~1", "--fail-on-candidates"]) == 1
    flagged = capsys.readouterr().out
    assert "AS001-dynamic-code-execution src/pkg/added.py:2" in flagged
    assert "legacy.py" not in flagged
