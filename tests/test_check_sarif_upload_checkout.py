# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — hosted SARIF upload checkout guard tests
"""Verify that an upload is admitted only from the commit that its report describes."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

import rigor_foundry
from tools.check_sarif_upload_checkout import checkout_errors

ROOT = Path(__file__).resolve().parents[1]


def _scanned(tmp_path: Path) -> tuple[GitRepository, Path]:
    """Return a real committed repository and the path of its written audit report."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/runner.py", "def run(command):\n    eval(command)\n")
    repository.commit()
    report = rigor_foundry.scan_repository(repository.root)
    path = tmp_path / "report.json"
    path.write_text(report.to_json(), encoding="utf-8")
    return repository, path


def _guard(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Run the real guard command from the repository checkout."""
    return subprocess.run(
        [sys.executable, "-m", "tools.check_sarif_upload_checkout", *arguments],
        cwd=ROOT,
        env=dict(os.environ),
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def test_the_report_commit_is_admitted(tmp_path: Path) -> None:
    """The checkout that was scanned is the commit the report describes.

    Parameters
    ----------
    tmp_path : Path
        Owned real Git repository and report allocation.
    """
    repository, report = _scanned(tmp_path)
    assert checkout_errors(report, repository.root) == []
    admitted = _guard(str(report), "--root", str(repository.root))
    assert (admitted.returncode, admitted.stdout) == (
        0,
        "SARIF upload checkout is the report's commit\n",
    )


def test_a_checkout_that_moved_past_the_report_is_refused(tmp_path: Path) -> None:
    """A later commit has another HEAD and tree, so both mismatches are named and refused.

    Parameters
    ----------
    tmp_path : Path
        Owned real Git repository and report allocation.
    """
    repository, report = _scanned(tmp_path)
    scanned = rigor_foundry.AuditReport.from_path(report)
    repository.write_text("src/pkg/other.py", "VALUE = 2\n")
    repository.commit("test: move past the report")
    errors = checkout_errors(report, repository.root)
    assert len(errors) == 2
    assert errors[0].startswith("checkout HEAD ") and errors[0].endswith(
        f"report head {scanned.head}"
    )
    assert errors[1].startswith("checkout tree ") and errors[1].endswith(
        f"report head tree {scanned.head_tree}"
    )
    refused = _guard(str(report), "--root", str(repository.root))
    assert refused.returncode == 1
    assert refused.stdout == ""
    assert refused.stderr == "\n".join(errors) + "\n"


def test_a_new_commit_with_the_same_tree_is_still_refused(tmp_path: Path) -> None:
    """An empty commit keeps the tree but not the HEAD, which alone is refused.

    Parameters
    ----------
    tmp_path : Path
        Owned real Git repository and report allocation.
    """
    repository, report = _scanned(tmp_path)
    repository.git_command("commit", "--allow-empty", "--quiet", "-m", "test: empty")
    errors = checkout_errors(report, repository.root)
    assert len(errors) == 1 and errors[0].startswith("checkout HEAD ")


@pytest.mark.parametrize("case", ["not-a-checkout", "no-report", "tampered-report"])
def test_an_unverifiable_report_or_checkout_is_refused(tmp_path: Path, case: str) -> None:
    """A checkout Git cannot read, a missing report or a tampered report exits 2.

    Parameters
    ----------
    tmp_path : Path
        Owned real Git repository and report allocation.
    case : str
        The input that cannot be verified.
    """
    repository, report = _scanned(tmp_path)
    root = repository.root
    if case == "not-a-checkout":
        root = tmp_path / "plain"
        root.mkdir()
    elif case == "no-report":
        report = tmp_path / "absent.json"
    else:
        report.write_text(
            report.read_text(encoding="utf-8").replace("eval", "exec"), encoding="utf-8"
        )
    with pytest.raises((OSError, ValueError)):
        checkout_errors(report, root)
    refused = _guard(str(report), "--root", str(root))
    assert refused.returncode == 2
    assert refused.stderr.startswith("cannot verify the SARIF upload checkout: ")
