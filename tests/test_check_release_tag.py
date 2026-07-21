# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Release tag guard tests
"""Verify tag and package version equality."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools.check_release_tag import main, release_tag_errors

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _run_release_guard(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Run the public guard without site packages or source-path injection."""
    environment = os.environ.copy()
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    return subprocess.run(
        [sys.executable, "-S", "-m", "tools.check_release_tag", *arguments],
        cwd=_REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_release_tag_matches_the_single_package_version() -> None:
    """Release automation rejects aliases and metadata drift."""
    assert release_tag_errors("v1.0.0") == []
    assert release_tag_errors("1.0.0") == ["release tag '1.0.0' does not match 'v1.0.0'"]


def test_release_tag_cli_runs_before_package_installation() -> None:
    """The workflow guard runs without site packages or source-path injection."""
    completed = _run_release_guard("v1.0.0")

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "Release tag guard passed\n"
    assert completed.stderr == ""


def test_release_tag_module_entrypoint_executes() -> None:
    """The public module entry point delegates to the validated CLI boundary."""
    completed = subprocess.run(
        [sys.executable, "-m", "tools.check_release_tag", "v1.0.0"],
        cwd=_REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "Release tag guard passed\n"
    assert completed.stderr == ""


@pytest.mark.parametrize(
    ("arguments", "expected_code", "expected_output"),
    [
        ((), 2, "usage: python -m tools.check_release_tag <tag>\n"),
        (
            ("v9.9.9",),
            1,
            "release tag 'v9.9.9' does not match 'v1.0.0'\n",
        ),
    ],
)
def test_release_tag_cli_rejects_invalid_invocations(
    arguments: tuple[str, ...],
    expected_code: int,
    expected_output: str,
) -> None:
    """The public CLI rejects missing arguments and version mismatches."""
    completed = _run_release_guard(*arguments)

    assert completed.returncode == expected_code
    assert completed.stdout == expected_output
    assert completed.stderr == ""


@pytest.mark.parametrize(
    ("arguments", "expected_code", "expected_output"),
    [
        ([], 2, "usage: python -m tools.check_release_tag <tag>\n"),
        (["v9.9.9"], 1, "release tag 'v9.9.9' does not match 'v1.0.0'\n"),
        (["v1.0.0"], 0, "Release tag guard passed\n"),
    ],
)
def test_release_tag_main_reports_each_public_outcome(
    arguments: list[str],
    expected_code: int,
    expected_output: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The callable CLI boundary reports usage, mismatch, and success."""
    assert main(arguments) == expected_code
    assert capsys.readouterr() == (expected_output, "")
