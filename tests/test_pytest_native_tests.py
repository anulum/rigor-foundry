# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Native pytest invocation qualification
"""Exercise native observer admission through actual complete pytest invocations."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools import pytest_native_tests
from tools._repository import ROOT
from tools.test_shard_evidence import validate_observations

NATIVE_OWNER = "tests/test_windows_job_observation.py"


def native_pytest(output: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    """Execute the actual plugin against a maintained public native owner.

    Parameters
    ----------
    output : Path
        Owned provisional observation path outside the checkout.
    *arguments : str
        Explicit invocation arguments to qualify.

    Returns
    -------
    subprocess.CompletedProcess[str]
        Actual terminal pytest status and captured output.
    """
    environment = dict(os.environ)
    environment.pop("PYTEST_ADDOPTS", None)
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            pytest_native_tests.__name__,
            "--test-shard-index=0",
            "--test-shard-count=1",
            "--test-shard-observations=" + str(output),
            "-q",
            *arguments,
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=45,
    )


def test_complete_native_file_preserves_real_parent_and_subtest_events(tmp_path: Path) -> None:
    """Observe every actual case and all public argument subtests without selectors.

    Parameters
    ----------
    tmp_path : Path
        Independent artifact allocation.
    """
    output = tmp_path / "observations.json"
    result = native_pytest(output, NATIVE_OWNER)
    assert result.returncode == 0, result.stdout + result.stderr
    record = json.loads(output.read_text())
    selected = validate_observations(record, 0, 1)
    assert len(selected) == 6
    assert all(node.startswith(NATIVE_OWNER + "::") for node in selected)
    assert sum(map(len, record["subtests"].values())) == 11
    assert len(record["phases"]) == 6


@pytest.mark.parametrize(
    "arguments",
    [
        (NATIVE_OWNER, "--test-shard-index=1"),
        (NATIVE_OWNER, "--test-shard-count=2"),
        (NATIVE_OWNER, "--test-shard-observations="),
        ("tests",),
        ("pyproject.toml",),
        ("tests/absent_native_owner.py",),
        (NATIVE_OWNER + "::JobObservationArgumentTests",),
        (NATIVE_OWNER, "--collect-only"),
        (NATIVE_OWNER, "--maxfail=1"),
        (NATIVE_OWNER, "-k", "Argument"),
        (NATIVE_OWNER, "-m", "native"),
        (NATIVE_OWNER, "--lf"),
        (NATIVE_OWNER, "--ff"),
        (NATIVE_OWNER, "--nf"),
        (NATIVE_OWNER, "--sw"),
        (NATIVE_OWNER, "--deselect=" + NATIVE_OWNER + "::JobObservationArgumentTests"),
        (NATIVE_OWNER, "--ignore=tests/unused.py"),
        (NATIVE_OWNER, "--ignore-glob=unused*"),
        (NATIVE_OWNER, "--pyargs"),
        (NATIVE_OWNER, "--keep-duplicates"),
    ],
)
def test_selective_or_incomplete_native_invocation_is_refused(
    tmp_path: Path, arguments: tuple[str, ...]
) -> None:
    """Refuse each actual selection mode before any native test is collected.

    Parameters
    ----------
    tmp_path : Path
        Independent path which must remain unpublished.
    arguments : tuple[str, ...]
        Real CLI switch or incomplete owner selection.
    """
    output = tmp_path / "observations.json"
    result = native_pytest(output, *arguments)
    assert result.returncode == pytest.ExitCode.USAGE_ERROR, result.stdout + result.stderr
    assert "complete native test-file invocation required" in result.stderr
    assert not output.exists()
