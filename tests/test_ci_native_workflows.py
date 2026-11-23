# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Native CI workflow qualification
"""Validate actual maintained native jobs and their complete producer dependencies."""

from __future__ import annotations

import copy
import os
import subprocess
import sys

import pytest

from tools._repository import ROOT
from tools.ci_native_workflows import NATIVE_WHOLE_FILE_STEP, check_native_jobs
from tools.ci_workflows import ci_jobs, read_workflow
from tools.native_test_profiles import DARWIN_TEST_FILES


def test_actual_native_workflow_passes_the_public_graph_guard() -> None:
    """Check the actual repository CLI and preserve all original Linux partitions."""
    result = subprocess.run(
        [sys.executable, "-m", "tools.check_ci_workflows"],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": os.pathsep.join((str(ROOT / "src"), str(ROOT)))},
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    actual = ci_jobs()
    matrix = actual["native"]["strategy"]["matrix"]
    assert matrix["python-version"] == ["3.11.15", "3.12.13", "3.13.14"]
    assert matrix["platform"] == ["win32", "darwin"]
    assert (
        actual["native"]["steps"][3]["run"] == "python -m tools.run_native_tests --role ordinary"
    )
    assert actual["native-quality"]["needs"] == ["native", "native-primary"]
    assert actual["test"]["needs"] == ["native", "native-primary"]
    assert actual["test"]["strategy"]["matrix"]["shard"] == list(range(8))
    assert actual["test-coverage"]["needs"] == [
        "native",
        "native-primary",
        "native-quality",
        "test",
    ]
    assert actual["test-coverage"]["if"] == "${{ always() }}"


@pytest.mark.parametrize(
    "case", ["producer", "primary", "provenance", "qualification", "metadata", "primary-metadata"]
)
def test_changed_native_job_or_consumer_input_is_refused(case: str) -> None:
    """Reject actual parsed workflow changes without launching any hosted job.

    Parameters
    ----------
    case : str
        Selective producer, missing provenance exercise, skipped qualification
        or missing metadata dependency.
    """
    jobs = copy.deepcopy(read_workflow(ROOT / ".github/workflows/ci-tests.yml")["jobs"])
    if case == "producer":
        jobs["native"]["steps"][3]["run"] += " --test-file tests/test_windows_abi.py"
    elif case == "primary":
        jobs["native-primary"]["steps"][3]["run"] = (
            "python -m tools.run_native_tests --role ordinary"
        )
    elif case == "provenance":
        jobs["native"]["steps"] = [
            step
            for step in jobs["native"]["steps"]
            if step.get("name") != "Verify installed dependency provenance"
        ]
    elif case == "qualification":
        jobs["native-quality"]["if"] = "${{ false() }}"
    else:
        jobs["test"]["steps"] = [
            step
            for step in jobs["test"]["steps"]
            if step.get("with", {}).get("name")
            != (
                "native-python-primary-win32-3.12.13-${{ github.run_attempt }}"
                if case == "primary-metadata"
                else "native-python-ordinary-win32-3.12.13-${{ github.run_attempt }}"
            )
        ]
    with pytest.raises(ValueError):
        check_native_jobs(jobs)


def test_actual_native_jobs_use_complete_cached_hash_locked_inputs() -> None:
    """Retain declared hardware, lock files and complete raw observation upload."""
    jobs = read_workflow(ROOT / ".github/workflows/ci-tests.yml")["jobs"]
    check_native_jobs(jobs)
    native = jobs["native"]
    profiles = native["strategy"]["matrix"]["include"]
    assert profiles == [
        {
            "platform": "win32",
            "runner": "windows-latest",
            "test-lock": "requirements/test-windows.txt",
        },
        {
            "platform": "darwin",
            "runner": "macos-15-intel",
            "test-lock": "requirements/test.txt",
        },
    ]
    assert native["steps"][1]["with"]["cache"] == "pip"
    assert set(native["steps"][1]["with"]["cache-dependency-path"].splitlines()) == {
        "requirements/bootstrap.txt",
        "requirements/test.txt",
        "requirements/runtime.txt",
        "requirements/test-windows.txt",
        "requirements/provenance.txt",
    }
    assert "--require-hashes" in native["steps"][2]["run"]
    assert "-r requirements/provenance.txt" in native["steps"][2]["run"]
    assert native["steps"][4]["run"] == (
        "python -m pytest -p no:cacheprovider -q "
        "tests/test_provenance_scan.py tests/test_provenance_attestation.py"
    )
    assert native["steps"][-1]["if"] == "${{ always() }}"
    assert native["steps"][-1]["with"]["include-hidden-files"] is True


def test_native_python_provisioning_has_one_verified_uv_acquisition_path() -> None:
    """Require the local provisioning action for all native consumers."""
    native = ci_jobs()
    editor = read_workflow(ROOT / ".github/workflows/ci-vscode.yml")["jobs"]
    action = "./.github/actions/setup-native-python"
    for name in ("native", "native-primary"):
        assert native[name]["steps"][1]["uses"] == action
    native_editor = [step for step in editor["vscode-host"]["steps"] if step.get("uses") == action]
    assert len(native_editor) == 1
    assert native_editor[0]["if"] == "runner.os == 'Windows'"

    setup = read_workflow(ROOT / ".github/actions/setup-native-python/action.yml")
    provision, pip_cache = setup["runs"]["steps"]
    assert setup["runs"]["using"] == "composite"
    assert "uses" not in provision
    assert provision["shell"] == "bash"
    assert pip_cache["uses"].startswith("actions/cache@")
    script = provision["run"]
    verify = script.index('"${hash_command[@]}" --check')
    assert script.index("https://github.com/astral-sh/uv/releases/download/") < verify
    assert verify < script.index("unzip -p") < script.index('"$uv" --version')
    assert verify < script.index("tar -xOzf") < script.index('"$uv" --no-config venv')


def test_whole_file_gate_covers_every_named_macos_module() -> None:
    """The macOS modules the darwin profile runs are also held to whole-file coverage."""
    generated = NATIVE_WHOLE_FILE_STEP["run"]
    actual = next(
        step["run"]
        for step in ci_jobs()["test-coverage"]["steps"]
        if step.get("name") == NATIVE_WHOLE_FILE_STEP["name"]
    )
    assert actual == generated
    arguments = generated.split("check_full_file_coverage", 1)[1].split()
    assert DARWIN_TEST_FILES
    assert all(name in arguments for name in DARWIN_TEST_FILES)
    assert '"${ordinary[@]}"' in arguments
