# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Native CI producer and qualification contracts
"""Declare complete native producer slots, original whole-owner gates and artifact consumers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

PYTHON_VERSIONS = ["3.11.15", "3.12.13", "3.13.14"]
NATIVE_METADATA_ENV = {
    "RIGOR_NATIVE_PRIMARY_EVIDENCE_DIR": "${{ runner.temp }}/rigor-native-primary",
    "RIGOR_NATIVE_WINDOWS_EVIDENCE_DIR": "${{ runner.temp }}/rigor-native-windows",
}
NATIVE_METADATA_DOWNLOAD = {
    "uses": "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333",
    "with": {
        "name": "native-python-ordinary-win32-3.12.13-${{ github.run_attempt }}",
        "path": "${{ runner.temp }}/rigor-native-windows",
    },
}
NATIVE_COVERAGE_DOWNLOAD = {
    "uses": "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333",
    "with": {
        "pattern": "native-python-ordinary-*-${{ matrix.python-version }}-${{ github.run_attempt }}",
        "path": "native-data",
    },
}
NATIVE_JOB: dict[str, Any] = {
    "env": {
        "PYTHONPATH": "${{ github.workspace }}",
        "PYTHONUTF8": "1",
        "RIGOR_TEST_SHARD_STRATEGY": "module-lpt-v1",
    },
    "runs-on": "${{ matrix.runner }}",
    "timeout-minutes": 20,
    "strategy": {
        "fail-fast": False,
        "matrix": {
            "python-version": PYTHON_VERSIONS,
            "platform": ["win32", "darwin"],
            "include": [
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
            ],
        },
    },
    "steps": [
        {
            "uses": "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
            "with": {"persist-credentials": False},
        },
        {
            "uses": "./.github/actions/setup-native-python",
            "with": {
                "python-version": "${{ matrix.python-version }}",
                "cache": "pip",
                "cache-dependency-path": "requirements/bootstrap.txt\nrequirements/test.txt\nrequirements/runtime.txt\nrequirements/test-windows.txt\n",
            },
        },
        {
            "name": "Install hash-locked native environment",
            "shell": "bash",
            "run": "python -m pip install --require-hashes -r requirements/bootstrap.txt\npython -m pip install --require-hashes --no-build-isolation -r requirements/runtime.txt -r ${{ matrix.test-lock }}\npython -m pip install --no-build-isolation --no-deps .\npython -m pip check\n",
        },
        {
            "name": "Run complete source-bound native profile",
            "run": "python -m tools.run_native_tests --role ordinary",
        },
        {
            "uses": "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
            "if": "${{ always() }}",
            "with": {
                "name": "native-python-ordinary-${{ matrix.platform }}-${{ matrix.python-version }}-${{ github.run_attempt }}",
                "path": ".rigor-native-coverage/",
                "include-hidden-files": True,
                "if-no-files-found": "error",
                "retention-days": 14,
            },
        },
    ],
}
PRIMARY_METADATA_DOWNLOAD = {
    **NATIVE_METADATA_DOWNLOAD,
    "with": {
        "name": "native-python-primary-win32-3.12.13-${{ github.run_attempt }}",
        "path": "${{ runner.temp }}/rigor-native-primary",
    },
}
PRIMARY_JOB = {
    "env": NATIVE_JOB["env"],
    "runs-on": "windows-latest",
    "timeout-minutes": 20,
    "steps": [
        NATIVE_JOB["steps"][0],
        {
            **NATIVE_JOB["steps"][1],
            "with": {
                **NATIVE_JOB["steps"][1]["with"],
                "python-version": "3.12.13",
            },
        },
        {
            **NATIVE_JOB["steps"][2],
            "run": NATIVE_JOB["steps"][2]["run"].replace(
                "${{ matrix.test-lock }}", "requirements/test-windows.txt"
            ),
        },
        {
            "name": "Run separate required primary acceptance",
            "run": "python -m tools.run_native_tests --role primary",
        },
        {
            "name": "Enforce complete primary test-owner coverage",
            "run": "python -m tools.check_full_file_coverage --data-file .rigor-native-primary/.coverage tests/test_windows_bootstrap_hostile.py tests/test_windows_hostile_controls.py",
        },
        {
            **NATIVE_JOB["steps"][-1],
            "with": {
                **NATIVE_JOB["steps"][-1]["with"],
                "name": "native-python-primary-win32-3.12.13-${{ github.run_attempt }}",
                "path": ".rigor-native-primary/",
            },
        },
    ],
}
NATIVE_QUALITY_STEP = {
    "name": "Qualify complete native tools and maintained tests",
    "shell": "bash",
    "env": NATIVE_METADATA_ENV,
    "run": """python -m pytest tests/test_run_native_tests.py tests/test_native_test_evidence.py tests/test_pytest_native_tests.py tests/test_native_coverage.py tests/test_native_test_profiles.py tests/test_ordinary_coverage.py tests/test_native_coverage_ownership.py tests/test_native_observation_identity.py --cov=tools.run_native_tests --cov=tools.native_test_evidence --cov=tools.pytest_native_tests --cov=tools.native_coverage --cov=test_run_native_tests --cov=test_native_test_evidence --cov=test_pytest_native_tests --cov=test_native_coverage --cov=tools.native_test_profiles --cov=tools.ordinary_coverage --cov=test_native_test_profiles --cov=test_ordinary_coverage --cov=test_native_coverage_ownership --cov=test_native_observation_identity --cov-branch --cov-report=term-missing --cov-fail-under=100
python -m tools.check_full_file_coverage --data-file .coverage tools/native_test_evidence.py tools/run_native_tests.py tools/pytest_native_tests.py tools/native_coverage.py tests/test_native_test_evidence.py tests/test_run_native_tests.py tests/test_pytest_native_tests.py tests/test_native_coverage.py tools/native_test_profiles.py tools/ordinary_coverage.py tests/test_native_test_profiles.py tests/test_ordinary_coverage.py tests/test_native_coverage_ownership.py tests/test_native_observation_identity.py
""",
}
NATIVE_QUALITY_JOB = {
    "if": "${{ always() }}",
    "needs": ["native", "native-primary"],
    "runs-on": "ubuntu-24.04",
    "timeout-minutes": 15,
    "env": {
        "PYTHONPATH": "${{ github.workspace }}/src",
        "RIGOR_TEST_SHARD_STRATEGY": "module-lpt-v1",
        "NATIVE_RESULT": "${{ needs.native.result }}",
        "PRIMARY_RESULT": "${{ needs['native-primary'].result }}",
    },
    "steps": [
        {
            "name": "Require complete native producers",
            "shell": "bash",
            "run": 'set -euo pipefail\ntest "$NATIVE_RESULT" = success\ntest "$PRIMARY_RESULT" = success\n',
        },
        {
            "uses": "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
            "with": {"persist-credentials": False},
        },
        {
            "uses": "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
            "with": {
                "python-version": "3.12.13",
                "cache": "pip",
                "cache-dependency-path": "requirements/bootstrap.txt\nrequirements/test.txt\nrequirements/runtime.txt\n",
            },
        },
        {
            "name": "Install hash-locked native qualification environment",
            "run": "python -m pip install --require-hashes -r requirements/bootstrap.txt\npython -m pip install --require-hashes --no-build-isolation -r requirements/test.txt -r requirements/runtime.txt\npython -m pip install --no-build-isolation --no-deps .\npython -m pip check\n",
        },
        NATIVE_METADATA_DOWNLOAD,
        PRIMARY_METADATA_DOWNLOAD,
        NATIVE_QUALITY_STEP,
    ],
}
UNION_PREREQUISITE_STEP = {
    "name": "Require complete interpreter and native producers",
    "shell": "bash",
    "run": 'set -euo pipefail\ntest "$TEST_RESULT" = success\ntest "$NATIVE_RESULT" = success\ntest "$NATIVE_QUALITY_RESULT" = success\ntest "$PRIMARY_RESULT" = success\n',
}
NATIVE_WHOLE_FILE_STEP = {
    "name": "Enforce complete native backend and maintained-test coverage",
    "if": "matrix.python-version == '3.12.13'",
    "shell": "bash",
    "run": """set -euo pipefail
ordinary=()
for path in tests/test_windows_*.py; do
  case "$path" in
    tests/test_windows_bootstrap_hostile.py|tests/test_windows_hostile_controls.py) ;;
    *) ordinary+=("$path") ;;
  esac
done
python -m tools.check_full_file_coverage --data-file .coverage \
  src/rigor_foundry/windows_abi.py src/rigor_foundry/windows_bootstrap.py \
  src/rigor_foundry/windows_file_io.py src/rigor_foundry/windows_git.py \
  src/rigor_foundry/windows_handles.py src/rigor_foundry/windows_permissions.py \
  src/rigor_foundry/windows_process.py src/rigor_foundry/bootstrap.py \
  src/rigor_foundry/git_provenance.py src/rigor_foundry/git_inventory.py \
  src/rigor_foundry/internal_storage.py src/rigor_foundry/safe_output.py \
  "${ordinary[@]}"
""",
}


def check_native_jobs(jobs: Mapping[str, Any]) -> None:
    """Require full native production and qualification before exhaustive Linux shards.

    Parameters
    ----------
    jobs : Mapping[str, Any]
        Actual parsed test-workflow jobs after the ordinary graph reader has
        validated category ownership and job mapping structure.

    Raises
    ------
    ValueError
        A native producer, its qualification or the actual metadata download is
        absent, selective, conditional or configured differently.
    """
    if (
        jobs["native"] != NATIVE_JOB
        or jobs["native-primary"] != PRIMARY_JOB
        or jobs["native-quality"] != NATIVE_QUALITY_JOB
    ):
        raise ValueError("incomplete native CI workflow contract")
    if any(
        jobs["test"]["steps"].count(step) != 1
        for step in (NATIVE_METADATA_DOWNLOAD, PRIMARY_METADATA_DOWNLOAD)
    ):
        raise ValueError("missing native metadata producer input")
