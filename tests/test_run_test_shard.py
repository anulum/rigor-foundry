# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Actual test shard process qualification
"""Exercise the real launcher, pytest phases, finalisation and nested processes."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import coverage
import pytest

from tools._repository import ROOT
from tools.run_test_shard import pytest_command, run_shard

FIXTURE_TESTS = """import subprocess
import sys
import pytest
from rigor_foundry.native_dispatch import dispatch

class TestDispatch:
    @pytest.mark.parametrize("command", ["version", "validate", "unknown", "version"])
    def test_dispatch(self, command):
        completed = subprocess.run(
            [sys.executable, "-c", "from rigor_foundry.native_dispatch import dispatch; print(dispatch('validate'))"],
            check=True, capture_output=True, text=True,
        )
        assert completed.stdout.strip() == "valid"
        assert dispatch(command) in {"1.0", "valid", "unsupported"}
"""


def shard_repository(destination: Path) -> Path:
    """Create an executable fixture with actual current tooling and branch data.

    Parameters
    ----------
    destination : Path
        Independent fixture repository root.

    Returns
    -------
    Path
        Repository for infrastructure qualification, not a product coverage grade.
    """
    source = destination / "src/rigor_foundry"
    source.mkdir(parents=True)
    (source / "__init__.py").write_text('"""Executable coverage-union fixture package."""\n')
    (source / "native_dispatch.py").write_text(
        "def dispatch(command):\n"
        '    if command == "version":\n        return "1.0"\n'
        '    if command == "validate":\n        return "valid"\n'
        '    return "unsupported"\n'
    )
    (destination / "tests").mkdir()
    (destination / "tests/test_dispatch.py").write_text(FIXTURE_TESTS)
    (destination / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\naddopts = "--strict-config --strict-markers"\n'
        "xfail_strict = true\n"
        '[tool.coverage.run]\nbranch = true\nsource = ["rigor_foundry"]\n'
        'patch = ["subprocess"]\n[tool.coverage.report]\nfail_under = 98\n'
    )
    return destination


def shard_environment(root: Path) -> dict[str, str]:
    """Supply deterministic explicit run identity and the fixture source import.

    Parameters
    ----------
    root : Path
        Actual fixture repository.

    Returns
    -------
    dict[str, str]
        Process environment without changing the outer test's environment.
    """
    return {
        **os.environ,
        "PYTHONPATH": os.pathsep.join((str(root / "src"), str(ROOT))),
        "PYTHONDONTWRITEBYTECODE": "1",
        "GITHUB_REPOSITORY": "qualification/shards",
        "GITHUB_RUN_ID": "12345",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_SHA": "a" * 40,
    }


def execute_shard(root: Path, index: int = 0, count: int = 4) -> subprocess.CompletedProcess[str]:
    """Execute the actual current launcher in an independent fixture repository.

    Parameters
    ----------
    root : Path
        Fixture containing the complete collected test inventory.
    index : int
        Selected zero-based partition.
    count : int
        Complete partition count.

    Returns
    -------
    subprocess.CompletedProcess[str]
        Actual process exit and captured pytest diagnostics.
    """
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "tools.run_test_shard",
            "--index",
            str(index),
            "--count",
            str(count),
        ],
        cwd=root,
        env=shard_environment(root),
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_launcher_records_actual_child_exit_and_refuses_output_reuse(tmp_path: Path) -> None:
    """Successful evidence binds real artifacts and cannot be replaced by retry.

    Parameters
    ----------
    tmp_path : Path
        Actual independent repository location.
    """
    root = shard_repository(tmp_path)
    result = execute_shard(root)
    assert result.returncode == 0, result.stdout + result.stderr
    directory = root / ".rigor-test-shard"
    receipt = json.loads((directory / "receipt.json").read_text())
    assert receipt["command"] == pytest_command(0, 4)
    assert receipt["identity"]["run_attempt"] == "2"
    assert set(receipt["artifacts"]) == {"observations.json", "junit.xml", ".coverage"}
    before = {path.name: path.read_bytes() for path in directory.iterdir()}
    refused = execute_shard(root)
    assert refused.returncode != 0
    assert {path.name: path.read_bytes() for path in directory.iterdir()} == before


@pytest.mark.parametrize(
    "case",
    [
        "assertion",
        "setup",
        "teardown",
        "interrupt",
        "late-finalisation",
        "early-zero",
        "source-change",
    ],
)
def test_real_failure_and_late_or_incomplete_exit_never_publish_success(
    tmp_path: Path, case: str
) -> None:
    """Run actual failing phases, interruption and post-session finalisation.

    Parameters
    ----------
    tmp_path : Path
        Actual independent repository location.
    case : str
        Actual process or fixture failure mechanism.
    """
    root = shard_repository(tmp_path)
    test = root / "tests/test_dispatch.py"
    if case == "assertion":
        test.write_text("def test_failure():\n    assert False, 'actual assertion failure'\n")
    elif case in {"setup", "teardown"}:
        test.write_text(
            "import pytest\n@pytest.fixture(autouse=True)\ndef lifecycle():\n"
            + (
                "    raise RuntimeError('setup')\n    yield\n"
                if case == "setup"
                else "    yield\n    raise RuntimeError('teardown')\n"
            )
            + "def test_case():\n    pass\n"
        )
    elif case == "interrupt":
        test.write_text("def test_interrupt():\n    raise KeyboardInterrupt\n")
    elif case == "late-finalisation":
        (root / "conftest.py").write_text(
            "def pytest_unconfigure(config):\n    raise RuntimeError('late finalisation')\n"
        )
    elif case == "early-zero":
        test.write_text(
            "import pytest\ndef test_early_exit():\n    pytest.exit('incomplete', returncode=0)\ndef test_unreached():\n    pass\n"
        )
    else:
        test.write_text(
            "from pathlib import Path\nfrom rigor_foundry.native_dispatch import dispatch\n"
            "def test_change():\n    assert dispatch('version') == '1.0'\n"
            "    p = Path('src/rigor_foundry/native_dispatch.py')\n"
            "    p.write_text(p.read_text() + '# source changed during execution\\n')\n"
        )
    result = execute_shard(root, count=1)
    assert result.returncode != 0, result.stdout + result.stderr
    assert not (root / ".rigor-test-shard/receipt.json").exists()
    if case == "late-finalisation":
        provisional = json.loads((root / ".rigor-test-shard/observations.json").read_text())
        assert provisional["exitstatus"] == 0
        assert "late finalisation" in result.stderr


@pytest.mark.parametrize(("index", "count"), [(-1, 4), (4, 4), (0, 0), (True, 4), (0, True)])
def test_launcher_refuses_invalid_partition_identity(index: int, count: int) -> None:
    """Invalid partition values fail before creating any process or output.

    Parameters
    ----------
    index : int
        Invalid or boolean partition index.
    count : int
        Invalid or boolean partition count.
    """
    with pytest.raises(ValueError, match="incomplete test shard"):
        run_shard(index, count)


def test_launcher_measures_actual_public_cli_from_complete_source_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exercise the real product CLI in a measured child, with no inherited filters.

    Parameters
    ----------
    tmp_path : Path
        Independent complete actual package copy and one focused public test.
    monkeypatch : pytest.MonkeyPatch
        Set only an inherited option that the explicit launcher must not forward.
    """
    root = shard_repository(tmp_path)
    target = root / "src/rigor_foundry"
    shutil.rmtree(target)
    shutil.copytree(
        ROOT / "src/rigor_foundry", target, ignore=shutil.ignore_patterns("__pycache__")
    )
    for original in (ROOT / "src/rigor_foundry").rglob("*.py"):
        assert (
            target / original.relative_to(ROOT / "src/rigor_foundry")
        ).read_bytes() == original.read_bytes()
    (root / "tests/test_dispatch.py").write_text(
        "import subprocess\nimport sys\nfrom rigor_foundry.version import __version__\n"
        "def test_public_cli():\n"
        '    result = subprocess.run([sys.executable, "-m", "rigor_foundry", "--version"], check=True, capture_output=True, text=True)\n'
        '    assert result.stdout == f"rigor {__version__}\\n"\n'
    )
    monkeypatch.setenv("PYTEST_ADDOPTS", "--not-a-real-option")
    result = execute_shard(root, count=1)
    assert result.returncode == 0, result.stdout + result.stderr
    data = coverage.CoverageData(basename=str(root / ".rigor-test-shard/.coverage"))
    data.read()
    cli = [name for name in data.measured_files() if name.endswith("/rigor_foundry/cli.py")]
    assert len(cli) == 1 and data.arcs(cli[0])
    assert str(target) in cli[0]
