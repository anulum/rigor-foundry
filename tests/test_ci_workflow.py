# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — CI workflow contract tests
"""Verify the hosted CI coverage publication boundary."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import coverage
import yaml


def test_coverage_jobs_share_source_imports_without_masking_wheel() -> None:
    """Measure checkout imports consistently while keeping wheel smoke isolated."""
    workflow = yaml.safe_load(Path(".github/workflows/ci.yml").read_text(encoding="utf-8"))
    assert "PYTHONPATH" not in workflow.get("env", {})
    for name in ("quality", "test"):
        job = workflow["jobs"][name]
        assert job["env"]["PYTHONPATH"] == "${{ github.workspace }}/src"
        for step in job["steps"]:
            assert "PYTHONPATH" not in step.get("env", {})
    distribution = workflow["jobs"]["distribution"]
    assert "PYTHONPATH" not in distribution.get("env", {})
    for step in distribution["steps"]:
        assert "PYTHONPATH" not in step.get("env", {})
        assert "PYTHONPATH" not in step.get("run", "")


def test_coverage_combines_real_cli_copies_from_distinct_working_directories(
    tmp_path: Path,
) -> None:
    """Combine actual CLI execution from identical checkout and site-package bytes."""
    root = Path(__file__).resolve().parents[1]
    installed = tmp_path / "site-packages"
    shutil.copytree(
        root / "src/rigor_foundry",
        installed / "rigor_foundry",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    data_file = tmp_path / ".coverage"
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("COVERAGE_", "COV_CORE_"))
    }
    environment["COVERAGE_FILE"] = str(data_file)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    for source, cwd in ((root / "src", root), (installed, tmp_path)):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "coverage",
                "run",
                "--rcfile",
                str(root / "pyproject.toml"),
                "--parallel-mode",
                "-m",
                "rigor_foundry",
                "--version",
            ],
            cwd=cwd,
            env=environment | {"PYTHONPATH": str(source)},
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        assert result.stdout.strip()
    raw_versions: set[str] = set()
    for path in tmp_path.glob(".coverage.*"):
        raw = coverage.CoverageData(basename=str(path))
        raw.read()
        raw_versions.update(name for name in raw.measured_files() if name.endswith("/version.py"))
    assert raw_versions == {
        str(root / "src/rigor_foundry/version.py"),
        str(installed / "rigor_foundry/version.py"),
    }
    measured = coverage.Coverage(
        config_file=str(root / "pyproject.toml"), data_file=str(data_file)
    )
    measured.combine(strict=True, keep=True)
    data = measured.get_data()
    version_files = [name for name in data.measured_files() if name.endswith("/version.py")]
    assert version_files == [str(root / "src/rigor_foundry/version.py")]
    assert data.lines(version_files[0])
    assert not any("/site-packages/rigor_foundry/" in name for name in data.measured_files())


def test_codecov_upload_is_exact_oidc_and_fail_closed() -> None:
    """Require isolated OIDC upload of the existing Python 3.12 report."""
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")

    coverage_job = workflow.split("\n  coverage:\n", maxsplit=1)[1].split(
        "\n  distribution:\n", maxsplit=1
    )[0]
    assert "needs: test" in coverage_job
    assert "permissions:\n      contents: read\n      id-token: write" in coverage_job
    assert "persist-credentials: false" in coverage_job
    assert "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c" in coverage_job
    assert "codecov/codecov-action@fb8b3582c8e4def4969c97caa2f19720cb33a72f" in coverage_job
    assert "use_oidc: true" in coverage_job
    assert "files: coverage.xml" in coverage_job
    assert "disable_search: true" in coverage_job
    assert "fail_ci_if_error: true" in coverage_job
    assert "CODECOV_TOKEN" not in coverage_job


def test_memory_documentation_cohort_is_enforced_in_ci_and_commit_hook() -> None:
    """Keep moved memory test owners inside both non-exempt documentation checks."""
    workflow = yaml.safe_load(Path(".github/workflows/ci.yml").read_text(encoding="utf-8"))
    hooks = yaml.safe_load(Path(".pre-commit-config.yaml").read_text(encoding="utf-8"))
    hosted = next(
        step["run"]
        for step in workflow["jobs"]["quality"]["steps"]
        if step.get("name") == "Memory preparation test documentation"
    )
    local = next(
        hook["entry"]
        for repository in hooks["repos"]
        for hook in repository["hooks"]
        if hook["id"] == "memory-test-documentation"
    )
    for command in (hosted, local):
        assert "--config 'lint.per-file-ignores={}'" in command
        for path in (
            "tests/test_project_memory_activation_plan.py",
            "tests/project_memory_store_support.py",
            "tests/test_project_memory_store.py",
            "tests/test_project_memory_reader.py",
            "tests/test_project_memory_history.py",
            "tests/test_project_memory_filesystem_safety.py",
            "tests/test_project_registry_cutover.py",
        ):
            assert path in command.split()
