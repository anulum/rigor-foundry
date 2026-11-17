# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Native evidence producer qualification
"""Exercise actual Git, complete package identity and real terminal pytest publication."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tools._repository import ROOT
from tools.run_native_tests import (
    main,
    native_package_root,
    native_source_identity,
    run_native_tests,
)

NATIVE_OWNER = "tests/test_windows_job_observation.py"


def native_repository(root: Path) -> Path:
    """Create a real committed Git fixture with the complete current production package.

    Parameters
    ----------
    root : Path
        Owned empty repository allocation.

    Returns
    -------
    Path
        Genuine repository containing unchanged maintained tools and a complete
        public native test owner. It is a local qualification fixture.
    """
    root.mkdir(exist_ok=True)
    shutil.copytree(
        ROOT / "src/rigor_foundry",
        root / "src/rigor_foundry",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    (root / "tests").mkdir()
    shutil.copyfile(ROOT / NATIVE_OWNER, root / NATIVE_OWNER)
    (root / "tools").mkdir()
    for path in (ROOT / "tools").glob("*.py"):
        shutil.copyfile(path, root / "tools" / path.name)
    (root / ".github").mkdir()
    for name in ("pyproject.toml", ".gitignore", ".github/test-timings.json"):
        shutil.copyfile(ROOT / name, root / name)
    for arguments in (
        ["init", "--initial-branch=main", "--quiet"],
        ["add", "."],
        [
            "-c",
            "user.name=RigorFoundry native qualification",
            "-c",
            "user.email=qualification@example.invalid",
            "commit",
            "--quiet",
            "--no-gpg-sign",
            "--message=test: native producer fixture",
        ],
    ):
        subprocess.run(["git", *arguments], cwd=root, check=True, capture_output=True, timeout=20)
    return root


def native_environment(root: Path) -> dict[str, str]:
    """Label nested qualification honestly and retain the actual source import paths.

    Parameters
    ----------
    root : Path
        Actual fixture checkout.

    Returns
    -------
    dict[str, str]
        Child-only environment. A hosted outer test does not turn its nested
        qualification fixture into a hosted native coverage producer.
    """
    return {
        **os.environ,
        "GITHUB_ACTIONS": "false",
        "PYTHONPATH": os.pathsep.join((str(root / "src"), str(ROOT))),
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def execute_native(root: Path) -> subprocess.CompletedProcess[str]:
    """Run the real producer entry point without importing a fixture tool replacement.

    Parameters
    ----------
    root : Path
        Actual qualification repository.

    Returns
    -------
    subprocess.CompletedProcess[str]
        Real terminal producer status and source-free CLI diagnostics.
    """
    return subprocess.run(
        [sys.executable, "-P", "-m", "tools.run_native_tests", "--test-file", NATIVE_OWNER],
        cwd=root,
        env=native_environment(root),
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


@pytest.fixture(scope="module")
def completed_native(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Retain real successful local producer evidence for consumer qualification.

    Parameters
    ----------
    tmp_path_factory : pytest.TempPathFactory
        Module-owned repository allocator.

    Returns
    -------
    Path
        Unchanged successful actual repository and raw artifacts.
    """
    root = native_repository(tmp_path_factory.mktemp("completed-native"))
    result = execute_native(root)
    assert result.returncode == 0, result.stdout + result.stderr
    return root


def test_actual_cli_publishes_source_bound_local_receipt(completed_native: Path) -> None:
    """Keep actual Git and package identities separate from hosted-run admission.

    Parameters
    ----------
    completed_native : Path
        Actual successful producer and its unchanged artifacts.
    """
    record = json.loads((completed_native / ".rigor-native-coverage/receipt.json").read_text())
    head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=completed_native, text=True, timeout=10
    ).strip()
    assert record["venue"] == "local"
    assert record["schema_version"] == 2 and record["role"] == "ordinary"
    assert record["identity"]["head"] == head
    assert record["identity"]["run_id"].startswith("local-")
    assert record["files"] == [NATIVE_OWNER]
    assert record["package_root"] == (completed_native / "src/rigor_foundry").as_posix()


@pytest.mark.parametrize("selection", [None, (NATIVE_OWNER,)])
def test_public_api_runs_whole_actual_owner_and_scrubs_inherited_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, selection: tuple[str, ...] | None
) -> None:
    """Publish only after real pytest success with default and explicit local selection.

    Parameters
    ----------
    tmp_path : Path
        Actual repository allocation.
    monkeypatch : pytest.MonkeyPatch
        Set only public invocation inputs and inherited process options.
    selection : tuple[str, ...] or None
        Discover the complete fixture profile or name its complete owner.
    """
    root = native_repository(tmp_path)
    monkeypatch.chdir(root)
    monkeypatch.setenv("GITHUB_ACTIONS", "false")
    monkeypatch.setenv("PYTEST_ADDOPTS", "--not-a-supported-native-option")
    monkeypatch.setenv("COVERAGE_RCFILE", str(root / "absent-inherited-config"))
    assert run_native_tests(selection) == 0
    record = json.loads((root / ".rigor-native-coverage/receipt.json").read_text())
    assert record["venue"] == "local" and record["files"] == [NATIVE_OWNER]
    assert Path(record["package_root"]) == native_package_root(root)


def test_main_uses_actual_public_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exercise in-process CLI parsing and successful receipt publication.

    Parameters
    ----------
    tmp_path : Path
        Actual repository allocation.
    monkeypatch : pytest.MonkeyPatch
        Supply actual cwd, CLI argument vector and local-qualification label.
    """
    root = native_repository(tmp_path)
    monkeypatch.chdir(root)
    monkeypatch.setenv("GITHUB_ACTIONS", "false")
    monkeypatch.setattr(sys, "argv", ["run_native_tests", "--test-file", NATIVE_OWNER])
    assert main() == 0


@pytest.mark.parametrize("selection", [(), (NATIVE_OWNER, NATIVE_OWNER), ("pyproject.toml",)])
def test_public_api_refuses_incomplete_or_duplicate_owner_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, selection: tuple[str, ...]
) -> None:
    """Refuse invalid declared inputs before creating a producer allocation.

    Parameters
    ----------
    tmp_path : Path
        Real repository containing an unchanged complete package.
    monkeypatch : pytest.MonkeyPatch
        Supply the actual repository and local qualification venue.
    selection : tuple[str, ...]
        Empty, duplicated or non-test owner selection.
    """
    root = native_repository(tmp_path)
    monkeypatch.chdir(root)
    monkeypatch.setenv("GITHUB_ACTIONS", "false")
    with pytest.raises(ValueError):
        run_native_tests(selection)
    assert not (root / ".rigor-native-coverage").exists()


def test_actual_pytest_configuration_failure_cannot_publish_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Preserve the real nonzero pytest status for an invalid strict configuration.

    Parameters
    ----------
    tmp_path : Path
        Owned real repository whose pytest configuration is invalidated.
    monkeypatch : pytest.MonkeyPatch
        Supply the actual repository and honest qualification venue.
    """
    root = native_repository(tmp_path)
    config = root / "pyproject.toml"
    config.write_text(
        config.read_text().replace(
            "[tool.pytest.ini_options]",
            "[tool.pytest.ini_options]\nqualification_unknown_option = true",
        )
    )
    monkeypatch.chdir(root)
    monkeypatch.setenv("GITHUB_ACTIONS", "false")
    assert run_native_tests() == pytest.ExitCode.USAGE_ERROR
    assert not (root / ".rigor-native-coverage/receipt.json").exists()


def test_actual_source_change_during_finalisation_refuses_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Detect a real source edit by a public pytest hook after successful case execution.

    Parameters
    ----------
    tmp_path : Path
        Owned repository; only this copied source is altered.
    monkeypatch : pytest.MonkeyPatch
        Supply actual cwd and an honest local venue.
    """
    root = native_repository(tmp_path)
    (root / "conftest.py").write_text(
        "from pathlib import Path\n"
        "def pytest_sessionfinish(session):\n"
        "    source = Path('src/rigor_foundry/__init__.py')\n"
        "    source.write_bytes(source.read_bytes() + b'\\n# actual qualification edit\\n')\n"
    )
    monkeypatch.chdir(root)
    monkeypatch.setenv("GITHUB_ACTIONS", "false")
    with pytest.raises(ValueError):
        run_native_tests()
    assert not (root / ".rigor-native-coverage/receipt.json").exists()


def test_real_git_metadata_parser_uses_actual_head_and_explicit_venue(
    tmp_path: Path,
) -> None:
    """Parse declared hosted metadata without inventing a hosted execution receipt.

    Parameters
    ----------
    tmp_path : Path
        Actual complete committed repository.
    """
    root = native_repository(tmp_path)
    local, first, environment = native_source_identity(root, {})
    assert local == "local" and first["head"] == environment["GITHUB_SHA"]
    _, second, _ = native_source_identity(root, {})
    assert first["source"] == second["source"] and first["run_id"] != second["run_id"]
    declared = {
        **environment,
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
    }
    venue, identity, _ = native_source_identity(root, declared)
    assert venue == "github" and identity["head"] == first["head"]
    for field, value in (("RUNNER_ENVIRONMENT", "self-hosted"), ("GITHUB_SHA", "wrong-head")):
        with pytest.raises(ValueError):
            native_source_identity(root, {**declared, field: value})


def test_missing_git_and_nonrepository_state_have_fixed_cli_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Use actual absent prerequisites without substituting an executable or Git response.

    Parameters
    ----------
    tmp_path : Path
        Real directory without Git metadata.
    monkeypatch : pytest.MonkeyPatch
        Supply actual cwd/CLI inputs and then an empty executable search path.
    capsys : pytest.CaptureFixture[str]
        Inspect only the fixed source-free diagnostic.
    """
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["run_native_tests"])
    assert main() == 1
    assert capsys.readouterr().err == "Native test evidence is incomplete\n"
    monkeypatch.setenv("PATH", str(tmp_path / "no-executables"))
    with pytest.raises(ValueError, match="Git is unavailable"):
        native_source_identity(tmp_path, {})


def test_complete_imported_package_identity_refuses_real_source_differences(
    tmp_path: Path,
) -> None:
    """Compare the full genuine package before and after a copied source is changed.

    Parameters
    ----------
    tmp_path : Path
        Actual source repository allocation.
    """
    root = native_repository(tmp_path)
    assert native_package_root(root) == (ROOT / "src/rigor_foundry").resolve()
    source = root / "src/rigor_foundry/__init__.py"
    source.write_bytes(source.read_bytes() + b"\n# actual source mismatch\n")
    with pytest.raises(ValueError):
        native_package_root(root)


def test_local_primary_selection_is_refused_before_any_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Refuse a local primary launch without reading or executing reserved controls.

    Parameters
    ----------
    tmp_path : Path
        Real ordinary-only Git repository.
    monkeypatch : pytest.MonkeyPatch
        Supply actual cwd and the honest local venue.
    """
    root = native_repository(tmp_path)
    monkeypatch.chdir(root)
    monkeypatch.setenv("GITHUB_ACTIONS", "false")
    with pytest.raises(ValueError):
        run_native_tests(role="primary")
    with pytest.raises(ValueError):
        run_native_tests((NATIVE_OWNER,), role="primary")
    assert not (root / ".rigor-native-primary").exists()
