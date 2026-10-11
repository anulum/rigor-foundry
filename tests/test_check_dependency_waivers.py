# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Dependency-waiver guard tests
"""Verify that scanner remediation removes every audit exception."""

import json
import subprocess
from pathlib import Path
from shutil import copy2

import pytest

from tools._repository import ROOT
from tools.check_dependency_audits import NODE_LOCK, PYTHON_LOCKS
from tools.check_dependency_waivers import dependency_waiver_errors, main


def _waiver_root(tmp_path: Path) -> Path:
    for relative in (
        ".github/dependency-waivers.json",
        ".github/workflows/security.yml",
        ".github/workflows/ci.yml",
        *PYTHON_LOCKS,
        NODE_LOCK,
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        copy2(ROOT / relative, target)
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True, timeout=10)
    return tmp_path


def test_repository_has_no_dependency_waivers() -> None:
    """The canonical security workflow audits every lock without exclusions."""
    assert dependency_waiver_errors() == []
    assert main() == 0


@pytest.mark.parametrize("waiver", [{"advisory_id": "PYSEC-2026-2132"}, None])
def test_any_waiver_fails_closed(tmp_path: Path, waiver: object) -> None:
    """A newly inserted exception cannot silently revive the old waiver lane."""
    root = _waiver_root(tmp_path)
    path = root / ".github/dependency-waivers.json"
    path.write_text(json.dumps({"schema_version": "1.0", "waivers": [waiver]}))
    assert "dependency-waiver set must be empty after scanner remediation" in (
        dependency_waiver_errors(root)
    )


@pytest.mark.parametrize("flag", ["--ignore-vuln PYSEC-2026-2132", "--ignore-vuln=ID"])
def test_workflow_cannot_ignore_findings(tmp_path: Path, flag: str) -> None:
    """Both supported pip-audit exclusion syntaxes are rejected."""
    root = _waiver_root(tmp_path)
    workflow = root / ".github/workflows/security.yml"
    workflow.write_text(workflow.read_text(encoding="utf-8") + f"\n# {flag}\n")
    assert "security workflow must not ignore vulnerability findings" in (
        dependency_waiver_errors(root)
    )


@pytest.mark.parametrize(
    ("content", "expected"),
    (
        ("{", "cannot read dependency waivers:"),
        ("[]", "dependency-waiver document must be a JSON object"),
        ('{"schema_version":"0","waivers":[]}', "schema_version must be '1.0'"),
        ('{"schema_version":"1.0","waivers":{}}', "set must be a list"),
        ('{"schema_version":"1.0","waivers":[],"extra":1}', "must contain only"),
    ),
)
def test_malformed_document_fails_closed(tmp_path: Path, content: str, expected: str) -> None:
    """Malformed or expanded waiver documents do not disable the guard."""
    root = _waiver_root(tmp_path)
    (root / ".github/dependency-waivers.json").write_text(content, encoding="utf-8")
    assert any(expected in error for error in dependency_waiver_errors(root))


def test_missing_document_fails_closed(tmp_path: Path) -> None:
    """An absent waiver document cannot silently remove governance."""
    root = _waiver_root(tmp_path)
    (root / ".github/dependency-waivers.json").unlink()
    assert any(
        "cannot read dependency waivers:" in error for error in dependency_waiver_errors(root)
    )


@pytest.mark.parametrize(
    "fragment",
    (
        "python -m tools.check_dependency_waivers",
        "python -m pip_audit -r requirements/ci.txt",
        "python -m pip_audit -r requirements/security.txt",
        "semgrep scan --error --config .semgrep.yml src tools",
    ),
)
def test_workflow_keeps_all_guarded_commands(tmp_path: Path, fragment: str) -> None:
    """Both dependency audits, the guard and the scanner remain enrolled.

    Parameters
    ----------
    tmp_path : Path
        Temporary directory supplied by pytest for repository inputs.
    fragment : str
        Required scanner or audit command removed from the workflow.
    """
    root = _waiver_root(tmp_path)
    workflow = root / ".github/workflows/security.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(fragment, ""), encoding="utf-8"
    )
    assert any(fragment in error for error in dependency_waiver_errors(root))


@pytest.mark.parametrize("replacement", ["# {command}", "echo '{command}'"])
def test_workflow_rejects_nonexecuting_command_text(tmp_path: Path, replacement: str) -> None:
    """Comments and echo output cannot stand in for the scanner step."""
    root = _waiver_root(tmp_path)
    workflow = root / ".github/workflows/security.yml"
    command = "semgrep scan --error --config .semgrep.yml src tools"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(
            f"run: {command}", f"run: {replacement.format(command=command)}"
        ),
        encoding="utf-8",
    )
    assert any(command in error for error in dependency_waiver_errors(root))


def test_workflow_rejects_command_in_unrelated_job(tmp_path: Path) -> None:
    """Only the enrolled scan job can satisfy the required command set.

    Parameters
    ----------
    tmp_path : Path
        Temporary directory supplied by pytest for repository inputs.
    """
    root = _waiver_root(tmp_path)
    workflow = root / ".github/workflows/security.yml"
    command = "semgrep scan --error --config .semgrep.yml src tools"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(
            f"run: {command}", f"run: true\n  decoy:\n    steps:\n      - run: {command}"
        ),
        encoding="utf-8",
    )
    assert any(command in error for error in dependency_waiver_errors(root))


@pytest.mark.parametrize("condition", ["if: false", "continue-on-error: true"])
def test_workflow_rejects_disabled_scanner_step(tmp_path: Path, condition: str) -> None:
    """An enrolled command must run and propagate its failure.

    Parameters
    ----------
    tmp_path : Path
        Temporary directory supplied by pytest for repository inputs.
    condition : str
        Step setting that skips scanning or permits scanner failure.
    """
    root = _waiver_root(tmp_path)
    workflow = root / ".github/workflows/security.yml"
    command = "semgrep scan --error --config .semgrep.yml src tools"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(
            f"run: {command}", f"run: {command}\n        {condition}"
        ),
        encoding="utf-8",
    )
    assert any(command in error for error in dependency_waiver_errors(root))


def test_missing_security_workflow_refuses(tmp_path: Path) -> None:
    """The composed public guard refuses an absent scanner workflow.

    Parameters
    ----------
    tmp_path : Path
        Temporary directory supplied by pytest for repository inputs.
    """
    root = _waiver_root(tmp_path)
    (root / ".github/workflows/security.yml").unlink()
    assert any(
        "cannot read security workflow" in error for error in dependency_waiver_errors(root)
    )


@pytest.mark.parametrize("content", ["[", "[]", "jobs: []", "jobs: {scan: {steps: wrong}}"])
def test_malformed_security_workflow_refuses(tmp_path: Path, content: str) -> None:
    """Malformed YAML and absent or malformed scanner steps remain failures.

    Parameters
    ----------
    tmp_path : Path
        Temporary directory supplied by pytest for repository inputs.
    content : str
        Malformed YAML or an invalid scanner-job step structure.
    """
    root = _waiver_root(tmp_path)
    (root / ".github/workflows/security.yml").write_text(content)
    assert dependency_waiver_errors(root)


@pytest.mark.parametrize("condition", ["if: false", "continue-on-error: true"])
def test_disabled_scan_job_refuses(tmp_path: Path, condition: str) -> None:
    """The owning scanner job cannot be skipped or allowed to ignore errors.

    Parameters
    ----------
    tmp_path : Path
        Temporary directory supplied by pytest for repository inputs.
    condition : str
        Job setting that skips scanning or permits scanner failure.
    """
    root = _waiver_root(tmp_path)
    path = root / ".github/workflows/security.yml"
    path.write_text(path.read_text().replace("  scan:\n", f"  scan:\n    {condition}\n"))
    assert (
        "security workflow scan job must be unconditional and fail-closed"
        in dependency_waiver_errors(root)
    )


def test_invalid_scanner_shell_quoting_refuses(tmp_path: Path) -> None:
    """A malformed real run step cannot satisfy the public scanner guard.

    Parameters
    ----------
    tmp_path : Path
        Temporary directory supplied by pytest for repository inputs.
    """
    root = _waiver_root(tmp_path)
    path = root / ".github/workflows/security.yml"
    path.write_text(
        path.read_text()
        .replace("run: semgrep scan", 'run: "\\"semgrep scan')
        .replace(".semgrep.yml src tools", '.semgrep.yml src tools"')
    )
    assert any(
        "cannot parse security workflow run step" in error
        for error in dependency_waiver_errors(root)
    )
