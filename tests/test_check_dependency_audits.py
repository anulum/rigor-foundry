# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Dependency audit enrolment tests
"""Exercise actual repository lock enrolment and blocking workflow policy."""

from __future__ import annotations

import os
import subprocess
import sys
from itertools import product
from pathlib import Path
from shutil import copy2

import pytest
import yaml

from tools._repository import ROOT
from tools.check_dependency_audits import (
    NODE_LOCK,
    PYTHON_COMMANDS,
    PYTHON_LOCKS,
    dependency_audit_errors,
)


@pytest.fixture
def audit_root(tmp_path: Path) -> Path:
    """Retain the complete actual lock set and workflow in a real Git worktree.

    Parameters
    ----------
    tmp_path : Path
        Empty temporary directory supplied by pytest for the copied Git worktree.

    Returns
    -------
    Path
        Real Git worktree retaining the complete current lock and workflow inputs.
    """
    for relative in (
        ".github/workflows/security.yml",
        ".github/workflows/ci.yml",
        ".github/dependency-waivers.json",
        *PYTHON_LOCKS,
        NODE_LOCK,
        "tools/__init__.py",
        "tools/_repository.py",
        "tools/check_dependency_audits.py",
        "tools/check_dependency_waivers.py",
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        copy2(ROOT / relative, target)
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True, timeout=10)
    return tmp_path


def test_actual_repository_enrols_every_lock(audit_root: Path) -> None:
    """The current repository and an unchanged independent copy are accepted.

    Parameters
    ----------
    audit_root : Path
        Independent Git worktree containing the actual locks and workflows.
    """
    assert dependency_audit_errors() == []
    assert dependency_audit_errors(audit_root) == []


@pytest.mark.parametrize("lock", [*PYTHON_LOCKS, NODE_LOCK])
def test_missing_and_linked_locks_refuse(audit_root: Path, lock: str) -> None:
    """Removing or linking an enrolled lock cannot erase its audit obligation.

    Parameters
    ----------
    audit_root : Path
        Independent Git worktree containing the actual locks and workflows.
    lock : str
        Committed lock path removed and then replaced by a symbolic link.
    """
    path = audit_root / lock
    data = path.read_bytes()
    path.unlink()
    assert any("missing or linked" in e for e in dependency_audit_errors(audit_root))
    retained = audit_root / "retained-dependency-input"
    retained.write_bytes(data)
    path.symlink_to(retained)
    assert any("missing or linked" in e for e in dependency_audit_errors(audit_root))


@pytest.mark.parametrize(
    "lock",
    [
        "new/Cargo.lock",
        "new/pnpm-lock.yaml",
        "new/pnpm-lock.yml",
        "new/bun.lockb",
        "new/go.sum",
        "new/Package.resolved",
        "new/packages.lock.json",
        "new/npm-shrinkwrap.json",
        "new/custom-lock.json",
        "new/custom-lock.yaml",
        "new/custom-lock.yml",
        "requirements/new.txt",
        "requirements/profiles/new.txt",
        "new/requirements-tools.txt",
    ],
)
def test_new_lock_requires_actual_enrolment(audit_root: Path, lock: str) -> None:
    """An additional visible lock is refused before it can escape audit coverage.

    Parameters
    ----------
    audit_root : Path
        Independent Git worktree containing the actual locks and workflows.
    lock : str
        Additional lock path absent from the qualified audit inventory.
    """
    target = audit_root / lock
    target.parent.mkdir(parents=True, exist_ok=True)
    copy2(ROOT / NODE_LOCK, target)
    assert f"dependency lock has no qualified audit enrolment: {lock}" in dependency_audit_errors(
        audit_root
    )


@pytest.mark.parametrize("command", PYTHON_COMMANDS)
@pytest.mark.parametrize("suffix", [" || true", " --dry-run", " --ignore-vuln ID"])
def test_each_python_audit_propagates_findings(
    audit_root: Path, command: str, suffix: str
) -> None:
    """Every profile retains the exact scanner command without suppression.

    Parameters
    ----------
    audit_root : Path
        Independent Git worktree containing the actual locks and workflows.
    command : str
        Required pip-audit command for a committed Python lock.
    suffix : str
        Shell suffix or scanner option that weakens the audit.
    """
    path = audit_root / ".github/workflows/security.yml"
    document = yaml.safe_load(path.read_text())
    for step in document["jobs"]["scan"]["steps"]:
        if step.get("run") == command:
            step["run"] += suffix
            break
    else:
        pytest.fail("actual workflow does not contain the enrolled audit")
    path.write_text(yaml.safe_dump(document))
    assert any(command in e for e in dependency_audit_errors(audit_root))


@pytest.mark.parametrize(
    "replacement",
    [
        "npm audit --audit-level=high --prefix editors/vscode",
        "npm audit --omit=dev --prefix editors/vscode",
        "npm audit --prefix editors/vscode || true",
        "echo 'npm audit --prefix editors/vscode'",
        "# npm audit --prefix editors/vscode",
    ],
)
def test_npm_audit_rejects_weakened_commands(audit_root: Path, replacement: str) -> None:
    """Thresholds, production-only filtering and nonexecuting text refuse.

    Parameters
    ----------
    audit_root : Path
        Independent Git worktree containing the actual locks and workflows.
    replacement : str
        Filtered, suppressed or nonexecuting npm audit command.
    """
    path = audit_root / ".github/workflows/security.yml"
    path.write_text(
        path.read_text().replace("run: npm audit --prefix editors/vscode", f"run: {replacement}")
    )
    assert any(
        "npm audit --prefix editors/vscode" in e for e in dependency_audit_errors(audit_root)
    )


@pytest.mark.parametrize("job", ["scan", "npm-audit"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("if", False),
        ("needs", ["decoy"]),
        ("strategy", {}),
        ("defaults", {}),
        ("continue-on-error", True),
        ("env", {"NPM_CONFIG_AUDIT_LEVEL": "none"}),
        ("env", "invalid"),
    ],
)
def test_job_cannot_skip_or_ignore_audit(
    audit_root: Path, job: str, field: str, value: object
) -> None:
    """Each audit job is unconditional and rejects unqualified overrides.

    Parameters
    ----------
    audit_root : Path
        Independent Git worktree containing the actual locks and workflows.
    job : str
        Python or npm audit job to alter.
    field : str
        Job-level setting that may disable or override the audit.
    value : object
        Unqualified value inserted into that job setting.
    """
    path = audit_root / ".github/workflows/security.yml"
    document = yaml.safe_load(path.read_text())
    document["jobs"][job][field] = value
    path.write_text(yaml.safe_dump(document))
    assert dependency_audit_errors(audit_root)


@pytest.mark.parametrize(
    "field,value",
    [
        ("if", False),
        ("env", {}),
        ("working-directory", "other"),
        ("continue-on-error", True),
        ("shell", "bash {0}"),
    ],
)
def test_audit_step_cannot_disable_failure(audit_root: Path, field: str, value: object) -> None:
    """A job-level declaration cannot conceal a disabled audit step.

    Parameters
    ----------
    audit_root : Path
        Independent Git worktree containing the actual locks and workflows.
    field : str
        Audit-step setting that may disable execution or failure propagation.
    value : object
        Unqualified value inserted into that step setting.
    """
    path = audit_root / ".github/workflows/security.yml"
    document = yaml.safe_load(path.read_text())
    document["jobs"]["npm-audit"]["steps"][-1][field] = value
    path.write_text(yaml.safe_dump(document))
    assert any("missing a blocking command" in e for e in dependency_audit_errors(audit_root))


@pytest.mark.parametrize(
    "event,value",
    [
        ("push", {"branches": ["main"]}),
        ("push", {"paths": ["requirements/**"]}),
        ("pull_request", {"branches": ["other"]}),
        ("pull_request", {"paths": ["src/**"]}),
    ],
)
def test_event_filters_cannot_omit_a_lock_head(
    audit_root: Path, event: str, value: object
) -> None:
    """Every push and every main-targeting pull request must run both audits.

    Parameters
    ----------
    audit_root : Path
        Independent Git worktree containing the actual locks and workflows.
    event : str
        Push or pull-request trigger to restrict.
    value : object
        Branch or path filter that can omit required audit runs.
    """
    path = audit_root / ".github/workflows/security.yml"
    document = yaml.safe_load(path.read_text())
    document[True][event] = value
    path.write_text(yaml.safe_dump(document))
    assert any("every push" in e for e in dependency_audit_errors(audit_root))


@pytest.mark.parametrize(
    "field,value",
    [
        ("needs", ["scan"]),
        ("if", False),
        ("continue-on-error", True),
        ("env", {}),
        ("defaults", {}),
        ("strategy", {}),
        ("steps", []),
    ],
)
def test_gate_requires_both_actual_successes(audit_root: Path, field: str, value: object) -> None:
    """The always-run aggregate cannot silently accept a skipped or failed audit.

    Parameters
    ----------
    audit_root : Path
        Independent Git worktree containing the actual locks and workflows.
    field : str
        Aggregate gate setting to alter.
    value : object
        Unqualified setting that can conceal an unsuccessful audit.
    """
    path = audit_root / ".github/workflows/security.yml"
    document = yaml.safe_load(path.read_text())
    document["jobs"]["security-gate"][field] = value
    path.write_text(yaml.safe_dump(document))
    assert (
        "security-gate must require successful Python and npm audit jobs"
        in dependency_audit_errors(audit_root)
    )


@pytest.mark.parametrize("content", ["[", "[]", "{}", "jobs: []", "on: []\njobs: {}"])
def test_unreadable_or_malformed_workflow_refuses(audit_root: Path, content: str) -> None:
    """Absent, malformed and nonmapping workflows remain unknown rather than pass.

    Parameters
    ----------
    audit_root : Path
        Independent Git worktree containing the actual locks and workflows.
    content : str
        Invalid or structurally incomplete security workflow YAML.
    """
    path = audit_root / ".github/workflows/security.yml"
    path.write_text(content)
    assert dependency_audit_errors(audit_root)
    path.unlink()
    assert dependency_audit_errors(audit_root)


def test_invalid_job_steps_and_shell_refuse(audit_root: Path) -> None:
    """Malformed jobs and shell quoting cannot qualify an audit command.

    Parameters
    ----------
    audit_root : Path
        Independent Git worktree containing the actual locks and workflows.
    """
    path = audit_root / ".github/workflows/security.yml"
    document = yaml.safe_load(path.read_text())
    document["jobs"]["scan"]["steps"] += [None, {"run": "'", "shell": "bash"}]
    path.write_text(yaml.safe_dump(document))
    assert any("invalid shell command" in e for e in dependency_audit_errors(audit_root))
    document["jobs"]["scan"] = {"steps": "invalid"}
    document["jobs"].pop("security-gate")
    document["env"] = {"NPM_CONFIG_AUDIT_LEVEL": "none"}
    path.write_text(yaml.safe_dump(document))
    assert any("job is missing" in e for e in dependency_audit_errors(audit_root))
    assert any("override environment" in e for e in dependency_audit_errors(audit_root))


def test_inventory_without_a_git_worktree_refuses(tmp_path: Path) -> None:
    """The scanner policy cannot establish coverage without an actual Git inventory.

    Parameters
    ----------
    tmp_path : Path
        Temporary directory with no Git inventory.
    """
    assert dependency_audit_errors(tmp_path)


@pytest.mark.parametrize("job", [None, {"steps": None}, {}])
def test_absent_audit_job_refuses(audit_root: Path, job: object) -> None:
    """Neither missing jobs nor missing step lists qualify an audit.

    Parameters
    ----------
    audit_root : Path
        Independent Git worktree containing the actual locks and workflows.
    job : object
        Missing or incomplete replacement for the npm audit job.
    """
    path = audit_root / ".github/workflows/security.yml"
    document = yaml.safe_load(path.read_text())
    document["jobs"]["npm-audit"] = job
    path.write_text(yaml.safe_dump(document))
    assert any("job is missing" in e for e in dependency_audit_errors(audit_root))


def test_invalid_utf8_workflow_refuses(audit_root: Path) -> None:
    """Unreadable source bytes cannot become a qualified audit workflow.

    Parameters
    ----------
    audit_root : Path
        Independent Git worktree containing the actual locks and workflows.
    """
    (audit_root / ".github/workflows/security.yml").write_bytes(b"\xff")
    assert dependency_audit_errors(audit_root)


def test_actual_gate_script_propagates_job_outcomes() -> None:
    """Execute the real gate command for success and every non-success job state."""
    document = yaml.safe_load((ROOT / ".github/workflows/security.yml").read_text())
    command = document["jobs"]["security-gate"]["steps"][0]["run"]
    states = ("success", "failure", "cancelled", "skipped", "")
    for scan, node in product(states, repeat=2):
        environment = os.environ.copy()
        environment.update(SCAN_RESULT=scan, NODE_RESULT=node)
        completed = subprocess.run(
            ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", command],
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert (completed.returncode == 0) == (scan == node == "success")


def test_actual_guard_cli_accepts_and_refuses(audit_root: Path) -> None:
    """The existing public repository guard executes the new enrolment check.

    Parameters
    ----------
    audit_root : Path
        Independent Git worktree containing the actual locks and workflows.
    """
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    argv = [sys.executable, "-B", "-m", "tools.check_dependency_waivers"]
    for name in (
        "__init__.py",
        "_repository.py",
        "check_dependency_audits.py",
        "check_dependency_waivers.py",
    ):
        assert (audit_root / "tools" / name).read_bytes() == (ROOT / "tools" / name).read_bytes()
    good = subprocess.run(
        argv, cwd=audit_root, env=environment, capture_output=True, text=True, timeout=30
    )
    assert good.returncode == 0, good.stderr
    (audit_root / NODE_LOCK).unlink()
    bad = subprocess.run(
        argv, cwd=audit_root, env=environment, capture_output=True, text=True, timeout=30
    )
    assert bad.returncode == 1
    assert (
        bad.stdout
        == "Dependency-waiver guard failed; finding details are redacted from process output.\n"
    )
    assert str(audit_root) not in bad.stdout + bad.stderr


@pytest.mark.parametrize("content", ["[", "[]", "jobs: []", "jobs: {quality: null}"])
def test_missing_or_malformed_quality_workflow_refuses(audit_root: Path, content: str) -> None:
    """The command-pinning tests must remain enrolled in the actual quality job.

    Parameters
    ----------
    audit_root : Path
        Independent Git worktree containing the actual locks and workflows.
    content : str
        Invalid or incomplete quality workflow YAML.
    """
    path = audit_root / ".github/workflows/ci.yml"
    path.write_text(content)
    assert dependency_audit_errors(audit_root)
    path.unlink()
    assert dependency_audit_errors(audit_root)


def test_quality_job_cannot_reduce_guard_coverage(audit_root: Path) -> None:
    """The complete owning guard tests retain their blocking 100 percent target.

    Parameters
    ----------
    audit_root : Path
        Independent Git worktree containing the actual locks and workflows.
    """
    path = audit_root / ".github/workflows/ci.yml"
    path.write_text(path.read_text().replace("--cov-fail-under=100", "--cov-fail-under=98"))
    assert any(
        "--cov=tools.check_dependency_audits" in e for e in dependency_audit_errors(audit_root)
    )
