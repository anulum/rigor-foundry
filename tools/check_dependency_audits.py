# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Committed dependency audit enrolment
"""Require blocking advisory audits for every enrolled dependency lock."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import yaml

from tools._repository import ROOT, RepositoryError, visible_files
from tools.ci_workflows import ci_jobs

PYTHON_LOCKS = tuple(
    f"requirements/{name}.txt"
    for name in (
        "bootstrap",
        "build",
        "ci",
        "fuzz",
        "native",
        "provenance",
        "runtime",
        "security",
        "test",
        "test-windows",
    )
)
NODE_LOCK = "editors/vscode/package-lock.json"
# The owner's 2026-11-23 decision keeps this one lock outside the advisory audit: Semgrep pins
# advisory-affected dependencies that no compatible release resolves. The lock installs only
# into a separate environment, and the repository policy scan runs from the digest-pinned
# image of the same version.
SEMGREP_LOCK = "requirements/semgrep.txt"
SEMGREP_IMAGE = re.compile(
    r"docker\.io/semgrep/semgrep:(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"
    r"@sha256:[0-9a-f]{64}(?![0-9A-Za-z])"
)
SEMGREP_PIN = re.compile(r"^semgrep==(?P<version>[0-9]+\.[0-9]+\.[0-9]+) \\$", re.MULTILINE)
AUDIT_FLAGS = "--require-hashes --disable-pip --strict"
PYTHON_COMMANDS = tuple(f"python -m pip_audit -r {path} {AUDIT_FLAGS}" for path in PYTHON_LOCKS)
NODE_COMMAND = "npm audit --prefix editors/vscode"
GUARD_COVERAGE_COMMAND = (
    "python -m pytest tests/test_check_dependency_audits.py tests/test_check_dependency_waivers.py "
    "tests/test_check_semgrep_isolation.py "
    "--cov=tools.check_dependency_audits --cov=tools.check_dependency_waivers "
    "--cov=tools.check_semgrep_isolation "
    "--cov-branch --cov-report=term-missing --cov-fail-under=100"
)
GATE_COMMAND = 'test "$SCAN_RESULT" = success\ntest "$NODE_RESULT" = success'
LOCK_NAMES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "pnpm-lock.yml",
    "bun.lockb",
    "go.sum",
    "packages.lock.json",
    "Package.resolved",
}


def _lock_candidate(path: Path) -> bool:
    return (
        path.name in LOCK_NAMES
        or path.suffix == ".lock"
        or path.name.endswith(("-lock.json", "-lock.yaml", "-lock.yml"))
        or ("requirements" in path.parts[:-1] and path.suffix == ".txt")
        or (
            path.name.startswith("requirements")
            and path.suffix == ".txt"
            and path.as_posix() not in {"requirements.txt", "requirements-dev.txt"}
        )
    )


def _blocking_commands(job: object, label: str, errors: list[str]) -> list[tuple[str, ...]]:
    if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
        errors.append(f"dependency audit job is missing: {label}")
        return []
    if any(key in job for key in ("if", "needs", "strategy", "defaults")) or job.get(
        "continue-on-error"
    ) not in (None, False):
        errors.append(f"dependency audit job must run unconditionally and block: {label}")
    environment = job.get("env", {})
    if not isinstance(environment, dict) or set(environment) - {"PYTHONPATH"}:
        errors.append(f"dependency audit job has unqualified environment overrides: {label}")
    commands: list[tuple[str, ...]] = []
    for step in job["steps"]:
        if not isinstance(step, dict) or not isinstance(step.get("run"), str):
            continue
        if (
            any(key in step for key in ("if", "env", "working-directory"))
            or step.get("continue-on-error") not in (None, False)
            or step.get("shell") != "bash"
        ):
            continue
        try:
            commands.append(tuple(shlex.split(step["run"], comments=True)))
        except ValueError:
            errors.append(f"dependency audit job contains an invalid shell command: {label}")
    return commands


def semgrep_isolation_errors(root: Path, workflow: str) -> list[str]:
    """Check that the isolated Semgrep lock and the policy-scan image name one version.

    Parameters
    ----------
    root:
        Actual Git worktree containing the isolated lock and every audited Python lock.
    workflow:
        Security workflow text, which names the digest-pinned policy-scan image.

    Returns
    -------
    list[str]
        Findings for a lock without exactly one Semgrep pin, an audited lock that
        installs Semgrep, an image reference without a digest or used more than once,
        or an image version that differs from the isolated lock.
    """
    try:
        lock = (root / SEMGREP_LOCK).read_text(encoding="utf-8")
        audited = [(root / path).read_text(encoding="utf-8") for path in PYTHON_LOCKS]
    except (OSError, UnicodeError):
        return ["cannot read the isolated Semgrep lock and the audited locks"]
    errors: list[str] = []
    pins = SEMGREP_PIN.findall(lock)
    images = SEMGREP_IMAGE.findall(workflow)
    if len(pins) != 1:
        errors.append("isolated Semgrep lock must pin exactly one Semgrep version")
    if any(SEMGREP_PIN.search(text) for text in audited):
        errors.append("an audited dependency lock must not install Semgrep")
    if len(images) != 1 or workflow.count("semgrep/semgrep") != 1:
        errors.append("security workflow must name one digest-pinned Semgrep image once")
    elif len(pins) == 1 and images[0] != pins[0]:
        errors.append("Semgrep image version differs from the isolated Semgrep lock")
    return errors


def dependency_audit_errors(root: Path = ROOT) -> list[str]:
    """Check lock inventory and unconditional, blocking CI audit enrolment.

    Parameters
    ----------
    root:
        Actual Git worktree containing dependency locks and the Security workflow.

    Returns
    -------
    list[str]
        Findings for missing locks, unenrolled lock formats, weakened commands,
        event filters, a gate that does not require both audit jobs, or an isolated
        Semgrep lock that differs from its image. No advisory query is performed; the
        actual CI scanner results remain separate evidence.
    """
    errors: list[str] = []
    try:
        visible = {path.as_posix() for path in visible_files(root)}
        workflow = (root / ".github/workflows/security.yml").read_text(encoding="utf-8")
        document: object = yaml.safe_load(workflow)
        quality_job = ci_jobs(root)["quality"]
    except (OSError, UnicodeError, RepositoryError, yaml.YAMLError, ValueError):
        return ["cannot establish dependency lock inventory and audit workflow"]
    supported = {*PYTHON_LOCKS, NODE_LOCK}
    for path in sorted(visible):
        if _lock_candidate(Path(path)) and path not in {*supported, SEMGREP_LOCK}:
            errors.append(f"dependency lock has no qualified audit enrolment: {path}")
    for path in sorted({*supported, SEMGREP_LOCK}):
        if path not in visible or (root / path).is_symlink():
            errors.append(f"required dependency lock is missing or linked: {path}")
    errors.extend(semgrep_isolation_errors(root, workflow))
    if not isinstance(document, dict):
        return [*errors, "dependency audit workflow must be a mapping"]
    events = document.get("on", document.get(True))
    if (
        not isinstance(events, dict)
        or events.get("push", "missing") is not None
        or events.get("pull_request") != {"branches": ["main"]}
    ):
        errors.append("dependency audits must run on every push and pull request to main")
    if "env" in document or "defaults" in document:
        errors.append("dependency audit workflow must not override environment or shell defaults")
    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        return [*errors, "dependency audit workflow must contain jobs"]
    python_commands = _blocking_commands(jobs.get("scan"), "scan", errors)
    node_commands = _blocking_commands(jobs.get("npm-audit"), "npm-audit", errors)
    quality_commands = _blocking_commands(quality_job, "quality", errors)
    for command, commands in (
        *((command, python_commands) for command in PYTHON_COMMANDS),
        ("python -m tools.check_dependency_waivers", python_commands),
        (NODE_COMMAND, node_commands),
        (GUARD_COVERAGE_COMMAND, quality_commands),
    ):
        if tuple(shlex.split(command)) not in commands:
            errors.append(f"dependency audit is missing a blocking command: {command}")
    gate = jobs.get("security-gate")
    if (
        not isinstance(gate, dict)
        or gate.get("needs") != ["scan", "npm-audit"]
        or gate.get("if") != "${{ always() }}"
        or gate.get("continue-on-error") not in (None, False)
        or any(key in gate for key in ("env", "defaults", "strategy"))
        or gate.get("steps")
        != [
            {
                "name": "Require both dependency audit jobs",
                "shell": "bash",
                "env": {
                    "SCAN_RESULT": "${{ needs.scan.result }}",
                    "NODE_RESULT": "${{ needs.npm-audit.result }}",
                },
                "run": GATE_COMMAND + "\n",
            }
        ]
    ):
        errors.append("security-gate must require successful Python and npm audit jobs")
    return errors
