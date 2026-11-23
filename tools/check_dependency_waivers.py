# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Dependency-waiver guard
"""Refuse security-audit exceptions after the patched scanner upgrade."""

from __future__ import annotations

import json
import re
import shlex
from pathlib import Path

import yaml

from tools._repository import ROOT, redacted_guard_exit_code
from tools.check_dependency_audits import SEMGREP_IMAGE, dependency_audit_errors

WAIVER_PATH = Path(".github/dependency-waivers.json")
SECURITY_WORKFLOW = Path(".github/workflows/security.yml")
REQUIRED_COMMANDS = (
    "python -m tools.check_dependency_waivers",
    "python -m tools.check_semgrep_isolation",
    "python -m pytest tests/test_semgrep_runtime.py --cov=test_semgrep_runtime --cov-branch --cov-report=term-missing --cov-fail-under=100",
    "python -m pip_audit -r requirements/ci.txt --require-hashes --disable-pip --strict",
    "python -m pip_audit -r requirements/security.txt --require-hashes --disable-pip --strict",
)
# The repository policy scan runs offline from the digest-pinned image: no network, a
# read-only root and workspace, an explicit finite stack and no metrics or version check.
SEMGREP_SCAN_PREFIX = tuple(
    shlex.split(
        "docker run --rm --network none --read-only --tmpfs /tmp:rw,size=256m "
        '--ulimit stack=8388608:8388608 --user "$(id -u):$(id -g)" --env HOME=/tmp '
        "--env SEMGREP_SEND_METRICS=off --env SEMGREP_ENABLE_VERSION_CHECK=0 "
        '--volume "$PWD:/src:ro" --workdir /src'
    )
)
SEMGREP_SCAN_SUFFIX = tuple(
    shlex.split("semgrep scan --error --metrics off --config .semgrep.yml src tools")
)


def _semgrep_policy_scan(command: tuple[str, ...]) -> bool:
    prefix, suffix = len(SEMGREP_SCAN_PREFIX), len(SEMGREP_SCAN_SUFFIX)
    return (
        len(command) == prefix + 1 + suffix
        and command[:prefix] == SEMGREP_SCAN_PREFIX
        and command[prefix + 1 :] == SEMGREP_SCAN_SUFFIX
        and SEMGREP_IMAGE.fullmatch(command[prefix]) is not None
    )


def dependency_waiver_errors(root: Path = ROOT) -> list[str]:
    """Check audit waivers, scanner commands and complete lock enrolment.

    Parameters
    ----------
    root:
        Actual repository containing the waiver document, dependency locks and CI.

    Returns
    -------
    list[str]
        Findings for malformed documents, exceptions, disabled scanners or missing
        blocking audit enrolment. Advisory queries are performed by CI scanners.
    """
    errors: list[str] = []
    try:
        document = json.loads((root / WAIVER_PATH).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"cannot read dependency waivers: {error}"]
    if not isinstance(document, dict):
        return ["dependency-waiver document must be a JSON object"]
    if set(document) != {"schema_version", "waivers"}:
        errors.append("dependency-waiver document must contain only schema_version and waivers")
    if document.get("schema_version") != "1.0":
        errors.append("dependency-waiver schema_version must be '1.0'")
    waivers = document.get("waivers")
    if not isinstance(waivers, list):
        errors.append("dependency-waiver set must be a list")
    elif waivers:
        errors.append("dependency-waiver set must be empty after scanner remediation")

    try:
        workflow = (root / SECURITY_WORKFLOW).read_text(encoding="utf-8")
    except OSError as error:
        return [*errors, f"cannot read security workflow: {error}"]
    try:
        parsed = yaml.safe_load(workflow)
    except yaml.YAMLError as error:
        return [*errors, f"cannot parse security workflow: {error}"]
    jobs = parsed.get("jobs") if isinstance(parsed, dict) else None
    scan = jobs.get("scan") if isinstance(jobs, dict) else None
    steps = scan.get("steps") if isinstance(scan, dict) else None
    if not isinstance(scan, dict) or not isinstance(steps, list):
        return [*errors, "security workflow scan job must contain steps"]
    if "if" in scan or scan.get("continue-on-error") not in (None, False):
        errors.append("security workflow scan job must be unconditional and fail-closed")
    commands: list[tuple[str, ...]] = []
    for step in steps:
        if (
            not isinstance(step, dict)
            or not isinstance(step.get("run"), str)
            or "if" in step
            or step.get("continue-on-error") not in (None, False)
        ):
            continue
        try:
            commands.append(tuple(shlex.split(step["run"], comments=True)))
        except ValueError as error:
            errors.append(f"cannot parse security workflow run step: {error}")
    for command in REQUIRED_COMMANDS:
        if tuple(shlex.split(command)) not in commands:
            errors.append(f"security workflow is missing guarded command: {command}")
    if not any(_semgrep_policy_scan(command) for command in commands):
        errors.append("security workflow is missing the digest-pinned Semgrep policy scan")
    if re.search(r"--ignore-vuln(?:\s|=|$)", workflow):
        errors.append("security workflow must not ignore vulnerability findings")
    return [*errors, *dependency_audit_errors(root)]


def main() -> int:
    """Validate the absence of audit waivers and return a process exit code."""
    return redacted_guard_exit_code("Dependency-waiver guard", dependency_waiver_errors)


if __name__ == "__main__":
    raise SystemExit(main())
