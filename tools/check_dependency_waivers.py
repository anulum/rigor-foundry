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
from pathlib import Path

from tools._repository import ROOT, redacted_guard_exit_code

WAIVER_PATH = Path(".github/dependency-waivers.json")
SECURITY_WORKFLOW = Path(".github/workflows/security.yml")
REQUIRED_COMMANDS = (
    "python -m tools.check_dependency_waivers",
    "python -m pip_audit -r requirements/ci.txt",
    "python -m pip_audit -r requirements/security.txt",
    "semgrep scan --error --config .semgrep.yml src tools",
)


def dependency_waiver_errors(root: Path = ROOT) -> list[str]:
    """Return errors if any audit waiver or unguarded scanner command remains."""
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
    for command in REQUIRED_COMMANDS:
        if command not in workflow:
            errors.append(f"security workflow is missing guarded command: {command}")
    if re.search(r"--ignore-vuln(?:\s|=|$)", workflow):
        errors.append("security workflow must not ignore vulnerability findings")
    return errors


def main() -> int:
    """Validate the absence of audit waivers and return a process exit code."""
    return redacted_guard_exit_code("Dependency-waiver guard", dependency_waiver_errors)


if __name__ == "__main__":
    raise SystemExit(main())
