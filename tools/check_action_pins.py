# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — GitHub Actions supply-chain guard
"""Reject mutable actions and unsafe workflow-level control surfaces."""

from __future__ import annotations

import re
from pathlib import Path

from tools._repository import ROOT, redacted_guard_exit_code

ACTION_PATTERN = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
CHECKOUT_PREFIX = "actions/checkout@"


def workflow_errors(path: Path) -> list[str]:
    """Return supply-chain and permission failures for one workflow."""
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    if "pull_request_target:" in text:
        errors.append("pull_request_target is forbidden")
    if "permissions:" not in text:
        errors.append("explicit permissions block is required")
    if "concurrency:" not in text:
        errors.append("concurrency control is required")
    if re.search(r"^\s*permissions:\s*write-all\s*$", text, re.MULTILINE):
        errors.append("write-all permissions are forbidden")

    lines = text.splitlines()
    for match in ACTION_PATTERN.finditer(text):
        reference = match.group(1)
        if reference.startswith("./"):
            continue
        if "@" not in reference:
            errors.append(f"action has no immutable revision: {reference}")
            continue
        action, revision = reference.rsplit("@", 1)
        if not SHA_PATTERN.fullmatch(revision):
            errors.append(f"action is not pinned to a full commit: {action}")

    for index, line in enumerate(lines):
        if f"uses: {CHECKOUT_PREFIX}" not in line:
            continue
        following = "\n".join(lines[index + 1 : index + 8])
        if not re.search(r"^\s*persist-credentials:\s*false\s*$", following, re.MULTILINE):
            errors.append(f"line {index + 1}: checkout must disable persisted credentials")
    return errors


def action_pin_errors(root: Path = ROOT) -> list[str]:
    """Return deterministic failures across all GitHub workflows."""
    workflows = sorted((root / ".github" / "workflows").glob("*.yml"))
    if not workflows:
        return [".github/workflows: no YAML workflows found"]
    errors: list[str] = []
    for workflow in workflows:
        for error in workflow_errors(workflow):
            errors.append(f"{workflow.relative_to(root).as_posix()}: {error}")
    return errors


def main() -> int:
    """Validate workflows and return a process exit code."""
    errors = action_pin_errors()
    return redacted_guard_exit_code("Action pin guard", errors)


if __name__ == "__main__":
    raise SystemExit(main())
