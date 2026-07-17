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
SETUP_PYTHON_PREFIX = "actions/setup-python@"
PYTHON_VERSION_PATTERN = re.compile(r"^3\.\d+\.\d+$")
DOCKER_IMAGE_PATTERN = re.compile(r'^\s*image:\s*"?(docker://[^"\s]+)"?\s*$', re.MULTILINE)
OCI_DIGEST_PATTERN = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")


def _setup_python_version_errors(text: str) -> list[str]:
    """Return failures for mutable Python toolchain selectors."""
    errors: list[str] = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if f"uses: {SETUP_PYTHON_PREFIX}" not in line:
            continue
        following = lines[index + 1 : index + 10]
        selector = next(
            (
                candidate.split(":", 1)[1].strip()
                for candidate in following
                if re.match(r"^\s*python-version:\s*", candidate)
            ),
            None,
        )
        if selector is None:
            errors.append(f"line {index + 1}: setup-python requires an exact version")
            continue
        if selector == "${{ matrix.python-version }}":
            continue
        version = selector.strip("'\"")
        if not PYTHON_VERSION_PATTERN.fullmatch(version):
            errors.append(f"line {index + 1}: setup-python version must include a patch release")

    for match in re.finditer(r"^\s*python-version:\s*\[([^]]+)\]\s*$", text, re.MULTILINE):
        versions = [item.strip().strip("'\"") for item in match.group(1).split(",")]
        if any(not PYTHON_VERSION_PATTERN.fullmatch(version) for version in versions):
            line_number = text.count("\n", 0, match.start()) + 1
            errors.append(
                f"line {line_number}: Python matrix versions must include patch releases"
            )
    return errors


def _reference_errors(text: str) -> list[str]:
    """Return immutable-revision failures for external action references."""
    errors: list[str] = []
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
    return errors


def _top_level_permission_errors(text: str) -> list[str]:
    """Return failures for write authority granted to every workflow job."""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line != "permissions:":
            continue
        errors: list[str] = []
        for candidate in lines[index + 1 :]:
            if candidate and not candidate.startswith((" ", "\t", "#")):
                break
            if re.match(r"^\s+[A-Za-z-]+:\s*write\s*$", candidate):
                errors.append("write permissions must be scoped to an explicit job")
        return errors
    return []


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
    if re.search(r"^\s*runs-on:\s*ubuntu-latest\s*$", text, re.MULTILINE):
        errors.append("Ubuntu runners must use an exact release label")

    lines = text.splitlines()
    errors.extend(_reference_errors(text))
    errors.extend(_setup_python_version_errors(text))
    errors.extend(_top_level_permission_errors(text))

    for index, line in enumerate(lines):
        if f"uses: {CHECKOUT_PREFIX}" not in line:
            continue
        following = "\n".join(lines[index + 1 : index + 8])
        if not re.search(r"^\s*persist-credentials:\s*false\s*$", following, re.MULTILINE):
            errors.append(f"line {index + 1}: checkout must disable persisted credentials")
    return errors


def action_metadata_errors(path: Path) -> list[str]:
    """Return supply-chain and shell-boundary failures for a composite action."""
    text = path.read_text(encoding="utf-8")
    errors = _reference_errors(text)
    errors.extend(_setup_python_version_errors(text))
    composite = re.search(r"^\s+using:\s*composite\s*$", text, re.MULTILINE)
    docker = re.search(r"^\s+using:\s*docker\s*$", text, re.MULTILINE)
    if not composite and not docker:
        errors.append("action must use the composite or Docker runtime")
    if docker:
        images = DOCKER_IMAGE_PATTERN.findall(text)
        if len(images) != 1 or not OCI_DIGEST_PATTERN.fullmatch(images[0]):
            errors.append("Docker action image must use one immutable OCI digest")
    for line_number, line in enumerate(text.splitlines(), start=1):
        if "${{ inputs." not in line:
            continue
        if re.match(r"^\s+(?:value|RF_[A-Z0-9_]+):\s*\$\{\{ inputs\.", line):
            continue
        errors.append(f"line {line_number}: action inputs must enter shell commands through env")
    return errors


def action_pin_errors(root: Path = ROOT) -> list[str]:
    """Return deterministic failures across workflows and action metadata."""
    workflows = sorted(
        {
            *(root / ".github" / "workflows").glob("*.yml"),
            *(root / ".github" / "workflows").glob("*.yaml"),
        }
    )
    if not workflows:
        return [".github/workflows: no YAML workflows found"]
    errors: list[str] = []
    for workflow in workflows:
        for error in workflow_errors(workflow):
            errors.append(f"{workflow.relative_to(root).as_posix()}: {error}")
    action_files = sorted(
        {
            *root.glob("action.yml"),
            *root.glob("action.yaml"),
            *(root / ".github" / "actions").glob("**/action.yml"),
            *(root / ".github" / "actions").glob("**/action.yaml"),
        }
    )
    for action in action_files:
        for error in action_metadata_errors(action):
            errors.append(f"{action.relative_to(root).as_posix()}: {error}")
    return errors


def main() -> int:
    """Validate workflows and return a process exit code."""
    return redacted_guard_exit_code("Action pin guard", action_pin_errors)


if __name__ == "__main__":
    raise SystemExit(main())
