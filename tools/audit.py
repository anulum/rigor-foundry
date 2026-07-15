# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Repository conformance audit
"""Audit the repository's own portable governance and authoring boundaries."""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path

from tools._repository import ROOT, read_text, run, visible_files
from tools.check_action_pins import action_pin_errors
from tools.check_data_boundary import data_boundary_errors
from tools.check_dependency_waivers import dependency_waiver_errors
from tools.check_headers import header_errors
from tools.check_metadata import metadata_errors
from tools.check_secrets import secret_errors

EXPECTED_ORIGIN = "https://github.com/anulum/rigor-foundry.git"
REQUIRED_PATHS = (
    ".github/CODEOWNERS",
    ".github/dependency-waivers.json",
    ".github/dependabot.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/pull_request_template.md",
    ".github/release.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/codeql.yml",
    ".github/workflows/docker.yml",
    ".github/workflows/docs.yml",
    ".github/workflows/pre-commit.yml",
    ".github/workflows/publish.yml",
    ".github/workflows/release.yml",
    ".github/workflows/scorecard.yml",
    ".github/workflows/security.yml",
    ".github/workflows/stale.yml",
    ".pre-commit-config.yaml",
    "ARCHITECTURE.md",
    "CHANGELOG.md",
    "CITATION.cff",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "Dockerfile",
    "GOVERNANCE.md",
    "LICENSE",
    "Makefile",
    "README.md",
    "REUSE.toml",
    "rigor-foundry-policy.json",
    "SECURITY.md",
    "SUPPORT.md",
    "VALIDATION.md",
    "docker-compose.yml",
    "mkdocs.yml",
    "pyproject.toml",
    "requirements/build.txt",
    "requirements/ci.txt",
    "requirements/runtime.txt",
    "requirements/security.txt",
    "requirements/test.txt",
    "tools/check_dependency_waivers.py",
)
FORBIDDEN_PUBLIC_PARTS = {".coordination", ".rigor"}
FORBIDDEN_PUBLIC_TERMS = tuple(
    "".join(parts)
    for parts in (
        ("SC", chr(80), chr(78), "-QUANTUM-CONTROL"),
        ("tools/", "repository_audit"),
        ("AGPL-", "3.0"),
        ("Commercial ", "license available"),
    )
)
FORBIDDEN_IDENTITIES = (
    "co" + "dex",
    "open" + "ai",
    "chat" + "gpt",
    "clau" + "de",
    "anthro" + "pic",
    "gr" + "ok",
    "x" + "ai",
)
FORBIDDEN_QUALITY_LABELS = tuple(
    "".join(parts) for parts in (("el", "ite"), ("sup", "erior"), ("str", "ong"), ("eta", "lon"))
)


def audit_errors(root: Path = ROOT, *, strict_authoring: bool = False) -> list[str]:
    """Return repository conformance failures.

    Parameters
    ----------
    root:
        Worktree to validate.
    strict_authoring:
        Also enforce local-authoring branch, filesystem, and virtualenv rules.
    """
    errors: list[str] = []
    visible = visible_files(root)
    visible_set = {path.as_posix() for path in visible}
    for required in REQUIRED_PATHS:
        if required not in visible_set:
            errors.append(f"missing required repository surface: {required}")
    for path in visible:
        if FORBIDDEN_PUBLIC_PARTS.intersection(path.parts):
            errors.append(f"internal state is Git-visible: {path.as_posix()}")
        text = read_text(path, root)
        if text is None or path == Path("tools/audit.py"):
            continue
        for term in FORBIDDEN_PUBLIC_TERMS:
            if term in text:
                errors.append(f"legacy or incompatible public term in {path.as_posix()}: {term}")
        lowered = text.casefold()
        for identity in FORBIDDEN_IDENTITIES:
            if re.search(rf"\b{re.escape(identity)}\b", lowered):
                errors.append(f"vendor identity is public in {path.as_posix()}")
        for label in FORBIDDEN_QUALITY_LABELS:
            if re.search(rf"\b{re.escape(label)}\b", lowered):
                errors.append(f"internal quality label is public in {path.as_posix()}")

    origin = run("git", "remote", "get-url", "origin", cwd=root)
    if origin.returncode != 0:
        errors.append("canonical origin remote is missing")
    else:
        origin_url = origin.stdout.strip().removesuffix(".git")
        if not origin_url.endswith("/rigor-foundry"):
            errors.append("origin does not identify a rigor-foundry repository")
        if strict_authoring and origin.stdout.strip() != EXPECTED_ORIGIN:
            errors.append(f"strict authoring requires origin {EXPECTED_ORIGIN!r}")

    virtualenv = root / ".venv"
    if virtualenv.is_symlink():
        errors.append(".venv must be a physical directory, not a symlink")
    if strict_authoring:
        branch = run("git", "branch", "--show-current", cwd=root)
        if branch.returncode != 0 or branch.stdout.strip() != "main":
            errors.append("strict authoring requires the main branch")
        filesystem = run("findmnt", "-T", str(root), "-n", "-o", "FSTYPE", cwd=root)
        if filesystem.returncode != 0 or filesystem.stdout.strip() != "ext4":
            errors.append("strict authoring requires the Samsung ext4 worktree")
        if virtualenv.exists() and os.stat(virtualenv).st_dev != os.stat(root).st_dev:
            errors.append(".venv must reside on the same filesystem as the worktree")

    errors.extend(header_errors(root))
    errors.extend(action_pin_errors(root))
    errors.extend(metadata_errors(root))
    errors.extend(secret_errors(root))
    errors.extend(data_boundary_errors(root))
    errors.extend(dependency_waiver_errors(root))
    return errors


def main() -> int:
    """Run the repository audit and return a process exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict-authoring", action="store_true")
    arguments = parser.parse_args()
    errors = audit_errors(strict_authoring=arguments.strict_authoring)
    if errors:
        print("Repository audit failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("Repository audit passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
