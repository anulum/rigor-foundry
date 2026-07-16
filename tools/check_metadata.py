# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Distribution metadata guard
"""Cross-check package, citation, archival, and licence metadata."""

from __future__ import annotations

import ast
import json
import re
import tomllib
from pathlib import Path
from typing import Any

from tools._repository import ROOT, redacted_guard_exit_code

EXPECTED_NAME = "rigor-foundry"
EXPECTED_LICENSE = "Apache-2.0"
EXPECTED_PYTHON = ">=3.11"
EXPECTED_REPOSITORY = "https://github.com/anulum/rigor-foundry"


def _package_version(path: Path) -> str | None:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        ):
            continue
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            return node.value.value
    return None


def _citation_value(text: str, key: str) -> str | None:
    match = re.search(rf"^{re.escape(key)}:\s*[\"']?([^\"'\n]+)", text, re.MULTILINE)
    return match.group(1).strip() if match else None


def metadata_errors(root: Path = ROOT) -> list[str]:
    """Return cross-file metadata inconsistencies."""
    errors: list[str] = []
    data: dict[str, Any]
    with (root / "pyproject.toml").open("rb") as stream:
        data = tomllib.load(stream)
    project = data.get("project", {})
    version = project.get("version")
    expected = {
        "project.name": (project.get("name"), EXPECTED_NAME),
        "project.license": (project.get("license"), EXPECTED_LICENSE),
        "project.requires-python": (project.get("requires-python"), EXPECTED_PYTHON),
    }
    for field, (actual, required) in expected.items():
        if actual != required:
            errors.append(f"{field} is {actual!r}, expected {required!r}")
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        errors.append("project.version must be a three-component release version")
        version = None

    urls = project.get("urls", {})
    if urls.get("Homepage") != EXPECTED_REPOSITORY:
        errors.append("project.urls.Homepage does not match the canonical repository")
    classifiers = set(project.get("classifiers", []))
    for minor in ("3.11", "3.12", "3.13"):
        classifier = f"Programming Language :: Python :: {minor}"
        if classifier not in classifiers:
            errors.append(f"missing classifier: {classifier}")

    package_version = _package_version(root / "src" / "rigor_foundry" / "__init__.py")
    if package_version != version:
        errors.append(f"package version {package_version!r} does not match {version!r}")

    citation = (root / "CITATION.cff").read_text(encoding="utf-8")
    if _citation_value(citation, "version") != version:
        errors.append("CITATION.cff version does not match pyproject.toml")
    if _citation_value(citation, "license") != EXPECTED_LICENSE:
        errors.append("CITATION.cff does not declare Apache-2.0")
    if _citation_value(citation, "repository-code") != EXPECTED_REPOSITORY:
        errors.append("CITATION.cff repository does not match the canonical repository")

    archive = json.loads((root / ".zenodo.json").read_text(encoding="utf-8"))
    if archive.get("version") != version:
        errors.append(".zenodo.json version does not match pyproject.toml")
    if archive.get("license") != "apache-2.0":
        errors.append(".zenodo.json does not declare the Zenodo Apache-2.0 identifier")

    licence = (root / "LICENSE").read_text(encoding="utf-8")
    if not licence.lstrip().startswith("Apache License") or "Version 2.0" not in licence[:200]:
        errors.append("LICENSE is not the canonical Apache-2.0 licence text")
    return errors


def main() -> int:
    """Validate distribution metadata and return a process exit code."""
    return redacted_guard_exit_code("Metadata guard", metadata_errors)


if __name__ == "__main__":
    raise SystemExit(main())
