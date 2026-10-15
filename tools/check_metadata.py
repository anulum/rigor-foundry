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

import yaml
from yaml.nodes import MappingNode, ScalarNode

from tools._repository import ROOT, redacted_guard_exit_code

EXPECTED_NAME = "rigor-foundry"
EXPECTED_LICENSE = "Apache-2.0"
EXPECTED_PYTHON = ">=3.11"
EXPECTED_REPOSITORY = "https://github.com/anulum/rigor-foundry"


def _package_version(path: Path) -> str | None:
    """Read one literal version assignment from the import-safe version owner."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    body = tree.body
    if ast.get_docstring(tree, clean=False) is not None:
        body = body[1:]
    if len(body) != 1:
        return None
    node = body[0]
    if not isinstance(node, ast.Assign) or len(node.targets) != 1:
        return None
    target = node.targets[0]
    if not isinstance(target, ast.Name) or target.id != "__version__":
        return None
    if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
        return None
    return node.value.value


def _citation_fields(text: str) -> dict[str, str]:
    """Read citation identity strings from a YAML mapping with unique field names."""
    document = yaml.compose(text, Loader=yaml.SafeLoader)
    if not isinstance(document, MappingNode) or document.tag != "tag:yaml.org,2002:map":
        raise ValueError("CITATION.cff must contain a YAML mapping")
    fields: dict[str, str] = {}
    seen: set[str] = set()
    for key, value in document.value:
        if not isinstance(key, ScalarNode) or key.tag != "tag:yaml.org,2002:str":
            raise ValueError("CITATION.cff field names must be strings")
        if key.value in seen:
            raise ValueError("CITATION.cff field names must be unique")
        seen.add(key.value)
        if key.value not in {"version", "license", "repository-code"}:
            continue
        if not isinstance(value, ScalarNode) or value.tag != "tag:yaml.org,2002:str":
            raise ValueError("CITATION.cff identity fields must be strings")
        fields[key.value] = value.value
    return fields


def metadata_errors(root: Path = ROOT) -> list[str]:
    """Return cross-file metadata inconsistencies without executing package code.

    Parameters
    ----------
    root:
        Repository containing the package, citation, archive and licence files.
        The version owner must contain only an optional module docstring and
        one assignment of a string literal to the sole target ``__version__``.
        Citation metadata must be one YAML mapping with unique string field
        names and string values for version, licence and repository identity.

    Returns
    -------
    list[str]
        Metadata inconsistencies, empty when all repository identities agree.

    Raises
    ------
    OSError
        If a required file cannot be read.
    ValueError
        If TOML or JSON metadata cannot be decoded, or citation fields have
        ambiguous names or invalid types.
    yaml.YAMLError
        If citation metadata is not a single valid YAML document.
    SyntaxError
        If the version owner is not valid Python syntax.
    """
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

    package_version = _package_version(root / "src" / "rigor_foundry" / "version.py")
    if package_version != version:
        errors.append(f"package version {package_version!r} does not match {version!r}")

    citation = _citation_fields((root / "CITATION.cff").read_text(encoding="utf-8"))
    if citation.get("version") != version:
        errors.append("CITATION.cff version does not match pyproject.toml")
    if citation.get("license") != EXPECTED_LICENSE:
        errors.append("CITATION.cff does not declare Apache-2.0")
    if citation.get("repository-code") != EXPECTED_REPOSITORY:
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
    """Validate distribution metadata and print fixed process status.

    Returns
    -------
    int
        Zero for consistent metadata; one for findings or unreadable inputs.
    """
    return redacted_guard_exit_code("Metadata guard", metadata_errors)


if __name__ == "__main__":
    raise SystemExit(main())
