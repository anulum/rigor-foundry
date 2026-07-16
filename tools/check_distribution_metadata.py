# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Built distribution metadata truth guard
"""Reject built wheels whose public metadata contradicts release availability."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path
from typing import cast
from zipfile import BadZipFile, ZipFile

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_EXPECTED_NAME = "rigor-foundry"
_PYPI_URL = "https://pypi.org/project/rigor-foundry/"
_FALSE_STATUS_PATTERNS = (
    ("not published to PyPI", re.compile(r"\bnot published to pypi\b")),
    ("remains unreleased", re.compile(r"\bremains unreleased\b")),
    (
        "no valid pip installation",
        re.compile(r"\bno valid [`'\"]?pip install rigor-foundry[`'\"]? instruction\b"),
    ),
    (
        "unreleased publication list",
        re.compile(r"\bnot been .*?published to pypi, or released\b"),
    ),
)


def _project_version(root: Path) -> str:
    with (root / "pyproject.toml").open("rb") as stream:
        configuration = tomllib.load(stream)
    project_value = configuration.get("project")
    if not isinstance(project_value, dict):
        raise ValueError("pyproject.toml has no project table")
    project = cast(dict[str, object], project_value)
    version = project.get("version")
    if not isinstance(version, str):
        raise ValueError("pyproject.toml project.version is not a string")
    return version


def _metadata_field(metadata: str, field: str) -> str | None:
    match = re.search(rf"^{re.escape(field)}:\s*(.+)$", metadata, re.MULTILINE)
    return match.group(1).strip() if match else None


def distribution_metadata_errors(
    wheel: Path,
    root: Path = _REPOSITORY_ROOT,
) -> list[str]:
    """Return contradictions in one built wheel's public metadata.

    Parameters
    ----------
    wheel:
        Wheel archive produced from the current release tree.
    root:
        Repository containing the authoritative package version.

    Returns
    -------
    list[str]
        Deterministic validation failures. An empty list means the wheel binds
        the current package identity and avoids pre-publication-only status text.
    """
    if not wheel.is_file():
        return [f"wheel does not exist: {wheel}"]
    try:
        with ZipFile(wheel) as archive:
            metadata_paths = [
                name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
            ]
            if len(metadata_paths) != 1:
                return [
                    "wheel must contain exactly one .dist-info/METADATA file, "
                    f"found {len(metadata_paths)}"
                ]
            metadata_bytes = archive.read(metadata_paths[0])
    except (BadZipFile, OSError, KeyError) as error:
        return [f"wheel metadata cannot be read: {error}"]

    try:
        metadata = metadata_bytes.decode("utf-8").replace("\r\n", "\n")
    except UnicodeDecodeError as error:
        return [f"wheel metadata is not UTF-8: {error}"]

    errors: list[str] = []
    try:
        version = _project_version(root)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        return [f"project version cannot be read: {error}"]
    if _metadata_field(metadata, "Name") != _EXPECTED_NAME:
        errors.append("wheel Name does not match rigor-foundry")
    if _metadata_field(metadata, "Version") != version:
        errors.append(f"wheel Version does not match {version}")

    _, separator, description = metadata.partition("\n\n")
    if not separator:
        errors.append("wheel METADATA has no long description")
        return errors
    normalised_description = re.sub(r"\s+", " ", description.casefold())
    for label, pattern in _FALSE_STATUS_PATTERNS:
        if pattern.search(normalised_description):
            errors.append(f"wheel description contains pre-publication status: {label}")

    install_command = f'python -m pip install "rigor-foundry=={version}"'
    if install_command not in description:
        errors.append(f"wheel description is missing exact install command: {install_command}")
    if _PYPI_URL not in description:
        errors.append(f"wheel description is missing public registry link: {_PYPI_URL}")
    return errors


def main(argv: list[str]) -> int:
    """Validate one built wheel supplied by release automation."""
    if len(argv) != 1:
        print("usage: python -m tools.check_distribution_metadata <wheel>")
        return 2
    errors = distribution_metadata_errors(Path(argv[0]))
    if errors:
        print("Distribution metadata guard failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("Distribution metadata guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
