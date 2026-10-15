# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Release tag and package version guard
"""Reject release tags that do not exactly match package metadata."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def release_tag_errors(tag: str, root: Path = _REPOSITORY_ROOT) -> list[str]:
    """Compare a release tag with the declared three-component version.

    Parameters
    ----------
    tag:
        Exact tag name, including its required ``v`` prefix.
    root:
        Repository containing ``pyproject.toml``. Its project version must be
        a string of three dot-separated decimal components.

    Returns
    -------
    list[str]
        Version-shape or tag-mismatch findings, empty for an exact match.

    Raises
    ------
    OSError
        If the project manifest cannot be read.
    ValueError
        If the manifest is not valid UTF-8 TOML.
    """
    with (root / "pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream).get("project")
    version = project.get("version") if isinstance(project, dict) else None
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        return ["project.version must be a three-component release version"]
    expected = f"v{version}"
    return [] if tag == expected else [f"release tag {tag!r} does not match {expected!r}"]


def main(argv: list[str]) -> int:
    """Validate one workflow tag without importing installed dependencies.

    Parameters
    ----------
    argv:
        Command arguments containing exactly one release tag.

    Returns
    -------
    int
        Zero for an exact valid match, one for invalid or unreadable metadata
        or a mismatch, and two for an incorrect argument count.
    """
    if len(argv) != 1:
        print("usage: python -m tools.check_release_tag <tag>")
        return 2
    try:
        errors = release_tag_errors(argv[0])
    except (OSError, ValueError):
        print("Release tag guard failed; project metadata is unavailable or invalid.")
        return 1
    if errors:
        print(errors[0])
        return 1
    print("Release tag guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
