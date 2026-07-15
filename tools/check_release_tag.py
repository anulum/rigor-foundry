# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Release tag and package version guard
"""Reject release tags that do not exactly match package metadata."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

from tools._repository import ROOT


def release_tag_errors(tag: str, root: Path = ROOT) -> list[str]:
    """Return an error unless ``tag`` is exactly ``v<project.version>``."""
    with (root / "pyproject.toml").open("rb") as stream:
        version = tomllib.load(stream)["project"]["version"]
    expected = f"v{version}"
    return [] if tag == expected else [f"release tag {tag!r} does not match {expected!r}"]


def main(argv: list[str] | None = None) -> int:
    """Validate one tag supplied by the release workflow."""
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        print("usage: python -m tools.check_release_tag <tag>")
        return 2
    errors = release_tag_errors(arguments[0])
    if errors:
        print(errors[0])
        return 1
    print("Release tag guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
