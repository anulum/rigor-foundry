# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — installed version contract tests
"""Verify one package version identity across metadata, API, and CLI."""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path

import rigor_foundry
from rigor_foundry.version import __version__


def test_package_metadata_and_public_api_share_one_version() -> None:
    """Build metadata and the top-level package expose the version owner exactly."""
    root = Path(__file__).resolve().parents[1]
    with (root / "pyproject.toml").open("rb") as stream:
        metadata = tomllib.load(stream)
    assert metadata["project"]["version"] == __version__
    assert rigor_foundry.__version__ == __version__


def test_module_cli_reports_version_outside_source_checkout(tmp_path: Path) -> None:
    """The real module entry point reports the installed package version."""
    completed = subprocess.run(  # nosec B603
        [sys.executable, "-m", "rigor_foundry", "--version"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        shell=False,
        text=True,
    )
    assert completed.returncode == 0
    assert completed.stdout == f"rigor {__version__}\n"
    assert completed.stderr == ""
