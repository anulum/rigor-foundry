# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Distribution metadata guard tests
"""Verify package, citation, archive, and licence metadata agree."""

from __future__ import annotations

import shutil
from pathlib import Path

from tools._repository import ROOT
from tools.check_metadata import metadata_errors


def test_release_metadata_is_consistent_across_public_surfaces() -> None:
    """The production repository has one package identity and version."""
    assert metadata_errors() == []


def test_release_metadata_rejects_drift_in_the_version_owner(tmp_path: Path) -> None:
    """The public metadata guard binds releases to the single version module."""
    repository = tmp_path / "repository"
    for relative in (
        ".zenodo.json",
        "CITATION.cff",
        "LICENSE",
        "pyproject.toml",
        "src/rigor_foundry/version.py",
    ):
        source = ROOT / relative
        destination = repository / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    version = repository / "src/rigor_foundry/version.py"
    version.write_text(
        version.read_text(encoding="utf-8").replace('"0.1.1"', '"0.1.2"'),
        encoding="utf-8",
    )

    assert metadata_errors(repository) == ["package version '0.1.2' does not match '0.1.1'"]
