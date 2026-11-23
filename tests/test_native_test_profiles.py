# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Separate native profile qualification
"""Inspect opaque source identities and refuse inadmissible profile inputs."""

from __future__ import annotations

from pathlib import Path

import pytest

from tools._repository import ROOT
from tools.native_test_profiles import (
    DARWIN_TEST_FILES,
    PRIMARY_TEST_HASHES,
    native_coverage_config,
    native_test_files,
)


def test_supported_windows_slot_has_two_disjoint_complete_profiles() -> None:
    """Keep all ordinary owners and exactly the separately required primary owners."""
    ordinary = native_test_files(ROOT, "win32", "3.12.13", hosted=True)
    primary = native_test_files(ROOT, "win32", "3.12.13", hosted=True, role="primary")
    complete = {p.relative_to(ROOT).as_posix() for p in ROOT.glob("tests/test_windows_*.py")}
    assert set(ordinary).isdisjoint(primary)
    assert set(ordinary) | set(primary) == complete
    assert primary == sorted(PRIMARY_TEST_HASHES)
    ordinary_config = native_coverage_config("ordinary")
    primary_config = native_coverage_config("primary")
    assert "patch = subprocess" in ordinary_config and "patch = subprocess" in primary_config
    assert all("*/" + name in ordinary_config for name in primary)
    assert "omit" not in primary_config


def test_only_the_macos_profile_admits_its_named_modules(tmp_path: Path) -> None:
    """Select the named macOS module only on darwin, and refuse a checkout without it.

    Parameters
    ----------
    tmp_path : Path
        Checkout holding one ordinary Windows module and no macOS module.
    """
    darwin = native_test_files(ROOT, "darwin", "3.12.13", hosted=True)
    windows = native_test_files(ROOT, "win32", "3.12.13", hosted=True)
    linux = native_test_files(ROOT, "linux", "3.12.13", hosted=True)
    assert darwin == sorted(darwin)
    assert set(darwin) - set(windows) == set(DARWIN_TEST_FILES)
    assert set(windows) <= set(darwin)
    assert linux == windows
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/test_windows_ordinary.py").write_text("", encoding="utf-8")
    assert native_test_files(tmp_path, "win32", "3.12.13", hosted=True) == [
        "tests/test_windows_ordinary.py"
    ]
    with pytest.raises(ValueError, match="darwin native test inventory is incomplete"):
        native_test_files(tmp_path, "darwin", "3.12.13", hosted=True)


@pytest.mark.parametrize(
    ("native_platform", "version", "hosted"),
    [
        ("linux", "3.12.13", True),
        ("darwin", "3.12.13", True),
        ("win32", "3.11.15", True),
        ("win32", "3.12.13", False),
    ],
)
def test_primary_role_is_refused_outside_its_admitted_slot(
    native_platform: str, version: str, hosted: bool
) -> None:
    """Refuse profile metadata before any reserved source content is inspected.

    Parameters
    ----------
    native_platform : str
        Unsupported primary platform.
    version : str
        Declared interpreter version.
    hosted : bool
        Declared producer venue.
    """
    with pytest.raises(ValueError, match=r"requires hosted Windows Python 3\.12"):
        native_test_files(ROOT, native_platform, version, hosted=hosted, role="primary")


@pytest.mark.parametrize("linked", [True, False])
def test_primary_role_refuses_linked_or_unrelated_actual_sources(
    tmp_path: Path, linked: bool
) -> None:
    """Reject invalid inventories made from ordinary sources without copying controls.

    Parameters
    ----------
    tmp_path : Path
        Invalid input allocation, never a claimed primary execution fixture.
    linked : bool
        Supply ordinary test aliases as links or unrelated ordinary source bytes.
    """
    actual = ROOT / "tests/test_windows_job_observation.py"
    for name in PRIMARY_TEST_HASHES:
        path = tmp_path / name
        path.parent.mkdir(exist_ok=True)
        if linked:
            path.symlink_to(actual)
        else:
            path.write_bytes(actual.read_bytes())
    with pytest.raises(ValueError, match=r"linked|identity differs"):
        native_test_files(tmp_path, "win32", "3.12.13", hosted=True, role="primary")
