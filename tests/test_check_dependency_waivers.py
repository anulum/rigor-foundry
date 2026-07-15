# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Dependency-waiver guard tests
"""Verify the security-tool exception is exact, bounded, and fail closed."""

from datetime import date
from pathlib import Path
from shutil import copy2

from tools._repository import ROOT
from tools.check_dependency_waivers import dependency_waiver_errors


def _waiver_root(tmp_path: Path) -> Path:
    for relative in (
        ".github/dependency-waivers.json",
        ".github/workflows/security.yml",
        "requirements/security.txt",
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        copy2(ROOT / relative, target)
    return tmp_path


def test_repository_dependency_waiver_is_current_and_exact() -> None:
    """The checked-in exception matches its lock and CI enforcement."""
    assert dependency_waiver_errors(today=date(2026, 7, 15)) == []


def test_dependency_waiver_expires_fail_closed(tmp_path: Path) -> None:
    """The expiry date itself is no longer an authorised day."""
    root = _waiver_root(tmp_path)
    errors = dependency_waiver_errors(root, today=date(2026, 8, 14))
    assert "dependency waiver PYSEC-2026-2132 is expired" in errors


def test_dependency_waiver_must_match_locked_version(tmp_path: Path) -> None:
    """A resolver change invalidates the exception instead of widening it."""
    root = _waiver_root(tmp_path)
    lock = root / "requirements/security.txt"
    lock.write_text(
        lock.read_text(encoding="utf-8").replace("click==8.1.8", "click==8.1.7"), encoding="utf-8"
    )
    errors = dependency_waiver_errors(root, today=date(2026, 7, 15))
    assert "dependency waiver version does not match the security lock" in errors


def test_dependency_waiver_requires_explicit_ci_binding(tmp_path: Path) -> None:
    """Removing the exact pip-audit suppression makes the guard fail."""
    root = _waiver_root(tmp_path)
    workflow = root / ".github/workflows/security.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace("--ignore-vuln PYSEC-2026-2132", ""),
        encoding="utf-8",
    )
    errors = dependency_waiver_errors(root, today=date(2026, 7, 15))
    assert any("--ignore-vuln PYSEC-2026-2132" in error for error in errors)


def test_dependency_waiver_requires_canonical_advisory_url(tmp_path: Path) -> None:
    """A dead advisory alias cannot remain accepted as source evidence."""
    root = _waiver_root(tmp_path)
    waiver = root / ".github/dependency-waivers.json"
    waiver.write_text(
        waiver.read_text(encoding="utf-8").replace(
            "https://github.com/tsigouris007/security-advisories/security/advisories/"
            "GHSA-47fr-3ffg-hgmw",
            "https://github.com/advisories/GHSA-47fr-3ffg-hgmw",
        ),
        encoding="utf-8",
    )
    errors = dependency_waiver_errors(root, today=date(2026, 7, 15))
    assert any("dependency waiver advisory_url must be" in error for error in errors)
