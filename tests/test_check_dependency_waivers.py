# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Dependency-waiver guard tests
"""Verify the security-tool exception is exact, bounded, and fail closed."""

import json
from datetime import date
from pathlib import Path
from shutil import copy2

import pytest

from tools._repository import ROOT
from tools.check_dependency_waivers import dependency_waiver_errors, main


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


def _waiver_document(root: Path) -> dict[str, object]:
    document = json.loads((root / ".github/dependency-waivers.json").read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _first_mcp_waiver(document: dict[str, object]) -> dict[str, object]:
    waivers = document["waivers"]
    assert isinstance(waivers, list)
    waiver = waivers[1]
    assert isinstance(waiver, dict)
    return waiver


def _write_waiver_document(root: Path, document: dict[str, object]) -> None:
    (root / ".github/dependency-waivers.json").write_text(
        json.dumps(document),
        encoding="utf-8",
    )


def test_repository_dependency_waiver_is_current_and_exact() -> None:
    """The checked-in exception matches its lock and CI enforcement."""
    assert dependency_waiver_errors(today=date(2026, 7, 16)) == []
    assert main() == 0


def test_dependency_waiver_expires_fail_closed(tmp_path: Path) -> None:
    """The expiry date itself is no longer an authorised day."""
    root = _waiver_root(tmp_path)
    errors = dependency_waiver_errors(root, today=date(2026, 8, 14))
    assert "dependency waiver PYSEC-2026-2132 is expired" in errors


@pytest.mark.parametrize(
    ("locked", "replacement", "advisory_id"),
    (
        ("click==8.1.8", "click==8.1.7", "PYSEC-2026-2132"),
        ("mcp==1.23.3", "mcp==1.23.2", "CVE-2026-52869"),
    ),
)
def test_dependency_waiver_must_match_locked_version(
    tmp_path: Path,
    locked: str,
    replacement: str,
    advisory_id: str,
) -> None:
    """A resolver change invalidates the exception instead of widening it."""
    root = _waiver_root(tmp_path)
    lock = root / "requirements/security.txt"
    lock.write_text(
        lock.read_text(encoding="utf-8").replace(locked, replacement),
        encoding="utf-8",
    )
    errors = dependency_waiver_errors(root, today=date(2026, 7, 16))
    assert f"dependency waiver {advisory_id} version does not match the security lock" in errors


@pytest.mark.parametrize(
    "advisory_id",
    (
        "PYSEC-2026-2132",
        "CVE-2026-52869",
        "CVE-2026-52870",
        "CVE-2026-59950",
    ),
)
def test_dependency_waiver_requires_explicit_ci_binding(tmp_path: Path, advisory_id: str) -> None:
    """Removing the exact pip-audit suppression makes the guard fail."""
    root = _waiver_root(tmp_path)
    workflow = root / ".github/workflows/security.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(f"--ignore-vuln {advisory_id}", ""),
        encoding="utf-8",
    )
    errors = dependency_waiver_errors(root, today=date(2026, 7, 16))
    assert any(f"--ignore-vuln {advisory_id}" in error for error in errors)


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
    errors = dependency_waiver_errors(root, today=date(2026, 7, 16))
    assert any(
        "dependency waiver PYSEC-2026-2132 advisory_url must be" in error for error in errors
    )


def test_dependency_waiver_ids_must_be_unique(tmp_path: Path) -> None:
    """A duplicated advisory cannot silently widen the exception set."""
    root = _waiver_root(tmp_path)
    document = _waiver_document(root)
    waivers = document["waivers"]
    assert isinstance(waivers, list)
    waivers.append(waivers[-1])
    _write_waiver_document(root, document)

    errors = dependency_waiver_errors(root, today=date(2026, 7, 16))
    assert "dependency-waiver advisory IDs must be unique strings" in errors


def test_dependency_waiver_set_must_be_exact(tmp_path: Path) -> None:
    """Removing an expected advisory fails closed."""
    root = _waiver_root(tmp_path)
    document = _waiver_document(root)
    waivers = document["waivers"]
    assert isinstance(waivers, list)
    waivers.pop()
    _write_waiver_document(root, document)

    errors = dependency_waiver_errors(root, today=date(2026, 7, 16))
    assert any("dependency-waiver set must contain exactly:" in error for error in errors)


def test_mcp_waivers_expire_after_thirty_days(tmp_path: Path) -> None:
    """The temporary upstream incompatibility cannot become an open-ended exception."""
    root = _waiver_root(tmp_path)
    errors = dependency_waiver_errors(root, today=date(2026, 8, 15))
    for advisory_id in ("CVE-2026-52869", "CVE-2026-52870", "CVE-2026-59950"):
        assert f"dependency waiver {advisory_id} is expired" in errors


@pytest.mark.parametrize(
    ("content", "expected"),
    (
        ("{", "cannot read dependency waivers:"),
        ("[]", "dependency-waiver document must be a JSON object"),
        (
            '{"schema_version":"0","waivers":[]}',
            "dependency-waiver schema_version must be '1.0'",
        ),
        (
            '{"schema_version":"1.0","waivers":{}}',
            "dependency-waiver set must be a list of objects",
        ),
    ),
)
def test_dependency_waiver_document_shape_fails_closed(
    tmp_path: Path,
    content: str,
    expected: str,
) -> None:
    """Malformed waiver documents return bounded validation errors."""
    root = _waiver_root(tmp_path)
    (root / ".github/dependency-waivers.json").write_text(content, encoding="utf-8")
    assert any(
        expected in error for error in dependency_waiver_errors(root, today=date(2026, 7, 16))
    )


def test_missing_dependency_waiver_document_fails_closed(tmp_path: Path) -> None:
    """An unreadable waiver document cannot disable the guard."""
    root = _waiver_root(tmp_path)
    (root / ".github/dependency-waivers.json").unlink()
    errors = dependency_waiver_errors(root, today=date(2026, 7, 16))
    assert any("cannot read dependency waivers:" in error for error in errors)


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    (
        ("aliases", [], "aliases must be"),
        ("introduced_by", "semgrep==0", "introduced_by does not match"),
        ("reviewed_on", None, "reviewed_on must be an ISO date"),
        ("expires_on", "not-a-date", "expires_on must be an ISO date"),
        ("reviewed_on", "2026-07-17", "review date is in the future"),
        ("expires_on", "2026-08-16", "lifetime must be between 1 and 30 days"),
        ("rationale", "", "rationale must be non-empty"),
        ("mitigations", ["one"], "must contain at least three non-empty mitigations"),
    ),
)
def test_dependency_waiver_fields_fail_closed(
    tmp_path: Path,
    field: str,
    value: object,
    expected: str,
) -> None:
    """Each mutable waiver field remains independently constrained."""
    root = _waiver_root(tmp_path)
    document = _waiver_document(root)
    _first_mcp_waiver(document)[field] = value
    _write_waiver_document(root, document)
    errors = dependency_waiver_errors(root, today=date(2026, 7, 16))
    assert any(expected in error for error in errors)


def test_dependency_waiver_fields_are_exact(tmp_path: Path) -> None:
    """Missing, extra, and unknown records are rejected."""
    root = _waiver_root(tmp_path)
    document = _waiver_document(root)
    waiver = _first_mcp_waiver(document)
    waiver.pop("scope")
    waiver["unexpected"] = True
    _write_waiver_document(root, document)

    errors = dependency_waiver_errors(root, today=date(2026, 7, 16))
    assert any("is missing fields: scope" in error for error in errors)
    assert any("has unexpected fields: unexpected" in error for error in errors)

    waiver["advisory_id"] = None
    _write_waiver_document(root, document)
    errors = dependency_waiver_errors(root, today=date(2026, 7, 16))
    assert "dependency-waiver advisory IDs must be unique strings" in errors
    assert any("dependency-waiver set must contain exactly:" in error for error in errors)


@pytest.mark.parametrize(
    "fragment",
    ("python -m tools.check_dependency_waivers", "semgrep scan --error --config .semgrep.yml"),
)
def test_dependency_waiver_requires_guarded_command(
    tmp_path: Path,
    fragment: str,
) -> None:
    """The guard and exact allowed command must remain in the workflow."""
    root = _waiver_root(tmp_path)
    workflow = root / ".github/workflows/security.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(fragment, ""),
        encoding="utf-8",
    )
    errors = dependency_waiver_errors(root, today=date(2026, 7, 16))
    assert any(fragment in error for error in errors)
