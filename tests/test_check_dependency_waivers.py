# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Dependency-waiver guard tests
"""Verify that scanner remediation removes every audit exception."""

import json
from pathlib import Path
from shutil import copy2

import pytest

from tools._repository import ROOT
from tools.check_dependency_waivers import dependency_waiver_errors, main


def _waiver_root(tmp_path: Path) -> Path:
    for relative in (".github/dependency-waivers.json", ".github/workflows/security.yml"):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        copy2(ROOT / relative, target)
    return tmp_path


def test_repository_has_no_dependency_waivers() -> None:
    """The canonical security workflow audits both locks without exclusions."""
    assert dependency_waiver_errors() == []
    assert main() == 0


@pytest.mark.parametrize("waiver", [{"advisory_id": "PYSEC-2026-2132"}, None])
def test_any_waiver_fails_closed(tmp_path: Path, waiver: object) -> None:
    """A newly inserted exception cannot silently revive the old waiver lane."""
    root = _waiver_root(tmp_path)
    path = root / ".github/dependency-waivers.json"
    path.write_text(json.dumps({"schema_version": "1.0", "waivers": [waiver]}))
    assert "dependency-waiver set must be empty after scanner remediation" in (
        dependency_waiver_errors(root)
    )


@pytest.mark.parametrize("flag", ["--ignore-vuln PYSEC-2026-2132", "--ignore-vuln=ID"])
def test_workflow_cannot_ignore_findings(tmp_path: Path, flag: str) -> None:
    """Both supported pip-audit exclusion syntaxes are rejected."""
    root = _waiver_root(tmp_path)
    workflow = root / ".github/workflows/security.yml"
    workflow.write_text(workflow.read_text(encoding="utf-8") + f"\n# {flag}\n")
    assert "security workflow must not ignore vulnerability findings" in (
        dependency_waiver_errors(root)
    )


@pytest.mark.parametrize(
    ("content", "expected"),
    (
        ("{", "cannot read dependency waivers:"),
        ("[]", "dependency-waiver document must be a JSON object"),
        ('{"schema_version":"0","waivers":[]}', "schema_version must be '1.0'"),
        ('{"schema_version":"1.0","waivers":{}}', "set must be a list"),
        ('{"schema_version":"1.0","waivers":[],"extra":1}', "must contain only"),
    ),
)
def test_malformed_document_fails_closed(tmp_path: Path, content: str, expected: str) -> None:
    """Malformed or expanded waiver documents do not disable the guard."""
    root = _waiver_root(tmp_path)
    (root / ".github/dependency-waivers.json").write_text(content, encoding="utf-8")
    assert any(expected in error for error in dependency_waiver_errors(root))


def test_missing_document_fails_closed(tmp_path: Path) -> None:
    """An absent waiver document cannot silently remove governance."""
    root = _waiver_root(tmp_path)
    (root / ".github/dependency-waivers.json").unlink()
    assert any(
        "cannot read dependency waivers:" in error for error in dependency_waiver_errors(root)
    )


@pytest.mark.parametrize(
    "fragment",
    (
        "python -m tools.check_dependency_waivers",
        "python -m pip_audit -r requirements/ci.txt",
        "python -m pip_audit -r requirements/security.txt",
        "semgrep scan --error --config .semgrep.yml src tools",
    ),
)
def test_workflow_keeps_all_guarded_commands(tmp_path: Path, fragment: str) -> None:
    """Both dependency audits, the guard and the scanner remain enrolled."""
    root = _waiver_root(tmp_path)
    workflow = root / ".github/workflows/security.yml"
    workflow.write_text(
        workflow.read_text(encoding="utf-8").replace(fragment, ""), encoding="utf-8"
    )
    assert any(fragment in error for error in dependency_waiver_errors(root))
