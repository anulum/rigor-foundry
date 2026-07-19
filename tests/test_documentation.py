# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — documentation, claims, and IP scanner tests
"""Verify bounded licence-header and package-version candidates in real Git trees."""

from __future__ import annotations

import collections
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.candidate_anchor import TrackedBlobAnchor
from rigor_foundry.documentation import scan_documentation
from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.models import AuditPolicy, Candidate
from rigor_foundry.scanner import scan_repository

_SPDX_SOURCE = "# SPDX-License-" + "Identifier: Apache-2.0\nVALUE = 1\n"
_PROJECT = "[project]\nname = 'demo-package'\nversion = '2.4.1'\n"


def test_public_scan_wires_precise_header_and_version_drift_candidates(tmp_path: Path) -> None:
    """The public scanner finds real drift while ignoring safe and historical surfaces."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("pyproject.toml", _PROJECT)
    repository.write_text("src/pkg/licensed.py", _SPDX_SOURCE)
    repository.write_text("src/pkg/unlicensed.py", "VALUE = 2\n")
    repository.write_text("src/pkg/shebang.py", "#!/usr/bin/env python3\n" + _SPDX_SOURCE)
    repository.write_bytes("src/pkg/binary.py", b"\xff\xfe")
    repository.write_text("scripts/outside.py", "VALUE = 3\n")
    repository.write_text("tests/test_unlicensed.py", "def test_value() -> None:\n    pass\n")
    repository.write_text(
        "README.md",
        "Install demo-package==2.4.1.\n"
        "Old pin: demo.package[cli] == 2.3.0.\n"
        "Two stale forms on one line: demo-package v2.2.0 / demo-package==2.1.0.\n",
    )
    repository.write_text("docs/setup.rst", "Demo_Package version 2.0.0\n")
    repository.write_text("docs/current.md", "demo-package version 2.4.1\n")
    repository.write_text("docs/changelog.md", "demo-package==1.0.0\n")
    repository.write_text("CHANGELOG.md", "demo-package v1.0.0\n")
    repository.write_text("docs/notes.txt", "demo-package==1.0.0\n")
    repository.write_text("NOTES.md", "demo-package==1.0.0\n")
    repository.write_policy(required_domains=frozenset({"documentation-claims-ip"}))
    repository.commit()

    report = scan_repository(repository.root)
    candidates = tuple(item for item in report.candidates if item.rule_id.startswith("DC"))

    assert collections.Counter(item.rule_id for item in candidates) == {
        "DC001-missing-license-header": 1,
        "DC002-doc-version-drift": 3,
    }
    header = next(item for item in candidates if item.rule_id.startswith("DC001"))
    assert header.category == "documentation"
    assert header.confidence == "high"
    assert header.symbol == "spdx-license-header"
    assert isinstance(header.anchor, TrackedBlobAnchor)
    assert header.anchor.path == "src/pkg/unlicensed.py"
    assert header.anchor.line_start == 1
    assert "file_sha256=" in header.evidence
    assert Candidate.from_dict(header.to_dict()) == header

    drift = tuple(item for item in candidates if item.rule_id.startswith("DC002"))
    assert [(item.anchor.path, item.anchor.line_start) for item in drift] == [
        ("README.md", 2),
        ("README.md", 3),
        ("docs/setup.rst", 1),
    ]
    assert all(item.symbol == "documented-package-version" for item in drift)
    assert all("expected_version_sha256=" in item.evidence for item in drift)
    assert all("package_name_sha256=" in item.evidence for item in drift)
    assert not any(
        item.rule_id == "GV004-uncontrolled-required-domain"
        and item.symbol == "documentation-claims-ip"
        for item in report.candidates
    )


@pytest.mark.parametrize(
    "pyproject",
    [
        None,
        b"\xff\xfe",
        "not = [\n",
        "[build-system]\nrequires = []\n",
        "[project]\nname = ['demo-package']\nversion = '2.4.1'\n",
        "[project]\nname = '---'\nversion = '2.4.1'\n",
    ],
)
def test_version_drift_requires_unambiguous_static_pep621_metadata(
    tmp_path: Path,
    pyproject: str | bytes | None,
) -> None:
    """Missing, binary, malformed, dynamic, and invalid project metadata never invent drift."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/licensed.py", _SPDX_SOURCE)
    repository.write_text("README.md", "demo-package==1.0.0\n")
    if isinstance(pyproject, str):
        repository.write_text("pyproject.toml", pyproject)
    elif isinstance(pyproject, bytes):
        repository.write_bytes("pyproject.toml", pyproject)
    policy_path = repository.write_policy()
    repository.commit()

    candidates = scan_documentation(
        load_git_inventory(repository.root),
        AuditPolicy.from_path(policy_path),
    )
    assert candidates == ()


def test_source_scope_requires_supported_text_under_declared_roots(tmp_path: Path) -> None:
    """Only supported UTF-8 source owners below declared roots receive DC001 candidates."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("pyproject.toml", _PROJECT)
    repository.write_text("src/pkg/unlicensed.rs", "pub fn value() -> i32 { 1 }\n")
    repository.write_text("src/pkg/empty.py", "")
    repository.write_text(
        "src/pkg/string.py",
        "MARKER = 'SPDX-License-" + "Identifier: Apache-2.0'\n",
    )
    repository.write_text("src/pkg/notes.txt", "unlicensed prose\n")
    repository.write_text("vendor/unlicensed.rs", "pub fn value() -> i32 { 1 }\n")
    repository.write_bytes("src/pkg/binary.rs", b"\xff\xfe")
    policy_path = repository.write_policy()
    repository.commit()

    candidates = scan_documentation(
        load_git_inventory(repository.root),
        AuditPolicy.from_path(policy_path),
    )
    assert [(item.rule_id, item.anchor.path) for item in candidates] == [
        ("DC001-missing-license-header", "src/pkg/empty.py"),
        ("DC001-missing-license-header", "src/pkg/string.py"),
        ("DC001-missing-license-header", "src/pkg/unlicensed.rs"),
    ]
