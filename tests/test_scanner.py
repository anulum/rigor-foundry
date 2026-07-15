# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — repository scan composition tests
"""Verify policy discovery and explicit accounting for unreadable tracked code."""

from __future__ import annotations

from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.scanner import scan_repository


def test_scan_reports_missing_repository_policy_without_hiding_portable_results(
    tmp_path: Path,
) -> None:
    """A missing adopter policy is evidence, not an implicit clean or fatal scan."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    repository.commit()

    report = scan_repository(repository.root)

    assert any(
        item.rule_id == "GV001-missing-repository-audit-policy" for item in report.candidates
    )
    assert report.tracked_file_count == 2


def test_scan_discovers_policy_and_accounts_for_non_text_code(tmp_path: Path) -> None:
    """Tracked code outside bounded UTF-8 parsing remains an explicit candidate."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_bytes("src/pkg/native.py", b"\xff\xfe\x00\x01")
    repository.write_policy()
    repository.commit()

    report = scan_repository(repository.root)

    candidate = next(
        item for item in report.candidates if item.rule_id == "GV002-unscanned-tracked-code"
    )
    assert candidate.path == "src/pkg/native.py"
    assert candidate.confidence == "high"
    assert not any(
        item.rule_id == "GV001-missing-repository-audit-policy" for item in report.candidates
    )


def test_scan_rejects_policy_symlink_escape(tmp_path: Path) -> None:
    """A tracked policy symlink can never substitute bytes outside the audited tree."""
    outside = tmp_path / "outside-policy.json"
    outside.write_text('{"schema_version":"1.0"}\n', encoding="utf-8")
    repository = GitRepository.create(tmp_path / "repository")
    repository.symlink("rigor-foundry-policy.json", str(outside))
    repository.commit()

    with pytest.raises(ValueError, match="tracked non-symlink"):
        scan_repository(repository.root)
    with pytest.raises(ValueError, match="repository-relative"):
        scan_repository(repository.root, Path("../outside-policy.json"))


def test_scan_always_reports_uninitialised_gitlink(tmp_path: Path) -> None:
    """Every gitlink is explicit even when its path has no source-code suffix."""
    child = GitRepository.create(tmp_path / "child")
    child.write_text("README.md", "child\n")
    child_head = child.commit()
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_policy()
    repository.git_command("add", ".gitignore", "rigor-foundry-policy.json")
    repository.git_command("update-index", "--add", "--cacheinfo", "160000", child_head, "vendor")
    repository.git_command("commit", "-m", "test: add gitlink")

    report = scan_repository(repository.root)

    candidate = next(item for item in report.candidates if item.path == "vendor")
    assert candidate.rule_id == "GV002-unscanned-tracked-code"
    assert "content_kind=gitlink" in candidate.evidence
