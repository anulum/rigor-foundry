# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — repository scan composition tests
"""Verify policy discovery and explicit accounting for unreadable tracked code."""

from __future__ import annotations

from pathlib import Path

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
