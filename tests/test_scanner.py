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

from rigor_foundry.models import canonical_digest
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


def test_language_registry_refactor_preserves_candidate_identity(tmp_path: Path) -> None:
    """A real multi-language repository retains the pre-refactor candidate tuple digest."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/core.py", "def value() -> int:\n    return 1\n")
    repository.write_text(
        "tests/test_core.py",
        "from pkg.core import value\n\ndef test_value() -> None:\n    assert value() == 1\n",
    )
    repository.write_text(
        "web/widget.ts",
        "export function widget(): number {\n  return 1;\n}\n",
    )
    repository.write_text(
        "web/widget.spec.ts",
        "import { widget } from './widget';\nif (widget() !== 1) throw Error();\n",
    )
    repository.write_text("native/kernel.rs", "pub fn kernel() -> i32 { 1 }\n")
    repository.write_text(
        "native/kernel_tests.rs",
        "#[test]\nfn kernel_returns_one() { assert_eq!(1, 1); }\n",
    )
    repository.write_bytes("config/settings.yaml", b"\xff\xfe")
    repository.write_policy(source_threshold=1, test_threshold=2)
    repository.commit()

    report = scan_repository(repository.root)
    candidate_identity = canonical_digest(
        [(item.rule_id, item.path, item.candidate_id) for item in report.candidates]
    )

    assert candidate_identity == "e236ad9c2deb0eb830f7ffbdc06dbdf288526553bcc68c730dbf8dab90381be9"
    yaml_candidate = next(item for item in report.candidates if item.path.endswith(".yaml"))
    assert yaml_candidate.rule_id == "GV002-unscanned-tracked-code"
    assert not any(
        item.path.endswith(".yaml") and item.rule_id.startswith(("GF", "AR"))
        for item in report.candidates
    )
