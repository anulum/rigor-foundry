# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — cross-language responsibility scanner tests
"""Verify size candidates and exact responsibility-registry drift."""

from __future__ import annotations

import json
from pathlib import Path

from repository_audit_git_repository import GitRepository

from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.godfiles import scan_godfiles
from rigor_foundry.models import AuditPolicy


def _rules(repository: GitRepository, policy_path: Path) -> set[str]:
    """Return GodFile rule identifiers for the repository's current worktree."""
    return {
        item.rule_id
        for item in scan_godfiles(
            load_git_inventory(repository.root),
            AuditPolicy.from_path(policy_path),
        )
    }


def test_large_owner_is_candidate_not_automatic_godfile_verdict(tmp_path: Path) -> None:
    """Line threshold opens a responsibility review with structural metrics."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "src/pkg/owner.py",
        "import json\nimport pathlib\n\n"
        "def control_value(value: int) -> int:\n"
        "    adjusted = value + 1\n    return adjusted\n",
    )
    policy_path = repository.write_policy(source_threshold=4)
    repository.commit()
    candidates = scan_godfiles(
        load_git_inventory(repository.root),
        AuditPolicy.from_path(policy_path),
    )
    large = next(item for item in candidates if item.rule_id == "GF001-large-responsibility-owner")
    assert large.path == "src/pkg/owner.py"
    assert "lines=6" in large.evidence
    assert "definitions=1" in large.evidence
    assert "import_fanout=2" in large.evidence
    assert "not itself a GodFile verdict" in large.rationale


def test_size_registry_reports_missing_invalid_incomplete_and_drift(tmp_path: Path) -> None:
    """Every registry failure mode is bound to real tracked content."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/owner.py", "VALUE = 1\nVALUE_2 = 2\n")
    registry_path = "tools/module_size_policy.json"
    complete_row = {
        "path": "src/pkg/owner.py",
        "lines": 2,
        "responsibility": "one constant owner",
        "dependency_boundary": "no dependencies",
        "reassess_when": "a second lifecycle appears",
    }
    repository.write_text(registry_path, json.dumps({"files": [complete_row]}))
    policy_path = repository.write_policy(registries=[registry_path])
    repository.commit()
    assert "GF005-size-decision-drift" not in _rules(repository, policy_path)

    repository.write_text(registry_path, json.dumps({"files": [{**complete_row, "lines": 3}]}))
    assert "GF005-size-decision-drift" in _rules(repository, policy_path)

    incomplete = {key: value for key, value in complete_row.items() if key != "responsibility"}
    repository.write_text(registry_path, json.dumps({"files": [incomplete]}))
    assert "GF004-incomplete-size-decision" in _rules(repository, policy_path)

    repository.write_text(registry_path, "{not json")
    assert "GF003-invalid-size-registry" in _rules(repository, policy_path)

    missing_policy = repository.write_policy(registries=["tools/absent.json"])
    assert "GF002-missing-size-registry" in _rules(repository, missing_policy)


def test_non_code_and_below_threshold_files_do_not_open_size_review(tmp_path: Path) -> None:
    """Only configured code owners above the exact threshold become candidates."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("README.md", "one\ntwo\nthree\n")
    repository.write_text("src/pkg/short.py", "one = 1\ntwo = 2\n")
    policy_path = repository.write_policy(source_threshold=2)
    repository.commit()
    assert not any(
        item.rule_id == "GF001-large-responsibility-owner"
        for item in scan_godfiles(
            load_git_inventory(repository.root),
            AuditPolicy.from_path(policy_path),
        )
    )
