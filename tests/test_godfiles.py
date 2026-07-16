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

from rigor_foundry.candidate_anchor import RepositoryTreeAnchor
from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.godfiles import scan_godfiles
from rigor_foundry.models import AuditPolicy
from rigor_foundry.scanner import scan_repository


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
        "import json\nfrom pathlib import Path\n\n"
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


def test_cross_language_metrics_bind_real_definitions_and_dependencies(tmp_path: Path) -> None:
    """Structural evidence reflects tracked TypeScript, Rust, Go, and Julia owners."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "web/controller.ts",
        "import { value } from './value';\n"
        "export function parseHTTPValue(input: string): string {\n"
        "  return input + value;\n}\n",
    )
    repository.write_text("web/value.ts", "export const value = 'ready';\n")
    repository.write_text("native/lib.rs", "mod controller;\nmod value;\n")
    repository.write_text(
        "native/controller.rs",
        "use crate::value::value;\n"
        "pub fn evaluate_signal(input: i32) -> i32 {\n    input + value()\n}\n",
    )
    repository.write_text("native/value.rs", "pub fn value() -> i32 { 1 }\n")
    repository.write_text(
        "service/controller.go",
        'package service\n\nimport "fmt"\n\ntype Engine struct{}\n\n'
        "func (engine *Engine) ComputeSignal(value int) int {\n"
        "    fmt.Print(value)\n    return value\n}\n",
    )
    repository.write_text(
        "julia/controller.jl",
        "using LinearAlgebra\nfunction solve_signal!(value)\n    return norm(value)\nend\n",
    )
    policy_path = repository.write_policy(source_threshold=1)
    repository.commit()

    candidates = scan_godfiles(
        load_git_inventory(repository.root),
        AuditPolicy.from_path(policy_path),
    )
    evidence = {
        item.path: item.evidence
        for item in candidates
        if item.rule_id == "GF001-large-responsibility-owner"
    }
    expected_definitions = {
        "web/controller.ts": 1,
        "native/controller.rs": 1,
        "service/controller.go": 2,
        "julia/controller.jl": 1,
    }
    for path, definition_count in expected_definitions.items():
        assert f"definitions={definition_count}" in evidence[path]
        assert "import_fanout=1" in evidence[path]
        assert "symbol_families=" in evidence[path]


def test_empty_and_invalid_python_owners_keep_bounded_metrics(tmp_path: Path) -> None:
    """Empty and syntactically invalid tracked owners neither crash nor invent symbols."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/empty.py", "")
    repository.write_text("src/pkg/broken.py", "def broken(:\n    pass\n")
    policy_path = repository.write_policy(source_threshold=1)
    repository.commit()

    candidates = scan_godfiles(
        load_git_inventory(repository.root),
        AuditPolicy.from_path(policy_path),
    )
    large = {
        item.path: item
        for item in candidates
        if item.rule_id == "GF001-large-responsibility-owner"
    }
    assert "src/pkg/empty.py" not in large
    assert "definitions=0" in large["src/pkg/broken.py"].evidence
    assert "import_fanout=0" in large["src/pkg/broken.py"].evidence


def test_registry_parser_reports_distinct_document_shape_failures(tmp_path: Path) -> None:
    """Tracked registries fail closed for invalid roots, file arrays, and row shapes."""
    repository = GitRepository.create(tmp_path / "repository")
    registry_path = "tools/module_size_policy.json"
    repository.write_text(registry_path, "{}")
    policy_path = repository.write_policy(registries=[registry_path])
    repository.commit()

    for document, message in (
        ([], "registry root must be an object"),
        ({"files": "rows"}, "registry files must be an array"),
        ({"files": [42]}, "registry row must be an object with string keys"),
    ):
        repository.write_text(registry_path, json.dumps(document))
        invalid = next(
            item
            for item in scan_godfiles(
                load_git_inventory(repository.root),
                AuditPolicy.from_path(policy_path),
            )
            if item.rule_id == "GF003-invalid-size-registry"
        )
        assert invalid.evidence == message


def test_registry_row_reports_unavailable_tracked_owner(tmp_path: Path) -> None:
    """A complete decision for an absent owner is explicit registry drift."""
    repository = GitRepository.create(tmp_path / "repository")
    registry_path = "tools/module_size_policy.json"
    repository.write_text(
        registry_path,
        json.dumps(
            {
                "files": [
                    {
                        "path": "src/pkg/absent.py",
                        "lines": 14,
                        "responsibility": "repository control owner",
                        "dependency_boundary": "standard library",
                        "reassess_when": "the owner is restored",
                    }
                ]
            }
        ),
    )
    policy_path = repository.write_policy(registries=[registry_path])
    repository.commit()

    drift = next(
        item
        for item in scan_godfiles(
            load_git_inventory(repository.root),
            AuditPolicy.from_path(policy_path),
        )
        if item.rule_id == "GF005-size-decision-drift"
    )
    assert drift.path == "src/pkg/absent.py"
    assert drift.evidence == "registered path unavailable; recorded_lines=14"


def test_deleted_registered_owner_is_tree_anchored_in_public_scan(tmp_path: Path) -> None:
    """A deleted tracked owner emits GF005 state evidence instead of crashing."""
    repository = GitRepository.create(tmp_path / "repository")
    owner = repository.write_text("src/pkg/owner.py", "VALUE = 1\nVALUE_2 = 2\n")
    registry_path = "tools/module_size_policy.json"
    repository.write_text(
        registry_path,
        json.dumps(
            {
                "files": [
                    {
                        "path": "src/pkg/owner.py",
                        "lines": 2,
                        "responsibility": "constant owner",
                        "dependency_boundary": "no dependencies",
                        "reassess_when": "the owner is restored",
                    }
                ]
            }
        ),
    )
    policy_path = repository.write_policy(registries=[registry_path])
    repository.commit()
    owner.unlink()

    report = scan_repository(repository.root, policy_path.relative_to(repository.root))
    drift = next(
        item
        for item in report.candidates
        if item.rule_id == "GF005-size-decision-drift" and item.path == "src/pkg/owner.py"
    )
    assert isinstance(drift.anchor, RepositoryTreeAnchor)
    assert drift.anchor.tree_oid == report.head_tree
    assert drift.anchor.tracked_content_sha256 == report.tracked_content_digest
    assert drift.evidence == "registered path unavailable; recorded_lines=2"
