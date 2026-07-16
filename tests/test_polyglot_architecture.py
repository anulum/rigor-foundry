# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — polyglot architecture scanner tests
"""Verify relative dependency and test ownership across real language files."""

from __future__ import annotations

from pathlib import Path

from repository_audit_git_repository import GitRepository

from rigor_foundry.candidate_anchor import RepositoryTreeAnchor
from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.models import AuditPolicy
from rigor_foundry.polyglot_architecture import scan_polyglot_architecture


def test_polyglot_scanner_finds_real_relative_cycle_and_missing_owner(tmp_path: Path) -> None:
    """TypeScript dependency direction and Rust test ownership remain visible."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("studio/src/a.ts", "import { b } from './b';\nexport const a = b;\n")
    repository.write_text("studio/src/b.ts", "import { a } from './a';\nexport const b = a;\n")
    repository.write_text("native/src/kernel.rs", "pub fn kernel() -> i32 { 1 }\n")
    repository.write_text(
        "tests/test_a.ts",
        "import { a } from '../studio/src/a';\nif (a === undefined) throw Error();\n",
    )
    repository.commit()
    candidates = scan_polyglot_architecture(
        load_git_inventory(repository.root),
        AuditPolicy(test_roots=("tests",)),
    )
    assert any(item.rule_id == "AR007-relative-dependency-cycle" for item in candidates)
    missing = [item for item in candidates if item.rule_id == "AR008-no-polyglot-test-owner"]
    assert any(item.path == "native/src/kernel.rs" for item in missing)
    assert all(isinstance(item.anchor, RepositoryTreeAnchor) for item in missing)
    assert not any(item.path == "studio/src/a.ts" for item in missing)


def test_polyglot_scanner_resolves_c_and_julia_relative_edges(tmp_path: Path) -> None:
    """C includes and Julia includes resolve only to tracked repository paths."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("native/a.c", '#include "b.h"\nint a(void) { return b(); }\n')
    repository.write_text("native/b.h", '#include "a.c"\nint b(void);\n')
    repository.write_text("julia/main.jl", 'include("part.jl")\n')
    repository.write_text("julia/part.jl", "value = 1\n")
    repository.commit()
    candidates = scan_polyglot_architecture(
        load_git_inventory(repository.root),
        AuditPolicy(),
    )
    cycles = [item for item in candidates if item.rule_id == "AR007-relative-dependency-cycle"]
    assert len(cycles) == 1
    assert "native/a.c" in cycles[0].evidence
    assert "native/b.h" in cycles[0].evidence


def test_polyglot_scanner_resolves_real_rust_module_without_a_false_cycle(
    tmp_path: Path,
) -> None:
    """A valid Rust child module resolves without inventing a reciprocal edge."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("native/lib.rs", "mod engine;\npub use engine::value;\n")
    repository.write_text("native/engine.rs", "pub fn value() -> i32 { 1 }\n")
    repository.commit()

    candidates = scan_polyglot_architecture(
        load_git_inventory(repository.root),
        AuditPolicy(),
    )
    assert not any(item.rule_id == "AR007-relative-dependency-cycle" for item in candidates)


def test_polyglot_scanner_rejects_escaping_unresolved_and_self_edges(tmp_path: Path) -> None:
    """Relative imports cannot escape the repository or fabricate/self-connect graph edges."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "web/a.ts",
        "import '../../outside';\nimport './missing';\nimport './a';\nexport const value = 1;\n",
    )
    repository.write_text(
        "service/main.go",
        'package main\nimport "fmt"\nfunc main() { fmt.Println("ready") }\n',
    )
    repository.commit()

    candidates = scan_polyglot_architecture(
        load_git_inventory(repository.root),
        AuditPolicy(),
    )
    assert not any(item.rule_id == "AR007-relative-dependency-cycle" for item in candidates)


def test_extensionless_resolution_preserves_language_priority(tmp_path: Path) -> None:
    """An ambiguous extensionless import keeps the established TypeScript-first owner."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("web/entry.ts", "import './shared';\nexport const entry = 1;\n")
    repository.write_text("web/shared.ts", "import './entry';\nexport const shared = 1;\n")
    repository.write_text("web/shared.js", "export const shared = 2;\n")
    repository.commit()

    candidates = scan_polyglot_architecture(
        load_git_inventory(repository.root),
        AuditPolicy(),
    )
    cycle = next(item for item in candidates if item.rule_id == "AR007-relative-dependency-cycle")
    assert "web/entry.ts" in cycle.evidence
    assert "web/shared.ts" in cycle.evidence
    assert "web/shared.js" not in cycle.evidence


def test_polyglot_test_suffix_owns_matching_source(tmp_path: Path) -> None:
    """A language-native plural test suffix is recognised as the source's owner."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("native/kernel.rs", "pub fn kernel() -> i32 { 1 }\n")
    repository.write_text(
        "tests/kernel_tests.rs",
        "use crate::kernel;\n#[test]\nfn kernel_returns_one() { assert_eq!(kernel(), 1); }\n",
    )
    repository.commit()

    candidates = scan_polyglot_architecture(
        load_git_inventory(repository.root),
        AuditPolicy(test_roots=("tests",)),
    )
    assert not any(
        item.rule_id == "AR008-no-polyglot-test-owner" and item.path == "native/kernel.rs"
        for item in candidates
    )


def test_large_typescript_cycle_keeps_bounded_identity_evidence(tmp_path: Path) -> None:
    """A large real TypeScript cycle emits one bounded, set-identified candidate."""
    repository = GitRepository.create(tmp_path / "repository")
    names = tuple(f"component_with_a_long_name_{index:02d}" for index in range(20))
    for index, name in enumerate(names):
        target = names[(index + 1) % len(names)]
        repository.write_text(
            f"studio/{name}.ts",
            f"import {{ value }} from './{target}';\nexport const current = value;\n",
        )
    repository.commit()

    candidates = scan_polyglot_architecture(
        load_git_inventory(repository.root),
        AuditPolicy(),
    )
    cycle = next(item for item in candidates if item.rule_id == "AR007-relative-dependency-cycle")
    assert len(cycle.evidence.encode("utf-8")) <= 512
    assert "count=20" in cycle.evidence
    assert "truncated=true" in cycle.evidence
