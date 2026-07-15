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
