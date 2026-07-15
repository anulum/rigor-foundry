# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Python architecture scanner tests
"""Exercise import, facade, ownership, and duplication rules on real files."""

from __future__ import annotations

from pathlib import Path

from repository_audit_git_repository import GitRepository

from rigor_foundry.architecture import scan_architecture
from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.models import AuditPolicy

_BODY = """\
def compute(value: int) -> int:
    first = value + 1
    second = first * 2
    third = second - 3
    fourth = third // 2
    fifth = fourth + value
    return fifth
"""


def test_python_architecture_rules_use_real_parsed_modules(tmp_path: Path) -> None:
    """Cycles, wildcards, broad guards, facades, ownership, and copies are visible."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "src/pkg/__init__.py",
        "from .a import compute\n\ndef facade_value() -> int:\n    return compute(1)\n",
    )
    repository.write_text("src/pkg/a.py", "from . import b\n\n" + _BODY)
    repository.write_text(
        "src/pkg/b.py",
        "from . import a\n\ndef compute_other(value: int) -> int:\n"
        "    first = value + 1\n    second = first * 2\n    third = second - 3\n"
        "    fourth = third // 2\n    fifth = fourth + value\n    return fifth\n",
    )
    repository.write_text("src/pkg/exports.py", "from .a import *\n")
    repository.write_text(
        "src/pkg/optional.py",
        "try:\n    import pkg.absent\nexcept Exception:\n    ABSENT = None\n",
    )
    repository.write_text(
        "tests/test_a.py",
        "from pkg.a import compute\n\ndef test_compute() -> None:\n    assert compute(2) == 4\n",
    )
    policy_path = repository.write_policy()
    repository.commit()

    candidates = scan_architecture(
        load_git_inventory(repository.root),
        AuditPolicy.from_path(policy_path),
    )
    by_rule = {item.rule_id for item in candidates}
    assert {
        "AR001-first-party-import-cycle",
        "AR002-wildcard-import-boundary",
        "AR003-broad-optional-import-boundary",
        "AR004-executable-facade",
        "AR005-no-module-named-test-owner",
        "AR006-duplicate-python-implementation",
    }.issubset(by_rule)
    cycle = next(item for item in candidates if item.rule_id == "AR001-first-party-import-cycle")
    assert "pkg.a" in cycle.symbol
    assert "pkg.b" in cycle.symbol
    duplicate = next(
        item for item in candidates if item.rule_id == "AR006-duplicate-python-implementation"
    )
    assert "pkg.a.compute" in duplicate.evidence
    assert "pkg.b.compute_other" in duplicate.evidence


def test_nested_src_root_resolves_package_names_and_test_owners(tmp_path: Path) -> None:
    """A nested Python src-layout does not leak filesystem prefixes into imports."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("engine/src/pkg/__init__.py", "from .core import value\n")
    repository.write_text("engine/src/pkg/core.py", "def value() -> int:\n    return 1\n")
    repository.write_text(
        "tests/test_core.py",
        "from pkg.core import value\n\ndef test_value() -> None:\n    assert value() == 1\n",
    )
    repository.commit()
    policy = AuditPolicy(source_roots=("engine/src",), test_roots=("tests",))
    candidates = scan_architecture(load_git_inventory(repository.root), policy)
    assert not any(
        item.rule_id == "AR005-no-module-named-test-owner" and item.symbol.endswith("pkg.core")
        for item in candidates
    )


def test_syntax_error_in_production_is_skipped_without_false_clean_scope_claim(
    tmp_path: Path,
) -> None:
    """The Python architecture parser does not invent edges for invalid syntax."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/broken.py", "def broken(:\n")
    repository.commit()
    candidates = scan_architecture(load_git_inventory(repository.root), AuditPolicy())
    assert candidates == ()
