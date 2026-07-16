# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
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
from rigor_foundry.candidate_anchor import RepositoryTreeAnchor, TrackedBlobAnchor
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
    assert isinstance(duplicate.anchor, TrackedBlobAnchor)
    assert duplicate.anchor.line_end > duplicate.anchor.line_start
    facade = next(item for item in candidates if item.rule_id == "AR004-executable-facade")
    assert isinstance(facade.anchor, TrackedBlobAnchor)
    assert facade.anchor.line_end > facade.anchor.line_start
    missing_owner = next(
        item for item in candidates if item.rule_id == "AR005-no-module-named-test-owner"
    )
    assert isinstance(missing_owner.anchor, RepositoryTreeAnchor)


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


def test_overlapping_source_roots_choose_the_most_specific_component_owner(
    tmp_path: Path,
) -> None:
    """Nested src-layout ownership is based on components rather than string length."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("engine/src/pkg/core.py", "def value() -> int:\n    return 1\n")
    repository.commit()

    candidates = scan_architecture(
        load_git_inventory(repository.root),
        AuditPolicy(source_roots=("engine", "engine/src"), test_roots=("tests",)),
    )
    missing = next(
        item for item in candidates if item.rule_id == "AR005-no-module-named-test-owner"
    )
    assert missing.symbol == "pkg.core"


def test_syntax_error_in_production_is_skipped_without_false_clean_scope_claim(
    tmp_path: Path,
) -> None:
    """The Python architecture parser does not invent edges for invalid syntax."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/broken.py", "def broken(:\n")
    repository.commit()
    candidates = scan_architecture(load_git_inventory(repository.root), AuditPolicy())
    assert candidates == ()


def test_absolute_imports_and_excessive_relative_climbs_respect_source_roots(
    tmp_path: Path,
) -> None:
    """Configured package roots resolve absolute cycles without accepting escaped imports."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("python/pkg/a.py", "from python.pkg import b\n")
    repository.write_text("python/pkg/b.py", "from python.pkg import a\n")
    repository.write_text("python/pkg/climb.py", "from ....outside import value\n")
    repository.write_text("src/__init__.py", "from python.pkg import a\n")
    repository.commit()

    candidates = scan_architecture(
        load_git_inventory(repository.root),
        AuditPolicy(source_roots=("python", "src"), test_roots=("tests",)),
    )
    cycles = [item for item in candidates if item.rule_id == "AR001-first-party-import-cycle"]
    assert len(cycles) == 1
    assert cycles[0].evidence.endswith("values=python.pkg.a, python.pkg.b")
    assert "outside" not in cycles[0].symbol
    assert not any(item.symbol == "src" for item in candidates)


def test_optional_import_candidates_distinguish_broad_and_narrow_handlers(
    tmp_path: Path,
) -> None:
    """Bare and tuple-wide handlers are reported while expected absence remains narrow."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "src/pkg/bare.py",
        "try:\n    import optional_dependency\nexcept:\n    optional_dependency = None\n",
    )
    repository.write_text(
        "src/pkg/tupled.py",
        "try:\n    import optional_dependency\n"
        "except (ImportError, Exception):\n    optional_dependency = None\n",
    )
    repository.write_text(
        "src/pkg/narrow.py",
        "try:\n    import optional_dependency\n"
        "except ImportError:\n    optional_dependency = None\n",
    )
    repository.write_text(
        "src/pkg/qualified.py",
        "import builtins\ntry:\n    import optional_dependency\n"
        "except builtins.Exception:\n    optional_dependency = None\n",
    )
    repository.commit()

    candidates = scan_architecture(load_git_inventory(repository.root), AuditPolicy())
    guarded = {
        item.path for item in candidates if item.rule_id == "AR003-broad-optional-import-boundary"
    }
    assert guarded == {"src/pkg/bare.py", "src/pkg/tupled.py"}


def test_test_owner_conventions_and_unique_bodies_avoid_false_candidates(
    tmp_path: Path,
) -> None:
    """Test-root and suffix ownership conventions suppress only their matching modules."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "src/pkg/core.py",
        "def compute(value: int) -> int:\n"
        "    first = value + 1\n    second = first * 2\n    third = second - 3\n"
        "    fourth = third // 2\n    fifth = fourth + value\n    return fifth\n",
    )
    repository.write_text(
        "src/pkg/engine.py",
        "def transform(value: int) -> int:\n"
        "    first = value - 1\n    second = first * 3\n    third = second + 4\n"
        "    fourth = third // 3\n    fifth = fourth - value\n    return fifth\n",
    )
    repository.write_text("tests/core.py", "from pkg.core import compute\n")
    repository.write_text("tests/engine_test.py", "from pkg.engine import transform\n")
    repository.commit()

    candidates = scan_architecture(load_git_inventory(repository.root), AuditPolicy())
    assert not any(
        item.rule_id == "AR005-no-module-named-test-owner"
        and item.path in {"src/pkg/core.py", "src/pkg/engine.py"}
        for item in candidates
    )
    assert not any(item.rule_id == "AR006-duplicate-python-implementation" for item in candidates)


def test_large_python_cycle_keeps_bounded_identity_evidence(tmp_path: Path) -> None:
    """A large real import cycle emits one bounded, set-identified candidate."""
    repository = GitRepository.create(tmp_path / "repository")
    names = tuple(f"component_with_a_long_name_{index:02d}" for index in range(20))
    for index, name in enumerate(names):
        target = names[(index + 1) % len(names)]
        repository.write_text(
            f"src/pkg/{name}.py",
            f"from pkg import {target}\n",
        )
    repository.commit()

    candidates = scan_architecture(load_git_inventory(repository.root), AuditPolicy())
    cycle = next(item for item in candidates if item.rule_id == "AR001-first-party-import-cycle")
    assert len(cycle.evidence.encode("utf-8")) <= 512
    assert "count=20" in cycle.evidence
    assert "truncated=true" in cycle.evidence
