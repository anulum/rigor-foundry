# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — typed language capability registry tests
"""Verify exact scanner projections and component-aware path classification."""

from __future__ import annotations

from pathlib import Path

from rigor_foundry.language_capabilities import (
    LANGUAGE_CAPABILITIES,
    dependency_family_for,
    extensionless_dependency_suffixes,
    filesystem_path_within,
    index_dependency_suffixes,
    is_test_path,
    owning_repository_root,
    repository_path_has_root,
    repository_path_under_roots,
    suffixes_with,
)

_RESPONSIBILITY_SUFFIXES = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".go",
        ".h",
        ".hpp",
        ".jl",
        ".js",
        ".jsx",
        ".lean",
        ".mojo",
        ".py",
        ".pyi",
        ".rs",
        ".sh",
        ".sv",
        ".ts",
        ".tsx",
        ".v",
    }
)


def test_registry_has_unique_lowercase_suffixes_and_exact_projections() -> None:
    """One typed registry preserves each scanner's deliberate capability boundary."""
    suffixes = tuple(LANGUAGE_CAPABILITIES)
    assert len(suffixes) == len(set(suffixes))
    assert all(suffix.startswith(".") and suffix == suffix.lower() for suffix in suffixes)
    assert suffixes_with("responsibility") == _RESPONSIBILITY_SUFFIXES
    assert suffixes_with("polyglot") == _RESPONSIBILITY_SUFFIXES - {".py", ".pyi", ".sh"}
    assert suffixes_with("scope") == _RESPONSIBILITY_SUFFIXES | {".yaml", ".yml"}


def test_dependency_capabilities_preserve_resolution_families_and_order() -> None:
    """Relative parsers and extensionless/index fallbacks remain explicitly projected."""
    assert dependency_family_for("web/OWNER.TS") == "javascript"
    assert dependency_family_for("native/owner.cc") == "c"
    assert dependency_family_for("service/owner.go") is None
    assert dependency_family_for("README.md") is None
    assert extensionless_dependency_suffixes() == (
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".rs",
        ".jl",
        ".c",
        ".cpp",
        ".h",
        ".hpp",
    )
    assert index_dependency_suffixes() == (".ts", ".tsx", ".js", ".jsx")


def test_repository_roots_are_component_aware_and_choose_most_specific_owner() -> None:
    """Nested roots match whole components without accepting lexical prefix collisions."""
    roots = ("src", "engine/src", "engine/src/pkg")
    assert repository_path_under_roots("engine/src/pkg/core.py", roots)
    assert not repository_path_under_roots("engine/source/pkg/core.py", roots)
    assert not repository_path_under_roots("/engine/src/pkg/core.py", roots)
    assert not repository_path_under_roots("engine/src/../pkg/core.py", roots)
    assert owning_repository_root("engine/src/pkg/core.py", roots) == "engine/src/pkg"
    assert (
        owning_repository_root(
            "engine/src/pkg/core.py",
            ("engine//src/.",),
        )
        == "engine/src"
    )
    assert owning_repository_root("srcish/core.py", roots) is None
    assert repository_path_has_root("workspace/quality/tests/core.py", ("quality/tests",))
    assert not repository_path_has_root("workspace/quality/testsuite/core.py", ("tests",))
    assert not repository_path_has_root("workspace/tests/core.py", ("",))


def test_test_profiles_preserve_generic_and_polyglot_naming_differences() -> None:
    """Plural native tests remain polyglot-only while roots and common names are shared."""
    assert is_test_path("workspace/QUALITY/tests/Core.PY", ("QUALITY/tests",))
    assert is_test_path("native/TEST_owner.GO", ())
    assert is_test_path("web/widget.SPEC.TS", ())
    assert is_test_path("native/kernel_tests.RS", (), profile="polyglot")
    assert not is_test_path("native/kernel_tests.RS", ())
    assert not is_test_path("contest/kernel.rs", ("test",))


def test_filesystem_containment_resolves_symlinks_and_rejects_prefix_siblings(
    tmp_path: Path,
) -> None:
    """Resolved containment accepts descendants but rejects symlink escapes and prefix siblings."""
    root = tmp_path / "repository"
    inside = root / "src" / "owner.py"
    outside = tmp_path / "outside" / "owner.py"
    sibling = tmp_path / "repository-backup" / "owner.py"
    inside.parent.mkdir(parents=True)
    outside.parent.mkdir(parents=True)
    sibling.parent.mkdir(parents=True)
    inside.write_text("VALUE = 1\n", encoding="utf-8")
    outside.write_text("VALUE = 2\n", encoding="utf-8")
    sibling.write_text("VALUE = 3\n", encoding="utf-8")
    (root / "escape").symlink_to(outside.parent, target_is_directory=True)
    (root / "loop").symlink_to(root / "loop", target_is_directory=True)

    assert filesystem_path_within(inside, root)
    assert not filesystem_path_within(root / "escape" / "owner.py", root)
    assert not filesystem_path_within(root / "loop" / "owner.py", root)
    assert not filesystem_path_within(root / "missing.py", root)
    assert not filesystem_path_within(sibling, root)
