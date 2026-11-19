# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — polyglot capability matrix tests
"""Verify the capability matrix reports scanner techniques honestly per language."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import get_args

import pytest

from rigor_foundry.adapter_profiles import profile_by_name
from rigor_foundry.language_capabilities import LanguageName
from rigor_foundry.polyglot_capability_matrix import (
    AST_SEMANTIC_LANGUAGES,
    NATIVE_ADAPTER_PROFILES,
    LanguageCapabilityRow,
    PolyglotCapabilityMatrix,
    _row_for,
    capability_matrix,
)

_GUIDE = Path(__file__).resolve().parents[1] / "docs/polyglot-capability-matrix.md"


def test_documented_matrix_matches_implemented_capabilities() -> None:
    """Keep the complete published technique table tied to the capability API."""
    _, section, guide = _GUIDE.read_text(encoding="utf-8").partition("\n## Matrix\n")
    assert section
    table = [
        [cell.strip() for cell in line.strip("|").split("|")]
        for line in guide.split("\n## ", 1)[0].splitlines()
        if line.startswith("|")
    ]
    assert table[0] == [
        "Language",
        "AST / semantic",
        "Size (GF001)",
        "Test ownership",
        "Dependency graph",
        "Structural",
    ]
    expected = []
    for row in capability_matrix().rows:
        language = "c / c++" if row.language == "c" else row.language
        ast = "No"
        if row.ast_semantic_controls:
            ast = "Built in" if row.language == "python" else "Native extra"
        flags = (
            row.responsibility_size_controls,
            row.ownership_controls,
            row.dependency_graph_controls,
            row.structural_controls,
        )
        expected.append([language, ast, *("Yes" if flag else "No" for flag in flags)])
    assert table[2:] == expected


def test_documented_programmatic_example_runs() -> None:
    """Execute the TypeScript guide example against the public Python API."""
    _, section, snippet = _GUIDE.read_text(encoding="utf-8").partition("\n```python\n")
    assert section
    source, end, _ = snippet.partition("\n```")
    assert end
    subprocess.run([sys.executable, "-c", source], check=True, timeout=30)


def test_matrix_reflects_actual_scanner_techniques() -> None:
    """Each language reports exactly the techniques the scanner applies to it."""
    matrix = capability_matrix()
    assert {row.language for row in matrix.rows} == set(get_args(LanguageName))
    # Python plus the native-extra languages have native AST controls.
    assert {row.language for row in matrix.rows if row.ast_semantic_controls} == {
        "python",
        "javascript",
        "typescript",
        "go",
        "rust",
        "c",
        "julia",
        "shell",
    }
    python = matrix.row("python")
    assert python.ast_semantic_controls and python.structural_controls
    # JavaScript/TypeScript now carry AST controls (via the optional extra) plus
    # their existing structural and dependency coverage.
    for language in ("javascript", "typescript"):
        row = matrix.row(language)
        assert row.structural_controls and row.dependency_graph_controls
        assert row.ast_semantic_controls
    # Go and Rust gain AST controls; Go still has no dependency-family parser.
    assert (
        matrix.row("go").ast_semantic_controls and not matrix.row("go").dependency_graph_controls
    )
    assert matrix.row("rust").ast_semantic_controls and matrix.row("rust").structural_controls
    # Go is owned for size and ownership but has no dependency-family parser.
    assert not matrix.row("go").dependency_graph_controls
    assert matrix.row("go").ownership_controls
    # Shell has size metrics but no ownership control.
    assert matrix.row("shell").responsibility_size_controls
    assert not matrix.row("shell").ownership_controls
    # YAML is scope-scannable data only: no structural technique applies.
    assert not matrix.row("yaml").structural_controls
    # structural_controls is exactly the union of the three heuristic techniques.
    for row in matrix.rows:
        expected = (
            row.responsibility_size_controls
            or row.ownership_controls
            or row.dependency_graph_controls
        )
        assert row.structural_controls is expected


def test_matrix_is_deterministic_and_row_lookup_is_strict() -> None:
    """The matrix is content-addressed and rejects unknown-language lookups."""
    assert capability_matrix().matrix_digest == capability_matrix().matrix_digest
    matrix = capability_matrix()
    assert matrix.row("rust").language == "rust"
    with pytest.raises(ValueError, match="no row for language"):
        matrix.row("cobol")
    with pytest.raises(ValueError, match="no registered suffixes"):
        _row_for("cobol")


def test_matrix_round_trips_and_rejects_tampering() -> None:
    """The serialised matrix round-trips and fails closed on tampering."""
    matrix = capability_matrix()
    assert PolyglotCapabilityMatrix.from_dict(matrix.to_dict()) == matrix
    row = matrix.rows[0]
    assert LanguageCapabilityRow.from_dict(row.to_dict()) == row
    good = matrix.to_dict()
    bad_schema = dict(good)
    bad_schema["schema_version"] = "9.9"
    with pytest.raises(ValueError, match="unsupported matrix schema"):
        PolyglotCapabilityMatrix.from_dict(bad_schema)
    bad_rows = dict(good)
    bad_rows["rows"] = "not-a-list"
    with pytest.raises(ValueError, match="rows must be a non-empty array"):
        PolyglotCapabilityMatrix.from_dict(bad_rows)
    empty_rows = dict(good)
    empty_rows["rows"] = []
    with pytest.raises(ValueError, match="rows must be a non-empty array"):
        PolyglotCapabilityMatrix.from_dict(empty_rows)
    bad_digest = dict(good)
    bad_digest["matrix_digest"] = "0" * 64
    with pytest.raises(ValueError, match="matrix digest"):
        PolyglotCapabilityMatrix.from_dict(bad_digest)


def test_declared_constants_are_grounded() -> None:
    """AST-semantic languages and adapter profiles resolve to real registry entries."""
    assert set(get_args(LanguageName)) >= AST_SEMANTIC_LANGUAGES
    assert capability_matrix().adapter_profiles == NATIVE_ADAPTER_PROFILES
    for name in NATIVE_ADAPTER_PROFILES:
        # profile_by_name raises for an unknown profile; this grounds the constant.
        assert profile_by_name(name).name == name
