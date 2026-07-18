# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — polyglot capability matrix
"""Publish, per language, which analysis techniques the scanner actually applies."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast, get_args

from .language_capabilities import LANGUAGE_CAPABILITIES, LanguageName
from .model_primitives import require_boolean, validate_unique_strings
from .models import canonical_digest, require_mapping, require_string, require_string_tuple

MATRIX_SCHEMA_VERSION = "1.0"

# Languages whose source the scanner parses into an abstract syntax tree for
# semantic controls. Verified against the scanner: the test-authenticity rules
# (TA001-TA011) and the Python import-graph architecture rules (AR001-AR004,
# AR006) operate on a parsed Python AST, and the native scanner parses a
# tree-sitter AST for JavaScript/TypeScript (AS006), Go (AS007), and Rust (AS008).
# The non-Python native analysis requires the optional ``native`` extra
# (tree-sitter); the capability is implemented, and a deployment without the extra
# degrades to structural controls.
AST_SEMANTIC_LANGUAGES: frozenset[str] = frozenset(
    {"python", "javascript", "typescript", "go", "rust"}
)

# Built-in adapter profiles that add native-adapter coverage. They are neither
# language-partitioned nor enabled by default: a profile is policy-wired into
# ``native_audits`` and its executable must pass the trusted-executable provenance
# gate before it runs. Recorded here so the matrix distinguishes adapter coverage
# from the scanner's own AST and structural controls.
NATIVE_ADAPTER_PROFILES: tuple[str, ...] = (
    "semgrep-local-json-v1",
    "trivy-repository-json-v1",
)

ADAPTER_NOTE = (
    "Native-adapter coverage is supplied by policy-wired adapter profiles, not by "
    "the scanner. A profile is opt-in per repository policy and only runs once its "
    "executable passes the trusted-executable provenance gate; it is not a "
    "per-language default."
)


@dataclass(frozen=True)
class LanguageCapabilityRow:
    """The scanner analysis techniques available for one language.

    Parameters
    ----------
    language:
        Stable language-family name.
    suffixes:
        The lower-case dotted file suffixes mapped to this language.
    ast_semantic_controls:
        Whether the scanner parses this language's source into an AST for
        semantic controls (currently Python only).
    responsibility_size_controls:
        Whether the responsibility-size scanner (GF001) owns the language.
    ownership_controls:
        Whether a missing-test-owner control (AR005 for Python, AR008 for the
        polyglot suffixes) applies to the language.
    dependency_graph_controls:
        Whether the scanner resolves this language's relative dependencies
        (Python imports, or a supported native dependency family).
    structural_controls:
        Whether any textual or structural heuristic applies at all — the union
        of size, ownership, and dependency-graph coverage.
    """

    language: LanguageName
    suffixes: tuple[str, ...]
    ast_semantic_controls: bool
    responsibility_size_controls: bool
    ownership_controls: bool
    dependency_graph_controls: bool
    structural_controls: bool

    def to_dict(self) -> dict[str, object]:
        """Serialise one language capability row."""
        return {
            "language": self.language,
            "suffixes": list(self.suffixes),
            "ast_semantic_controls": self.ast_semantic_controls,
            "responsibility_size_controls": self.responsibility_size_controls,
            "ownership_controls": self.ownership_controls,
            "dependency_graph_controls": self.dependency_graph_controls,
            "structural_controls": self.structural_controls,
        }

    @classmethod
    def from_dict(cls, value: object) -> LanguageCapabilityRow:
        """Parse one language capability row."""
        data = require_mapping(value, "row")
        return cls(
            language=cast(LanguageName, require_string(data.get("language"), "row.language")),
            suffixes=require_string_tuple(data.get("suffixes"), "row.suffixes"),
            ast_semantic_controls=require_boolean(
                data.get("ast_semantic_controls"), "row.ast_semantic_controls"
            ),
            responsibility_size_controls=require_boolean(
                data.get("responsibility_size_controls"), "row.responsibility_size_controls"
            ),
            ownership_controls=require_boolean(
                data.get("ownership_controls"), "row.ownership_controls"
            ),
            dependency_graph_controls=require_boolean(
                data.get("dependency_graph_controls"), "row.dependency_graph_controls"
            ),
            structural_controls=require_boolean(
                data.get("structural_controls"), "row.structural_controls"
            ),
        )


@dataclass(frozen=True)
class PolyglotCapabilityMatrix:
    """A derived, content-addressed matrix of per-language scanner techniques."""

    rows: tuple[LanguageCapabilityRow, ...]
    adapter_profiles: tuple[str, ...]
    adapter_note: str
    matrix_digest: str

    @classmethod
    def build(cls) -> PolyglotCapabilityMatrix:
        """Derive the matrix from the live language-capability registry."""
        rows = tuple(_row_for(language) for language in sorted(get_args(LanguageName)))
        adapter_profiles = tuple(
            validate_unique_strings(NATIVE_ADAPTER_PROFILES, "matrix.adapter_profiles", minimum=1)
        )
        note = require_string(ADAPTER_NOTE, "matrix.adapter_note")
        body: dict[str, object] = {
            "schema_version": MATRIX_SCHEMA_VERSION,
            "rows": [row.to_dict() for row in rows],
            "adapter_profiles": list(adapter_profiles),
            "adapter_note": note,
        }
        return cls(
            rows=rows,
            adapter_profiles=adapter_profiles,
            adapter_note=note,
            matrix_digest=canonical_digest(body),
        )

    def row(self, language: str) -> LanguageCapabilityRow:
        """Return the row for one language or raise if it is unknown."""
        for row in self.rows:
            if row.language == language:
                return row
        raise ValueError(f"matrix has no row for language {language}")

    def to_dict(self) -> dict[str, object]:
        """Serialise the whole capability matrix."""
        return {
            "schema_version": MATRIX_SCHEMA_VERSION,
            "rows": [row.to_dict() for row in self.rows],
            "adapter_profiles": list(self.adapter_profiles),
            "adapter_note": self.adapter_note,
            "matrix_digest": self.matrix_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> PolyglotCapabilityMatrix:
        """Parse and integrity-check a serialised matrix."""
        data = require_mapping(value, "matrix")
        if data.get("schema_version") != MATRIX_SCHEMA_VERSION:
            raise ValueError("unsupported matrix schema version")
        rows_value = data.get("rows")
        if not isinstance(rows_value, list) or not rows_value:
            raise ValueError("matrix.rows must be a non-empty array")
        rows = tuple(
            LanguageCapabilityRow.from_dict(item) for item in cast(list[object], rows_value)
        )
        adapter_profiles = tuple(
            validate_unique_strings(
                require_string_tuple(data.get("adapter_profiles"), "matrix.adapter_profiles"),
                "matrix.adapter_profiles",
                minimum=1,
            )
        )
        note = require_string(data.get("adapter_note"), "matrix.adapter_note")
        body: dict[str, object] = {
            "schema_version": MATRIX_SCHEMA_VERSION,
            "rows": [row.to_dict() for row in rows],
            "adapter_profiles": list(adapter_profiles),
            "adapter_note": note,
        }
        matrix = cls(
            rows=rows,
            adapter_profiles=adapter_profiles,
            adapter_note=note,
            matrix_digest=canonical_digest(body),
        )
        if data.get("matrix_digest") != matrix.matrix_digest:
            raise ValueError("matrix digest does not match its content")
        return matrix


def _row_for(language: str) -> LanguageCapabilityRow:
    """Derive one language's row from the aggregated capability registry."""
    suffixes = tuple(
        sorted(
            suffix
            for suffix, capability in LANGUAGE_CAPABILITIES.items()
            if capability.language == language
        )
    )
    if not suffixes:
        raise ValueError(f"language {language} has no registered suffixes")
    capabilities = tuple(LANGUAGE_CAPABILITIES[suffix] for suffix in suffixes)
    responsibility = any(item.responsibility_metrics for item in capabilities)
    # Python's missing-test-owner control is AR005; the polyglot suffixes carry
    # AR008 via the polyglot_ownership flag.
    ownership = language == "python" or any(item.polyglot_ownership for item in capabilities)
    # Python resolves its own import graph; other languages need a native
    # dependency family parser.
    dependency = language == "python" or any(
        item.dependency_family is not None for item in capabilities
    )
    ast_semantic = language in AST_SEMANTIC_LANGUAGES
    structural = responsibility or ownership or dependency
    return LanguageCapabilityRow(
        language=cast(LanguageName, language),
        suffixes=suffixes,
        ast_semantic_controls=ast_semantic,
        responsibility_size_controls=responsibility,
        ownership_controls=ownership,
        dependency_graph_controls=dependency,
        structural_controls=structural,
    )


def capability_matrix() -> PolyglotCapabilityMatrix:
    """Return the current derived polyglot capability matrix."""
    return PolyglotCapabilityMatrix.build()
