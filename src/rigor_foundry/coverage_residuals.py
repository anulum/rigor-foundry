# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — classified coverage-residual contracts
"""Validate expiring evidence for intentionally unreachable fail-closed guards."""

from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Final, Literal, cast

from .audit_primitives import require_mapping, require_string, require_string_tuple

COVERAGE_RESIDUAL_SCHEMA_VERSION: Final = "1.1"
DEFAULT_COVERAGE_RESIDUAL_MANIFEST: Final = Path("coverage-residuals.json")
MAX_REVIEW_WINDOW: Final = timedelta(days=90)

ResidualClassification = Literal[
    "platform-primitive",
    "runtime-invariant",
    "race-window",
]
_CLASSIFICATIONS: Final = frozenset({"platform-primitive", "runtime-invariant", "race-window"})
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+\Z")
_SYMBOL = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z")
_IMPORT_PREFIX = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+\Z")


def _strict_fields(
    data: dict[str, object],
    expected: frozenset[str],
    field: str,
) -> None:
    """Reject missing or unrecognised fields in one versioned record."""
    observed = frozenset(data)
    if observed != expected:
        missing = ", ".join(sorted(expected - observed)) or "none"
        extra = ", ".join(sorted(observed - expected)) or "none"
        raise ValueError(f"{field} fields are invalid; missing={missing}; extra={extra}")


def _relative_path(value: object, field: str) -> str:
    """Return one canonical repository-relative POSIX path."""
    text = require_string(value, field)
    path = Path(text)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != text:
        raise ValueError(f"{field} must be a canonical repository-relative path")
    return text


def _iso_date(value: object, field: str) -> date:
    """Return one strict ISO calendar date."""
    text = require_string(value, field)
    try:
        parsed = date.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO date") from exc
    if parsed.isoformat() != text:
        raise ValueError(f"{field} must be an ISO date")
    return parsed


def _ordered_nonempty(values: tuple[str, ...], field: str) -> tuple[str, ...]:
    """Require a sorted, unique, non-empty tuple."""
    if not values or tuple(sorted(set(values))) != values:
        raise ValueError(f"{field} must be sorted, unique, and non-empty")
    return values


@dataclass(frozen=True)
class CoverageResidual:
    """One expiring disposition for a fail-closed guard without honest local coverage."""

    residual_id: str
    classification: ResidualClassification
    source_path: str
    symbol: str
    guard: str
    source_digest: str
    owner: str
    rationale: str
    public_verification: tuple[str, ...]
    revisit_triggers: tuple[str, ...]
    reviewed_on: date
    review_by: date

    @classmethod
    def from_dict(cls, value: object, index: int = 0) -> CoverageResidual:
        """Parse one strict residual disposition."""
        field = f"coverage_residuals[{index}]"
        data = require_mapping(value, field)
        _strict_fields(
            data,
            frozenset(
                {
                    "residual_id",
                    "classification",
                    "source_path",
                    "symbol",
                    "guard",
                    "source_digest",
                    "owner",
                    "rationale",
                    "public_verification",
                    "revisit_triggers",
                    "reviewed_on",
                    "review_by",
                }
            ),
            field,
        )
        residual_id = require_string(data.get("residual_id"), f"{field}.residual_id")
        if _IDENTIFIER.fullmatch(residual_id) is None:
            raise ValueError(f"{field}.residual_id is invalid")
        classification = require_string(
            data.get("classification"),
            f"{field}.classification",
        )
        if classification not in _CLASSIFICATIONS:
            raise ValueError(f"{field}.classification is unsupported")
        symbol = require_string(data.get("symbol"), f"{field}.symbol")
        if _SYMBOL.fullmatch(symbol) is None:
            raise ValueError(f"{field}.symbol is invalid")
        digest = require_string(data.get("source_digest"), f"{field}.source_digest")
        if _DIGEST.fullmatch(digest) is None:
            raise ValueError(f"{field}.source_digest must be a lowercase SHA-256 digest")
        reviewed_on = _iso_date(data.get("reviewed_on"), f"{field}.reviewed_on")
        review_by = _iso_date(data.get("review_by"), f"{field}.review_by")
        lifetime = review_by - reviewed_on
        if lifetime <= timedelta(0) or lifetime > MAX_REVIEW_WINDOW:
            raise ValueError(f"{field} review window must be between 1 and 90 days")
        return cls(
            residual_id=residual_id,
            classification=cast(ResidualClassification, classification),
            source_path=_relative_path(data.get("source_path"), f"{field}.source_path"),
            symbol=symbol,
            guard=require_string(data.get("guard"), f"{field}.guard"),
            source_digest=digest,
            owner=require_string(data.get("owner"), f"{field}.owner"),
            rationale=require_string(data.get("rationale"), f"{field}.rationale"),
            public_verification=_ordered_nonempty(
                require_string_tuple(
                    data.get("public_verification"),
                    f"{field}.public_verification",
                ),
                f"{field}.public_verification",
            ),
            revisit_triggers=_ordered_nonempty(
                require_string_tuple(
                    data.get("revisit_triggers"),
                    f"{field}.revisit_triggers",
                ),
                f"{field}.revisit_triggers",
            ),
            reviewed_on=reviewed_on,
            review_by=review_by,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one residual without host-dependent fields."""
        return {
            "residual_id": self.residual_id,
            "classification": self.classification,
            "source_path": self.source_path,
            "symbol": self.symbol,
            "guard": self.guard,
            "source_digest": self.source_digest,
            "owner": self.owner,
            "rationale": self.rationale,
            "public_verification": list(self.public_verification),
            "revisit_triggers": list(self.revisit_triggers),
            "reviewed_on": self.reviewed_on.isoformat(),
            "review_by": self.review_by.isoformat(),
        }


@dataclass(frozen=True)
class NegativeSearch:
    """One preregistered repository search that must remain empty."""

    search_id: str
    include: tuple[str, ...]
    forbidden_import_prefixes: tuple[str, ...]
    patterns: tuple[str, ...]
    rationale: str

    @classmethod
    def from_dict(cls, value: object, index: int = 0) -> NegativeSearch:
        """Parse one strict negative-search contract."""
        field = f"negative_searches[{index}]"
        data = require_mapping(value, field)
        _strict_fields(
            data,
            frozenset(
                {
                    "search_id",
                    "include",
                    "forbidden_import_prefixes",
                    "patterns",
                    "rationale",
                }
            ),
            field,
        )
        search_id = require_string(data.get("search_id"), f"{field}.search_id")
        if _IDENTIFIER.fullmatch(search_id) is None:
            raise ValueError(f"{field}.search_id is invalid")
        include = tuple(
            _relative_path(path, f"{field}.include")
            for path in require_string_tuple(data.get("include"), f"{field}.include")
        )
        forbidden_import_prefixes = _ordered_nonempty(
            require_string_tuple(
                data.get("forbidden_import_prefixes"),
                f"{field}.forbidden_import_prefixes",
            ),
            f"{field}.forbidden_import_prefixes",
        )
        if any(_IMPORT_PREFIX.fullmatch(prefix) is None for prefix in forbidden_import_prefixes):
            raise ValueError(f"{field}.forbidden_import_prefixes contains an invalid prefix")
        patterns = _ordered_nonempty(
            require_string_tuple(data.get("patterns"), f"{field}.patterns"),
            f"{field}.patterns",
        )
        for pattern in patterns:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"{field}.patterns contains invalid regular expression") from exc
        return cls(
            search_id=search_id,
            include=_ordered_nonempty(include, f"{field}.include"),
            forbidden_import_prefixes=forbidden_import_prefixes,
            patterns=patterns,
            rationale=require_string(data.get("rationale"), f"{field}.rationale"),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one negative-search contract."""
        return {
            "search_id": self.search_id,
            "include": list(self.include),
            "forbidden_import_prefixes": list(self.forbidden_import_prefixes),
            "patterns": list(self.patterns),
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class CoverageResidualManifest:
    """Versioned residual dispositions and prohibited test-simulation searches."""

    residuals: tuple[CoverageResidual, ...]
    negative_searches: tuple[NegativeSearch, ...]

    @classmethod
    def from_dict(cls, value: object) -> CoverageResidualManifest:
        """Parse one strict manifest."""
        data = require_mapping(value, "coverage_residual_manifest")
        _strict_fields(
            data,
            frozenset({"schema_version", "residuals", "negative_searches"}),
            "coverage_residual_manifest",
        )
        if data.get("schema_version") != COVERAGE_RESIDUAL_SCHEMA_VERSION:
            raise ValueError("unsupported coverage-residual schema version")
        raw_residuals = data.get("residuals")
        raw_searches = data.get("negative_searches")
        if not isinstance(raw_residuals, list) or not raw_residuals:
            raise ValueError("coverage_residual_manifest.residuals must be a non-empty array")
        if not isinstance(raw_searches, list) or not raw_searches:
            raise ValueError(
                "coverage_residual_manifest.negative_searches must be a non-empty array"
            )
        residuals = tuple(
            CoverageResidual.from_dict(item, index) for index, item in enumerate(raw_residuals)
        )
        searches = tuple(
            NegativeSearch.from_dict(item, index) for index, item in enumerate(raw_searches)
        )
        residual_ids = tuple(item.residual_id for item in residuals)
        search_ids = tuple(item.search_id for item in searches)
        if tuple(sorted(set(residual_ids))) != residual_ids:
            raise ValueError("coverage residual identifiers must be sorted and unique")
        if tuple(sorted(set(search_ids))) != search_ids:
            raise ValueError("negative-search identifiers must be sorted and unique")
        return cls(residuals=residuals, negative_searches=searches)

    @classmethod
    def from_path(cls, path: Path) -> CoverageResidualManifest:
        """Read and parse one UTF-8 JSON manifest."""
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read coverage-residual manifest {path}") from exc
        return cls.from_dict(value)

    def to_dict(self) -> dict[str, object]:
        """Serialise the complete deterministic manifest."""
        return {
            "schema_version": COVERAGE_RESIDUAL_SCHEMA_VERSION,
            "residuals": [item.to_dict() for item in self.residuals],
            "negative_searches": [item.to_dict() for item in self.negative_searches],
        }


def _forbidden_imports(
    text: str,
    prefixes: tuple[str, ...],
) -> tuple[tuple[str, int], ...]:
    """Return structurally matched import prefixes and source lines."""
    tree = ast.parse(text)
    matches: set[tuple[str, int]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported = tuple(alias.name for alias in node.names)
            for prefix in prefixes:
                if any(name.startswith(prefix) for name in imported):
                    matches.add((prefix, node.lineno))
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            for prefix in prefixes:
                package, separator, member_prefix = prefix.rpartition(".")
                imports_private_module = node.module.startswith(prefix)
                imports_private_member = (
                    bool(separator)
                    and node.module == package
                    and any(alias.name.startswith(member_prefix) for alias in node.names)
                )
                if imports_private_module or imports_private_member:
                    matches.add((prefix, node.lineno))
    return tuple(sorted(matches, key=lambda item: (item[1], item[0])))


def _symbol_source(text: str, symbol: str, path: Path) -> str:
    """Return exact source for one module or class-owned symbol."""
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        raise ValueError(f"cannot parse residual source {path}") from exc
    body: list[ast.stmt] = list(tree.body)
    parts = symbol.split(".")
    selected = next(
        (
            node
            for node in body
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == parts[0]
        ),
        None,
    )
    if selected is None:
        raise ValueError(f"coverage residual symbol is unavailable: {path}:{symbol}")
    for part in parts[1:]:
        body = list(selected.body) if isinstance(selected, ast.ClassDef) else []
        selected = next(
            (
                node
                for node in body
                if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == part
            ),
            None,
        )
        if selected is None:
            raise ValueError(f"coverage residual symbol is unavailable: {path}:{symbol}")
    end_lineno = cast(int, selected.end_lineno)
    lines = text.splitlines(keepends=True)
    return "".join(lines[selected.lineno - 1 : end_lineno])


def _verification_error(root: Path, reference: str) -> str | None:
    """Return an error when a public test reference no longer names a real test."""
    path_text, separator, test_name = reference.partition("::")
    if separator != "::" or not test_name.startswith("test_"):
        return f"coverage residual verification reference is invalid: {reference}"
    path = root / _relative_path(path_text, "public_verification.path")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return f"coverage residual verification file is unavailable: {path_text}"
    if re.search(rf"^def {re.escape(test_name)}\(", text, re.MULTILINE) is None:
        return f"coverage residual verification test is unavailable: {reference}"
    return None


def coverage_residual_errors(
    root: Path,
    manifest_path: Path = DEFAULT_COVERAGE_RESIDUAL_MANIFEST,
    *,
    today: date | None = None,
) -> tuple[str, ...]:
    """Return manifest, source-binding, expiry, and negative-search failures.

    Parameters
    ----------
    root:
        Repository root whose source and tests are authoritative.
    manifest_path:
        Repository-relative manifest location.
    today:
        Optional deterministic date for validator tests.
    """
    errors: list[str] = []
    try:
        root = root.resolve(strict=True)
        manifest_relative = _relative_path(
            manifest_path.as_posix(),
            "coverage_residual_manifest.path",
        )
        manifest = CoverageResidualManifest.from_path(root / manifest_relative)
    except (OSError, ValueError) as exc:
        return (str(exc),)
    current = today or datetime.now(UTC).date()
    for residual in manifest.residuals:
        source_path = root / residual.source_path
        try:
            text = source_path.read_text(encoding="utf-8")
            segment = _symbol_source(text, residual.symbol, source_path)
        except (OSError, UnicodeError, ValueError) as exc:
            errors.append(str(exc))
            continue
        observed_digest = hashlib.sha256(segment.encode("utf-8")).hexdigest()
        if observed_digest != residual.source_digest:
            errors.append(
                f"{residual.residual_id}: source digest changed for "
                f"{residual.source_path}:{residual.symbol}"
            )
        if residual.guard not in segment:
            errors.append(
                f"{residual.residual_id}: guard is absent from "
                f"{residual.source_path}:{residual.symbol}"
            )
        if residual.reviewed_on > current:
            errors.append(f"{residual.residual_id}: review date is in the future")
        if residual.review_by <= current:
            errors.append(f"{residual.residual_id}: coverage residual review is expired")
        for reference in residual.public_verification:
            if error := _verification_error(root, reference):
                errors.append(f"{residual.residual_id}: {error}")
    for search in manifest.negative_searches:
        for path_text in search.include:
            path = root / path_text
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                errors.append(
                    f"{search.search_id}: negative-search file is unavailable: {path_text}"
                )
                continue
            if path.suffix == ".py":
                try:
                    import_matches = _forbidden_imports(
                        text,
                        search.forbidden_import_prefixes,
                    )
                except SyntaxError as exc:
                    errors.append(
                        f"{search.search_id}: negative-search Python file is unparseable: "
                        f"{path_text}:{exc.lineno or 1}"
                    )
                else:
                    errors.extend(
                        f"{search.search_id}: prohibited import prefix matches "
                        f"{path_text}:{line}: {prefix}"
                        for prefix, line in import_matches
                    )
            for pattern in search.patterns:
                match = re.search(pattern, text, re.MULTILINE)
                if match is not None:
                    line = text.count("\n", 0, match.start()) + 1
                    errors.append(
                        f"{search.search_id}: prohibited test simulation matches "
                        f"{path_text}:{line}: {pattern}"
                    )
    return tuple(errors)
