# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — classified coverage-residual tests
"""Verify residual expiry, source binding, and prohibited-simulation searches."""

from __future__ import annotations

import json
import shutil
from datetime import date
from pathlib import Path
from typing import Any, cast

import pytest

from rigor_foundry.cli import main
from rigor_foundry.coverage_residuals import (
    COVERAGE_RESIDUAL_SCHEMA_VERSION,
    CoverageResidualManifest,
    coverage_residual_errors,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = Path("coverage-residuals.json")


def _document() -> dict[str, object]:
    """Return a detached copy of the tracked residual document."""
    return cast(
        dict[str, object],
        json.loads((ROOT / MANIFEST).read_text(encoding="utf-8")),
    )


def _copy_contract(tmp_path: Path) -> Path:
    """Copy only files bound by the tracked residual contract."""
    root = tmp_path / "repository"
    document = _document()
    residuals = cast(list[dict[str, object]], document["residuals"])
    searches = cast(list[dict[str, object]], document["negative_searches"])
    paths = {cast(str, residual["source_path"]) for residual in residuals}
    paths.update(
        cast(str, reference).partition("::")[0]
        for residual in residuals
        for reference in cast(list[object], residual["public_verification"])
    )
    paths.update(
        cast(str, path) for search in searches for path in cast(list[object], search["include"])
    )
    for relative in sorted(paths):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)
    root.mkdir(parents=True, exist_ok=True)
    (root / MANIFEST).write_text(
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return root


def _write_document(root: Path, document: dict[str, object]) -> None:
    """Write one deterministic manifest below an existing copied contract."""
    (root / MANIFEST).write_text(
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _first_residual(document: dict[str, object]) -> dict[str, Any]:
    """Return the first mutable residual mapping."""
    residuals = cast(list[dict[str, Any]], document["residuals"])
    return residuals[0]


def _first_search(document: dict[str, object]) -> dict[str, Any]:
    """Return the first mutable negative-search mapping."""
    searches = cast(list[dict[str, Any]], document["negative_searches"])
    return searches[0]


def test_tracked_manifest_round_trips_and_passes_public_cli(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The live repository contract is strict, deterministic, and CLI-addressable."""
    manifest = CoverageResidualManifest.from_path(ROOT / MANIFEST)

    assert manifest.to_dict() == _document()
    assert COVERAGE_RESIDUAL_SCHEMA_VERSION == "1.1"
    assert coverage_residual_errors(ROOT) == ()
    assert main(["residuals-check", "--root", str(ROOT)]) == 0
    assert capsys.readouterr().out == "coverage residuals: PASS\n"


def test_manifest_rejects_unknown_fields_and_duplicate_identifiers() -> None:
    """Versioned residual documents reject schema drift and ambiguous ownership."""
    extra = _document()
    extra["implicit_waiver"] = True
    with pytest.raises(ValueError, match="extra=implicit_waiver"):
        CoverageResidualManifest.from_dict(extra)

    duplicate = _document()
    residuals = cast(list[dict[str, object]], duplicate["residuals"])
    residuals[1]["residual_id"] = residuals[0]["residual_id"]
    with pytest.raises(ValueError, match="sorted and unique"):
        CoverageResidualManifest.from_dict(duplicate)

    duplicate_search = _document()
    searches = cast(list[dict[str, object]], duplicate_search["negative_searches"])
    searches.append(dict(searches[0]))
    with pytest.raises(ValueError, match="negative-search identifiers"):
        CoverageResidualManifest.from_dict(duplicate_search)


@pytest.mark.parametrize(
    ("target", "value", "message"),
    [
        ("schema_version", "2.0", "unsupported coverage-residual schema"),
        ("residuals", [], "residuals must be a non-empty array"),
        ("negative_searches", [], "negative_searches must be a non-empty array"),
    ],
)
def test_manifest_rejects_unsupported_or_empty_envelopes(
    target: str,
    value: object,
    message: str,
) -> None:
    """Schema version and both required collections fail closed."""
    document = _document()
    document[target] = value
    with pytest.raises(ValueError, match=message):
        CoverageResidualManifest.from_dict(document)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("residual_id", "lowercase", "residual_id is invalid"),
        ("classification", "waiver", "classification is unsupported"),
        ("source_path", "../outside.py", "repository-relative path"),
        ("symbol", "invalid-symbol!", "symbol is invalid"),
        ("source_digest", "A" * 64, "lowercase SHA-256"),
        ("reviewed_on", "not-a-date", "must be an ISO date"),
        ("reviewed_on", "20260716", "must be an ISO date"),
        ("review_by", "2026-07-16", "review window"),
        ("review_by", "2027-07-16", "review window"),
        ("public_verification", [], "sorted, unique, and non-empty"),
        (
            "revisit_triggers",
            ["second", "first"],
            "sorted, unique, and non-empty",
        ),
    ],
)
def test_residual_parser_rejects_ambiguous_dispositions(
    field: str,
    value: object,
    message: str,
) -> None:
    """Every residual identity, source, date, and evidence field is strict."""
    document = _document()
    _first_residual(document)[field] = value
    with pytest.raises(ValueError, match=message):
        CoverageResidualManifest.from_dict(document)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("search_id", "lowercase", "search_id is invalid"),
        ("include", ["/absolute.py"], "repository-relative path"),
        ("include", [], "sorted, unique, and non-empty"),
        ("forbidden_import_prefixes", [], "sorted, unique, and non-empty"),
        ("forbidden_import_prefixes", ["not dotted"], "invalid prefix"),
        ("patterns", [], "sorted, unique, and non-empty"),
        ("patterns", ["["], "invalid regular expression"),
    ],
)
def test_negative_search_parser_rejects_ambiguous_contracts(
    field: str,
    value: object,
    message: str,
) -> None:
    """Negative-search identifiers, paths, and expressions are strict."""
    document = _document()
    _first_search(document)[field] = value
    with pytest.raises(ValueError, match=message):
        CoverageResidualManifest.from_dict(document)


def test_manifest_read_failures_are_normalised(tmp_path: Path) -> None:
    """Missing and malformed JSON expose one stable public parse error."""
    missing = tmp_path / "missing.json"
    with pytest.raises(ValueError, match="cannot read coverage-residual manifest"):
        CoverageResidualManifest.from_path(missing)

    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match="cannot read coverage-residual manifest"):
        CoverageResidualManifest.from_path(malformed)


def test_source_guard_and_digest_drift_fail_closed(tmp_path: Path) -> None:
    """Changing one classified guard invalidates its exact source disposition."""
    root = _copy_contract(tmp_path)
    source = root / "src/rigor_foundry/adapters.py"
    text = source.read_text(encoding="utf-8")
    source.write_text(
        text.replace(
            "native audit output pipes were not created",
            "native audit stream contract changed",
            1,
        ),
        encoding="utf-8",
    )

    errors = coverage_residual_errors(root)

    assert any("CR-ADAPTER-PIPE-INVARIANT: source digest changed" in error for error in errors)
    assert any("CR-ADAPTER-PIPE-INVARIANT: guard is absent" in error for error in errors)


def test_expiry_and_negative_searches_are_enforced_on_real_files(tmp_path: Path) -> None:
    """Expired review and reintroduced production simulation both block validation."""
    root = _copy_contract(tmp_path)
    adapters_test = root / "tests/test_adapters.py"
    adapters_test.write_text(
        adapters_test.read_text(encoding="utf-8")
        + "\nmonkeypatch.setattr(target, 'boundary', replacement)\n",
        encoding="utf-8",
    )

    errors = coverage_residual_errors(root, today=date(2026, 10, 14))

    assert any("coverage residual review is expired" in error for error in errors)
    assert any(
        "NS-NO-PRIVATE-SIMULATION: prohibited test simulation matches "
        "tests/test_adapters.py" in error
        for error in errors
    )


@pytest.mark.parametrize(
    "statement",
    [
        "from rigor_foundry import _remediation_graph",
        "from rigor_foundry import (\n    _remediation_graph as graph,\n)",
        "from rigor_foundry._remediation_graph import argv_digest",
        "import rigor_foundry._remediation_graph as graph",
    ],
)
def test_negative_search_rejects_private_production_imports(
    tmp_path: Path,
    statement: str,
) -> None:
    """Protocol tests cannot reconstruct evidence with private production helpers."""
    root = _copy_contract(tmp_path)
    remediation_test = root / "tests/test_remediation_plan.py"
    remediation_test.write_text(
        remediation_test.read_text(encoding="utf-8") + f"\n{statement}\n",
        encoding="utf-8",
    )

    errors = coverage_residual_errors(root)

    assert any(
        "NS-NO-PRIVATE-SIMULATION: prohibited import prefix matches "
        "tests/test_remediation_plan.py" in error
        for error in errors
    )


def test_negative_search_fails_closed_on_unparseable_python(tmp_path: Path) -> None:
    """Structural import validation cannot silently skip invalid Python."""
    root = _copy_contract(tmp_path)
    remediation_test = root / "tests/test_remediation_plan.py"
    remediation_test.write_text(
        remediation_test.read_text(encoding="utf-8") + "\nfrom rigor_foundry import (\n",
        encoding="utf-8",
    )

    errors = coverage_residual_errors(root)

    assert any(
        "NS-NO-PRIVATE-SIMULATION: negative-search Python file is unparseable: "
        "tests/test_remediation_plan.py" in error
        for error in errors
    )


def test_negative_search_keeps_regex_support_for_non_python_files(tmp_path: Path) -> None:
    """Structural import checks do not displace generic text searches."""
    root = _copy_contract(tmp_path)
    document = _document()
    search = _first_search(document)
    include = cast(list[str], search["include"])
    include.append("tests/negative-search.txt")
    include.sort()
    (root / "tests/negative-search.txt").write_text("public evidence\n", encoding="utf-8")
    _write_document(root, document)

    assert coverage_residual_errors(root) == ()


def test_missing_public_verification_reference_blocks_manifest(tmp_path: Path) -> None:
    """A residual cannot outlive the public regression named as its nearest evidence."""
    root = _copy_contract(tmp_path)
    document = cast(
        dict[str, object],
        json.loads((root / MANIFEST).read_text(encoding="utf-8")),
    )
    _first_residual(document)["public_verification"] = [
        "tests/test_adapters.py::test_removed_contract"
    ]
    _write_document(root, document)

    errors = coverage_residual_errors(root)

    assert any("verification test is unavailable" in error for error in errors)


@pytest.mark.parametrize(
    ("reference", "message"),
    [
        ("tests/test_adapters.py", "verification reference is invalid"),
        ("tests/missing.py::test_contract", "verification file is unavailable"),
    ],
)
def test_invalid_public_verification_references_fail_closed(
    tmp_path: Path,
    reference: str,
    message: str,
) -> None:
    """Malformed and missing public-test references remain explicit errors."""
    root = _copy_contract(tmp_path)
    document = cast(
        dict[str, object],
        json.loads((root / MANIFEST).read_text(encoding="utf-8")),
    )
    _first_residual(document)["public_verification"] = [reference]
    _write_document(root, document)

    assert any(message in error for error in coverage_residual_errors(root))


@pytest.mark.parametrize(
    ("source_change", "message"),
    [
        (None, "No such file or directory"),
        ("def broken(:\n", "cannot parse residual source"),
        ("def unrelated():\n    return 1\n", "coverage residual symbol is unavailable"),
    ],
)
def test_missing_malformed_or_unrelated_source_fails_closed(
    tmp_path: Path,
    source_change: str | None,
    message: str,
) -> None:
    """Source disappearance, syntax failure, and symbol drift are never ignored."""
    root = _copy_contract(tmp_path)
    source = root / "src/rigor_foundry/adapters.py"
    if source_change is None:
        source.unlink()
    else:
        source.write_text(source_change, encoding="utf-8")

    assert any(message in error for error in coverage_residual_errors(root))


def test_nested_symbol_drift_fails_closed(tmp_path: Path) -> None:
    """A removed class-owned guard is detected through the public validator."""
    root = _copy_contract(tmp_path)
    document = cast(
        dict[str, object],
        json.loads((root / MANIFEST).read_text(encoding="utf-8")),
    )
    residuals = cast(list[dict[str, Any]], document["residuals"])
    git_residual = next(
        residual for residual in residuals if residual["residual_id"] == "CR-GIT-DESCRIPTOR-ROOT"
    )
    git_residual["symbol"] = "GitRunner.removed_guard"
    _write_document(root, document)

    assert any(
        "coverage residual symbol is unavailable" in error
        for error in coverage_residual_errors(root)
    )


def test_future_review_missing_search_file_and_invalid_root_are_reported(
    tmp_path: Path,
) -> None:
    """Host and lifecycle failures return deterministic public validation evidence."""
    root = _copy_contract(tmp_path)
    document = cast(
        dict[str, object],
        json.loads((root / MANIFEST).read_text(encoding="utf-8")),
    )
    _first_residual(document)["reviewed_on"] = "2026-08-01"
    _first_residual(document)["review_by"] = "2026-08-02"
    missing_search_path = cast(list[str], _first_search(document)["include"])[0]
    (root / missing_search_path).unlink()
    _write_document(root, document)

    errors = coverage_residual_errors(root, today=date(2026, 7, 16))

    assert any("review date is in the future" in error for error in errors)
    assert any("negative-search file is unavailable" in error for error in errors)
    assert any(
        "No such file or directory" in error
        for error in coverage_residual_errors(tmp_path / "absent")
    )
    assert any(
        "canonical repository-relative path" in error
        for error in coverage_residual_errors(root, Path("/absolute.json"))
    )
