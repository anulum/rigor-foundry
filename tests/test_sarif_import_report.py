# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — SARIF import report integrity tests
"""Verify the import report's binding, provenance rule, ordering and tamper refusals."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.candidate_anchor import TrackedBlobAnchor
from rigor_foundry.sarif_import_records import (
    ImportedCandidate,
    ImportObservation,
    ImportSkip,
    LocationMetadata,
    PreservedResult,
)
from rigor_foundry.sarif_import_report import (
    IMPORT_REPORT_SCHEMA,
    ImportReport,
    read_import_report,
    verify_import_report,
)
from rigor_foundry.sarif_import_rules import RunRules, ToolComponent

ROOT = Path(__file__).resolve().parents[1]
REAL_SARIF = ROOT / "tests/fixtures/sarif/canonical-states.sarif"


def _records() -> tuple[tuple[ImportedCandidate, ...], ImportObservation, ImportSkip]:
    """Return candidates, one observation and one skip built from a real exported SARIF run."""
    (run,) = json.loads(REAL_SARIF.read_text(encoding="utf-8"))["runs"]
    rules = RunRules.build("semgrep", run)
    preserved = [
        PreservedResult.build("semgrep", result, rules, run_index=0, result_index=index)
        for index, result in enumerate(run["results"])
    ]
    candidates = sorted(
        (
            ImportedCandidate.build(
                "semgrep",
                TrackedBlobAnchor(
                    path=f"src/pkg/file_{item.result_index}.py",
                    line_start=1,
                    line_end=1,
                    blob_oid="a" * 40,
                    content_sha256="b" * 64,
                ),
                item,
                LocationMetadata(None, None, None, None, False, None, None, False, 1),
            )
            for item in preserved
            if item.is_candidate_kind
        ),
        key=lambda candidate: candidate.candidate_id,
    )
    observed = next(item for item in preserved if not item.is_candidate_kind)
    return (
        tuple(candidates[:2]),
        ImportObservation("semgrep", f"kind-{observed.kind}", observed),
        ImportSkip(0, 99, "untracked-path"),
    )


def _report(**changes: Any) -> ImportReport:
    """Return one declared import report over real records, with optional field changes."""
    candidates, observation, skip = _records()
    fields: dict[str, Any] = {
        "head": "c" * 40,
        "head_tree": "d" * 40,
        "tracked_content_digest": "e" * 64,
        "producer_id": "semgrep",
        "producer_declaration_digest": "f" * 64,
        "driver": ToolComponent("Semgrep OSS", "1.186.0"),
        "provenance": "declared",
        "profile_evidence_digest": None,
        "sarif_sha256": "0" * 64,
        "imported_candidates": candidates,
        "observations": (observation,),
        "skipped": (skip,),
    }
    fields.update(changes)
    return ImportReport(**fields)


def test_a_report_round_trips_and_its_digest_covers_every_field(tmp_path: Path) -> None:
    """The written report reads back verified, with exact counts and a reproducible digest.

    Parameters
    ----------
    tmp_path : Path
        Owned report file allocation.
    """
    report = _report()
    path = tmp_path / "import-report.json"
    path.write_text(report.to_json(), encoding="utf-8")
    verified = read_import_report(path)
    assert verified == json.loads(report.to_json())
    assert verified["schema"] == IMPORT_REPORT_SCHEMA
    assert verified["counts"] == {"imported_candidates": 2, "observations": 1, "skipped": 1}
    assert report.report_digest == _report().report_digest
    assert report.report_digest != _report(head="9" * 40).report_digest
    assert all(
        item["state"] == "unreviewed"
        for item in json.loads(path.read_text(encoding="utf-8"))["imported_candidates"]
    )


def test_provenance_binds_executed_to_evidence_and_declared_to_none() -> None:
    """Executed provenance must cite profile evidence, and declared provenance must not."""
    assert (
        _report(provenance="executed", profile_evidence_digest="1" * 64).provenance == "executed"
    )
    for changes in (
        {"provenance": "executed", "profile_evidence_digest": None},
        {"provenance": "declared", "profile_evidence_digest": "1" * 64},
    ):
        with pytest.raises(ValueError, match="executed provenance, and only it"):
            _report(**changes)
    with pytest.raises(ValueError, match="executed or declared"):
        _report(provenance="verified")
    with pytest.raises(ValueError, match="lower-case slug"):
        _report(producer_id="Semgrep")


def test_candidates_must_be_unique_and_sorted_by_id() -> None:
    """A reversed or repeated candidate sequence is refused."""
    candidates, _, _ = _records()
    for disorder in (tuple(reversed(candidates)), (candidates[0], candidates[0])):
        with pytest.raises(ValueError, match="unique and sorted"):
            _report(imported_candidates=disorder)


def _redigest(document: dict[str, Any]) -> None:
    """Recompute the report digest so that only the targeted check can refuse."""
    document["report_digest"] = canonical_digest(
        {key: value for key, value in document.items() if key != "report_digest"}
    )


def _tamper_digest(document: dict[str, Any]) -> None:
    """Change a field without recomputing the digest."""
    document["head"] = "9" * 40


def _extra_field(document: dict[str, Any]) -> None:
    """Add a field outside the schema."""
    document["verdict"] = "valid"


def _other_schema(document: dict[str, Any]) -> None:
    """Declare another schema and recompute the digest."""
    document["schema"] = "rigor.import-report.v0"
    _redigest(document)


def _wrong_counts(document: dict[str, Any]) -> None:
    """Misstate the candidate count and recompute the digest."""
    document["counts"]["imported_candidates"] = 5
    _redigest(document)


def _forged_candidate_id(document: dict[str, Any]) -> None:
    """Replace a candidate id and recompute the digest."""
    document["imported_candidates"][0]["candidate_id"] = "1" * 64
    _redigest(document)


def _reviewed_candidate(document: dict[str, Any]) -> None:
    """Mark a candidate as decided and recompute the digest."""
    document["imported_candidates"][0]["state"] = "valid"
    _redigest(document)


def _moved_anchor(document: dict[str, Any]) -> None:
    """Move a candidate's anchor without its id and recompute the digest."""
    document["imported_candidates"][0]["anchor"]["line_end"] = 3
    _redigest(document)


def _records_object(document: dict[str, Any]) -> None:
    """Replace the skip list with an object and recompute the digest."""
    document["skipped"] = {}
    _redigest(document)


def _driver_extra_field(document: dict[str, Any]) -> None:
    """Add a field to the driver identity and recompute the digest."""
    document["driver"]["verified"] = True
    _redigest(document)


def _driver_without_version(document: dict[str, Any]) -> None:
    """Replace the driver version with null and recompute the digest."""
    document["driver"]["version"] = None
    _redigest(document)


def _bad_digest(document: dict[str, Any]) -> None:
    """Write a non-hex report digest."""
    document["report_digest"] = "x" * 64


REFUSALS: tuple[tuple[Callable[[dict[str, Any]], None], str], ...] = (
    (_tamper_digest, "digest does not match its fields"),
    (_extra_field, "fields do not match the schema"),
    (_other_schema, "schema must be rigor.import-report.v1"),
    (_wrong_counts, "counts do not match its records"),
    (_forged_candidate_id, "candidate id does not match its recorded identity"),
    (_reviewed_candidate, "must be unreviewed and from the producer"),
    (_moved_anchor, "candidate id does not match its recorded identity"),
    (_records_object, "must be arrays"),
    (_driver_extra_field, "driver fields do not match the schema"),
    (_driver_without_version, "driver name and version must be strings"),
    (_bad_digest, "lower-case SHA-256 digest"),
)


@pytest.mark.parametrize(
    ("alter", "message"), REFUSALS, ids=[item[0].__name__ for item in REFUSALS]
)
def test_a_changed_report_is_refused(
    alter: Callable[[dict[str, Any]], None], message: str
) -> None:
    """Each field change, forged identity or decided state is refused on verification.

    Parameters
    ----------
    alter : Callable[[dict[str, Any]], None]
        Changes one fact of the serialised report.
    message : str
        Text the refusal must contain.
    """
    document = json.loads(_report().to_json())
    assert verify_import_report(json.loads(_report().to_json())) == document
    alter(document)
    with pytest.raises(ValueError, match=message):
        verify_import_report(document)


def test_a_report_file_that_is_not_json_is_refused(tmp_path: Path) -> None:
    """A broken report file is refused before verification.

    Parameters
    ----------
    tmp_path : Path
        Owned report file allocation.
    """
    path = tmp_path / "import-report.json"
    path.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match="not JSON"):
        read_import_report(path)
