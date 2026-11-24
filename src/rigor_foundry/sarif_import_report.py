# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — the import report of one third-party SARIF file
"""Bind imported candidates, observations and skips to one commit, producer and SARIF file.

The import report is a separate artefact from the audit report. It never changes the rule
registry, the rule-pack digest or any audit report, and its candidates stay ``unreviewed``.
Its integrity digest covers every field, and loading it recomputes that digest and every
candidate identifier.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, cast

from .audit_primitives import (
    canonical_digest,
    require_exact_fields,
    require_mapping,
    require_string,
)
from .sarif_import_records import (
    IMPORT_STATE,
    ImportedCandidate,
    ImportObservation,
    ImportSkip,
    anchor_from_record,
    require_producer_id,
)

IMPORT_REPORT_SCHEMA: Final = "rigor.import-report.v1"
Provenance = Literal["executed", "declared"]
_FIELDS: Final = frozenset(
    {
        "schema",
        "head",
        "head_tree",
        "tracked_content_digest",
        "producer_id",
        "producer_declaration_digest",
        "provenance",
        "profile_evidence_digest",
        "sarif_sha256",
        "imported_candidates",
        "observations",
        "skipped",
        "counts",
        "report_digest",
    }
)


def _sha256(value: object, field: str) -> str:
    """Return one lower-case SHA-256 digest, or refuse the field."""
    digest = require_string(value, field)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError(f"{field} must be a lower-case SHA-256 digest")
    return digest


@dataclass(frozen=True)
class ImportReport:
    """One import of one producer's SARIF file into anchored, unreviewed records."""

    head: str
    head_tree: str
    tracked_content_digest: str
    producer_id: str
    producer_declaration_digest: str
    provenance: Provenance
    profile_evidence_digest: str | None
    sarif_sha256: str
    imported_candidates: tuple[ImportedCandidate, ...]
    observations: tuple[ImportObservation, ...]
    skipped: tuple[ImportSkip, ...]

    def __post_init__(self) -> None:
        """Refuse a provenance claim that its evidence does not back."""
        require_producer_id(self.producer_id)
        if self.provenance not in ("executed", "declared"):
            raise ValueError("provenance must be executed or declared")
        if (self.provenance == "executed") != (self.profile_evidence_digest is not None):
            raise ValueError("executed provenance, and only it, cites adapter profile evidence")
        ids = [candidate.candidate_id for candidate in self.imported_candidates]
        if ids != sorted(ids) or len(ids) != len(set(ids)):
            raise ValueError("imported candidates must be unique and sorted by id")

    @property
    def counts(self) -> dict[str, int]:
        """Return the number of candidates, observations and skipped results."""
        return {
            "imported_candidates": len(self.imported_candidates),
            "observations": len(self.observations),
            "skipped": len(self.skipped),
        }

    def _body(self) -> dict[str, object]:
        """Return every field that the report digest covers."""
        return {
            "schema": IMPORT_REPORT_SCHEMA,
            "head": self.head,
            "head_tree": self.head_tree,
            "tracked_content_digest": self.tracked_content_digest,
            "producer_id": self.producer_id,
            "producer_declaration_digest": self.producer_declaration_digest,
            "provenance": self.provenance,
            "profile_evidence_digest": self.profile_evidence_digest,
            "sarif_sha256": self.sarif_sha256,
            "imported_candidates": [item.to_dict() for item in self.imported_candidates],
            "observations": [item.to_dict() for item in self.observations],
            "skipped": [item.to_dict() for item in self.skipped],
            "counts": self.counts,
        }

    @property
    def report_digest(self) -> str:
        """Return the integrity digest over every report field."""
        return canonical_digest(self._body())

    def to_dict(self) -> dict[str, object]:
        """Serialise the report with its integrity digest."""
        return {**self._body(), "report_digest": self.report_digest}

    def to_json(self) -> str:
        """Render deterministic human-readable JSON with a trailing newline."""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def verify_import_report(value: object) -> dict[str, object]:
    """Verify a serialised import report's digest, fields and every candidate identifier.

    Parameters
    ----------
    value : object
        A decoded import report.

    Returns
    -------
    dict[str, object]
        The verified report fields.

    Raises
    ------
    ValueError
        If any field is missing or extra, the schema or a digest differs, a count disagrees,
        or a candidate's identifier does not match its recorded producer, rule, anchor,
        message digest and partial fingerprints.
    """
    data = require_mapping(value, "import report")
    require_exact_fields(data, _FIELDS, "import report")
    if data["schema"] != IMPORT_REPORT_SCHEMA:
        raise ValueError(f"import report schema must be {IMPORT_REPORT_SCHEMA}")
    body = {key: item for key, item in data.items() if key != "report_digest"}
    if _sha256(data["report_digest"], "report_digest") != canonical_digest(body):
        raise ValueError("import report digest does not match its fields")
    producer = require_producer_id(data["producer_id"])
    lists = {name: data[name] for name in ("imported_candidates", "observations", "skipped")}
    if not all(isinstance(items, list) for items in lists.values()):
        raise ValueError("candidates, observations and skips must be arrays")
    counts = require_mapping(data["counts"], "counts")
    if counts != {name: len(cast(list[object], items)) for name, items in lists.items()}:
        raise ValueError("import report counts do not match its records")
    for item in cast(list[object], lists["imported_candidates"]):
        record = require_mapping(item, "imported candidate")
        result = require_mapping(record.get("result"), "imported candidate result")
        if record.get("state") != IMPORT_STATE or record.get("producer_id") != producer:
            raise ValueError("an imported candidate must be unreviewed and from the producer")
        identity = {
            "producer_id": producer,
            "rule_id": result.get("rule_id"),
            "anchor": anchor_from_record(record.get("anchor")).to_dict(),
            "message_text_sha256": result.get("message_text_sha256"),
            "partial_fingerprints_sha256": result.get("partial_fingerprints_sha256"),
        }
        if record.get("candidate_id") != canonical_digest(identity):
            raise ValueError("an imported candidate id does not match its recorded identity")
    return data


def read_import_report(path: Path) -> dict[str, object]:
    """Read and verify one import report file.

    Parameters
    ----------
    path : Path
        An import report written by ``ImportReport.to_json``.

    Returns
    -------
    dict[str, object]
        The verified report fields.

    Raises
    ------
    ValueError
        If the file is not JSON or fails ``verify_import_report``.
    """
    try:
        decoded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError("import report is not JSON") from error
    return verify_import_report(decoded)
