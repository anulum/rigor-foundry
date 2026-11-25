# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — the binding of an executed SARIF second output to its JSON profile run
"""Bind a SARIF second output to the JSON profile run that wrote it, or refuse the binding.

The JSON profile evidence stays the execution authority. A binding record is built only when
that evidence is complete, the run scanned the tracked content the SARIF is anchored against,
its output digest matches the exact JSON and error bytes, the reported version is one exact
release equal to the SARIF driver's, and the SARIF findings agree with the JSON findings as a
multiset of rule id, resolved tracked path and start line. The record also names the bounded
launch that wrote both outputs. The evidence never appears outside this record.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from typing import Final, cast

from .adapter_profiles import AdapterProfileEvidence, _strict_json
from .adapter_runtime import process_output_digest
from .audit_primitives import canonical_digest, require_exact_fields, require_mapping
from .sarif_import_document import SarifImportRefused
from .sarif_import_execution import FILE_SIZE_CAP, LAUNCH_VECTOR_VERSION, ImportRun
from .sarif_import_producers import _VERSION
from .sarif_import_profile import ImportProfile, import_profile_by_name
from .sarif_import_report import ImportReport

BINDING_SCHEMA: Final = "rigor.executed-sarif-binding.v1"
_COMPLETE: Final = frozenset({"clean", "findings"})
_FIELDS: Final = frozenset(
    {
        "schema",
        "import_profile",
        "import_profile_digest",
        "evidence",
        "tracked_content_digest",
        "launch_vector",
        "stdout_sha256",
        "stdout_bytes",
        "stderr_sha256",
        "stderr_bytes",
        "sarif_sha256",
        "sarif_bytes",
        "driver_version",
        "consistent_findings",
        "binding_digest",
    }
)
_VECTOR_FIELDS: Final = frozenset({"version", "launcher_identity", "file_size_cap"})
_DIGEST: Final = re.compile(r"[0-9a-f]{64}")
Finding = tuple[str, str, int]


def exact_version(tool_version: str, driver_version: str | None) -> str:
    """Return the one exact release that both the tool and the SARIF driver report.

    Parameters
    ----------
    tool_version : str
        The normalised ``--version`` output of the profile run.
    driver_version : str | None
        The version the SARIF driver states.

    Returns
    -------
    str
        The shared release.

    Raises
    ------
    SarifImportRefused
        With ``version-mismatch`` unless the tool printed exactly one line that is a
        ``MAJOR.MINOR.PATCH`` release equal to the driver's version.
    """
    if _VERSION.fullmatch(tool_version) is None or tool_version != driver_version:
        raise SarifImportRefused("version-mismatch", "the tool and the driver name no one release")
    return tool_version


def json_findings(stdout: bytes) -> Counter[Finding]:
    """Return the multiset of rule id, path and start line in Semgrep's JSON output.

    Parameters
    ----------
    stdout : bytes
        The JSON profile run's exact standard output.

    Returns
    -------
    Counter[Finding]
        How often each finding occurs.

    Raises
    ------
    ValueError
        If the output is not Semgrep's strict JSON with typed results.
    """
    document = require_mapping(_strict_json(stdout), "semgrep output")
    results = document.get("results")
    if not isinstance(results, list):
        raise ValueError("Semgrep JSON results are not an array")
    findings: Counter[Finding] = Counter()
    for item in cast(list[object], results):
        result = require_mapping(item, "semgrep result")
        start = result.get("start")
        line = start.get("line") if isinstance(start, dict) else None
        rule, path = result.get("check_id"), result.get("path")
        if not isinstance(rule, str) or not isinstance(path, str) or type(line) is not int:
            raise ValueError("a Semgrep JSON result lacks its rule, path or line")
        findings[(rule, path, line)] += 1
    return findings


def sarif_findings(report: ImportReport) -> Counter[Finding]:
    """Return the multiset of raw rule id, resolved tracked path and start line of the import.

    Parameters
    ----------
    report : ImportReport
        The import of the SARIF second output.

    Returns
    -------
    Counter[Finding]
        How often each anchored candidate occurs.
    """
    prefix = f"ext:{report.producer_id}:"
    return Counter(
        (
            candidate.result.rule_id.removeprefix(prefix),
            candidate.anchor.path,
            candidate.anchor.line_start,
        )
        for candidate in report.imported_candidates
    )


@dataclass(frozen=True)
class ExecutedSarifBinding:
    """The record that binds one SARIF second output to its complete JSON profile run."""

    import_profile: ImportProfile
    evidence: AdapterProfileEvidence
    tracked_content_digest: str
    launch_vector: dict[str, object]
    stdout_sha256: str
    stdout_bytes: int
    stderr_sha256: str
    stderr_bytes: int
    sarif_sha256: str
    sarif_bytes: int
    driver_version: str
    consistent_findings: int

    def _body(self) -> dict[str, object]:
        """Return every field the binding digest covers."""
        return {
            "schema": BINDING_SCHEMA,
            "import_profile": self.import_profile.name,
            "import_profile_digest": self.import_profile.profile_digest,
            "evidence": self.evidence.to_dict(),
            "tracked_content_digest": self.tracked_content_digest,
            "launch_vector": self.launch_vector,
            "stdout_sha256": self.stdout_sha256,
            "stdout_bytes": self.stdout_bytes,
            "stderr_sha256": self.stderr_sha256,
            "stderr_bytes": self.stderr_bytes,
            "sarif_sha256": self.sarif_sha256,
            "sarif_bytes": self.sarif_bytes,
            "driver_version": self.driver_version,
            "consistent_findings": self.consistent_findings,
        }

    @property
    def binding_digest(self) -> str:
        """Return the digest over every binding field."""
        return canonical_digest(self._body())

    def to_dict(self) -> dict[str, object]:
        """Serialise the binding with its digest."""
        return {**self._body(), "binding_digest": self.binding_digest}

    def to_json(self) -> str:
        """Render deterministic JSON with a trailing newline."""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def complete_output_digest(stdout: bytes, stderr: bytes) -> str:
    """Return the process output digest of one complete run, untruncated and in time.

    Parameters
    ----------
    stdout : bytes
        Every byte the run wrote to standard output.
    stderr : bytes
        Every byte the run wrote to standard error.

    Returns
    -------
    str
        The digest that ``stream_process`` records for that output.
    """
    return process_output_digest(
        stdout_digest=hashlib.sha256(stdout).hexdigest(),
        stdout_bytes=len(stdout),
        stderr_digest=hashlib.sha256(stderr).hexdigest(),
        stderr_bytes=len(stderr),
        truncated=False,
        timed_out=False,
    )


def bind_executed_sarif(run: ImportRun, *, report: ImportReport) -> ExecutedSarifBinding:
    """Bind a SARIF second output to its JSON profile run, or refuse the binding.

    Parameters
    ----------
    run : ImportRun
        One complete import-profile run: its profile, JSON evidence, exact output, second
        output, scanned tracked content and bounded launch.
    report : ImportReport
        The import of the run's SARIF against the inventory it is anchored against.

    Returns
    -------
    ExecutedSarifBinding
        The binding record.

    Raises
    ------
    SarifImportRefused
        With ``other-evidence``, ``other-content``, ``incomplete-evidence``,
        ``output-mismatch``, ``sarif-mismatch``, ``version-mismatch`` or
        ``inconsistent-second-output``.
    """
    profile, evidence, stdout, stderr = run.profile, run.evidence, run.stdout, run.stderr
    if (evidence.profile, evidence.profile_digest) != (
        profile.base.name,
        profile.base.profile_digest,
    ) or report.producer_id != profile.producer_id:
        raise SarifImportRefused("other-evidence", "the evidence is not this profile's base run")
    if run.tracked_content_digest != report.tracked_content_digest:
        raise SarifImportRefused(
            "other-content", "the run scanned other tracked content than the SARIF is anchored to"
        )
    if evidence.status not in _COMPLETE:
        raise SarifImportRefused("incomplete-evidence", "only a complete run is bound")
    if evidence.output_digest != complete_output_digest(stdout, stderr):
        raise SarifImportRefused("output-mismatch", "the JSON bytes are not the run's output")
    if report.sarif_sha256 != hashlib.sha256(run.sarif).hexdigest():
        raise SarifImportRefused("sarif-mismatch", "the report imports other SARIF bytes")
    version = exact_version(evidence.tool_version, report.driver.version)
    expected = json_findings(stdout)
    if expected != sarif_findings(report) or evidence.finding_count != expected.total():
        raise SarifImportRefused("inconsistent-second-output", "SARIF and JSON findings differ")
    return ExecutedSarifBinding(
        import_profile=profile,
        evidence=evidence,
        tracked_content_digest=run.tracked_content_digest,
        launch_vector=run.launch_vector,
        stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stdout_bytes=len(stdout),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        stderr_bytes=len(stderr),
        sarif_sha256=report.sarif_sha256,
        sarif_bytes=len(run.sarif),
        driver_version=version,
        consistent_findings=expected.total(),
    )


def _require_digest(value: object, field: str) -> None:
    """Refuse a value that is not one lowercase SHA-256 hex digest."""
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"the binding's {field} is not a SHA-256 digest")


def verify_executed_binding(value: object) -> dict[str, object]:
    """Verify one serialised binding's fields, profile digest, evidence and digest.

    Parameters
    ----------
    value : object
        A decoded binding record.

    Returns
    -------
    dict[str, object]
        The verified fields.

    Raises
    ------
    ValueError
        If a field is missing or extra, the schema differs, the import profile digest is not
        the built-in profile's, the evidence does not verify or names another profile, the
        tracked content digest is not a digest, the launch vector is not the bounded import
        launch, or the binding digest differs.
    """
    data = require_mapping(value, "executed SARIF binding")
    require_exact_fields(data, _FIELDS, "executed SARIF binding")
    if data["schema"] != BINDING_SCHEMA:
        raise ValueError(f"the binding schema must be {BINDING_SCHEMA}")
    profile = import_profile_by_name(data["import_profile"])
    if data["import_profile_digest"] != profile.profile_digest:
        raise ValueError("the import profile digest is not the built-in profile's")
    evidence = AdapterProfileEvidence.from_dict(data["evidence"])
    if (evidence.profile, evidence.profile_digest) != (
        profile.base.name,
        profile.base.profile_digest,
    ):
        raise ValueError("the binding's evidence names another profile")
    _require_digest(data["tracked_content_digest"], "tracked content digest")
    vector = require_mapping(data["launch_vector"], "launch vector")
    require_exact_fields(vector, _VECTOR_FIELDS, "launch vector")
    cap = vector["file_size_cap"]
    if vector["version"] != LAUNCH_VECTOR_VERSION or type(cap) is not int or cap != FILE_SIZE_CAP:
        raise ValueError("the launch vector is not the bounded import launch")
    _require_digest(vector["launcher_identity"], "launcher identity")
    body = {key: item for key, item in data.items() if key != "binding_digest"}
    if data["binding_digest"] != canonical_digest(body):
        raise ValueError("the binding digest does not match its fields")
    return data


def verify_executed_import(report: dict[str, object], binding: dict[str, object]) -> None:
    """Verify that one executed import report and one binding record belong together.

    Parameters
    ----------
    report : dict[str, object]
        A report that ``verify_import_report`` accepted.
    binding : dict[str, object]
        A binding that ``verify_executed_binding`` accepted.

    Raises
    ------
    ValueError
        Unless the report is executed, cites the binding's digest, imports the bound SARIF
        bytes, is anchored against the tracked content the run scanned, states the bound
        driver version, and comes from the import profile's producer.
    """
    driver = require_mapping(report["driver"], "driver")
    profile = import_profile_by_name(binding["import_profile"])
    if report["provenance"] != "executed":
        raise ValueError("the report's provenance is not executed")
    if report["profile_evidence_digest"] != binding["binding_digest"]:
        raise ValueError("the report does not cite this binding")
    if report["sarif_sha256"] != binding["sarif_sha256"]:
        raise ValueError("the report imports other SARIF bytes than the binding names")
    if report["tracked_content_digest"] != binding["tracked_content_digest"]:
        raise ValueError("the report is anchored against other tracked content than the run")
    if driver["version"] != binding["driver_version"]:
        raise ValueError("the report's driver version is not the bound version")
    if report["producer_id"] != profile.producer_id:
        raise ValueError("the report's producer is not the import profile's producer")
