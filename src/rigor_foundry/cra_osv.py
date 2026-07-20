# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — CRA OSV awareness evidence bridge
"""Bind an exact complete offline OSV adapter finding to CRA awareness evidence."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .adapters import AdapterResult
from .audit_primitives import canonical_digest, require_exact_fields
from .cra_protocol import CRA_SCHEMA_VERSION, JsonObject, json_text, require_cra_timestamp
from .cra_sbom import read_import_file
from .model_primitives import require_digest
from .models import require_mapping, require_string

MAX_OSV_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_ADAPTER_RESULT_BYTES = 1024 * 1024
MAX_OSV_RESULTS = 10_000
MAX_OSV_PACKAGES = 100_000
MAX_OSV_FINDINGS = 500_000

_FIELDS = frozenset(
    {
        "schema_version",
        "profile",
        "adapter_result_digest",
        "profile_evidence_digest",
        "adapter_output_sha256",
        "tool_version",
        "external_id",
        "package_name",
        "package_version",
        "package_ecosystem",
        "source_path",
        "imported_at",
        "awareness_digest",
    }
)


def _strict_json(payload: bytes, label: str) -> object:
    """Decode strict UTF-8 JSON without duplicate keys or non-finite values."""

    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ValueError(f"{label} contains a non-finite number: {value}")

    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=unique_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not complete strict UTF-8 JSON") from exc


@dataclass(frozen=True, order=True)
class _OsvFinding:
    """Carry one exact OSV result tuple selected from retained adapter output."""

    external_id: str
    package_name: str
    package_version: str
    package_ecosystem: str
    source_path: str


def _osv_findings(document: object) -> tuple[tuple[_OsvFinding, ...], int]:
    """Parse bounded OSV-Scanner output and return findings plus source count."""
    data = require_mapping(document, "OSV output")
    results = data.get("results")
    if not isinstance(results, list):
        raise ValueError("OSV results must be an array")
    if len(results) > MAX_OSV_RESULTS:
        raise ValueError("OSV results exceed the import limit")
    findings: list[_OsvFinding] = []
    sources: set[str] = set()
    package_count = 0
    for result_index, raw_result in enumerate(results):
        field = f"OSV output.results[{result_index}]"
        result = require_mapping(raw_result, field)
        source = require_mapping(result.get("source"), f"{field}.source")
        source_path = require_string(source.get("path"), f"{field}.source.path")
        if source.get("type") != "lockfile":
            raise ValueError(f"{field}.source.type must be lockfile")
        raw_packages = result.get("packages")
        if not isinstance(raw_packages, list):
            raise ValueError(f"{field}.packages must be an array")
        sources.add(source_path)
        package_count += len(raw_packages)
        if package_count > MAX_OSV_PACKAGES:
            raise ValueError("OSV packages exceed the import limit")
        for package_index, raw_package in enumerate(raw_packages):
            package_field = f"{field}.packages[{package_index}]"
            package_result = require_mapping(raw_package, package_field)
            package = require_mapping(package_result.get("package"), f"{package_field}.package")
            name = require_string(package.get("name"), f"{package_field}.package.name")
            version = require_string(package.get("version"), f"{package_field}.package.version")
            ecosystem = require_string(
                package.get("ecosystem"), f"{package_field}.package.ecosystem"
            )
            raw_vulnerabilities = package_result.get("vulnerabilities", [])
            if not isinstance(raw_vulnerabilities, list):
                raise ValueError(f"{package_field}.vulnerabilities must be an array")
            for vulnerability_index, raw_vulnerability in enumerate(raw_vulnerabilities):
                vulnerability = require_mapping(
                    raw_vulnerability,
                    f"{package_field}.vulnerabilities[{vulnerability_index}]",
                )
                findings.append(
                    _OsvFinding(
                        external_id=require_string(
                            vulnerability.get("id"),
                            f"{package_field}.vulnerabilities[{vulnerability_index}].id",
                        ),
                        package_name=name,
                        package_version=version,
                        package_ecosystem=ecosystem,
                        source_path=source_path,
                    )
                )
                if len(findings) > MAX_OSV_FINDINGS:
                    raise ValueError("OSV findings exceed the import limit")
    return tuple(findings), len(sources)


@dataclass(frozen=True)
class OsvAwarenessEvidence:
    """Record one exact OSV finding as awareness, never exploitation proof."""

    profile: str
    adapter_result_digest: str
    profile_evidence_digest: str
    adapter_output_sha256: str
    tool_version: str
    external_id: str
    package_name: str
    package_version: str
    package_ecosystem: str
    source_path: str
    imported_at: str
    awareness_digest: str

    @property
    def component_ref(self) -> str:
        """Return a deterministic human-readable affected-component reference."""
        return f"{self.package_ecosystem}:{self.package_name}@{self.package_version}"

    @classmethod
    def build(
        cls,
        *,
        adapter_result_digest: str,
        profile_evidence_digest: str,
        adapter_output_sha256: str,
        tool_version: str,
        finding: _OsvFinding,
        imported_at: str,
    ) -> OsvAwarenessEvidence:
        """Build a digest-bound awareness record from one selected finding."""
        body: JsonObject = {
            "schema_version": CRA_SCHEMA_VERSION,
            "profile": "osv-lockfile-offline-json-v1",
            "adapter_result_digest": require_digest(
                adapter_result_digest, "adapter_result_digest"
            ),
            "profile_evidence_digest": require_digest(
                profile_evidence_digest, "profile_evidence_digest"
            ),
            "adapter_output_sha256": require_digest(
                adapter_output_sha256, "adapter_output_sha256"
            ),
            "tool_version": require_string(tool_version, "tool_version"),
            "external_id": require_string(finding.external_id, "external_id"),
            "package_name": require_string(finding.package_name, "package_name"),
            "package_version": require_string(finding.package_version, "package_version"),
            "package_ecosystem": require_string(finding.package_ecosystem, "package_ecosystem"),
            "source_path": require_string(finding.source_path, "source_path"),
            "imported_at": require_cra_timestamp(imported_at, "imported_at"),
        }
        return cls(
            profile="osv-lockfile-offline-json-v1",
            adapter_result_digest=cast(str, body["adapter_result_digest"]),
            profile_evidence_digest=cast(str, body["profile_evidence_digest"]),
            adapter_output_sha256=cast(str, body["adapter_output_sha256"]),
            tool_version=cast(str, body["tool_version"]),
            external_id=cast(str, body["external_id"]),
            package_name=cast(str, body["package_name"]),
            package_version=cast(str, body["package_version"]),
            package_ecosystem=cast(str, body["package_ecosystem"]),
            source_path=cast(str, body["source_path"]),
            imported_at=cast(str, body["imported_at"]),
            awareness_digest=canonical_digest(body),
        )

    def to_dict(self) -> JsonObject:
        """Serialise exact OSV awareness evidence."""
        return {
            "schema_version": CRA_SCHEMA_VERSION,
            "profile": self.profile,
            "adapter_result_digest": self.adapter_result_digest,
            "profile_evidence_digest": self.profile_evidence_digest,
            "adapter_output_sha256": self.adapter_output_sha256,
            "tool_version": self.tool_version,
            "external_id": self.external_id,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "package_ecosystem": self.package_ecosystem,
            "source_path": self.source_path,
            "imported_at": self.imported_at,
            "awareness_digest": self.awareness_digest,
        }

    def to_json(self) -> str:
        """Serialise deterministic human-readable JSON."""
        return json_text(self.to_dict())

    @classmethod
    def from_dict(cls, value: object) -> OsvAwarenessEvidence:
        """Parse and integrity-check one awareness record."""
        data = require_mapping(value, "osv_awareness")
        require_exact_fields(data, _FIELDS, "osv_awareness")
        if data.get("schema_version") != CRA_SCHEMA_VERSION:
            raise ValueError("osv_awareness schema_version is unsupported")
        if data.get("profile") != "osv-lockfile-offline-json-v1":
            raise ValueError("osv_awareness profile is unsupported")
        finding = _OsvFinding(
            external_id=require_string(data.get("external_id"), "external_id"),
            package_name=require_string(data.get("package_name"), "package_name"),
            package_version=require_string(data.get("package_version"), "package_version"),
            package_ecosystem=require_string(data.get("package_ecosystem"), "package_ecosystem"),
            source_path=require_string(data.get("source_path"), "source_path"),
        )
        expected = cls.build(
            adapter_result_digest=require_digest(
                data.get("adapter_result_digest"), "adapter_result_digest"
            ),
            profile_evidence_digest=require_digest(
                data.get("profile_evidence_digest"), "profile_evidence_digest"
            ),
            adapter_output_sha256=require_digest(
                data.get("adapter_output_sha256"), "adapter_output_sha256"
            ),
            tool_version=require_string(data.get("tool_version"), "tool_version"),
            finding=finding,
            imported_at=require_string(data.get("imported_at"), "imported_at"),
        )
        if (
            require_digest(data.get("awareness_digest"), "awareness_digest")
            != expected.awareness_digest
        ):
            raise ValueError("osv_awareness digest does not match its content")
        return expected


@dataclass(frozen=True)
class ImportedOsvAwareness:
    """Carry a verified record and the exact retained source bytes."""

    evidence: OsvAwarenessEvidence
    adapter_result_text: str
    output_text: str


def import_osv_awareness(
    *,
    adapter_result_path: Path,
    output_path: Path,
    external_id: str,
    package_name: str,
    imported_at: str,
) -> ImportedOsvAwareness:
    """Import one explicit OSV finding bound to complete G1 adapter evidence."""
    adapter_payload, _ = read_import_file(
        adapter_result_path,
        maximum_bytes=MAX_ADAPTER_RESULT_BYTES,
        label="OSV adapter result",
    )
    output_payload, output_digest = read_import_file(
        output_path,
        maximum_bytes=MAX_OSV_OUTPUT_BYTES,
        label="OSV adapter output",
    )
    adapter_value = _strict_json(adapter_payload, "OSV adapter result")
    result = AdapterResult.from_dict(adapter_value)
    profile = result.profile_evidence
    if (
        profile is None
        or profile.profile != "osv-lockfile-offline-json-v1"
        or not result.complete
        or profile.status != "findings"
    ):
        raise ValueError("OSV adapter result must contain complete findings evidence")
    if output_digest != result.output_digest or output_digest != profile.output_digest:
        raise ValueError("OSV output bytes do not match adapter evidence")
    if len(output_payload) != result.output_bytes:
        raise ValueError("OSV output byte count does not match adapter evidence")
    findings, source_count = _osv_findings(_strict_json(output_payload, "OSV adapter output"))
    if len(findings) != profile.finding_count or source_count != profile.scanned_target_count:
        raise ValueError("OSV output counts do not match adapter profile evidence")
    matches = tuple(
        finding
        for finding in findings
        if finding.external_id == external_id and finding.package_name == package_name
    )
    if len(matches) != 1:
        raise ValueError("OSV identity and package must select exactly one finding")
    evidence = OsvAwarenessEvidence.build(
        adapter_result_digest=canonical_digest(result.to_dict()),
        profile_evidence_digest=profile.evidence_digest,
        adapter_output_sha256=output_digest,
        tool_version=profile.tool_version,
        finding=matches[0],
        imported_at=imported_at,
    )
    return ImportedOsvAwareness(
        evidence,
        json_text(result.to_dict()),
        output_payload.decode("utf-8"),
    )
