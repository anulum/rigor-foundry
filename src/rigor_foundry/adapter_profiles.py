# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — verified built-in adapter profiles
"""Define immutable Semgrep and Trivy execution and evidence contracts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Literal, cast

from .audit_primitives import canonical_digest, require_integer, require_mapping, require_string

ProfileName = Literal["semgrep-local-json-v1", "trivy-repository-json-v1"]
ProfileStatus = Literal["clean", "findings", "partial", "unavailable"]
ProfileReason = Literal[
    "clean",
    "findings",
    "executable-unavailable",
    "invalid-output",
    "invalid-returncode",
    "no-scanned-targets",
    "output-truncated",
    "scan-errors",
    "timed-out",
    "version-unavailable",
]

PROFILE_EVIDENCE_SCHEMA_VERSION = "1.0"
_PROFILE_EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
        "profile",
        "profile_digest",
        "status",
        "reason",
        "tool_version",
        "version_output_digest",
        "configuration_digest",
        "input_digest",
        "output_digest",
        "finding_count",
        "scanned_target_count",
        "evidence_digest",
    }
)


def _digest(value: object, field: str) -> str:
    """Return one validated lowercase SHA-256 digest."""
    digest = require_string(value, field)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return digest


def _strict_json(payload: bytes) -> object:
    """Decode bounded UTF-8 JSON while rejecting duplicate and non-finite values."""

    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("adapter output contains duplicate JSON keys")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ValueError(f"adapter output contains non-finite number: {value}")

    try:
        text = payload.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=unique_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("adapter output is not strict UTF-8 JSON") from exc


@dataclass(frozen=True)
class AdapterProfile:
    """Immutable command, parser, and domain ownership for one built-in tool."""

    name: ProfileName
    executable: str
    version_arguments: tuple[str, ...]
    domains: tuple[str, ...]
    parser: Literal["semgrep", "trivy"]

    @property
    def profile_digest(self) -> str:
        """Return the canonical identity of the complete built-in profile."""
        return canonical_digest(
            {
                "name": self.name,
                "executable": self.executable,
                "version_arguments": list(self.version_arguments),
                "domains": list(self.domains),
                "parser": self.parser,
                "command_contract": list(self.command_arguments("CONFIG", ("TARGET",))),
            }
        )

    def command_arguments(
        self,
        configuration_path: str,
        target_paths: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Return fixed arguments for one configuration and exact target set."""
        if self.parser == "semgrep":
            return (
                "scan",
                "--config",
                configuration_path,
                "--json",
                "--error",
                "--metrics",
                "off",
                "--disable-version-check",
                "--no-rewrite-rule-ids",
                *target_paths,
            )
        if len(target_paths) != 1:
            raise ValueError("the Trivy repository profile requires exactly one target")
        return (
            "filesystem",
            "--config",
            configuration_path,
            "--format",
            "json",
            "--exit-code",
            "1",
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-check-update",
            "--offline-scan",
            "--scanners",
            "misconfig,secret",
            "--include-non-failures",
            target_paths[0],
        )


_PROFILES: dict[ProfileName, AdapterProfile] = {
    "semgrep-local-json-v1": AdapterProfile(
        name="semgrep-local-json-v1",
        executable="semgrep",
        version_arguments=("--version",),
        domains=("application-security",),
        parser="semgrep",
    ),
    "trivy-repository-json-v1": AdapterProfile(
        name="trivy-repository-json-v1",
        executable="trivy",
        version_arguments=("--version",),
        domains=("application-security",),
        parser="trivy",
    ),
}


def profile_by_name(value: object, field: str = "profile") -> AdapterProfile:
    """Return one named built-in profile or reject unsupported values."""
    name = require_string(value, field)
    if name not in _PROFILES:
        raise ValueError(f"{field} is unsupported")
    return _PROFILES[name]


@dataclass(frozen=True)
class AdapterProfileEvidence:
    """Content-addressed interpretation of one built-in adapter execution."""

    profile: ProfileName
    profile_digest: str
    status: ProfileStatus
    reason: ProfileReason
    tool_version: str
    version_output_digest: str
    configuration_digest: str
    input_digest: str
    output_digest: str
    finding_count: int
    scanned_target_count: int
    evidence_digest: str

    @property
    def complete(self) -> bool:
        """Return whether the tool produced interpretable scan evidence."""
        return self.status in {"clean", "findings"}

    @property
    def passed(self) -> bool:
        """Return whether complete evidence contains no findings."""
        return self.status == "clean"

    @classmethod
    def build(
        cls,
        *,
        profile: AdapterProfile,
        status: ProfileStatus,
        reason: ProfileReason,
        tool_version: str,
        version_output_digest: str,
        configuration_digest: str,
        input_digest: str,
        output_digest: str,
        finding_count: int,
        scanned_target_count: int,
    ) -> AdapterProfileEvidence:
        """Build evidence after validating every static status relation."""
        fields = {
            "schema_version": PROFILE_EVIDENCE_SCHEMA_VERSION,
            "profile": profile.name,
            "profile_digest": profile.profile_digest,
            "status": status,
            "reason": reason,
            "tool_version": tool_version,
            "version_output_digest": version_output_digest,
            "configuration_digest": configuration_digest,
            "input_digest": input_digest,
            "output_digest": output_digest,
            "finding_count": finding_count,
            "scanned_target_count": scanned_target_count,
        }
        return cls._from_fields(fields, canonical_digest(fields))

    @classmethod
    def _from_fields(
        cls,
        fields: dict[str, object],
        evidence_digest: str,
    ) -> AdapterProfileEvidence:
        """Construct one validated record from canonical fields."""
        profile = profile_by_name(fields.get("profile"), "profile_evidence.profile")
        status_value = require_string(fields.get("status"), "profile_evidence.status")
        reason_value = require_string(fields.get("reason"), "profile_evidence.reason")
        statuses = {"clean", "findings", "partial", "unavailable"}
        reasons = {
            "clean",
            "findings",
            "executable-unavailable",
            "invalid-output",
            "invalid-returncode",
            "no-scanned-targets",
            "output-truncated",
            "scan-errors",
            "timed-out",
            "version-unavailable",
        }
        if status_value not in statuses or reason_value not in reasons:
            raise ValueError("profile evidence status or reason is unsupported")
        status = cast(ProfileStatus, status_value)
        reason = cast(ProfileReason, reason_value)
        finding_count = require_integer(
            fields.get("finding_count"), "profile_evidence.finding_count", minimum=0
        )
        scanned_target_count = require_integer(
            fields.get("scanned_target_count"),
            "profile_evidence.scanned_target_count",
            minimum=0,
        )
        expected_reason: dict[ProfileStatus, frozenset[ProfileReason]] = {
            "clean": frozenset({"clean"}),
            "findings": frozenset({"findings"}),
            "partial": frozenset(
                {
                    "invalid-output",
                    "invalid-returncode",
                    "no-scanned-targets",
                    "output-truncated",
                    "scan-errors",
                    "timed-out",
                }
            ),
            "unavailable": frozenset({"executable-unavailable", "version-unavailable"}),
        }
        if reason not in expected_reason[status]:
            raise ValueError("profile evidence reason contradicts status")
        if status == "clean" and finding_count != 0:
            raise ValueError("clean profile evidence cannot contain findings")
        if status == "findings" and finding_count == 0:
            raise ValueError("findings profile evidence requires at least one finding")
        if status in {"clean", "findings"} and scanned_target_count == 0:
            raise ValueError("complete profile evidence requires scanned targets")
        tool_version = require_string(
            fields.get("tool_version"),
            "profile_evidence.tool_version",
            allow_empty=status == "unavailable",
        )
        if status == "unavailable" and tool_version:
            raise ValueError("unavailable profile evidence cannot claim a tool version")
        if status == "unavailable" and (finding_count != 0 or scanned_target_count != 0):
            raise ValueError("unavailable profile evidence requires zero result counts")
        if reason in {"invalid-output", "output-truncated", "timed-out"} and (
            finding_count != 0 or scanned_target_count != 0
        ):
            raise ValueError(f"{reason} profile evidence requires zero result counts")
        if reason == "no-scanned-targets" and scanned_target_count != 0:
            raise ValueError("no-scanned-targets evidence requires zero scanned targets")
        if reason == "invalid-returncode" and scanned_target_count == 0:
            raise ValueError("invalid-returncode evidence requires scanned targets")
        if reason == "scan-errors" and profile.parser != "semgrep":
            raise ValueError("scan-errors evidence is supported only by the Semgrep profile")
        if _digest(fields.get("profile_digest"), "profile_evidence.profile_digest") != (
            profile.profile_digest
        ):
            raise ValueError("profile evidence digest does not match built-in profile")
        return cls(
            profile=profile.name,
            profile_digest=profile.profile_digest,
            status=status,
            reason=reason,
            tool_version=tool_version,
            version_output_digest=_digest(
                fields.get("version_output_digest"),
                "profile_evidence.version_output_digest",
            ),
            configuration_digest=_digest(
                fields.get("configuration_digest"),
                "profile_evidence.configuration_digest",
            ),
            input_digest=_digest(fields.get("input_digest"), "profile_evidence.input_digest"),
            output_digest=_digest(fields.get("output_digest"), "profile_evidence.output_digest"),
            finding_count=finding_count,
            scanned_target_count=scanned_target_count,
            evidence_digest=_digest(evidence_digest, "profile_evidence.evidence_digest"),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the complete evidence record."""
        return {
            "schema_version": PROFILE_EVIDENCE_SCHEMA_VERSION,
            "profile": self.profile,
            "profile_digest": self.profile_digest,
            "status": self.status,
            "reason": self.reason,
            "tool_version": self.tool_version,
            "version_output_digest": self.version_output_digest,
            "configuration_digest": self.configuration_digest,
            "input_digest": self.input_digest,
            "output_digest": self.output_digest,
            "finding_count": self.finding_count,
            "scanned_target_count": self.scanned_target_count,
            "evidence_digest": self.evidence_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> AdapterProfileEvidence:
        """Parse and integrity-check one imported profile evidence record."""
        data = require_mapping(value, "profile_evidence")
        if frozenset(data) != _PROFILE_EVIDENCE_FIELDS:
            raise ValueError("profile evidence fields do not match schema")
        if data.get("schema_version") != PROFILE_EVIDENCE_SCHEMA_VERSION:
            raise ValueError("profile evidence schema version is unsupported")
        fields = {key: data[key] for key in _PROFILE_EVIDENCE_FIELDS - {"evidence_digest"}}
        evidence_digest = _digest(data.get("evidence_digest"), "profile_evidence.evidence_digest")
        if evidence_digest != canonical_digest(fields):
            raise ValueError("profile evidence digest does not match its content")
        return cls._from_fields(fields, evidence_digest)


def _semgrep_counts(document: object) -> tuple[int, int, bool]:
    """Return finding, scanned-target, and error state from Semgrep JSON."""
    data = require_mapping(document, "semgrep output")
    results = data.get("results")
    errors = data.get("errors")
    paths = require_mapping(data.get("paths"), "semgrep output.paths")
    scanned = paths.get("scanned")
    if (
        not isinstance(results, list)
        or not isinstance(errors, list)
        or not isinstance(scanned, list)
    ):
        raise ValueError("Semgrep JSON arrays are invalid")
    if not all(isinstance(item, dict) for item in results + errors):
        raise ValueError("Semgrep result or error entry is invalid")
    if not all(isinstance(item, str) and item for item in scanned):
        raise ValueError("Semgrep scanned paths are invalid")
    return len(results), len(scanned), bool(errors)


def _trivy_counts(document: object) -> tuple[int, int]:
    """Return finding and scanned-result counts from Trivy JSON."""
    data = require_mapping(document, "trivy output")
    if data.get("SchemaVersion") != 2:
        raise ValueError("Trivy JSON schema version is unsupported")
    results = data.get("Results")
    if not isinstance(results, list):
        raise ValueError("Trivy Results must be an array")
    finding_count = 0
    scanned_count = 0
    for index, raw in enumerate(results):
        result = require_mapping(raw, f"trivy output.Results[{index}]")
        target = result.get("Target")
        result_class = result.get("Class")
        result_type = result.get("Type")
        if not isinstance(target, str) or not target or not isinstance(result_class, str):
            raise ValueError("Trivy result identity is invalid")
        if not isinstance(result_type, str) or not result_type:
            raise ValueError("Trivy result type is invalid")
        scanned_count += 1
        misconfigurations = result.get("Misconfigurations", [])
        secrets = result.get("Secrets", [])
        if not isinstance(misconfigurations, list) or not isinstance(secrets, list):
            raise ValueError("Trivy findings arrays are invalid")
        for finding in misconfigurations:
            item = require_mapping(finding, "Trivy misconfiguration")
            status = item.get("Status")
            if status not in {"PASS", "FAIL", "EXCEPTION"}:
                raise ValueError("Trivy misconfiguration status is invalid")
            if status == "FAIL":
                finding_count += 1
        for finding in secrets:
            require_mapping(finding, "Trivy secret")
            finding_count += 1
    return finding_count, scanned_count


def interpret_profile_output(
    profile: AdapterProfile,
    *,
    stdout: bytes,
    returncode: int,
    timed_out: bool,
    truncated: bool,
) -> tuple[ProfileStatus, ProfileReason, int, int]:
    """Interpret one bounded tool response without turning ambiguity into pass."""
    if timed_out:
        return "partial", "timed-out", 0, 0
    if truncated:
        return "partial", "output-truncated", 0, 0
    try:
        document = _strict_json(stdout)
        if profile.parser == "semgrep":
            findings, scanned, errors = _semgrep_counts(document)
            if errors:
                return "partial", "scan-errors", findings, scanned
        else:
            findings, scanned = _trivy_counts(document)
    except ValueError:
        return "partial", "invalid-output", 0, 0
    if scanned == 0:
        return "partial", "no-scanned-targets", findings, 0
    if returncode not in {0, 1}:
        return "partial", "invalid-returncode", findings, scanned
    expected = 1 if findings else 0
    if returncode != expected:
        return "partial", "invalid-returncode", findings, scanned
    if findings:
        return "findings", "findings", findings, scanned
    return "clean", "clean", 0, scanned


def normalise_version_output(payload: bytes) -> str:
    """Return one bounded single-line tool version string."""
    try:
        text = payload.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("tool version output is not UTF-8") from exc
    lines = tuple(line.strip() for line in text.splitlines() if line.strip())
    if not lines or len(lines) > 8 or len(text) > 4096:
        raise ValueError("tool version output is empty or unbounded")
    return " | ".join(lines)
