# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — immutable multi-agent audit protocol records
"""Define content-addressed campaign and per-agent audit attestations."""

from __future__ import annotations

import hashlib
import platform
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

from .adapters import ADAPTER_RESULT_SCHEMA_VERSION, AdapterResult
from .campaign_inputs import validate_campaign_input
from .git_provenance import GitExecutableProvenance
from .models import (
    AuditReport,
    canonical_digest,
    require_integer,
    require_mapping,
    require_string,
    require_string_tuple,
)
from .sandbox_provenance import BubblewrapProvenance

CAMPAIGN_SCHEMA_VERSION = "1.3"
RunStatus = Literal["complete", "incomplete"]
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_TOOLCHAIN_FIELDS = frozenset(
    {
        "python_implementation",
        "python_version",
        "platform",
        "executable_digest",
        "identity_digest",
    }
)
_CAMPAIGN_FIELDS = frozenset(
    {
        "schema_version",
        "campaign_id",
        "project",
        "repository_root",
        "policy_path",
        "head",
        "head_tree",
        "branch",
        "tracked_content_digest",
        "dirty_paths",
        "tracked_file_count",
        "policy_digest",
        "rule_pack_version",
        "rule_pack_digest",
        "scanner_version",
        "required_domains",
        "git_provenance",
        "toolchain",
        "created_by",
        "created_at",
        "expected_independent_runs",
        "contract_digest",
    }
)
_ATTESTATION_FIELDS = frozenset(
    {
        "schema_version",
        "run_id",
        "campaign_id",
        "input_contract_digest",
        "agent_identity",
        "session_identity",
        "started_at",
        "finished_at",
        "status",
        "report_relative_path",
        "report_digest",
        "candidate_count",
        "covered_domains",
        "omitted_domains",
        "adapter_evidence",
        "toolchain",
        "command_digest",
        "limitations",
        "attestation_digest",
    }
)


def _identifier(value: object, field: str) -> str:
    """Return one filesystem-safe stable protocol identifier."""
    result = require_string(value, field)
    if _IDENTIFIER.fullmatch(result) is None:
        raise ValueError(f"{field} must be a portable identifier")
    return result


def _utc_datetime(value: object, field: str) -> datetime:
    """Parse one timezone-aware UTC timestamp."""
    result = require_string(value, field)
    normalised = result[:-1] + "+00:00" if result.endswith("Z") else result
    try:
        parsed = datetime.fromisoformat(normalised)
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError(f"{field} must use UTC")
    return parsed.astimezone(UTC)


def _utc_timestamp(value: object, field: str) -> str:
    """Return a normalised, timezone-aware UTC timestamp string."""
    return _utc_datetime(value, field).isoformat().replace("+00:00", "Z")


def _relative_path(value: object, field: str) -> str:
    """Return one safe repository-relative POSIX path."""
    result = require_string(value, field)
    path = Path(result)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{field} must be repository-relative")
    return path.as_posix()


def _file_digest(path: Path) -> str:
    """Return SHA-256 for one runtime executable without loading it at once."""
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise RuntimeError(f"cannot hash runtime executable: {path}") from exc
    return digest.hexdigest()


@dataclass(frozen=True)
class ToolchainIdentity:
    """Runtime identity used to detect cross-agent input divergence."""

    python_implementation: str
    python_version: str
    platform: str
    executable_digest: str
    identity_digest: str

    @classmethod
    def current(cls) -> ToolchainIdentity:
        """Capture the active Python runtime and platform identity."""
        fields = {
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "executable_digest": _file_digest(Path(sys.executable).resolve(strict=True)),
        }
        return cls(**fields, identity_digest=canonical_digest(fields))

    def to_dict(self) -> dict[str, str]:
        """Serialise the runtime identity."""
        return {
            "python_implementation": self.python_implementation,
            "python_version": self.python_version,
            "platform": self.platform,
            "executable_digest": self.executable_digest,
            "identity_digest": self.identity_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> ToolchainIdentity:
        """Parse and integrity-check a runtime identity."""
        data = require_mapping(value, "toolchain")
        if frozenset(data) != _TOOLCHAIN_FIELDS:
            raise ValueError("toolchain identity fields do not match schema")
        fields = {
            "python_implementation": require_string(
                data.get("python_implementation"),
                "toolchain.python_implementation",
            ),
            "python_version": require_string(
                data.get("python_version"),
                "toolchain.python_version",
            ),
            "platform": require_string(data.get("platform"), "toolchain.platform"),
            "executable_digest": require_string(
                data.get("executable_digest"),
                "toolchain.executable_digest",
            ),
        }
        identity = cls(
            **fields,
            identity_digest=require_string(
                data.get("identity_digest"),
                "toolchain.identity_digest",
            ),
        )
        if identity.identity_digest != canonical_digest(fields):
            raise ValueError("toolchain identity digest does not match its content")
        return identity


@dataclass(frozen=True)
class AuditCampaign:
    """Immutable input contract shared by independent audit agents."""

    campaign_id: str
    project: str
    repository_root: str
    policy_path: str
    head: str
    head_tree: str
    branch: str
    tracked_content_digest: str
    dirty_paths: tuple[str, ...]
    tracked_file_count: int
    policy_digest: str
    rule_pack_version: str
    rule_pack_digest: str
    scanner_version: str
    required_domains: tuple[str, ...]
    git_provenance: GitExecutableProvenance
    toolchain: ToolchainIdentity
    created_by: str
    created_at: str
    expected_independent_runs: int
    contract_digest: str

    @classmethod
    def build(
        cls,
        report: AuditReport,
        *,
        campaign_id: str,
        project: str,
        policy_path: str,
        toolchain: ToolchainIdentity,
        created_by: str,
        created_at: str,
        expected_independent_runs: int,
    ) -> AuditCampaign:
        """Build a campaign bound to one exact report input surface."""
        fields = {
            "schema_version": CAMPAIGN_SCHEMA_VERSION,
            "campaign_id": _identifier(campaign_id, "campaign_id"),
            "project": _identifier(project, "project"),
            "repository_root": str(Path(report.repository_root).resolve(strict=True)),
            "policy_path": _relative_path(policy_path, "policy_path"),
            "head": report.head,
            "head_tree": report.head_tree,
            "branch": report.branch,
            "tracked_content_digest": report.tracked_content_digest,
            "dirty_paths": list(report.dirty_paths),
            "tracked_file_count": report.tracked_file_count,
            "policy_digest": report.policy_digest,
            "rule_pack_version": report.rule_pack_version,
            "rule_pack_digest": report.rule_pack_digest,
            "scanner_version": report.scanner_version,
            "required_domains": sorted(
                domain.name
                for domain in report.policy.audit_domains
                if domain.applicability == "required"
            ),
            "git_provenance": report.git_provenance.to_dict(),
            "toolchain": toolchain.to_dict(),
            "created_by": require_string(created_by, "created_by"),
            "created_at": _utc_timestamp(created_at, "created_at"),
            "expected_independent_runs": require_integer(
                expected_independent_runs,
                "expected_independent_runs",
                minimum=1,
            ),
        }
        return cls._from_fields(fields, canonical_digest(fields))

    @classmethod
    def _from_fields(cls, fields: dict[str, object], digest: str) -> AuditCampaign:
        """Construct a campaign from already validated canonical fields."""
        return cls(
            campaign_id=cast(str, fields["campaign_id"]),
            project=cast(str, fields["project"]),
            repository_root=cast(str, fields["repository_root"]),
            policy_path=cast(str, fields["policy_path"]),
            head=cast(str, fields["head"]),
            head_tree=cast(str, fields["head_tree"]),
            branch=cast(str, fields["branch"]),
            tracked_content_digest=cast(str, fields["tracked_content_digest"]),
            dirty_paths=tuple(cast(list[str], fields["dirty_paths"])),
            tracked_file_count=cast(int, fields["tracked_file_count"]),
            policy_digest=cast(str, fields["policy_digest"]),
            rule_pack_version=cast(str, fields["rule_pack_version"]),
            rule_pack_digest=cast(str, fields["rule_pack_digest"]),
            scanner_version=cast(str, fields["scanner_version"]),
            required_domains=tuple(cast(list[str], fields["required_domains"])),
            git_provenance=GitExecutableProvenance.from_dict(fields["git_provenance"]),
            toolchain=ToolchainIdentity.from_dict(fields["toolchain"]),
            created_by=cast(str, fields["created_by"]),
            created_at=cast(str, fields["created_at"]),
            expected_independent_runs=cast(int, fields["expected_independent_runs"]),
            contract_digest=digest,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the campaign input contract."""
        return {
            "schema_version": CAMPAIGN_SCHEMA_VERSION,
            "campaign_id": self.campaign_id,
            "project": self.project,
            "repository_root": self.repository_root,
            "policy_path": self.policy_path,
            "head": self.head,
            "head_tree": self.head_tree,
            "branch": self.branch,
            "tracked_content_digest": self.tracked_content_digest,
            "dirty_paths": list(self.dirty_paths),
            "tracked_file_count": self.tracked_file_count,
            "policy_digest": self.policy_digest,
            "rule_pack_version": self.rule_pack_version,
            "rule_pack_digest": self.rule_pack_digest,
            "scanner_version": self.scanner_version,
            "required_domains": list(self.required_domains),
            "git_provenance": self.git_provenance.to_dict(),
            "toolchain": self.toolchain.to_dict(),
            "created_by": self.created_by,
            "created_at": self.created_at,
            "expected_independent_runs": self.expected_independent_runs,
            "contract_digest": self.contract_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> AuditCampaign:
        """Parse and integrity-check an immutable campaign contract."""
        data = require_mapping(value, "campaign")
        if frozenset(data) != _CAMPAIGN_FIELDS:
            raise ValueError("audit campaign fields do not match schema")
        if data.get("schema_version") != CAMPAIGN_SCHEMA_VERSION:
            raise ValueError("unsupported audit campaign schema version")
        fields: dict[str, object] = {
            "schema_version": CAMPAIGN_SCHEMA_VERSION,
            "campaign_id": _identifier(data.get("campaign_id"), "campaign_id"),
            "project": _identifier(data.get("project"), "project"),
            "repository_root": require_string(
                data.get("repository_root"),
                "repository_root",
            ),
            "policy_path": _relative_path(data.get("policy_path"), "policy_path"),
            "head": require_string(data.get("head"), "head"),
            "head_tree": require_string(data.get("head_tree"), "head_tree"),
            "branch": require_string(data.get("branch"), "branch"),
            "tracked_content_digest": require_string(
                data.get("tracked_content_digest"),
                "tracked_content_digest",
            ),
            "dirty_paths": list(require_string_tuple(data.get("dirty_paths"), "dirty_paths")),
            "tracked_file_count": require_integer(
                data.get("tracked_file_count"),
                "tracked_file_count",
            ),
            "policy_digest": require_string(data.get("policy_digest"), "policy_digest"),
            "rule_pack_version": require_string(
                data.get("rule_pack_version"),
                "rule_pack_version",
            ),
            "rule_pack_digest": require_string(
                data.get("rule_pack_digest"),
                "rule_pack_digest",
            ),
            "scanner_version": require_string(
                data.get("scanner_version"),
                "scanner_version",
            ),
            "required_domains": list(
                require_string_tuple(data.get("required_domains"), "required_domains")
            ),
            "git_provenance": GitExecutableProvenance.from_dict(
                data.get("git_provenance")
            ).to_dict(),
            "toolchain": ToolchainIdentity.from_dict(data.get("toolchain")).to_dict(),
            "created_by": require_string(data.get("created_by"), "created_by"),
            "created_at": _utc_timestamp(data.get("created_at"), "created_at"),
            "expected_independent_runs": require_integer(
                data.get("expected_independent_runs"),
                "expected_independent_runs",
                minimum=1,
            ),
        }
        recorded = require_string(data.get("contract_digest"), "contract_digest")
        if recorded != canonical_digest(fields):
            raise ValueError("campaign contract digest does not match its content")
        return cls._from_fields(fields, recorded)


@dataclass(frozen=True)
class AdapterEvidence:
    """Bounded native-adapter evidence retained in one run attestation."""

    name: str
    required: bool
    returncode: int
    timed_out: bool
    output_digest: str
    output_bytes: int
    output_truncated: bool
    spec_digest: str
    executable_digest: str
    command_digest: str
    environment_digest: str
    sandbox_digest: str
    sandbox_provenance: BubblewrapProvenance
    passed: bool

    @classmethod
    def from_result(cls, result: AdapterResult) -> AdapterEvidence:
        """Capture stable evidence from an adapter execution result."""
        return cls(
            name=result.name,
            required=result.required,
            returncode=result.returncode,
            timed_out=result.timed_out,
            output_digest=result.output_digest,
            output_bytes=result.output_bytes,
            output_truncated=result.output_truncated,
            spec_digest=result.spec_digest,
            executable_digest=result.executable_digest,
            command_digest=result.command_digest,
            environment_digest=result.environment_digest,
            sandbox_digest=result.sandbox_digest,
            sandbox_provenance=result.sandbox_provenance,
            passed=result.passed,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one native-adapter evidence record."""
        return {
            "schema_version": ADAPTER_RESULT_SCHEMA_VERSION,
            "name": self.name,
            "required": self.required,
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "output_digest": self.output_digest,
            "output_bytes": self.output_bytes,
            "output_truncated": self.output_truncated,
            "spec_digest": self.spec_digest,
            "executable_digest": self.executable_digest,
            "command_digest": self.command_digest,
            "environment_digest": self.environment_digest,
            "sandbox_digest": self.sandbox_digest,
            "sandbox_provenance": self.sandbox_provenance.to_dict(),
            "passed": self.passed,
        }

    @classmethod
    def from_dict(cls, value: object, index: int) -> AdapterEvidence:
        """Parse one native-adapter evidence record."""
        result = AdapterResult.from_dict(value, index)
        return cls.from_result(result)


@dataclass(frozen=True)
class AuditRunAttestation:
    """Append-only identity and evidence record for one independent audit run."""

    run_id: str
    campaign_id: str
    input_contract_digest: str
    agent_identity: str
    session_identity: str
    started_at: str
    finished_at: str
    status: RunStatus
    report_relative_path: str
    report_digest: str
    candidate_count: int
    covered_domains: tuple[str, ...]
    omitted_domains: tuple[str, ...]
    adapter_evidence: tuple[AdapterEvidence, ...]
    toolchain: ToolchainIdentity
    command_digest: str
    limitations: tuple[str, ...]
    attestation_digest: str

    @classmethod
    def build(
        cls,
        *,
        run_id: str,
        campaign: AuditCampaign,
        agent_identity: str,
        session_identity: str,
        started_at: str,
        finished_at: str,
        status: RunStatus,
        report_relative_path: str,
        report: AuditReport,
        covered_domains: tuple[str, ...],
        omitted_domains: tuple[str, ...],
        adapter_results: tuple[AdapterResult, ...],
        toolchain: ToolchainIdentity,
        command_digest: str,
        limitations: tuple[str, ...],
    ) -> AuditRunAttestation:
        """Build a content-addressed run attestation."""
        validate_campaign_input(campaign, report, toolchain)
        fields: dict[str, object] = {
            "schema_version": CAMPAIGN_SCHEMA_VERSION,
            "run_id": _identifier(run_id, "run_id"),
            "campaign_id": campaign.campaign_id,
            "input_contract_digest": campaign.contract_digest,
            "agent_identity": require_string(agent_identity, "agent_identity"),
            "session_identity": require_string(session_identity, "session_identity"),
            "started_at": _utc_timestamp(started_at, "started_at"),
            "finished_at": _utc_timestamp(finished_at, "finished_at"),
            "status": status,
            "report_relative_path": _relative_path(
                report_relative_path,
                "report_relative_path",
            ),
            "report_digest": report.report_digest,
            "candidate_count": len(report.candidates),
            "covered_domains": sorted(covered_domains),
            "omitted_domains": sorted(omitted_domains),
            "adapter_evidence": [
                AdapterEvidence.from_result(result).to_dict() for result in adapter_results
            ],
            "toolchain": toolchain.to_dict(),
            "command_digest": require_string(command_digest, "command_digest"),
            "limitations": list(limitations),
        }
        started = _utc_datetime(fields["started_at"], "started_at")
        finished = _utc_datetime(fields["finished_at"], "finished_at")
        if finished < started:
            raise ValueError("finished_at must not precede started_at")
        if status not in {"complete", "incomplete"}:
            raise ValueError("unsupported audit run status")
        return cls._from_fields(fields, canonical_digest(fields))

    @classmethod
    def _from_fields(
        cls,
        fields: dict[str, object],
        digest: str,
    ) -> AuditRunAttestation:
        """Construct one attestation from canonical validated fields."""
        raw_evidence = cast(list[object], fields["adapter_evidence"])
        return cls(
            run_id=cast(str, fields["run_id"]),
            campaign_id=cast(str, fields["campaign_id"]),
            input_contract_digest=cast(str, fields["input_contract_digest"]),
            agent_identity=cast(str, fields["agent_identity"]),
            session_identity=cast(str, fields["session_identity"]),
            started_at=cast(str, fields["started_at"]),
            finished_at=cast(str, fields["finished_at"]),
            status=cast(RunStatus, fields["status"]),
            report_relative_path=cast(str, fields["report_relative_path"]),
            report_digest=cast(str, fields["report_digest"]),
            candidate_count=cast(int, fields["candidate_count"]),
            covered_domains=tuple(cast(list[str], fields["covered_domains"])),
            omitted_domains=tuple(cast(list[str], fields["omitted_domains"])),
            adapter_evidence=tuple(
                AdapterEvidence.from_dict(item, index) for index, item in enumerate(raw_evidence)
            ),
            toolchain=ToolchainIdentity.from_dict(fields["toolchain"]),
            command_digest=cast(str, fields["command_digest"]),
            limitations=tuple(cast(list[str], fields["limitations"])),
            attestation_digest=digest,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one immutable run attestation."""
        return {
            "schema_version": CAMPAIGN_SCHEMA_VERSION,
            "run_id": self.run_id,
            "campaign_id": self.campaign_id,
            "input_contract_digest": self.input_contract_digest,
            "agent_identity": self.agent_identity,
            "session_identity": self.session_identity,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "status": self.status,
            "report_relative_path": self.report_relative_path,
            "report_digest": self.report_digest,
            "candidate_count": self.candidate_count,
            "covered_domains": list(self.covered_domains),
            "omitted_domains": list(self.omitted_domains),
            "adapter_evidence": [item.to_dict() for item in self.adapter_evidence],
            "toolchain": self.toolchain.to_dict(),
            "command_digest": self.command_digest,
            "limitations": list(self.limitations),
            "attestation_digest": self.attestation_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> AuditRunAttestation:
        """Parse and integrity-check one run attestation."""
        data = require_mapping(value, "attestation")
        if frozenset(data) != _ATTESTATION_FIELDS:
            raise ValueError("audit attestation fields do not match schema")
        if data.get("schema_version") != CAMPAIGN_SCHEMA_VERSION:
            raise ValueError("unsupported audit attestation schema version")
        status = require_string(data.get("status"), "status")
        if status not in {"complete", "incomplete"}:
            raise ValueError("unsupported audit run status")
        raw_evidence = data.get("adapter_evidence")
        if not isinstance(raw_evidence, list):
            raise ValueError("adapter_evidence must be an array")
        fields: dict[str, object] = {
            "schema_version": CAMPAIGN_SCHEMA_VERSION,
            "run_id": _identifier(data.get("run_id"), "run_id"),
            "campaign_id": _identifier(data.get("campaign_id"), "campaign_id"),
            "input_contract_digest": require_string(
                data.get("input_contract_digest"),
                "input_contract_digest",
            ),
            "agent_identity": require_string(data.get("agent_identity"), "agent_identity"),
            "session_identity": require_string(
                data.get("session_identity"),
                "session_identity",
            ),
            "started_at": _utc_timestamp(data.get("started_at"), "started_at"),
            "finished_at": _utc_timestamp(data.get("finished_at"), "finished_at"),
            "status": status,
            "report_relative_path": _relative_path(
                data.get("report_relative_path"),
                "report_relative_path",
            ),
            "report_digest": require_string(data.get("report_digest"), "report_digest"),
            "candidate_count": require_integer(data.get("candidate_count"), "candidate_count"),
            "covered_domains": list(
                require_string_tuple(data.get("covered_domains"), "covered_domains")
            ),
            "omitted_domains": list(
                require_string_tuple(data.get("omitted_domains"), "omitted_domains")
            ),
            "adapter_evidence": [
                AdapterEvidence.from_dict(item, index).to_dict()
                for index, item in enumerate(raw_evidence)
            ],
            "toolchain": ToolchainIdentity.from_dict(data.get("toolchain")).to_dict(),
            "command_digest": require_string(data.get("command_digest"), "command_digest"),
            "limitations": list(require_string_tuple(data.get("limitations"), "limitations")),
        }
        if _utc_datetime(fields["finished_at"], "finished_at") < _utc_datetime(
            fields["started_at"],
            "started_at",
        ):
            raise ValueError("finished_at must not precede started_at")
        recorded = require_string(data.get("attestation_digest"), "attestation_digest")
        if recorded != canonical_digest(fields):
            raise ValueError("attestation digest does not match its content")
        return cls._from_fields(fields, recorded)
