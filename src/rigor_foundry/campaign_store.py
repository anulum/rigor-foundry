# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — immutable internal audit storage
"""Persist campaign evidence only below Git-ignored repository paths."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .campaign_inputs import validate_campaign_input
from .campaign_models import AuditCampaign, AuditRunAttestation
from .git_inventory import is_git_ignored
from .git_provenance import GitExecutableProvenance, GitTrustPolicy
from .models import AuditReport, ReviewRecord, reviews_from_path

_RECORD_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


@dataclass(frozen=True)
class StoredAuditRun:
    """Integrity-verified attestation and report loaded from one run directory."""

    attestation: AuditRunAttestation
    report: AuditReport


def _json_text(value: dict[str, object]) -> str:
    """Render deterministic protocol JSON."""
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _internal_path(
    root: Path,
    relative: Path,
    git_trust_policy: GitTrustPolicy | None = None,
    expected_git_provenance: GitExecutableProvenance | None = None,
) -> Path:
    """Resolve one safe ignored repository-relative internal path."""
    repository = root.resolve(strict=True)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("audit storage path must be repository-relative")
    if not is_git_ignored(
        repository,
        relative,
        git_trust_policy=git_trust_policy,
        expected_git_provenance=expected_git_provenance,
    ):
        raise ValueError("audit storage path must be covered by repository Git ignore rules")
    cursor = repository
    for part in relative.parts:
        cursor /= part
        if cursor.exists() and cursor.is_symlink():
            raise ValueError("audit storage path must not contain symlinks")
    resolved = (repository / relative).resolve(strict=False)
    try:
        resolved.relative_to(repository)
    except ValueError as exc:
        raise ValueError("audit storage path escapes the repository") from exc
    return resolved


def _write_new(path: Path, text: str) -> None:
    """Create and fsync one immutable UTF-8 record without overwrite."""
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            descriptor = None
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise ValueError(f"immutable audit record already exists: {path}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def campaign_relative_path(
    audit_root: Path,
    project: str,
    campaign_id: str,
) -> Path:
    """Return the canonical repository-relative campaign manifest path."""
    return audit_root / project / "campaigns" / campaign_id / "campaign.json"


def store_campaign(
    repository_root: Path,
    audit_root: Path,
    campaign: AuditCampaign,
    *,
    git_trust_policy: GitTrustPolicy | None = None,
) -> Path:
    """Persist one new campaign contract below ignored internal storage."""
    relative = campaign_relative_path(audit_root, campaign.project, campaign.campaign_id)
    target = _internal_path(
        repository_root,
        relative,
        git_trust_policy,
        campaign.git_provenance,
    )
    target.parent.mkdir(parents=True, exist_ok=False)
    _write_new(target, _json_text(campaign.to_dict()))
    return target


def load_campaign(path: Path) -> AuditCampaign:
    """Load and integrity-check one campaign manifest."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read audit campaign {path}") from exc
    return AuditCampaign.from_dict(value)


def store_run(
    campaign_path: Path,
    report: AuditReport,
    attestation: AuditRunAttestation,
    *,
    git_trust_policy: GitTrustPolicy | None = None,
) -> Path:
    """Persist one new per-agent report and attestation bundle."""
    campaign = load_campaign(campaign_path)
    report = AuditReport.from_dict(report.to_dict())
    attestation = AuditRunAttestation.from_dict(attestation.to_dict())
    if attestation.campaign_id != campaign.campaign_id:
        raise ValueError("attestation belongs to a different campaign")
    if attestation.input_contract_digest != campaign.contract_digest:
        raise ValueError("attestation input contract does not match campaign")
    if attestation.report_digest != report.report_digest:
        raise ValueError("attestation report digest does not match report")
    validate_campaign_input(campaign, report, attestation.toolchain)
    campaign_directory = campaign_path.resolve(strict=True).parent
    repository = Path(campaign.repository_root).resolve(strict=True)
    try:
        campaign_relative = campaign_directory.relative_to(repository)
    except ValueError as exc:
        raise ValueError("campaign storage is outside its repository") from exc
    run_relative = campaign_relative / "runs" / attestation.run_id
    expected_report_path = (run_relative / "report.json").relative_to(campaign_relative)
    if attestation.report_relative_path != expected_report_path.as_posix():
        raise ValueError("attestation report path is not canonical")
    run_directory = _internal_path(
        repository,
        run_relative,
        git_trust_policy,
        campaign.git_provenance,
    )
    run_directory.parent.mkdir(parents=True, exist_ok=True)
    run_directory.mkdir(exist_ok=False)
    _write_new(run_directory / "report.json", report.to_json())
    _write_new(run_directory / "attestation.json", _json_text(attestation.to_dict()))
    return run_directory


def load_runs(campaign_path: Path) -> tuple[StoredAuditRun, ...]:
    """Load every complete, integrity-verified run for one campaign."""
    campaign = load_campaign(campaign_path)
    campaign_directory = campaign_path.resolve(strict=True).parent
    runs_directory = campaign_directory / "runs"
    if not runs_directory.exists():
        return ()
    loaded: list[StoredAuditRun] = []
    for run_directory in sorted(path for path in runs_directory.iterdir() if path.is_dir()):
        attestation_path = run_directory / "attestation.json"
        try:
            attestation_value = json.loads(attestation_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read audit attestation {attestation_path}") from exc
        attestation = AuditRunAttestation.from_dict(attestation_value)
        if attestation.campaign_id != campaign.campaign_id:
            raise ValueError(f"run {attestation.run_id} belongs to a different campaign")
        if attestation.input_contract_digest != campaign.contract_digest:
            raise ValueError(f"run {attestation.run_id} has a different input contract")
        report_path = (campaign_directory / attestation.report_relative_path).resolve(strict=True)
        try:
            report_path.relative_to(run_directory.resolve(strict=True))
        except ValueError as exc:
            raise ValueError(f"run {attestation.run_id} report path escapes its run") from exc
        report = AuditReport.from_path(report_path)
        if report.report_digest != attestation.report_digest:
            raise ValueError(f"run {attestation.run_id} report digest mismatch")
        try:
            validate_campaign_input(campaign, report, attestation.toolchain)
        except ValueError as exc:
            raise ValueError(
                f"run {attestation.run_id} has campaign input divergence: "
                + str(exc).partition(": ")[2]
            ) from exc
        if len(report.candidates) != attestation.candidate_count:
            raise ValueError(f"run {attestation.run_id} candidate count mismatch")
        loaded.append(StoredAuditRun(attestation=attestation, report=report))
    identifiers = tuple(item.attestation.run_id for item in loaded)
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("campaign contains duplicate run identifiers")
    return tuple(loaded)


def load_campaign_reviews(campaign_path: Path) -> tuple[tuple[ReviewRecord, ...], ...]:
    """Load every immutable independent review document in filename order."""
    reviews_directory = campaign_path.resolve(strict=True).parent / "reviews"
    if not reviews_directory.exists():
        return ()
    documents: list[tuple[ReviewRecord, ...]] = []
    for path in sorted(reviews_directory.glob("*.json")):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"campaign review must be a regular non-symlink file: {path}")
        documents.append(reviews_from_path(path))
    return tuple(documents)


def store_comparison_record(
    campaign_path: Path,
    comparison_id: str,
    value: dict[str, object],
    *,
    git_trust_policy: GitTrustPolicy | None = None,
) -> Path:
    """Persist one immutable comparison below the campaign's ignored storage."""
    if _RECORD_IDENTIFIER.fullmatch(comparison_id) is None:
        raise ValueError("comparison_id must be a portable identifier")
    campaign = load_campaign(campaign_path)
    campaign_directory = campaign_path.resolve(strict=True).parent
    repository = Path(campaign.repository_root).resolve(strict=True)
    try:
        campaign_relative = campaign_directory.relative_to(repository)
    except ValueError as exc:
        raise ValueError("campaign storage is outside its repository") from exc
    relative = campaign_relative / "comparisons" / f"{comparison_id}.json"
    target = _internal_path(
        repository,
        relative,
        git_trust_policy,
        campaign.git_provenance,
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_new(target, _json_text(value))
    return target
