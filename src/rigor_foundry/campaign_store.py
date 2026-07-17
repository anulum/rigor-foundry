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
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .campaign_evidence import validate_adapter_evidence
from .campaign_inputs import validate_campaign_input
from .campaign_models import AuditCampaign, AuditRunAttestation
from .git_inventory import is_git_ignored
from .git_provenance import GitExecutableProvenance, GitTrustPolicy
from .models import (
    REVIEW_SCHEMA_VERSION,
    AuditReport,
    ReviewRecord,
    require_mapping,
)

if TYPE_CHECKING:
    from .campaign_compare import AuditComparison

_RECORD_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_MAX_CAMPAIGN_RECORD_BYTES = 4 * 1024 * 1024


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


def _open_directory_no_follow(path: Path) -> int:
    """Open an absolute directory through a component-safe descriptor walk."""
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise OSError("platform does not support no-follow directory traversal")
    absolute = path.absolute()
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    descriptor = os.open(absolute.anchor or os.sep, flags)
    try:
        for part in absolute.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            state = os.fstat(child)
            if not stat.S_ISDIR(state.st_mode):
                os.close(child)
                raise OSError(f"non-directory path component: {part}")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_single_link_json(path: Path, *, label: str) -> object:
    """Read one bounded inode-bound JSON record and reject concurrent mutation."""
    parent_descriptor: int | None = None
    parent_recheck_descriptor: int | None = None
    descriptor: int | None = None
    try:
        parent_descriptor = _open_directory_no_follow(path.parent)
        parent_before = os.fstat(parent_descriptor)
        file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
        descriptor = os.open(path.name, file_flags, dir_fd=parent_descriptor)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > _MAX_CAMPAIGN_RECORD_BYTES
        ):
            raise ValueError(f"{label} must be a bounded single-link regular file")
        chunks: list[bytes] = []
        observed = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            observed += len(chunk)
            if observed > _MAX_CAMPAIGN_RECORD_BYTES:
                raise ValueError(f"{label} exceeds the record size limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        stable_file = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            before.st_nlink,
        ) == (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_nlink,
        )
        path_file = os.stat(
            path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        parent_recheck_descriptor = _open_directory_no_follow(path.parent)
        parent_recheck = os.fstat(parent_recheck_descriptor)
        if (
            not stable_file
            or observed != before.st_size
            or (path_file.st_dev, path_file.st_ino) != (before.st_dev, before.st_ino)
            or (parent_recheck.st_dev, parent_recheck.st_ino)
            != (parent_before.st_dev, parent_before.st_ino)
        ):
            raise ValueError(f"{label} changed while it was read")
        try:
            return json.loads(b"".join(chunks).decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot parse {label} {path}") from exc
    except OSError as exc:
        raise ValueError(f"cannot read {label} {path}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_recheck_descriptor is not None:
            os.close(parent_recheck_descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def _review_document_from_value(value: object) -> tuple[ReviewRecord, ...]:
    """Parse one strict review document already read through durable storage."""
    data = require_mapping(value, "review document")
    if data.get("schema_version") != REVIEW_SCHEMA_VERSION:
        raise ValueError("unsupported review schema version")
    raw_reviews = data.get("reviews")
    if not isinstance(raw_reviews, list):
        raise ValueError("review document reviews must be an array")
    return tuple(ReviewRecord.from_dict(item) for item in raw_reviews)


def campaign_relative_path(
    audit_root: Path,
    project: str,
    campaign_id: str,
) -> Path:
    """Return the canonical repository-relative campaign manifest path."""
    return audit_root / project / "campaigns" / campaign_id / "campaign.json"


def prepare_campaign_storage_root(
    repository_root: Path,
    audit_root: Path,
    *,
    git_trust_policy: GitTrustPolicy | None = None,
) -> Path:
    """Create the validated ignored storage root before freezing campaign input."""
    target = _internal_path(
        repository_root,
        audit_root,
        git_trust_policy,
    )
    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ValueError(f"cannot create campaign storage root: {target}") from exc
    if target.is_symlink() or not target.is_dir():
        raise ValueError("campaign storage root must be a non-symlink directory")
    return target


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
    return AuditCampaign.from_dict(_read_single_link_json(path, label="audit campaign"))


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
    validate_adapter_evidence(report.policy, attestation.adapter_evidence)
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
    campaign_directory = campaign_path.absolute().parent
    runs_directory = campaign_directory / "runs"
    try:
        runs_descriptor = _open_directory_no_follow(runs_directory)
    except FileNotFoundError:
        return ()
    except OSError as exc:
        raise ValueError(f"cannot enumerate campaign runs {runs_directory}") from exc
    run_names: list[str]
    try:
        run_names = sorted(os.listdir(runs_descriptor))
        for name in run_names:
            state = os.stat(name, dir_fd=runs_descriptor, follow_symlinks=False)
            if _RECORD_IDENTIFIER.fullmatch(name) is None or not stat.S_ISDIR(state.st_mode):
                raise ValueError(
                    f"campaign run entry must be a portable non-symlink directory: {name}"
                )
    except OSError as exc:
        raise ValueError(f"cannot enumerate campaign runs {runs_directory}") from exc
    finally:
        os.close(runs_descriptor)
    loaded: list[StoredAuditRun] = []
    for name in run_names:
        run_directory = runs_directory / name
        attestation_path = run_directory / "attestation.json"
        attestation = AuditRunAttestation.from_dict(
            _read_single_link_json(
                attestation_path,
                label="audit attestation",
            )
        )
        if attestation.campaign_id != campaign.campaign_id:
            raise ValueError(f"run {attestation.run_id} belongs to a different campaign")
        if attestation.input_contract_digest != campaign.contract_digest:
            raise ValueError(f"run {attestation.run_id} has a different input contract")
        if name != attestation.run_id:
            raise ValueError(
                f"run directory {name} does not match attestation {attestation.run_id}"
            )
        expected_report_path = f"runs/{attestation.run_id}/report.json"
        if attestation.report_relative_path != expected_report_path:
            raise ValueError(f"run {attestation.run_id} report path is not canonical")
        report_path = run_directory / "report.json"
        report = AuditReport.from_dict(_read_single_link_json(report_path, label="audit report"))
        if report.report_digest != attestation.report_digest:
            raise ValueError(f"run {attestation.run_id} report digest mismatch")
        try:
            validate_campaign_input(campaign, report, attestation.toolchain)
        except ValueError as exc:
            raise ValueError(
                f"run {attestation.run_id} has campaign input divergence: "
                + str(exc).partition(": ")[2]
            ) from exc
        try:
            validate_adapter_evidence(report.policy, attestation.adapter_evidence)
        except ValueError as exc:
            raise ValueError(
                f"run {attestation.run_id} has adapter evidence divergence: {exc}"
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
    load_campaign(campaign_path)
    reviews_directory = campaign_path.absolute().parent / "reviews"
    try:
        reviews_descriptor = _open_directory_no_follow(reviews_directory)
    except FileNotFoundError:
        return ()
    except OSError as exc:
        raise ValueError(f"cannot enumerate campaign reviews {reviews_directory}") from exc
    review_names: list[str]
    try:
        review_names = sorted(
            name for name in os.listdir(reviews_descriptor) if name.endswith(".json")
        )
        for name in review_names:
            state = os.stat(name, dir_fd=reviews_descriptor, follow_symlinks=False)
            if not stat.S_ISREG(state.st_mode):
                raise ValueError(
                    f"campaign review must be a regular non-symlink file: "
                    f"{reviews_directory / name}"
                )
    except OSError as exc:
        raise ValueError(f"cannot enumerate campaign reviews {reviews_directory}") from exc
    finally:
        os.close(reviews_descriptor)
    documents: list[tuple[ReviewRecord, ...]] = []
    for name in review_names:
        path = reviews_directory / name
        documents.append(
            _review_document_from_value(_read_single_link_json(path, label="campaign review"))
        )
    return tuple(documents)


def store_comparison_record(
    campaign_path: Path,
    comparison_id: str,
    value: dict[str, object],
    *,
    git_trust_policy: GitTrustPolicy | None = None,
) -> Path:
    """Persist one immutable comparison below the campaign's ignored storage."""
    from .campaign_compare import AuditComparison

    if _RECORD_IDENTIFIER.fullmatch(comparison_id) is None:
        raise ValueError("comparison_id must be a portable identifier")
    campaign = load_campaign(campaign_path)
    comparison = AuditComparison.from_dict(value)
    if comparison.comparison_id != comparison_id:
        raise ValueError("comparison identifier does not match its storage name")
    if (
        comparison.campaign_id != campaign.campaign_id
        or comparison.input_contract_digest != campaign.contract_digest
    ):
        raise ValueError("comparison does not match its campaign contract")
    if (
        comparison.purpose != campaign.purpose
        or comparison.expected_run_count != campaign.expected_runs
        or comparison.required_model_witnesses != campaign.required_model_witnesses
    ):
        raise ValueError("comparison requirements do not match its campaign contract")
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
    _write_new(target, _json_text(comparison.to_dict()))
    return target


def load_comparison_record(
    campaign_path: Path,
    comparison_path: Path,
) -> AuditComparison:
    """Load one canonical comparison and verify its campaign binding."""
    from .campaign_compare import AuditComparison

    campaign = load_campaign(campaign_path)
    campaign_directory = campaign_path.absolute().parent
    expected_directory = campaign_directory / "comparisons"
    comparison_absolute = comparison_path.absolute()
    if comparison_absolute.parent != expected_directory:
        raise ValueError("comparison path is outside the campaign comparison directory")
    value = _read_single_link_json(comparison_path, label="audit comparison")
    comparison = AuditComparison.from_dict(value)
    if comparison_path.stem != comparison.comparison_id:
        raise ValueError("comparison identifier does not match its storage name")
    if (
        comparison.campaign_id != campaign.campaign_id
        or comparison.input_contract_digest != campaign.contract_digest
    ):
        raise ValueError("comparison does not match its campaign contract")
    if (
        comparison.purpose != campaign.purpose
        or comparison.expected_run_count != campaign.expected_runs
        or comparison.required_model_witnesses != campaign.required_model_witnesses
    ):
        raise ValueError("comparison requirements do not match its campaign contract")
    return comparison
