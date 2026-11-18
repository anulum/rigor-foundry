# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Source-bound provenance scan records
"""Build separate provenance evidence for an exact static scan and lock file."""

from __future__ import annotations

import re
from dataclasses import dataclass
from hashlib import sha256
from importlib.util import find_spec
from pathlib import Path, PurePosixPath
from typing import Literal

from .audit_primitives import (
    canonical_digest,
    require_exact_fields,
    require_mapping,
    require_string,
)
from .git_inventory import GitInventory, TrackedFile
from .models import AuditReport
from .source_capture import MAX_SOURCE_BYTES, read_source_payload
from .source_provenance import _json_without_duplicate_keys
from .supply_chain import _logical_lines

PROVENANCE_PROFILE_SCHEMA_VERSION = "1.0"
PROVENANCE_SCAN_SCHEMA_VERSION = "rigor.provenance-scan.v1"
PUBLISH = "https://docs.pypi.org/attestations/publish/v1"
SLSA = "https://slsa.dev/provenance/v1"
_SHA256 = re.compile(r"[a-f0-9]{64}")
_LOCK_PIN = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)(?=\s|;|$)")
_HASH_OPTION = re.compile(r"(?:^|\s)--hash=sha256:([a-f0-9]{64})(?=\s|$)")
_DISTRIBUTION_FIELDS = frozenset(
    {
        "project",
        "version",
        "artifact",
        "sha256",
        "predicate",
        "identity",
        "issuer",
        "source_commit",
        "bundle",
        "bundle_sha256",
        "root",
        "root_sha256",
    }
)
Status = Literal["verified", "unavailable", "unsupported", "refused"]


def require_sha256(value: object, field: str) -> str:
    """Accept a complete lower-case SHA-256 digest."""
    value = require_string(value, field)
    if not _SHA256.fullmatch(value):
        raise ValueError(f"{field} must be a SHA-256 digest")
    return value


def _relative(value: object, field: str) -> str:
    """Parse a relative evidence path without traversal or platform ambiguity."""
    text = require_string(value, field)
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or not path.parts
        or ".." in path.parts
        or path.as_posix() != text
        or any(character in text for character in ("\\", ":", "\x00"))
    ):
        raise ValueError(f"{field} must be a portable relative path")
    return text


def _name(value: str) -> str:
    """Normalise a Python distribution name as in the Simple API."""
    return re.sub(r"[-_.]+", "-", value).lower()


def _pinned_hashes(lock: TrackedFile) -> dict[tuple[str, str], set[str]]:
    """Return explicitly hash-pinned distribution keys from the tracked lock."""
    if lock.text is None or lock.content_kind != "text" or lock.scanned_blob_id != lock.object_id:
        raise ValueError("provenance lock must be tracked, unchanged UTF-8 text")
    result: dict[tuple[str, str], set[str]] = {}
    for _, line in _logical_lines(lock.text):
        requirement = line.split("#", 1)[0].strip()
        match = _LOCK_PIN.match(requirement)
        if match is not None:
            pins = result.setdefault((_name(match[1]), match[2]), set())
            pins.update(_HASH_OPTION.findall(requirement))
    return result


@dataclass(frozen=True)
class VerificationMaterial:
    """Complete paths and independent digests for one signed distribution."""

    bundle: str
    bundle_sha256: str
    root: str
    root_sha256: str


@dataclass(frozen=True)
class AttestationInput:
    """One exact distribution, expected publisher, and independent local proof."""

    project: str
    version: str
    artifact: str
    sha256: str
    predicate: str
    identity: str
    issuer: str
    source_commit: str | None
    material: VerificationMaterial | None

    @classmethod
    def parse(cls, value: object) -> AttestationInput:
        """Parse one strict caller-selected distribution and verification policy."""
        item = require_mapping(value, "distribution")
        require_exact_fields(item, _DISTRIBUTION_FIELDS, "distribution")
        commit = item["source_commit"]
        if commit is not None and (
            not isinstance(commit, str) or not re.fullmatch(r"[a-f0-9]{40}", commit)
        ):
            raise ValueError("source_commit must be an exact GitHub commit or null")
        parts = (item["bundle"], item["bundle_sha256"], item["root"], item["root_sha256"])
        material = None
        if any(part is not None for part in parts):
            if any(part is None for part in parts):
                raise ValueError("bundle, root and both digests must be supplied together")
            material = VerificationMaterial(
                bundle=_relative(parts[0], "bundle"),
                bundle_sha256=require_sha256(parts[1], "bundle_sha256"),
                root=_relative(parts[2], "root"),
                root_sha256=require_sha256(parts[3], "root_sha256"),
            )
        predicate = require_string(item["predicate"], "predicate")
        if predicate == SLSA and commit is None:
            raise ValueError("SLSA requires an explicit source commit")
        return cls(
            project=require_string(item["project"], "project"),
            version=require_string(item["version"], "version"),
            artifact=_relative(item["artifact"], "artifact"),
            sha256=require_sha256(item["sha256"], "sha256"),
            predicate=predicate,
            identity=require_string(item["identity"], "identity"),
            issuer=require_string(item["issuer"], "issuer"),
            source_commit=commit,
            material=material,
        )


def _read_bound(directory: Path, relative: str, digest: str, limit: int) -> bytes:
    """Read one stable file and compare its SHA-256 to the independent profile."""
    payload = read_source_payload(directory / relative, maximum_bytes=limit)
    if sha256(payload).hexdigest() != digest:
        raise ValueError("local verification input digest mismatch")
    return payload


def _attestation(directory: Path, request: AttestationInput) -> dict[str, object]:
    """Evaluate a distribution without executing or trusting its contents."""
    status: Status
    result: dict[str, str] | None = None
    material = request.material
    if request.predicate not in {PUBLISH, SLSA}:
        status = "unsupported"
    elif (
        material is None or find_spec("pypi_attestations") is None or find_spec("sigstore") is None
    ):
        status = "unavailable"
    else:
        from .provenance_attestation import verify_attestation

        try:
            _read_bound(directory, request.artifact, request.sha256, MAX_SOURCE_BYTES)
            evidence = _read_bound(directory, material.bundle, material.bundle_sha256, 1_048_576)
            root = _read_bound(directory, material.root, material.root_sha256, 256_000)
            result = verify_attestation(
                evidence=evidence,
                root_bytes=root,
                predicate=request.predicate,
                identity=request.identity,
                issuer=request.issuer,
                source_commit=request.source_commit,
                filename=PurePosixPath(request.artifact).name,
                project=request.project,
                release_version=request.version,
                artifact_digest=request.sha256,
            )
        except (OSError, RuntimeError, ValueError):
            result = None
        status = "verified" if result is not None else "refused"
    return {
        "name": _name(request.project),
        "version": request.version,
        "artifact": PurePosixPath(request.artifact).name,
        "sha256": request.sha256,
        "predicate": request.predicate,
        "identity": request.identity,
        "issuer": request.issuer,
        "source_commit": request.source_commit,
        "bundle_sha256": None if material is None else material.bundle_sha256,
        "root_sha256": None if material is None else material.root_sha256,
        "status": status,
        "verification": result,
    }


def _scorecard(directory: Path, value: object, expected_head: str) -> dict[str, object] | None:
    """Read named, source-bound measurements without an aggregate verdict."""
    if value is None:
        return None
    profile = require_mapping(value, "scorecard")
    require_exact_fields(
        profile, frozenset({"path", "sha256", "repository", "version"}), "scorecard"
    )
    digest = require_sha256(profile["sha256"], "scorecard.sha256")
    repo = require_string(profile["repository"], "scorecard.repository")
    tool = require_string(profile["version"], "scorecard.version")
    payload = _read_bound(
        directory, _relative(profile["path"], "scorecard.path"), digest, 1_048_576
    )
    document = require_mapping(_json_without_duplicate_keys(payload), "scorecard response")
    source = require_mapping(document.get("repo"), "scorecard source")
    producer = require_mapping(document.get("scorecard"), "scorecard producer")
    if (
        source.get("name") != repo
        or source.get("commit") != expected_head
        or producer.get("version") != tool
    ):
        raise ValueError("Scorecard source or producer mismatch")
    checks = document.get("checks")
    if not isinstance(checks, list) or len(checks) > 256:
        raise ValueError("Scorecard requires a bounded checks array")
    scores: dict[str, int | None] = {}
    for value in checks:
        row = require_mapping(value, "Scorecard check")
        name = require_string(row.get("name"), "Scorecard check name")
        score = row.get("score")
        if name in scores or type(score) is not int or not -1 <= score <= 10:
            raise ValueError("invalid or duplicate Scorecard measurement")
        scores[name] = None if score == -1 else score
    return {
        "repository": repo,
        "head": expected_head,
        "producer_version": tool,
        "sha256": digest,
        "checks": scores,
    }


def build_provenance_scan(
    report: AuditReport, inventory: GitInventory, profile_path: Path, profile_sha256: str
) -> dict[str, object]:
    """Attach exact dependency attestations and probes to an audit digest.

    Parameters
    ----------
    report : AuditReport
        Completed static scan to include in the output.
    inventory : GitInventory
        Observation of the same repository snapshot as the report.
    profile_path : Path
        Local profile and the base directory for its retained inputs.
    profile_sha256 : str
        Independently authenticated SHA-256 of the profile.

    Returns
    -------
    dict[str, object]
        Static report and separately digested provenance evidence.

    Raises
    ------
    ValueError
        Repository observations disagree or the profile fails validation.
    """
    if (
        str(inventory.root) != report.repository_root
        or inventory.head != report.head
        or inventory.head_tree != report.head_tree
        or inventory.tracked_content_digest != report.tracked_content_digest
        or inventory.git_provenance != report.git_provenance
    ):
        raise ValueError("repository changed during provenance scan")
    digest = require_sha256(profile_sha256, "profile SHA-256")
    raw = _read_bound(profile_path.parent, profile_path.name, digest, 131_072)
    profile = require_mapping(_json_without_duplicate_keys(raw), "provenance profile")
    require_exact_fields(
        profile,
        frozenset({"schema_version", "lock", "distributions", "scorecard"}),
        "provenance profile",
    )
    if profile["schema_version"] != PROVENANCE_PROFILE_SCHEMA_VERSION:
        raise ValueError("unsupported provenance profile schema")
    lock_path = _relative(profile["lock"], "lock")
    lock = next((item for item in inventory.files if item.path == lock_path), None)
    if lock is None:
        raise ValueError("provenance lock is not in the scan inventory")
    pins = _pinned_hashes(lock)
    distributions = profile["distributions"]
    if not isinstance(distributions, list) or len(distributions) > 256:
        raise ValueError("provenance requires a bounded distributions array")
    requests = [AttestationInput.parse(item) for item in distributions]
    keys = [(_name(item.project), item.version, item.sha256) for item in requests]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate provenance distributions")
    for name, version, sha in keys:
        if sha not in pins.get((name, version), ()):
            raise ValueError("distribution is absent from the exact tracked hash lock")
    score = _scorecard(profile_path.parent, profile["scorecard"], report.head)
    provenance: dict[str, object] = {
        "schema_version": PROVENANCE_SCAN_SCHEMA_VERSION,
        "report_digest": report.report_digest,
        "head": report.head,
        "head_tree": report.head_tree,
        "profile_sha256": digest,
        "lock_path": lock.path,
        "lock_blob": lock.object_id,
        "lock_sha256": lock.content_digest,
        "scorecard": score,
        "distributions": [_attestation(profile_path.parent, item) for item in requests],
    }
    return {
        "audit_report": report.to_dict(),
        "provenance": {**provenance, "provenance_digest": canonical_digest(provenance)},
    }
