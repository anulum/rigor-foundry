# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — turnkey release-quorum certificate driver
"""Assemble or verify one sealed release-quorum certificate from evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rigor_foundry.campaign_evidence import ToolchainIdentity
from rigor_foundry.campaign_models import AuditCampaign
from rigor_foundry.cross_repository_campaign import InterRepositoryEdge
from rigor_foundry.cross_repository_capture import (
    RepositoryCaptureRequest,
    capture_cross_repository_campaign,
)
from rigor_foundry.cross_repository_execution import (
    CrossRepositoryExecution,
    CrossRepositoryExecutionPlan,
    adapter_lock_digest,
)
from rigor_foundry.cross_repository_runtime import execute_cross_repository_campaign
from rigor_foundry.model_primitives import (
    parse_utc_timestamp,
    require_utc_timestamp,
)
from rigor_foundry.models import require_integer, require_mapping, require_string
from rigor_foundry.release_quorum import (
    ReleaseArtefacts,
    ReleaseCandidateAnchor,
    ReleaseQuorumCertificate,
    ReleaseSurfaceReferences,
)
from rigor_foundry.review_attestation import ReviewerAttestation
from rigor_foundry.scanner import scan_repository
from rigor_foundry.trust import VerificationTrustStore


def _require_list(value: object, field: str) -> list[object]:
    """Return a list value or raise for one manifest field."""
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    return value


def _load_json(path: Path, field: str) -> object:
    """Read and parse one JSON evidence file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ValueError(f"{field} could not be read at {path}") from error
    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError(f"{field} is not valid JSON at {path}") from error


def _candidate(value: object) -> ReleaseCandidateAnchor:
    """Build the release-candidate anchor from the manifest."""
    data = require_mapping(value, "candidate")
    return ReleaseCandidateAnchor.build(
        commit=require_string(data.get("commit"), "candidate.commit"),
        tree=require_string(data.get("tree"), "candidate.tree"),
        version=require_string(data.get("version"), "candidate.version"),
    )


def _artefacts(value: object) -> ReleaseArtefacts:
    """Build the release-artefact identities from the manifest."""
    data = require_mapping(value, "artefacts")
    return ReleaseArtefacts.build(
        wheel_sha256=require_string(data.get("wheel_sha256"), "artefacts.wheel_sha256"),
        sdist_sha256=require_string(data.get("sdist_sha256"), "artefacts.sdist_sha256"),
        sbom_sha256=require_string(data.get("sbom_sha256"), "artefacts.sbom_sha256"),
    )


def _surface(value: object) -> ReleaseSurfaceReferences:
    """Build the release-surface references from the manifest."""
    data = require_mapping(value, "surface")
    bundles = _require_list(data.get("signing_bundle_digests"), "surface.signing_bundle_digests")
    return ReleaseSurfaceReferences.build(
        signing_bundle_digests=tuple(
            require_string(item, f"surface.signing_bundle_digests[{index}]")
            for index, item in enumerate(bundles)
        ),
        provenance_digest=require_string(
            data.get("provenance_digest"), "surface.provenance_digest"
        ),
        pages_digest=require_string(data.get("pages_digest"), "surface.pages_digest"),
    )


def _capture_request(value: object, index: int) -> tuple[RepositoryCaptureRequest, str]:
    """Scan one repository at its current head and freeze its capture request."""
    data = require_mapping(value, f"replay.repositories[{index}]")
    repository_id = require_string(data.get("repository_id"), f"replay.repositories[{index}].id")
    repository_root = Path(
        require_string(data.get("repository_root"), f"replay.repositories[{index}].root")
    )
    policy_path = require_string(
        data.get("policy_path"), f"replay.repositories[{index}].policy_path"
    )
    report = scan_repository(repository_root, Path(policy_path))
    request = RepositoryCaptureRequest.build(
        repository_id=repository_id,
        repository_root=repository_root,
        requested_commit=report.head,
        policy_digest=report.policy_digest,
        rule_pack_version=report.rule_pack_version,
        rule_pack_digest=report.rule_pack_digest,
        adapter_lock_digest=adapter_lock_digest(report.policy),
        toolchain_digest=ToolchainIdentity.current().identity_digest,
    )
    return request, policy_path


def _edge(value: object, index: int) -> InterRepositoryEdge:
    """Build one declared inter-repository dependency edge."""
    data = require_mapping(value, f"replay.edges[{index}]")
    return InterRepositoryEdge.build(
        from_repository=require_string(data.get("from_repository"), f"replay.edges[{index}].from"),
        to_repository=require_string(data.get("to_repository"), f"replay.edges[{index}].to"),
        relationship=require_string(
            data.get("relationship"), f"replay.edges[{index}].relationship"
        ),
        rationale=require_string(data.get("rationale"), f"replay.edges[{index}].rationale"),
    )


def _run_replay(value: object) -> CrossRepositoryExecution:
    """Capture and replay the declared representative campaign live."""
    data = require_mapping(value, "replay")
    repositories = _require_list(data.get("repositories"), "replay.repositories")
    prepared = tuple(_capture_request(item, index) for index, item in enumerate(repositories))
    requests = tuple(request for request, _policy in prepared)
    policy_paths = tuple(policy for _request, policy in prepared)
    edge_specs = _require_list(data.get("edges", []), "replay.edges")
    edges = tuple(_edge(item, index) for index, item in enumerate(edge_specs))
    capture = capture_cross_repository_campaign(
        campaign_id=require_string(data.get("campaign_id"), "replay.campaign_id"),
        frozen_at=require_utc_timestamp(data.get("frozen_at"), "replay.frozen_at"),
        requests=requests,
        edges=edges,
    )
    plan = CrossRepositoryExecutionPlan.build(
        capture=capture,
        requests=requests,
        policy_paths=policy_paths,
    )
    return execute_cross_repository_campaign(plan=plan, capture=capture, requests=requests)


def _reviewer_attestations(value: object) -> tuple[ReviewerAttestation, ...]:
    """Load every declared reviewer attestation from its JSON file."""
    paths = _require_list(value, "reviewers.attestations")
    return tuple(
        ReviewerAttestation.from_dict(
            _load_json(
                Path(require_string(item, f"reviewers.attestations[{index}]")),
                f"reviewers.attestations[{index}]",
            )
        )
        for index, item in enumerate(paths)
    )


def seal(manifest_path: Path) -> ReleaseQuorumCertificate:
    """Build one sealed certificate from a release-evidence manifest.

    Parameters
    ----------
    manifest_path:
        Path to the JSON manifest declaring the candidate, the replay
        repositories and edges, and the campaign, reviewer, trust-store,
        artefact, and surface evidence.

    Returns
    -------
    ReleaseQuorumCertificate
        The sealed, validated certificate.

    Raises
    ------
    ValueError
        If the manifest is malformed or any release gate is unmet.
    """
    manifest = require_mapping(_load_json(manifest_path, "manifest"), "manifest")
    candidate = _candidate(manifest.get("candidate"))
    artefacts = _artefacts(manifest.get("artefacts"))
    surface = _surface(manifest.get("surface"))
    campaign = AuditCampaign.from_dict(
        _load_json(
            Path(require_string(manifest.get("attestation_campaign"), "attestation_campaign")),
            "attestation_campaign",
        )
    )
    reviewers = require_mapping(manifest.get("reviewers"), "reviewers")
    trust_store = VerificationTrustStore.from_dict(
        _load_json(
            Path(require_string(reviewers.get("trust_store"), "reviewers.trust_store")),
            "reviewers.trust_store",
        )
    )
    attestations = _reviewer_attestations(reviewers.get("attestations"))
    instant = parse_utc_timestamp(
        require_utc_timestamp(reviewers.get("instant"), "reviewers.instant"),
        "reviewers.instant",
    )
    execution = _run_replay(manifest.get("replay"))
    return ReleaseQuorumCertificate.build(
        candidate=candidate,
        execution=execution,
        campaign=campaign,
        observed_runs=require_integer(manifest.get("observed_runs"), "observed_runs", minimum=1),
        observed_model_witnesses=require_integer(
            manifest.get("observed_model_witnesses"),
            "observed_model_witnesses",
            minimum=1,
        ),
        reviewer_attestations=attestations,
        reviewer_assessment_digest=require_string(
            reviewers.get("assessment_digest"),
            "reviewers.assessment_digest",
        ),
        required_reviewers=require_integer(
            reviewers.get("required"),
            "reviewers.required",
            minimum=1,
        ),
        trust_store=trust_store,
        instant=instant,
        artefacts=artefacts,
        surface=surface,
    )


def verify(certificate_path: Path) -> ReleaseQuorumCertificate:
    """Reload and integrity-check one sealed certificate JSON file."""
    return ReleaseQuorumCertificate.from_dict(_load_json(certificate_path, "certificate"))


def _seal_command(args: argparse.Namespace) -> int:
    """Seal a certificate from a manifest and write it to the output path."""
    certificate = seal(args.manifest)
    args.output.write_text(
        json.dumps(certificate.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"sealed release-quorum certificate {certificate.certificate_digest} at {args.output}")
    return 0


def _verify_command(args: argparse.Namespace) -> int:
    """Verify a sealed certificate file and report its bound identity."""
    certificate = verify(args.certificate)
    print(
        "verified release-quorum certificate "
        f"{certificate.certificate_digest} for candidate {certificate.candidate.commit}"
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    """Build the release-quorum driver argument parser."""
    parser = argparse.ArgumentParser(description="Seal or verify a release-quorum certificate.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    seal_parser = subparsers.add_parser(
        "seal", help="Seal a certificate from an evidence manifest."
    )
    seal_parser.add_argument("--manifest", type=Path, required=True)
    seal_parser.add_argument("--output", type=Path, required=True)
    seal_parser.set_defaults(handler=_seal_command)
    verify_parser = subparsers.add_parser("verify", help="Verify one sealed certificate file.")
    verify_parser.add_argument("--certificate", type=Path, required=True)
    verify_parser.set_defaults(handler=_verify_command)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the release-quorum driver over one command."""
    args = _parser().parse_args(argv)
    handler: object = args.handler
    if not callable(handler):  # pragma: no cover - argparse always binds a handler
        raise SystemExit(2)
    try:
        return int(handler(args))
    except ValueError as error:
        print(f"release-quorum error: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
