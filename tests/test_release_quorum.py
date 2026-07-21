# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — fail-closed release-quorum certificate tests
"""Prove the release certificate certifies only fully evidenced candidates."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository
from signing_fixtures import sign_message, trust_store

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
from rigor_foundry.models import canonical_digest
from rigor_foundry.release_quorum import (
    RELEASE_QUORUM_SCHEMA_VERSION,
    ReleaseArtefacts,
    ReleaseCandidateAnchor,
    ReleaseQuorumCertificate,
    ReleaseSurfaceReferences,
    _anchor_from_dict,
    _artefacts_from_dict,
    _require_resolution,
    _surface_from_dict,
)
from rigor_foundry.review_attestation import ReviewerAttestation
from rigor_foundry.trust import (
    ED25519_ALGORITHM,
    REVIEW_ATTESTATION_SIGNATURE_DOMAIN,
    VerificationTrustStore,
)

POLICY_PATH = Path("rigor-foundry-policy.json")
FROZEN_AT = "2026-07-21T02:00:00Z"
INSTANT = datetime(2026, 7, 25, tzinfo=UTC)
REVIEWED_AT = "2026-07-20T10:00:00Z"
EXPIRES_AT = "2026-08-20T10:00:00Z"
COMMIT = "e5a68bdd11ae7dd30982eb6c265fb4d436a14847"
TREE = "9fb1b3e2ce922fdb81647e05f2489ed2a930e51c"


def _prepare(path: Path, repository_id: str) -> RepositoryCaptureRequest:
    """Create one historical commit and its exact frozen capture request."""
    repository = GitRepository.create(path)
    repository.write_text(f"src/{repository_id}.py", "VALUE = 1\n")
    repository.write_policy()
    historical_head = repository.commit(f"test: create {repository_id}")
    report = scan_report(repository.root)
    return RepositoryCaptureRequest.build(
        repository_id=repository_id,
        repository_root=repository.root,
        requested_commit=historical_head,
        policy_digest=report.policy_digest,
        rule_pack_version=report.rule_pack_version,
        rule_pack_digest=report.rule_pack_digest,
        adapter_lock_digest=adapter_lock_digest(report.policy),
        toolchain_digest=ToolchainIdentity.current().identity_digest,
    )


def scan_report(root: Path):  # type: ignore[no-untyped-def]
    """Scan one repository through the production scanner."""
    from rigor_foundry.scanner import scan_repository

    return scan_repository(root, POLICY_PATH)


def _succeeded_execution(tmp_path: Path) -> CrossRepositoryExecution:
    """Replay a real two-repository campaign to a fully succeeded record."""
    app = _prepare(tmp_path / "sources" / "app", "app")
    library = _prepare(tmp_path / "sources" / "library", "library")
    requests = (app, library)
    edge = InterRepositoryEdge.build(
        from_repository="app",
        to_repository="library",
        relationship="depends-on",
        rationale="the app imports the library",
    )
    capture = capture_cross_repository_campaign(
        campaign_id="release-quorum",
        frozen_at=FROZEN_AT,
        requests=requests,
        edges=(edge,),
    )
    plan = CrossRepositoryExecutionPlan.build(
        capture=capture,
        requests=requests,
        policy_paths=(POLICY_PATH.as_posix(), POLICY_PATH.as_posix()),
    )
    temporary_parent = tmp_path / "temporary"
    temporary_parent.mkdir()
    execution = execute_cross_repository_campaign(
        plan=plan,
        capture=capture,
        requests=requests,
        temporary_parent=temporary_parent,
    )
    assert execution.resolution == "succeeded"
    return execution


def _campaign(tmp_path: Path) -> AuditCampaign:
    """Build one real attestation campaign with a two-run, two-witness floor."""
    root = tmp_path / "campaign-source"
    repository = GitRepository.create(root)
    repository.write_text("src/campaign.py", "VALUE = 1\n")
    repository.write_policy()
    repository.commit("test: create campaign source")
    return AuditCampaign.build(
        scan_report(repository.root),
        campaign_id="release-attestation",
        project="rigor-foundry",
        policy_path=POLICY_PATH.as_posix(),
        toolchain=ToolchainIdentity.current(),
        created_by="release-operator",
        created_at=FROZEN_AT,
        purpose="diagnostic",
        expected_runs=2,
        required_model_witnesses=2,
    )


def _artefacts() -> ReleaseArtefacts:
    """Return three distinct artefact digests."""
    return ReleaseArtefacts.build(
        wheel_sha256=canonical_digest({"artefact": "wheel"}),
        sdist_sha256=canonical_digest({"artefact": "sdist"}),
        sbom_sha256=canonical_digest({"artefact": "sbom"}),
    )


def _surface() -> ReleaseSurfaceReferences:
    """Return one valid signing, provenance, and documentation reference set."""
    return ReleaseSurfaceReferences.build(
        signing_bundle_digests=(
            canonical_digest({"bundle": "wheel"}),
            canonical_digest({"bundle": "sdist"}),
        ),
        provenance_digest=canonical_digest({"provenance": "slsa"}),
        pages_digest=canonical_digest({"pages": "docs"}),
    )


def _attestation(
    key_id: str,
    assessment_digest: str,
    *,
    decision: str = "pass",
    reviewed_at: str = REVIEWED_AT,
    expires_at: str = EXPIRES_AT,
) -> ReviewerAttestation:
    """Build one genuinely signed reviewer attestation for a fixture key."""
    payload_digest = ReviewerAttestation.payload_digest(
        reviewer_id=key_id,
        algorithm=ED25519_ALGORITHM,
        key_id=key_id,
        assessment_body_digest=assessment_digest,
        decision=decision,  # type: ignore[arg-type]
        reviewed_at=reviewed_at,
        expires_at=expires_at,
    )
    signature = sign_message(key_id, REVIEW_ATTESTATION_SIGNATURE_DOMAIN, payload_digest)
    return ReviewerAttestation.build(
        reviewer_id=key_id,
        key_id=key_id,
        assessment_body_digest=assessment_digest,
        decision=decision,  # type: ignore[arg-type]
        reviewed_at=reviewed_at,
        expires_at=expires_at,
        signature_hex=signature,
    )


@dataclass(frozen=True)
class _Inputs:
    """Complete, self-consistent inputs for one release certificate."""

    candidate: ReleaseCandidateAnchor
    execution: CrossRepositoryExecution
    campaign: AuditCampaign
    attestations: tuple[ReviewerAttestation, ...]
    assessment_digest: str
    trust: VerificationTrustStore
    artefacts: ReleaseArtefacts
    surface: ReleaseSurfaceReferences


def _inputs(tmp_path: Path) -> _Inputs:
    """Assemble every real input a fully evidenced certificate requires."""
    candidate = ReleaseCandidateAnchor.build(commit=COMMIT, tree=TREE, version="1.0.0")
    artefacts = _artefacts()
    assessment_digest = canonical_digest(
        {"candidate": candidate.anchor_digest, "artefacts": artefacts.artefacts_digest}
    )
    return _Inputs(
        candidate=candidate,
        execution=_succeeded_execution(tmp_path),
        campaign=_campaign(tmp_path),
        attestations=(
            _attestation("reviewer-a", assessment_digest),
            _attestation("reviewer-b", assessment_digest),
        ),
        assessment_digest=assessment_digest,
        trust=trust_store("reviewer-a", "reviewer-b"),
        artefacts=artefacts,
        surface=_surface(),
    )


def _certify(inputs: _Inputs, **overrides: object) -> ReleaseQuorumCertificate:
    """Build one certificate from the inputs with optional overrides."""
    arguments: dict[str, object] = {
        "candidate": inputs.candidate,
        "execution": inputs.execution,
        "campaign": inputs.campaign,
        "observed_runs": 2,
        "observed_model_witnesses": 2,
        "reviewer_attestations": inputs.attestations,
        "reviewer_assessment_digest": inputs.assessment_digest,
        "required_reviewers": 2,
        "trust_store": inputs.trust,
        "instant": INSTANT,
        "artefacts": inputs.artefacts,
        "surface": inputs.surface,
    }
    arguments.update(overrides)
    return ReleaseQuorumCertificate.build(**arguments)  # type: ignore[arg-type]


def test_full_evidence_seals_a_content_addressed_certificate(tmp_path: Path) -> None:
    """A candidate with every gate met produces a stable, verifiable certificate."""
    inputs = _inputs(tmp_path)
    certificate = _certify(inputs)

    assert certificate.schema_version == RELEASE_QUORUM_SCHEMA_VERSION
    assert certificate.execution_resolution == "succeeded"
    assert certificate.rollback_proven is True
    assert certificate.verified_reviewer_keys == ("reviewer-a", "reviewer-b")
    assert certificate.historical_execution_digest == inputs.execution.execution_digest
    assert certificate.attestation_campaign_digest == inputs.campaign.contract_digest
    certificate.validate()
    assert ReleaseQuorumCertificate.from_dict(certificate.to_dict()) == certificate


def test_replay_that_did_not_fully_succeed_is_rejected(tmp_path: Path) -> None:
    """Any non-succeeded historical resolution cannot be certified."""
    inputs = _inputs(tmp_path)
    degraded = replace(inputs.execution, resolution="partial")
    with pytest.raises(ValueError, match="fully succeeded historical replay"):
        _certify(inputs, execution=degraded)


def test_missing_rollback_proof_is_rejected(tmp_path: Path) -> None:
    """A replay that retained its temporary workspace cannot be certified."""
    inputs = _inputs(tmp_path)
    unrolled = replace(inputs.execution, temporary_workspaces_removed=False)
    with pytest.raises(ValueError, match="proven temporary rollback"):
        _certify(inputs, execution=unrolled)


def test_observed_runs_below_the_campaign_floor_are_rejected(tmp_path: Path) -> None:
    """Fewer independent runs than the campaign requires fail the quorum."""
    inputs = _inputs(tmp_path)
    with pytest.raises(ValueError, match="observed runs to meet the campaign floor"):
        _certify(inputs, observed_runs=1)


def test_observed_witnesses_below_the_floor_are_rejected(tmp_path: Path) -> None:
    """Fewer distinct model witnesses than required fail the quorum."""
    inputs = _inputs(tmp_path)
    with pytest.raises(ValueError, match="observed model witnesses to meet the floor"):
        _certify(inputs, observed_model_witnesses=1)


def test_reviewer_quorum_short_of_unique_trusted_keys_is_rejected(tmp_path: Path) -> None:
    """One trusted signature cannot satisfy a two-reviewer quorum."""
    inputs = _inputs(tmp_path)
    with pytest.raises(ValueError, match="more unique trusted reviewer signatures"):
        _certify(inputs, reviewer_attestations=(inputs.attestations[0],))


def test_duplicate_reviewer_key_counts_once(tmp_path: Path) -> None:
    """Two signatures from one key are one vote, not a forged quorum."""
    inputs = _inputs(tmp_path)
    duplicate = _attestation("reviewer-a", inputs.assessment_digest)
    with pytest.raises(ValueError, match="more unique trusted reviewer signatures"):
        _certify(
            inputs,
            reviewer_attestations=(inputs.attestations[0], duplicate),
            trust_store=trust_store("reviewer-a"),
        )


def test_untrusted_or_wrong_decision_signatures_do_not_count(tmp_path: Path) -> None:
    """Untrusted keys and non-pass decisions never reach the reviewer quorum."""
    inputs = _inputs(tmp_path)
    untrusted = _attestation("reviewer-c", inputs.assessment_digest)
    blocked = _attestation("reviewer-b", inputs.assessment_digest, decision="blocked")
    with pytest.raises(ValueError, match="more unique trusted reviewer signatures"):
        _certify(
            inputs,
            reviewer_attestations=(inputs.attestations[0], untrusted, blocked),
        )


def test_expired_reviewer_signature_does_not_count(tmp_path: Path) -> None:
    """A review that has lapsed by the evaluation instant is not current."""
    inputs = _inputs(tmp_path)
    late = datetime(2026, 9, 1, tzinfo=UTC)
    with pytest.raises(ValueError, match="more unique trusted reviewer signatures"):
        _certify(inputs, instant=late)


def test_forged_candidate_anchor_is_rejected(tmp_path: Path) -> None:
    """A candidate anchor whose digest was substituted cannot be certified."""
    inputs = _inputs(tmp_path)
    forged = replace(inputs.candidate, commit="0" * 40)
    with pytest.raises(ValueError, match="candidate anchor digest"):
        _certify(inputs, candidate=forged)


def test_forged_artefacts_are_rejected(tmp_path: Path) -> None:
    """An artefact set whose digest was substituted cannot be certified."""
    inputs = _inputs(tmp_path)
    forged = replace(inputs.artefacts, wheel_sha256=canonical_digest({"artefact": "swap"}))
    with pytest.raises(ValueError, match="release artefacts digest"):
        _certify(inputs, artefacts=forged)


def test_forged_surface_is_rejected(tmp_path: Path) -> None:
    """A surface reference set whose digest was substituted cannot be certified."""
    inputs = _inputs(tmp_path)
    forged = replace(inputs.surface, pages_digest=canonical_digest({"pages": "swap"}))
    with pytest.raises(ValueError, match="release surface references digest"):
        _certify(inputs, surface=forged)


def test_surface_requires_at_least_one_signing_bundle() -> None:
    """A release without any signing bundle is not a signed release."""
    with pytest.raises(ValueError, match="at least one signing bundle"):
        ReleaseSurfaceReferences.build(
            signing_bundle_digests=(),
            provenance_digest=canonical_digest({"provenance": "slsa"}),
            pages_digest=canonical_digest({"pages": "docs"}),
        )


def test_surface_rejects_duplicate_signing_bundles() -> None:
    """Repeated bundle digests cannot inflate the signed-artefact count."""
    bundle = canonical_digest({"bundle": "wheel"})
    with pytest.raises(ValueError, match="signing bundles must be unique"):
        ReleaseSurfaceReferences.build(
            signing_bundle_digests=(bundle, bundle),
            provenance_digest=canonical_digest({"provenance": "slsa"}),
            pages_digest=canonical_digest({"pages": "docs"}),
        )


def test_candidate_anchor_rejects_a_non_semantic_version() -> None:
    """The candidate version must be a real semantic version."""
    with pytest.raises(ValueError, match=r"candidate\.version"):
        ReleaseCandidateAnchor.build(commit=COMMIT, tree=TREE, version="not-a-version")


def test_validate_rejects_a_tampered_certificate_digest(tmp_path: Path) -> None:
    """A certificate whose sealed digest was swapped fails validation."""
    inputs = _inputs(tmp_path)
    certificate = _certify(inputs)
    tampered = replace(certificate, certificate_digest=canonical_digest({"swap": True}))
    with pytest.raises(ValueError, match="certificate digest does not match"):
        tampered.validate()


def test_validate_rejects_a_downgraded_observed_count(tmp_path: Path) -> None:
    """Editing an observed count below the floor is caught by validation."""
    inputs = _inputs(tmp_path)
    certificate = _certify(inputs)
    downgraded = replace(certificate, observed_runs=1)
    with pytest.raises(ValueError, match="observed counts fall below the floor"):
        downgraded.validate()


def test_validate_rejects_an_unsupported_schema_version(tmp_path: Path) -> None:
    """A certificate carrying an unknown schema version is rejected."""
    inputs = _inputs(tmp_path)
    certificate = _certify(inputs)
    with pytest.raises(ValueError, match="unsupported release-quorum schema version"):
        replace(certificate, schema_version="9.9").validate()


def test_validate_rejects_non_unique_reviewer_keys(tmp_path: Path) -> None:
    """A duplicated reviewer key in the sealed evidence fails validation."""
    inputs = _inputs(tmp_path)
    certificate = _certify(inputs)
    with pytest.raises(ValueError, match="reviewer keys must be unique"):
        replace(certificate, verified_reviewer_keys=("reviewer-a", "reviewer-a")).validate()


def test_validate_rejects_a_reviewer_count_below_threshold(tmp_path: Path) -> None:
    """Dropping a sealed reviewer key below the threshold fails validation."""
    inputs = _inputs(tmp_path)
    certificate = _certify(inputs)
    with pytest.raises(ValueError, match="below the reviewer quorum"):
        replace(certificate, verified_reviewer_keys=("reviewer-a",)).validate()


def test_validate_rejects_a_degraded_resolution(tmp_path: Path) -> None:
    """A certificate edited to a non-succeeded resolution fails validation."""
    inputs = _inputs(tmp_path)
    certificate = _certify(inputs)
    with pytest.raises(ValueError, match="requires a succeeded replay"):
        replace(certificate, execution_resolution="partial").validate()


def test_validate_rejects_a_cleared_rollback_flag(tmp_path: Path) -> None:
    """A certificate edited to drop rollback proof fails validation."""
    inputs = _inputs(tmp_path)
    certificate = _certify(inputs)
    with pytest.raises(ValueError, match="requires proven rollback"):
        replace(certificate, rollback_proven=False).validate()


def test_from_dict_rejects_missing_fields(tmp_path: Path) -> None:
    """A serialised certificate missing a field cannot be parsed."""
    inputs = _inputs(tmp_path)
    payload = _certify(inputs).to_dict()
    payload.pop("artefacts")
    with pytest.raises(ValueError, match="fields do not match schema"):
        ReleaseQuorumCertificate.from_dict(payload)


def test_from_dict_rejects_an_unsupported_schema_version(tmp_path: Path) -> None:
    """A serialised certificate with an unknown schema version is rejected."""
    inputs = _inputs(tmp_path)
    payload = _certify(inputs).to_dict()
    payload["schema_version"] = "9.9"
    with pytest.raises(ValueError, match="unsupported release-quorum schema version"):
        ReleaseQuorumCertificate.from_dict(payload)


def test_from_dict_rejects_a_non_succeeded_resolution(tmp_path: Path) -> None:
    """A serialised certificate with a degraded resolution is rejected."""
    inputs = _inputs(tmp_path)
    payload = _certify(inputs).to_dict()
    payload["execution_resolution"] = "partial"
    with pytest.raises(ValueError, match="requires a succeeded replay"):
        ReleaseQuorumCertificate.from_dict(payload)


def test_from_dict_rejects_a_cleared_rollback_flag(tmp_path: Path) -> None:
    """A serialised certificate that dropped rollback proof is rejected."""
    inputs = _inputs(tmp_path)
    payload = _certify(inputs).to_dict()
    payload["rollback_proven"] = False
    with pytest.raises(ValueError, match="requires proven rollback"):
        ReleaseQuorumCertificate.from_dict(payload)


def test_from_dict_rejects_non_list_reviewer_keys(tmp_path: Path) -> None:
    """The serialised reviewer-key evidence must be a list."""
    inputs = _inputs(tmp_path)
    payload = _certify(inputs).to_dict()
    payload["verified_reviewer_keys"] = "reviewer-a"
    with pytest.raises(ValueError, match="verified_reviewer_keys must be a list"):
        ReleaseQuorumCertificate.from_dict(payload)


def test_require_resolution_rejects_a_non_succeeded_literal() -> None:
    """The resolution helper accepts only the succeeded literal."""
    assert _require_resolution("succeeded") == "succeeded"
    with pytest.raises(ValueError, match="requires a succeeded replay"):
        _require_resolution("failed")


def test_anchor_from_dict_rejects_field_and_digest_drift(tmp_path: Path) -> None:
    """The anchor parser rejects unexpected fields and substituted digests."""
    inputs = _inputs(tmp_path)
    body = inputs.candidate.to_dict()
    with pytest.raises(ValueError, match="anchor fields do not match schema"):
        _anchor_from_dict({**body, "extra": "x"})
    with pytest.raises(ValueError, match="anchor digest does not match"):
        _anchor_from_dict({**body, "anchor_digest": canonical_digest({"swap": True})})


def test_artefacts_from_dict_rejects_field_and_digest_drift() -> None:
    """The artefact parser rejects unexpected fields and substituted digests."""
    body = _artefacts().to_dict()
    with pytest.raises(ValueError, match="artefacts fields do not match schema"):
        _artefacts_from_dict({**body, "extra": "x"})
    with pytest.raises(ValueError, match="artefacts digest does not match"):
        _artefacts_from_dict({**body, "artefacts_digest": canonical_digest({"swap": True})})


def test_surface_from_dict_rejects_field_type_and_digest_drift() -> None:
    """The surface parser rejects bad fields, non-list bundles, and digests."""
    body = _surface().to_dict()
    with pytest.raises(ValueError, match="surface fields do not match schema"):
        _surface_from_dict({**body, "extra": "x"})
    with pytest.raises(ValueError, match="signing_bundle_digests must be a list"):
        _surface_from_dict({**body, "signing_bundle_digests": "one"})
    with pytest.raises(ValueError, match="surface references digest does not match"):
        _surface_from_dict({**body, "references_digest": canonical_digest({"swap": True})})
