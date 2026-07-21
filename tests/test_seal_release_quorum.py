# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — release-quorum seal driver tests
"""Prove the driver seals only fully evidenced candidates and verifies seals."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository
from signing_fixtures import sign_message, trust_store

from rigor_foundry.campaign_evidence import ToolchainIdentity
from rigor_foundry.campaign_models import AuditCampaign
from rigor_foundry.models import canonical_digest
from rigor_foundry.review_attestation import ReviewerAttestation
from rigor_foundry.scanner import scan_repository
from rigor_foundry.trust import ED25519_ALGORITHM, REVIEW_ATTESTATION_SIGNATURE_DOMAIN
from tools import seal_release_quorum as driver

POLICY_PATH = Path("rigor-foundry-policy.json")
FROZEN_AT = "2026-07-21T03:00:00Z"
INSTANT = "2026-07-25T00:00:00Z"
REVIEWED_AT = "2026-07-20T10:00:00Z"
EXPIRES_AT = "2026-08-20T10:00:00Z"
COMMIT = "f2038c686ed15e175ea9e86bc87e6b91182277f0"
TREE = "7817012b57c45103e6f8e0debdd2591fde28fef4"


def _prepare(path: Path, repository_id: str) -> Path:
    """Create one real historical repository and return its root."""
    repository = GitRepository.create(path)
    repository.write_text(f"src/{repository_id}.py", "VALUE = 1\n")
    repository.write_policy()
    repository.commit(f"test: create {repository_id}")
    return repository.root


def _write_campaign(path: Path) -> Path:
    """Write one real attestation campaign JSON and return its path."""
    root = _prepare(path / "campaign-source", "campaign")
    campaign = AuditCampaign.build(
        scan_repository(root, POLICY_PATH),
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
    target = path / "campaign.json"
    target.write_text(json.dumps(campaign.to_dict()), encoding="utf-8")
    return target


def _write_attestation(path: Path, key_id: str, assessment_digest: str) -> Path:
    """Write one genuinely signed reviewer attestation JSON and return its path."""
    payload_digest = ReviewerAttestation.payload_digest(
        reviewer_id=key_id,
        algorithm=ED25519_ALGORITHM,
        key_id=key_id,
        assessment_body_digest=assessment_digest,
        decision="pass",
        reviewed_at=REVIEWED_AT,
        expires_at=EXPIRES_AT,
    )
    attestation = ReviewerAttestation.build(
        reviewer_id=key_id,
        key_id=key_id,
        assessment_body_digest=assessment_digest,
        decision="pass",
        reviewed_at=REVIEWED_AT,
        expires_at=EXPIRES_AT,
        signature_hex=sign_message(key_id, REVIEW_ATTESTATION_SIGNATURE_DOMAIN, payload_digest),
    )
    target = path / f"{key_id}.json"
    target.write_text(json.dumps(attestation.to_dict()), encoding="utf-8")
    return target


def _manifest(tmp_path: Path) -> Path:
    """Assemble a complete, self-consistent release-evidence manifest."""
    app = _prepare(tmp_path / "sources" / "app", "app")
    library = _prepare(tmp_path / "sources" / "library", "library")
    assessment_digest = canonical_digest({"candidate": COMMIT, "tree": TREE})
    trust = trust_store("reviewer-a", "reviewer-b")
    trust_path = tmp_path / "trust.json"
    trust_path.write_text(json.dumps(trust.to_dict()), encoding="utf-8")
    manifest = {
        "candidate": {"commit": COMMIT, "tree": TREE, "version": "1.0.0"},
        "replay": {
            "campaign_id": "release-replay",
            "frozen_at": FROZEN_AT,
            "repositories": [
                {
                    "repository_id": "app",
                    "repository_root": str(app),
                    "policy_path": "rigor-foundry-policy.json",
                },
                {
                    "repository_id": "library",
                    "repository_root": str(library),
                    "policy_path": "rigor-foundry-policy.json",
                },
            ],
            "edges": [
                {
                    "from_repository": "app",
                    "to_repository": "library",
                    "relationship": "depends-on",
                    "rationale": "the app imports the library",
                }
            ],
        },
        "attestation_campaign": str(_write_campaign(tmp_path)),
        "observed_runs": 2,
        "observed_model_witnesses": 2,
        "reviewers": {
            "attestations": [
                str(_write_attestation(tmp_path, "reviewer-a", assessment_digest)),
                str(_write_attestation(tmp_path, "reviewer-b", assessment_digest)),
            ],
            "assessment_digest": assessment_digest,
            "required": 2,
            "trust_store": str(trust_path),
            "instant": INSTANT,
        },
        "artefacts": {
            "wheel_sha256": canonical_digest({"a": "wheel"}),
            "sdist_sha256": canonical_digest({"a": "sdist"}),
            "sbom_sha256": canonical_digest({"a": "sbom"}),
        },
        "surface": {
            "signing_bundle_digests": [
                canonical_digest({"b": "wheel"}),
                canonical_digest({"b": "sdist"}),
            ],
            "provenance_digest": canonical_digest({"p": "slsa"}),
            "pages_digest": canonical_digest({"p": "docs"}),
        },
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest_path


def test_seal_produces_a_valid_certificate(tmp_path: Path) -> None:
    """A complete manifest seals a certificate that round-trips through from_dict."""
    certificate = driver.seal(_manifest(tmp_path))
    certificate.validate()
    assert certificate.candidate.commit == COMMIT
    assert certificate.verified_reviewer_keys == ("reviewer-a", "reviewer-b")
    assert certificate.execution_resolution == "succeeded"


def test_seal_command_writes_and_verify_command_reads(tmp_path: Path) -> None:
    """The CLI seals to a file and verifies the same file end to end."""
    manifest_path = _manifest(tmp_path)
    output = tmp_path / "certificate.json"
    assert driver.main(["seal", "--manifest", str(manifest_path), "--output", str(output)]) == 0
    assert output.exists()
    assert driver.main(["verify", "--certificate", str(output)]) == 0


def test_verify_rejects_a_tampered_certificate(tmp_path: Path) -> None:
    """A certificate whose sealed digest was altered fails CLI verification."""
    manifest_path = _manifest(tmp_path)
    output = tmp_path / "certificate.json"
    driver.main(["seal", "--manifest", str(manifest_path), "--output", str(output)])
    payload = json.loads(output.read_text(encoding="utf-8"))
    payload["certificate_digest"] = canonical_digest({"swap": True})
    output.write_text(json.dumps(payload), encoding="utf-8")
    assert driver.main(["verify", "--certificate", str(output)]) == 1


def test_seal_command_reports_a_sub_quorum_manifest(tmp_path: Path) -> None:
    """A manifest short of the reviewer quorum fails the seal command."""
    manifest_path = _manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["reviewers"]["attestations"] = manifest["reviewers"]["attestations"][:1]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    output = tmp_path / "certificate.json"
    assert driver.main(["seal", "--manifest", str(manifest_path), "--output", str(output)]) == 1
    assert not output.exists()


def test_seal_rejects_a_missing_manifest(tmp_path: Path) -> None:
    """A manifest path that does not exist is reported, not crashed."""
    output = tmp_path / "certificate.json"
    assert (
        driver.main(["seal", "--manifest", str(tmp_path / "absent.json"), "--output", str(output)])
        == 1
    )


def test_seal_rejects_invalid_manifest_json(tmp_path: Path) -> None:
    """A manifest that is not valid JSON is reported cleanly."""
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text("{not json", encoding="utf-8")
    output = tmp_path / "certificate.json"
    assert driver.main(["seal", "--manifest", str(manifest_path), "--output", str(output)]) == 1


def test_seal_rejects_a_forged_candidate(tmp_path: Path) -> None:
    """A candidate with a non-Git commit is rejected before any replay."""
    manifest_path = _manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["candidate"]["commit"] = "not-a-commit"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match=r"candidate\.commit"):
        driver.seal(manifest_path)


def test_surface_rejects_non_list_signing_bundles(tmp_path: Path) -> None:
    """A surface whose signing bundles are not a list is rejected."""
    with pytest.raises(ValueError, match="signing_bundle_digests must be a list"):
        driver._surface(
            {
                "signing_bundle_digests": "one",
                "provenance_digest": canonical_digest({"p": "slsa"}),
                "pages_digest": canonical_digest({"p": "docs"}),
            }
        )


def test_reviewer_attestations_must_be_a_list() -> None:
    """A reviewers block whose attestations are not a list is rejected."""
    with pytest.raises(ValueError, match=r"reviewers\.attestations must be a list"):
        driver._reviewer_attestations("not-a-list")


def test_require_list_accepts_a_list() -> None:
    """The list guard returns the value unchanged for a real list."""
    assert driver._require_list([1, 2], "field") == [1, 2]
