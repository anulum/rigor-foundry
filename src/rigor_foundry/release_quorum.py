# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — fail-closed release-candidate quorum certificate
"""Bind one exact release candidate to its replay, quorum, and rollback proof."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Final

from .campaign_models import AuditCampaign
from .cross_repository_execution import CrossRepositoryExecution, ExecutionResolution
from .model_primitives import (
    require_digest,
    require_git_object,
    require_semantic_version,
)
from .models import canonical_digest, require_integer, require_mapping, require_string
from .review_attestation import ReviewerAttestation
from .trust import VerificationTrustStore

RELEASE_QUORUM_SCHEMA_VERSION: Final = "1.0"

_RELEASE_REVIEW_DECISION: Final = "pass"
_REQUIRED_RESOLUTION: Final[ExecutionResolution] = "succeeded"


@dataclass(frozen=True)
class ReleaseCandidateAnchor:
    """Exact frozen Git object and version of one release candidate.

    Parameters
    ----------
    commit:
        Full SHA-1 or SHA-256 commit identity of the candidate.
    tree:
        Full Git tree identity reachable from ``commit``.
    version:
        Semantic version that the candidate publishes; the release tag is
        ``v{version}``.
    anchor_digest:
        Content identity that rejects any substituted candidate field.
    """

    commit: str
    tree: str
    version: str
    anchor_digest: str

    @classmethod
    def build(cls, *, commit: str, tree: str, version: str) -> ReleaseCandidateAnchor:
        """Build one validated release-candidate anchor."""
        body = {
            "commit": require_git_object(commit, "candidate.commit"),
            "tree": require_git_object(tree, "candidate.tree"),
            "version": require_semantic_version(version, "candidate.version"),
        }
        return cls(**body, anchor_digest=canonical_digest(body))

    def to_dict(self) -> dict[str, str]:
        """Serialise one release-candidate anchor."""
        return {
            "commit": self.commit,
            "tree": self.tree,
            "version": self.version,
            "anchor_digest": self.anchor_digest,
        }


def _validate_anchor(anchor: ReleaseCandidateAnchor) -> None:
    """Reject a forged candidate anchor or anchor digest."""
    rebuilt = ReleaseCandidateAnchor.build(
        commit=anchor.commit,
        tree=anchor.tree,
        version=anchor.version,
    )
    if anchor != rebuilt:
        raise ValueError("release candidate anchor digest does not match its content")


@dataclass(frozen=True)
class ReleaseArtefacts:
    """Content identities of the exact published release artefacts.

    Parameters
    ----------
    wheel_sha256, sdist_sha256, sbom_sha256:
        SHA-256 digests of the built wheel, source distribution, and
        CycloneDX software bill of materials.
    artefacts_digest:
        Content identity that rejects any substituted artefact digest.
    """

    wheel_sha256: str
    sdist_sha256: str
    sbom_sha256: str
    artefacts_digest: str

    @classmethod
    def build(cls, *, wheel_sha256: str, sdist_sha256: str, sbom_sha256: str) -> ReleaseArtefacts:
        """Build one validated release-artefact identity set."""
        body = {
            "wheel_sha256": require_digest(wheel_sha256, "artefacts.wheel_sha256"),
            "sdist_sha256": require_digest(sdist_sha256, "artefacts.sdist_sha256"),
            "sbom_sha256": require_digest(sbom_sha256, "artefacts.sbom_sha256"),
        }
        return cls(**body, artefacts_digest=canonical_digest(body))

    def to_dict(self) -> dict[str, str]:
        """Serialise one release-artefact identity set."""
        return {
            "wheel_sha256": self.wheel_sha256,
            "sdist_sha256": self.sdist_sha256,
            "sbom_sha256": self.sbom_sha256,
            "artefacts_digest": self.artefacts_digest,
        }


def _validate_artefacts(artefacts: ReleaseArtefacts) -> None:
    """Reject a forged artefact set or artefact digest."""
    rebuilt = ReleaseArtefacts.build(
        wheel_sha256=artefacts.wheel_sha256,
        sdist_sha256=artefacts.sdist_sha256,
        sbom_sha256=artefacts.sbom_sha256,
    )
    if artefacts != rebuilt:
        raise ValueError("release artefacts digest does not match its content")


@dataclass(frozen=True)
class ReleaseSurfaceReferences:
    """Signing, provenance, and documentation references for the candidate.

    Parameters
    ----------
    signing_bundle_digests:
        SHA-256 digests of every detached signing bundle; at least one is
        required and duplicates are rejected.
    provenance_digest:
        SHA-256 digest of the SLSA build-provenance attestation.
    pages_digest:
        SHA-256 digest of the published documentation snapshot.
    references_digest:
        Content identity that rejects any substituted reference.
    """

    signing_bundle_digests: tuple[str, ...]
    provenance_digest: str
    pages_digest: str
    references_digest: str

    @classmethod
    def build(
        cls,
        *,
        signing_bundle_digests: tuple[str, ...],
        provenance_digest: str,
        pages_digest: str,
    ) -> ReleaseSurfaceReferences:
        """Build one validated release-surface reference set."""
        if not signing_bundle_digests:
            raise ValueError("release surface requires at least one signing bundle")
        bundles = tuple(
            require_digest(digest, f"surface.signing_bundle_digests[{index}]")
            for index, digest in enumerate(signing_bundle_digests)
        )
        if len(set(bundles)) != len(bundles):
            raise ValueError("release surface signing bundles must be unique")
        checked_provenance = require_digest(provenance_digest, "surface.provenance_digest")
        checked_pages = require_digest(pages_digest, "surface.pages_digest")
        body: dict[str, object] = {
            "signing_bundle_digests": list(bundles),
            "provenance_digest": checked_provenance,
            "pages_digest": checked_pages,
        }
        return cls(
            signing_bundle_digests=bundles,
            provenance_digest=checked_provenance,
            pages_digest=checked_pages,
            references_digest=canonical_digest(body),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one release-surface reference set."""
        return {
            "signing_bundle_digests": list(self.signing_bundle_digests),
            "provenance_digest": self.provenance_digest,
            "pages_digest": self.pages_digest,
            "references_digest": self.references_digest,
        }


def _validate_surface(surface: ReleaseSurfaceReferences) -> None:
    """Reject a forged surface reference set or reference digest."""
    rebuilt = ReleaseSurfaceReferences.build(
        signing_bundle_digests=surface.signing_bundle_digests,
        provenance_digest=surface.provenance_digest,
        pages_digest=surface.pages_digest,
    )
    if surface != rebuilt:
        raise ValueError("release surface references digest does not match its content")


def _verified_reviewer_keys(
    *,
    attestations: tuple[ReviewerAttestation, ...],
    assessment_digest: str,
    trust_store: VerificationTrustStore,
    instant: datetime,
) -> tuple[str, ...]:
    """Return the sorted unique trusted keys that signed a current ``pass``.

    An attestation contributes only when a trusted key signed the exact
    ``pass`` decision over ``assessment_digest`` and the review is current at
    ``instant``. Unsigned, untrusted, expired, mismatched, or forged
    attestations never count, so missing evidence can never reach quorum.
    """
    keys = {
        attestation.key_id
        for attestation in attestations
        if attestation.verified_at(
            instant,
            _RELEASE_REVIEW_DECISION,
            assessment_digest,
            trust_store,
        )
    }
    return tuple(sorted(keys))


@dataclass(frozen=True)
class ReleaseQuorumCertificate:
    """Fail-closed proof that one exact candidate met every release gate.

    The certificate binds a single release candidate to its historical-tree
    replay resolution and rollback proof, its attestation-campaign quorum, an
    independent reviewer quorum of unique trusted signatures, the published
    artefact identities, and the signing, provenance, and documentation
    references. It refuses construction whenever any gate is unmet.
    """

    schema_version: str
    candidate: ReleaseCandidateAnchor
    historical_execution_digest: str
    historical_campaign_digest: str
    execution_resolution: ExecutionResolution
    rollback_proven: bool
    attestation_campaign_digest: str
    expected_runs: int
    required_model_witnesses: int
    observed_runs: int
    observed_model_witnesses: int
    reviewer_assessment_digest: str
    required_reviewers: int
    verified_reviewer_keys: tuple[str, ...]
    artefacts: ReleaseArtefacts
    surface: ReleaseSurfaceReferences
    certificate_digest: str

    @classmethod
    def build(
        cls,
        *,
        candidate: ReleaseCandidateAnchor,
        execution: CrossRepositoryExecution,
        campaign: AuditCampaign,
        observed_runs: int,
        observed_model_witnesses: int,
        reviewer_attestations: tuple[ReviewerAttestation, ...],
        reviewer_assessment_digest: str,
        required_reviewers: int,
        trust_store: VerificationTrustStore,
        instant: datetime,
        artefacts: ReleaseArtefacts,
        surface: ReleaseSurfaceReferences,
    ) -> ReleaseQuorumCertificate:
        """Certify one candidate only when every release gate is proven.

        Parameters
        ----------
        candidate:
            Exact frozen release-candidate object.
        execution:
            Historical-tree replay of the representative frozen campaign; its
            resolution must be ``succeeded`` and its temporary workspaces must
            have been removed.
        campaign:
            Attestation campaign whose ``expected_runs`` and
            ``required_model_witnesses`` set the quorum floor.
        observed_runs, observed_model_witnesses:
            Independent runs and distinct model witnesses actually recorded.
        reviewer_attestations:
            Candidate detached reviewer signatures; only trusted, current
            ``pass`` signatures over ``reviewer_assessment_digest`` count.
        reviewer_assessment_digest:
            Exact assessment body the independent reviewers signed.
        required_reviewers:
            Minimum count of unique trusted reviewer keys.
        trust_store:
            Offline trust store that validates each reviewer signature.
        instant:
            Timezone-aware evaluation time for reviewer currency.
        artefacts:
            Published wheel, source distribution, and SBOM identities.
        surface:
            Signing, provenance, and documentation references.

        Returns
        -------
        ReleaseQuorumCertificate
            The sealed, content-addressed release certificate.

        Raises
        ------
        ValueError
            If any replay, quorum, reviewer, artefact, or surface gate fails.
        """
        _validate_anchor(candidate)
        _validate_artefacts(artefacts)
        _validate_surface(surface)
        if execution.resolution != _REQUIRED_RESOLUTION:
            raise ValueError("release quorum requires a fully succeeded historical replay")
        if not execution.temporary_workspaces_removed:
            raise ValueError("release quorum requires proven temporary rollback")
        parsed_expected_runs = require_integer(
            campaign.expected_runs, "campaign.expected_runs", minimum=1
        )
        parsed_required_witnesses = require_integer(
            campaign.required_model_witnesses,
            "campaign.required_model_witnesses",
            minimum=1,
        )
        parsed_observed_runs = require_integer(observed_runs, "observed_runs", minimum=1)
        parsed_observed_witnesses = require_integer(
            observed_model_witnesses,
            "observed_model_witnesses",
            minimum=1,
        )
        if parsed_observed_runs < parsed_expected_runs:
            raise ValueError("release quorum requires observed runs to meet the campaign floor")
        if parsed_observed_witnesses < parsed_required_witnesses:
            raise ValueError("release quorum requires observed model witnesses to meet the floor")
        parsed_required_reviewers = require_integer(
            required_reviewers,
            "required_reviewers",
            minimum=1,
        )
        assessment_digest = require_digest(
            reviewer_assessment_digest,
            "reviewer_assessment_digest",
        )
        verified_keys = _verified_reviewer_keys(
            attestations=reviewer_attestations,
            assessment_digest=assessment_digest,
            trust_store=trust_store,
            instant=instant,
        )
        if len(verified_keys) < parsed_required_reviewers:
            raise ValueError("release quorum requires more unique trusted reviewer signatures")
        body: dict[str, object] = {
            "schema_version": RELEASE_QUORUM_SCHEMA_VERSION,
            "candidate": candidate.to_dict(),
            "historical_execution_digest": execution.execution_digest,
            "historical_campaign_digest": execution.campaign_digest,
            "execution_resolution": execution.resolution,
            "rollback_proven": True,
            "attestation_campaign_digest": campaign.contract_digest,
            "expected_runs": parsed_expected_runs,
            "required_model_witnesses": parsed_required_witnesses,
            "observed_runs": parsed_observed_runs,
            "observed_model_witnesses": parsed_observed_witnesses,
            "reviewer_assessment_digest": assessment_digest,
            "required_reviewers": parsed_required_reviewers,
            "verified_reviewer_keys": list(verified_keys),
            "artefacts": artefacts.to_dict(),
            "surface": surface.to_dict(),
        }
        return cls(
            schema_version=RELEASE_QUORUM_SCHEMA_VERSION,
            candidate=candidate,
            historical_execution_digest=execution.execution_digest,
            historical_campaign_digest=execution.campaign_digest,
            execution_resolution=execution.resolution,
            rollback_proven=True,
            attestation_campaign_digest=campaign.contract_digest,
            expected_runs=parsed_expected_runs,
            required_model_witnesses=parsed_required_witnesses,
            observed_runs=parsed_observed_runs,
            observed_model_witnesses=parsed_observed_witnesses,
            reviewer_assessment_digest=assessment_digest,
            required_reviewers=parsed_required_reviewers,
            verified_reviewer_keys=verified_keys,
            artefacts=artefacts,
            surface=surface,
            certificate_digest=canonical_digest(body),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the complete release-quorum certificate."""
        return {
            "schema_version": self.schema_version,
            "candidate": self.candidate.to_dict(),
            "historical_execution_digest": self.historical_execution_digest,
            "historical_campaign_digest": self.historical_campaign_digest,
            "execution_resolution": self.execution_resolution,
            "rollback_proven": self.rollback_proven,
            "attestation_campaign_digest": self.attestation_campaign_digest,
            "expected_runs": self.expected_runs,
            "required_model_witnesses": self.required_model_witnesses,
            "observed_runs": self.observed_runs,
            "observed_model_witnesses": self.observed_model_witnesses,
            "reviewer_assessment_digest": self.reviewer_assessment_digest,
            "required_reviewers": self.required_reviewers,
            "verified_reviewer_keys": list(self.verified_reviewer_keys),
            "artefacts": self.artefacts.to_dict(),
            "surface": self.surface.to_dict(),
            "certificate_digest": self.certificate_digest,
        }

    def validate(self) -> None:
        """Verify the complete certificate body and its content identity.

        Raises
        ------
        ValueError
            If any bound field, threshold relation, or the certificate digest
            is inconsistent with the sealed content.
        """
        if self.schema_version != RELEASE_QUORUM_SCHEMA_VERSION:
            raise ValueError("unsupported release-quorum schema version")
        _validate_anchor(self.candidate)
        _validate_artefacts(self.artefacts)
        _validate_surface(self.surface)
        if self.execution_resolution != _REQUIRED_RESOLUTION:
            raise ValueError("release quorum certificate requires a succeeded replay")
        if self.rollback_proven is not True:
            raise ValueError("release quorum certificate requires proven rollback")
        expected_runs = require_integer(self.expected_runs, "expected_runs", minimum=1)
        required_witnesses = require_integer(
            self.required_model_witnesses,
            "required_model_witnesses",
            minimum=1,
        )
        observed_runs = require_integer(self.observed_runs, "observed_runs", minimum=1)
        observed_witnesses = require_integer(
            self.observed_model_witnesses,
            "observed_model_witnesses",
            minimum=1,
        )
        if observed_runs < expected_runs or observed_witnesses < required_witnesses:
            raise ValueError("release quorum certificate observed counts fall below the floor")
        required_reviewers = require_integer(
            self.required_reviewers,
            "required_reviewers",
            minimum=1,
        )
        keys = tuple(
            require_string(key, f"verified_reviewer_keys[{index}]")
            for index, key in enumerate(self.verified_reviewer_keys)
        )
        if len(set(keys)) != len(keys):
            raise ValueError("release quorum certificate reviewer keys must be unique")
        if len(keys) < required_reviewers:
            raise ValueError("release quorum certificate falls below the reviewer quorum")
        body: dict[str, object] = {
            "schema_version": RELEASE_QUORUM_SCHEMA_VERSION,
            "candidate": self.candidate.to_dict(),
            "historical_execution_digest": require_digest(
                self.historical_execution_digest,
                "historical_execution_digest",
            ),
            "historical_campaign_digest": require_digest(
                self.historical_campaign_digest,
                "historical_campaign_digest",
            ),
            "execution_resolution": self.execution_resolution,
            "rollback_proven": True,
            "attestation_campaign_digest": require_digest(
                self.attestation_campaign_digest,
                "attestation_campaign_digest",
            ),
            "expected_runs": expected_runs,
            "required_model_witnesses": required_witnesses,
            "observed_runs": observed_runs,
            "observed_model_witnesses": observed_witnesses,
            "reviewer_assessment_digest": require_digest(
                self.reviewer_assessment_digest,
                "reviewer_assessment_digest",
            ),
            "required_reviewers": required_reviewers,
            "verified_reviewer_keys": list(keys),
            "artefacts": self.artefacts.to_dict(),
            "surface": self.surface.to_dict(),
        }
        if canonical_digest(body) != self.certificate_digest:
            raise ValueError("release quorum certificate digest does not match its content")

    @classmethod
    def from_dict(cls, value: object) -> ReleaseQuorumCertificate:
        """Parse and integrity-check one sealed release-quorum certificate.

        Reviewer signatures are re-checked against a live trust store only by
        :meth:`build`; :meth:`from_dict` proves that the frozen quorum evidence
        and every bound digest are internally consistent and untampered.
        """
        data = require_mapping(value, "certificate")
        expected_fields = frozenset(
            {
                "schema_version",
                "candidate",
                "historical_execution_digest",
                "historical_campaign_digest",
                "execution_resolution",
                "rollback_proven",
                "attestation_campaign_digest",
                "expected_runs",
                "required_model_witnesses",
                "observed_runs",
                "observed_model_witnesses",
                "reviewer_assessment_digest",
                "required_reviewers",
                "verified_reviewer_keys",
                "artefacts",
                "surface",
                "certificate_digest",
            }
        )
        if frozenset(data) != expected_fields:
            raise ValueError("release quorum certificate fields do not match schema")
        if data.get("schema_version") != RELEASE_QUORUM_SCHEMA_VERSION:
            raise ValueError("unsupported release-quorum schema version")
        candidate = _anchor_from_dict(data.get("candidate"))
        artefacts = _artefacts_from_dict(data.get("artefacts"))
        surface = _surface_from_dict(data.get("surface"))
        resolution = require_string(data.get("execution_resolution"), "execution_resolution")
        if resolution != _REQUIRED_RESOLUTION:
            raise ValueError("release quorum certificate requires a succeeded replay")
        if data.get("rollback_proven") is not True:
            raise ValueError("release quorum certificate requires proven rollback")
        raw_keys = data.get("verified_reviewer_keys")
        if not isinstance(raw_keys, list):
            raise ValueError("verified_reviewer_keys must be a list")
        keys = tuple(
            require_string(key, f"verified_reviewer_keys[{index}]")
            for index, key in enumerate(raw_keys)
        )
        certificate = cls(
            schema_version=RELEASE_QUORUM_SCHEMA_VERSION,
            candidate=candidate,
            historical_execution_digest=require_digest(
                data.get("historical_execution_digest"),
                "historical_execution_digest",
            ),
            historical_campaign_digest=require_digest(
                data.get("historical_campaign_digest"),
                "historical_campaign_digest",
            ),
            execution_resolution=_require_resolution(resolution),
            rollback_proven=True,
            attestation_campaign_digest=require_digest(
                data.get("attestation_campaign_digest"),
                "attestation_campaign_digest",
            ),
            expected_runs=require_integer(data.get("expected_runs"), "expected_runs", minimum=1),
            required_model_witnesses=require_integer(
                data.get("required_model_witnesses"),
                "required_model_witnesses",
                minimum=1,
            ),
            observed_runs=require_integer(data.get("observed_runs"), "observed_runs", minimum=1),
            observed_model_witnesses=require_integer(
                data.get("observed_model_witnesses"),
                "observed_model_witnesses",
                minimum=1,
            ),
            reviewer_assessment_digest=require_digest(
                data.get("reviewer_assessment_digest"),
                "reviewer_assessment_digest",
            ),
            required_reviewers=require_integer(
                data.get("required_reviewers"),
                "required_reviewers",
                minimum=1,
            ),
            verified_reviewer_keys=keys,
            artefacts=artefacts,
            surface=surface,
            certificate_digest=require_digest(
                data.get("certificate_digest"),
                "certificate_digest",
            ),
        )
        certificate.validate()
        return certificate


def _require_resolution(value: str) -> ExecutionResolution:
    """Return the required ``succeeded`` resolution literal."""
    if value != _REQUIRED_RESOLUTION:
        raise ValueError("release quorum certificate requires a succeeded replay")
    return _REQUIRED_RESOLUTION


def _anchor_from_dict(value: object) -> ReleaseCandidateAnchor:
    """Parse and integrity-check one release-candidate anchor mapping."""
    data = require_mapping(value, "candidate")
    if frozenset(data) != frozenset({"commit", "tree", "version", "anchor_digest"}):
        raise ValueError("release candidate anchor fields do not match schema")
    anchor = ReleaseCandidateAnchor.build(
        commit=require_string(data.get("commit"), "candidate.commit"),
        tree=require_string(data.get("tree"), "candidate.tree"),
        version=require_string(data.get("version"), "candidate.version"),
    )
    if anchor.anchor_digest != require_digest(
        data.get("anchor_digest"), "candidate.anchor_digest"
    ):
        raise ValueError("release candidate anchor digest does not match its content")
    return anchor


def _artefacts_from_dict(value: object) -> ReleaseArtefacts:
    """Parse and integrity-check one release-artefact mapping."""
    data = require_mapping(value, "artefacts")
    expected = frozenset({"wheel_sha256", "sdist_sha256", "sbom_sha256", "artefacts_digest"})
    if frozenset(data) != expected:
        raise ValueError("release artefacts fields do not match schema")
    artefacts = ReleaseArtefacts.build(
        wheel_sha256=require_string(data.get("wheel_sha256"), "artefacts.wheel_sha256"),
        sdist_sha256=require_string(data.get("sdist_sha256"), "artefacts.sdist_sha256"),
        sbom_sha256=require_string(data.get("sbom_sha256"), "artefacts.sbom_sha256"),
    )
    if artefacts.artefacts_digest != require_digest(
        data.get("artefacts_digest"),
        "artefacts.artefacts_digest",
    ):
        raise ValueError("release artefacts digest does not match its content")
    return artefacts


def _surface_from_dict(value: object) -> ReleaseSurfaceReferences:
    """Parse and integrity-check one release-surface mapping."""
    data = require_mapping(value, "surface")
    expected = frozenset(
        {"signing_bundle_digests", "provenance_digest", "pages_digest", "references_digest"}
    )
    if frozenset(data) != expected:
        raise ValueError("release surface fields do not match schema")
    raw_bundles = data.get("signing_bundle_digests")
    if not isinstance(raw_bundles, list):
        raise ValueError("signing_bundle_digests must be a list")
    surface = ReleaseSurfaceReferences.build(
        signing_bundle_digests=tuple(
            require_string(bundle, f"surface.signing_bundle_digests[{index}]")
            for index, bundle in enumerate(raw_bundles)
        ),
        provenance_digest=require_string(
            data.get("provenance_digest"), "surface.provenance_digest"
        ),
        pages_digest=require_string(data.get("pages_digest"), "surface.pages_digest"),
    )
    if surface.references_digest != require_digest(
        data.get("references_digest"),
        "surface.references_digest",
    ):
        raise ValueError("release surface references digest does not match its content")
    return surface
