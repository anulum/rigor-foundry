# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — public API stability contract
"""Inventory top-level exports and validate compatibility classifications."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .model_primitives import require_semantic_version

API_STABILITY_SCHEMA_VERSION = "1.0"
MINIMUM_DEPRECATION_MINOR_RELEASES = 2

STABLE_PUBLIC_API: frozenset[str] = frozenset(
    {
        "AuditPolicy",
        "AuditReport",
        "Candidate",
        "GitTrustPolicy",
        "ReviewRecord",
        "__version__",
        "report_markdown",
        "review_templates",
        "scan_repository",
        "validate_reviews",
    }
)

PROVISIONAL_PUBLIC_API: frozenset[str] = frozenset(
    {
        "ANCHOR_SCHEMA_VERSION",
        "COVERAGE_RESIDUAL_SCHEMA_VERSION",
        "DIGEST_DEPENDENCIES",
        "DIGEST_DEPENDENCY_SCHEMA_VERSION",
        "DIGEST_NODES",
        "ED25519_SIGNATURE_MESSAGE_VERSION",
        "IGNORED_INVENTORY_SCHEMA_VERSION",
        "INFERENCE_IDENTITY_SCHEMA_VERSION",
        "MODEL_WITNESS_SCHEMA_VERSION",
        "REVIEW_ATTESTATION_SIGNATURE_DOMAIN",
        "STANDARD_PACK_SIGNATURE_DOMAIN",
        "AdapterLock",
        "ApplicabilityDecision",
        "BubblewrapCompatibilityPolicy",
        "BubblewrapProvenance",
        "CandidateAnchor",
        "ConditionExpression",
        "ControlAssessment",
        "ControlDefinition",
        "ControlOverlay",
        "CoverageResidual",
        "CoverageResidualManifest",
        "DigestDependency",
        "DigestNodeSpec",
        "EffectiveControl",
        "EffectiveProfileLock",
        "EvidenceContract",
        "EvidenceReference",
        "ExceptionWaiver",
        "GitExecutableProvenance",
        "IgnoredInventoryDeclaration",
        "IgnoredInventoryEvidence",
        "InferenceIdentity",
        "ModelWitness",
        "NegativeSearch",
        "PackSelection",
        "PackSignature",
        "PackVerification",
        "PlanApproval",
        "PolicyContradiction",
        "ProcedureStep",
        "ProfileResolution",
        "ProjectIntent",
        "ProjectProfile",
        "RemediationContract",
        "RemediationLane",
        "RemediationPlan",
        "RepositoryTreeAnchor",
        "RequirementBinding",
        "ResolvedVariable",
        "ReviewerAttestation",
        "SecretReference",
        "StandardPack",
        "TargetGap",
        "TrackedBlobAnchor",
        "TrustedPublicKey",
        "VariableAssignment",
        "VariableConstraints",
        "VariableDefinition",
        "VerificationTrustStore",
        "WorkClosure",
        "WorkEvent",
        "WorkEvidence",
        "WorkRecord",
        "WorkTask",
        "bounded_candidate_evidence",
        "campaign_input_divergence",
        "candidate_anchor_errors",
        "collapse_model_witnesses",
        "collect_ignored_inventory",
        "coverage_residual_errors",
        "digest_dependency_graph",
        "digest_dependency_graph_digest",
        "direct_dependents",
        "ed25519_signature_message",
        "ignored_inventory_digest",
        "render_todo_entry",
        "resolve_effective_profile",
        "review_errors",
        "transitive_dependents",
        "validate_campaign_input",
        "validate_digest_dependency_graph",
        "validate_promotion_campaign",
    }
)


@dataclass(frozen=True)
class ApiDeprecation:
    """Lifecycle commitment for one still-exported deprecated top-level name."""

    name: str
    deprecated_in: str
    removal_not_before: str
    replacement: str


DEPRECATED_PUBLIC_API: tuple[ApiDeprecation, ...] = ()


def _final_release(value: str, field: str) -> tuple[int, int, int]:
    """Return a final semantic release tuple for lifecycle comparisons."""
    version = require_semantic_version(value, field)
    if "-" in version or "+" in version:
        raise ValueError(f"{field} must be a final semantic version")
    major, minor, patch = version.split(".")
    return int(major), int(minor), int(patch)


def _deprecation_errors(deprecation: ApiDeprecation) -> tuple[str, ...]:
    """Return lifecycle errors for one direct-constructed deprecation record."""
    errors: list[str] = []
    if not deprecation.name.isidentifier():
        errors.append("deprecated API name must be a Python identifier")
    try:
        deprecated = _final_release(deprecation.deprecated_in, "deprecated_in")
        removal = _final_release(deprecation.removal_not_before, "removal_not_before")
    except ValueError as exc:
        errors.append(str(exc))
        return tuple(errors)
    if removal <= deprecated:
        errors.append("removal_not_before must follow deprecated_in")
    elif removal[0] == deprecated[0]:
        release_distance = removal[1] - deprecated[1]
        if release_distance < MINIMUM_DEPRECATION_MINOR_RELEASES:
            errors.append("removal_not_before must preserve at least two minor releases")
    if deprecation.replacement == deprecation.name:
        errors.append("deprecated API replacement must differ from its name")
    return tuple(errors)


def public_api_contract_errors(
    exports: Iterable[str],
    *,
    stable: frozenset[str] = STABLE_PUBLIC_API,
    provisional: frozenset[str] = PROVISIONAL_PUBLIC_API,
    deprecated: tuple[ApiDeprecation, ...] = DEPRECATED_PUBLIC_API,
) -> tuple[str, ...]:
    """Return deterministic errors for one top-level export classification."""
    errors: list[str] = []
    exported = tuple(exports)
    if len(exported) != len(set(exported)):
        errors.append("top-level exports must be unique")
    deprecated_names = tuple(item.name for item in deprecated)
    if len(deprecated_names) != len(set(deprecated_names)):
        errors.append("deprecated API names must be unique")
    overlaps = (
        (stable & provisional)
        | (stable & set(deprecated_names))
        | (provisional & set(deprecated_names))
    )
    if overlaps:
        errors.append("API stability classifications overlap: " + ", ".join(sorted(overlaps)))
    classified = stable | provisional | set(deprecated_names)
    invalid_names = sorted(name for name in classified if not name.isidentifier())
    if invalid_names:
        errors.append(
            "classified API names must be Python identifiers: " + ", ".join(invalid_names)
        )
    missing = set(exported) - classified
    unknown = classified - set(exported)
    if missing:
        errors.append("unclassified top-level exports: " + ", ".join(sorted(missing)))
    if unknown:
        errors.append("classified names are not exported: " + ", ".join(sorted(unknown)))
    for item in deprecated:
        errors.extend(f"{item.name}: {error}" for error in _deprecation_errors(item))
        if item.replacement and item.replacement not in classified:
            errors.append(f"{item.name}: replacement is not a classified top-level export")
    return tuple(sorted(set(errors)))


def public_api_manifest() -> dict[str, object]:
    """Return the deterministic machine-readable top-level API inventory."""
    return {
        "schema_version": API_STABILITY_SCHEMA_VERSION,
        "stable": sorted(STABLE_PUBLIC_API),
        "provisional": sorted(PROVISIONAL_PUBLIC_API),
        "deprecated": [
            {
                "name": item.name,
                "deprecated_in": item.deprecated_in,
                "removal_not_before": item.removal_not_before,
                "replacement": item.replacement,
            }
            for item in sorted(DEPRECATED_PUBLIC_API, key=lambda value: value.name)
        ],
    }
