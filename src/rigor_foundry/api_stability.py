# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — public API stability contract
"""Inventory top-level exports and validate compatibility classifications."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from .candidate_anchor import Candidate
from .cli import report_markdown
from .git_provenance import GitTrustPolicy
from .model_primitives import require_semantic_version
from .models import AuditPolicy, AuditReport, ReviewRecord
from .review import review_templates, validate_reviews
from .scanner import scan_repository
from .version import __version__

API_STABILITY_SCHEMA_VERSION = "1.1"
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
        "SARIF_SCHEMA_URI",
        "SARIF_VERSION",
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
        "report_sarif",
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


@dataclass(frozen=True)
class StableApiBinding:
    """Expected runtime identity class for one stable top-level export."""

    kind: str
    module: str | None
    qualname: str | None


STABLE_PUBLIC_API_BINDINGS: Mapping[str, StableApiBinding] = MappingProxyType(
    {
        "AuditPolicy": StableApiBinding("class", "rigor_foundry.models", "AuditPolicy"),
        "AuditReport": StableApiBinding("class", "rigor_foundry.models", "AuditReport"),
        "Candidate": StableApiBinding("class", "rigor_foundry.candidate_anchor", "Candidate"),
        "GitTrustPolicy": StableApiBinding(
            "class", "rigor_foundry.git_provenance", "GitTrustPolicy"
        ),
        "ReviewRecord": StableApiBinding("class", "rigor_foundry.models", "ReviewRecord"),
        "__version__": StableApiBinding("str", None, None),
        "report_markdown": StableApiBinding("function", "rigor_foundry.cli", "report_markdown"),
        "review_templates": StableApiBinding(
            "function", "rigor_foundry.review", "review_templates"
        ),
        "scan_repository": StableApiBinding(
            "function", "rigor_foundry.scanner", "scan_repository"
        ),
        "validate_reviews": StableApiBinding(
            "function", "rigor_foundry.review", "validate_reviews"
        ),
    }
)

_STABLE_PUBLIC_API_TARGETS: Mapping[str, object] = MappingProxyType(
    {
        "AuditPolicy": AuditPolicy,
        "AuditReport": AuditReport,
        "Candidate": Candidate,
        "GitTrustPolicy": GitTrustPolicy,
        "ReviewRecord": ReviewRecord,
        "__version__": __version__,
        "report_markdown": report_markdown,
        "review_templates": review_templates,
        "scan_repository": scan_repository,
        "validate_reviews": validate_reviews,
    }
)


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


def _stable_binding_errors(
    exports: Mapping[str, object],
    stable: frozenset[str],
    binding_contract: Mapping[str, StableApiBinding],
    target_contract: Mapping[str, object] | None,
) -> tuple[str, ...]:
    """Return stable-export runtime identity errors."""
    errors: list[str] = []
    missing_contracts = stable - set(binding_contract)
    extra_contracts = set(binding_contract) - stable
    if missing_contracts:
        errors.append(
            "stable binding contracts are missing: " + ", ".join(sorted(missing_contracts))
        )
    if extra_contracts:
        errors.append(
            "stable binding contracts are unknown: " + ", ".join(sorted(extra_contracts))
        )
    if target_contract is not None:
        missing_targets = stable - set(target_contract)
        extra_targets = set(target_contract) - stable
        if missing_targets:
            errors.append(
                "stable object targets are missing: " + ", ".join(sorted(missing_targets))
            )
        if extra_targets:
            errors.append("stable object targets are unknown: " + ", ".join(sorted(extra_targets)))
    for name in sorted(stable & set(exports) & set(binding_contract)):
        value = exports[name]
        expected = binding_contract[name]
        if (
            target_contract is not None
            and name in target_contract
            and value is not target_contract[name]
        ):
            errors.append(f"{name}: stable export object changed")
        if expected.kind == "class":
            kind_matches = isinstance(value, type)
        elif expected.kind == "function":
            kind_matches = callable(value) and not isinstance(value, type)
        elif expected.kind == "str":
            kind_matches = type(value) is str
        else:
            errors.append(f"{name}: stable binding kind is invalid")
            continue
        if not kind_matches:
            errors.append(f"{name}: stable export kind changed")
            continue
        if expected.module is not None and getattr(value, "__module__", None) != expected.module:
            errors.append(f"{name}: stable export module changed")
        if (
            expected.qualname is not None
            and getattr(value, "__qualname__", None) != expected.qualname
        ):
            errors.append(f"{name}: stable export qualified name changed")
    return tuple(errors)


def public_api_contract_errors(
    exports: Iterable[str],
    bindings: Mapping[str, object],
    *,
    stable: frozenset[str] = STABLE_PUBLIC_API,
    provisional: frozenset[str] = PROVISIONAL_PUBLIC_API,
    deprecated: tuple[ApiDeprecation, ...] = DEPRECATED_PUBLIC_API,
    stable_bindings: Mapping[str, StableApiBinding] = STABLE_PUBLIC_API_BINDINGS,
    stable_targets: Mapping[str, object] | None = None,
) -> tuple[str, ...]:
    """Return deterministic classification and runtime-binding errors."""
    errors: list[str] = []
    exported = tuple(exports)
    missing_bindings = set(exported) - set(bindings)
    if missing_bindings:
        errors.append(
            "top-level export bindings are missing: " + ", ".join(sorted(missing_bindings))
        )
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
    target_contract = (
        _STABLE_PUBLIC_API_TARGETS
        if stable_targets is None and stable == STABLE_PUBLIC_API
        else stable_targets
    )
    errors.extend(_stable_binding_errors(bindings, stable, stable_bindings, target_contract))
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
        "stable_bindings": {
            name: {
                "kind": binding.kind,
                "module": binding.module,
                "qualname": binding.qualname,
            }
            for name, binding in sorted(STABLE_PUBLIC_API_BINDINGS.items())
        },
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
