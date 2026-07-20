# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — reusable repository-audit API
"""Public API for evidence-first repository auditing."""

from .campaign_identity import (
    INFERENCE_IDENTITY_SCHEMA_VERSION,
    MODEL_WITNESS_SCHEMA_VERSION,
    InferenceIdentity,
    ModelWitness,
    collapse_model_witnesses,
)
from .campaign_inputs import campaign_input_divergence, validate_campaign_input
from .campaign_promotion import validate_promotion_campaign
from .candidate_anchor import (
    ANCHOR_SCHEMA_VERSION,
    CandidateAnchor,
    RepositoryTreeAnchor,
    TrackedBlobAnchor,
    bounded_candidate_evidence,
    candidate_anchor_errors,
)
from .cli import report_markdown
from .condition_language import ConditionExpression
from .control_assessment import ControlAssessment, EvidenceReference
from .coverage_residuals import (
    COVERAGE_RESIDUAL_SCHEMA_VERSION,
    CoverageResidual,
    CoverageResidualManifest,
    NegativeSearch,
    coverage_residual_errors,
)
from .digest_dependencies import (
    DIGEST_DEPENDENCIES,
    DIGEST_DEPENDENCY_SCHEMA_VERSION,
    DIGEST_NODES,
    DigestDependency,
    DigestNodeSpec,
    digest_dependency_graph,
    digest_dependency_graph_digest,
    direct_dependents,
    transitive_dependents,
    validate_digest_dependency_graph,
)
from .effective_profile import (
    AdapterLock,
    EffectiveControl,
    EffectiveProfileLock,
    PackVerification,
    PolicyContradiction,
    ProfileResolution,
    ResolvedVariable,
)
from .git_provenance import GitExecutableProvenance, GitTrustPolicy
from .ignored_inventory import (
    IGNORED_INVENTORY_SCHEMA_VERSION,
    IgnoredInventoryDeclaration,
    IgnoredInventoryEvidence,
    collect_ignored_inventory,
    ignored_inventory_digest,
)
from .model_primitives import (
    SecretReference,
    VariableAssignment,
    VariableConstraints,
    VariableDefinition,
    WorkEvidence,
)
from .models import AuditPolicy, AuditReport, Candidate, ReviewRecord
from .profile_resolution import resolve_effective_profile
from .project_profile import (
    ApplicabilityDecision,
    ControlOverlay,
    ExceptionWaiver,
    PackSelection,
    ProjectIntent,
    ProjectProfile,
    RequirementBinding,
)
from .remediation_plan import (
    PlanApproval,
    ProcedureStep,
    RemediationLane,
    RemediationPlan,
    TargetGap,
)
from .report_diff import (
    REPORT_DIFF_SCHEMA_VERSION,
    CandidateAnchorChange,
    CandidateAnchorMatch,
    ReportDiff,
    ReportDiffCompatibility,
    compare_reports,
)
from .review import render_todo_entry, review_errors, review_templates, validate_reviews
from .review_attestation import ReviewerAttestation
from .rule_maturity import (
    RULE_MATURITY_SCHEMA_VERSION,
    RuleMaturityAssessment,
    RuleMaturityPolicy,
    RuleMaturityReport,
    RuleReviewEvidence,
)
from .rule_maturity_manifest import (
    MATURITY_CASE_MANIFEST_SCHEMA_VERSION,
    evaluate_rule_maturity_manifest,
)
from .sandbox_provenance import BubblewrapCompatibilityPolicy, BubblewrapProvenance
from .sarif import SARIF_SCHEMA_URI, SARIF_VERSION, report_sarif
from .scanner import scan_repository
from .source_capture import (
    SOURCE_PROVENANCE_SCHEMA_VERSION,
    SourceCapture,
    SourceRetrievalPolicy,
    read_source_payload,
)
from .source_provenance import (
    ExternalSourceClaim,
    SourceVerification,
    source_provenance_to_json,
    verify_external_source,
)
from .standard_pack import (
    ControlDefinition,
    EvidenceContract,
    PackSignature,
    RemediationContract,
    StandardPack,
)
from .trust import (
    ED25519_SIGNATURE_MESSAGE_VERSION,
    REVIEW_ATTESTATION_SIGNATURE_DOMAIN,
    STANDARD_PACK_SIGNATURE_DOMAIN,
    TrustedPublicKey,
    VerificationTrustStore,
    ed25519_signature_message,
)
from .version import __version__
from .work_closure import WorkClosure
from .work_models import WorkEvent, WorkRecord, WorkTask

__all__ = [
    "ANCHOR_SCHEMA_VERSION",
    "COVERAGE_RESIDUAL_SCHEMA_VERSION",
    "DIGEST_DEPENDENCIES",
    "DIGEST_DEPENDENCY_SCHEMA_VERSION",
    "DIGEST_NODES",
    "ED25519_SIGNATURE_MESSAGE_VERSION",
    "IGNORED_INVENTORY_SCHEMA_VERSION",
    "INFERENCE_IDENTITY_SCHEMA_VERSION",
    "MATURITY_CASE_MANIFEST_SCHEMA_VERSION",
    "MODEL_WITNESS_SCHEMA_VERSION",
    "REPORT_DIFF_SCHEMA_VERSION",
    "REVIEW_ATTESTATION_SIGNATURE_DOMAIN",
    "RULE_MATURITY_SCHEMA_VERSION",
    "SARIF_SCHEMA_URI",
    "SARIF_VERSION",
    "SOURCE_PROVENANCE_SCHEMA_VERSION",
    "STANDARD_PACK_SIGNATURE_DOMAIN",
    "AdapterLock",
    "ApplicabilityDecision",
    "AuditPolicy",
    "AuditReport",
    "BubblewrapCompatibilityPolicy",
    "BubblewrapProvenance",
    "Candidate",
    "CandidateAnchor",
    "CandidateAnchorChange",
    "CandidateAnchorMatch",
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
    "ExternalSourceClaim",
    "GitExecutableProvenance",
    "GitTrustPolicy",
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
    "ReportDiff",
    "ReportDiffCompatibility",
    "RepositoryTreeAnchor",
    "RequirementBinding",
    "ResolvedVariable",
    "ReviewRecord",
    "ReviewerAttestation",
    "RuleMaturityAssessment",
    "RuleMaturityPolicy",
    "RuleMaturityReport",
    "RuleReviewEvidence",
    "SecretReference",
    "SourceCapture",
    "SourceRetrievalPolicy",
    "SourceVerification",
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
    "__version__",
    "bounded_candidate_evidence",
    "campaign_input_divergence",
    "candidate_anchor_errors",
    "collapse_model_witnesses",
    "collect_ignored_inventory",
    "compare_reports",
    "coverage_residual_errors",
    "digest_dependency_graph",
    "digest_dependency_graph_digest",
    "direct_dependents",
    "ed25519_signature_message",
    "evaluate_rule_maturity_manifest",
    "ignored_inventory_digest",
    "read_source_payload",
    "render_todo_entry",
    "report_markdown",
    "report_sarif",
    "resolve_effective_profile",
    "review_errors",
    "review_templates",
    "scan_repository",
    "source_provenance_to_json",
    "transitive_dependents",
    "validate_campaign_input",
    "validate_digest_dependency_graph",
    "validate_promotion_campaign",
    "validate_reviews",
    "verify_external_source",
]
