# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — reusable repository-audit API
"""Public API for evidence-first repository auditing."""

__version__ = "0.1.0"

from .cli import report_markdown
from .condition_language import ConditionExpression
from .control_assessment import ControlAssessment, EvidenceReference
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
from .review import render_todo_entry, review_errors, review_templates, validate_reviews
from .review_attestation import ReviewerAttestation
from .sandbox_provenance import BubblewrapCompatibilityPolicy, BubblewrapProvenance
from .scanner import scan_repository
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
from .work_closure import WorkClosure
from .work_models import WorkEvent, WorkRecord, WorkTask

__all__ = [
    "DIGEST_DEPENDENCIES",
    "DIGEST_DEPENDENCY_SCHEMA_VERSION",
    "DIGEST_NODES",
    "ED25519_SIGNATURE_MESSAGE_VERSION",
    "REVIEW_ATTESTATION_SIGNATURE_DOMAIN",
    "STANDARD_PACK_SIGNATURE_DOMAIN",
    "AdapterLock",
    "ApplicabilityDecision",
    "AuditPolicy",
    "AuditReport",
    "BubblewrapCompatibilityPolicy",
    "BubblewrapProvenance",
    "Candidate",
    "ConditionExpression",
    "ControlAssessment",
    "ControlDefinition",
    "ControlOverlay",
    "DigestDependency",
    "DigestNodeSpec",
    "EffectiveControl",
    "EffectiveProfileLock",
    "EvidenceContract",
    "EvidenceReference",
    "ExceptionWaiver",
    "GitExecutableProvenance",
    "GitTrustPolicy",
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
    "RequirementBinding",
    "ResolvedVariable",
    "ReviewRecord",
    "ReviewerAttestation",
    "SecretReference",
    "StandardPack",
    "TargetGap",
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
    "digest_dependency_graph",
    "digest_dependency_graph_digest",
    "direct_dependents",
    "ed25519_signature_message",
    "render_todo_entry",
    "report_markdown",
    "resolve_effective_profile",
    "review_errors",
    "review_templates",
    "scan_repository",
    "transitive_dependents",
    "validate_digest_dependency_graph",
    "validate_reviews",
]
