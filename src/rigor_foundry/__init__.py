# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — reusable repository-audit API
"""Public API for evidence-first repository auditing."""

__version__ = "0.1.0"

from .cli import report_markdown
from .condition_language import ConditionExpression
from .control_assessment import (
    ControlAssessment,
    EvidenceReference,
    ReviewerAttestation,
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
from .scanner import scan_repository
from .standard_pack import (
    ControlDefinition,
    EvidenceContract,
    PackSignature,
    RemediationContract,
    StandardPack,
)
from .work_models import WorkEvent, WorkRecord, WorkTask

__all__ = [
    "AdapterLock",
    "ApplicabilityDecision",
    "AuditPolicy",
    "AuditReport",
    "Candidate",
    "ConditionExpression",
    "ControlAssessment",
    "ControlDefinition",
    "ControlOverlay",
    "EffectiveControl",
    "EffectiveProfileLock",
    "EvidenceContract",
    "EvidenceReference",
    "ExceptionWaiver",
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
    "VariableAssignment",
    "VariableConstraints",
    "VariableDefinition",
    "WorkEvent",
    "WorkEvidence",
    "WorkRecord",
    "WorkTask",
    "__version__",
    "render_todo_entry",
    "report_markdown",
    "resolve_effective_profile",
    "review_errors",
    "review_templates",
    "scan_repository",
    "validate_reviews",
]
