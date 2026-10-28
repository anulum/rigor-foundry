# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — selected control assessment declarations
"""Bind exact selected assessment inputs without authenticating a gate verdict."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar, Literal, cast

from .assessment_evidence_validation import (
    validate_original_evidence_bindings,
    validate_original_pass_evidence,
    validate_original_reviewers,
)
from .audit_primitives import canonical_digest, require_string
from .control_assessment import AssessmentStatus, EvidenceReference
from .effective_profile import AdapterLock
from .model_primitives import require_digest, require_identifier, require_utc_timestamp
from .policy_model_inputs import (
    checked_policy_budget,
    policy_record_mapping,
    policy_reference,
    policy_wire_size,
)
from .policy_read_budget import PolicyReadBudget1
from .quality_projection_v3 import ContractCase, QualityProjectionRowV3
from .review_attestation import ReviewerAttestation
from .source_component_reader import PolicyComponent1
from .standard_pack import ControlDefinition
from .trust import TrustedPublicKey, VerificationTrustStore
from .typed_object_reference import TypedObjectRef1

SELECTED_CONTROL_ASSESSMENT_V2_SCHEMA_VERSION = "2.0"
AssessmentApplicability = Literal["true", "false", "unknown"]
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "lock_digest",
        "quality_projection_digest",
        "task_context_digest",
        "event_request_digest",
        "control",
        "contract_case",
        "applicability",
        "status",
        "evidence",
        "reviews",
        "assessor",
        "assessed_at",
        "reason_code",
        "assessment_digest",
    }
)
_STATUSES = frozenset({"unassessed", "needs-evidence", "blocked", "fail", "pass", "accepted-risk"})


def _references(
    value: tuple[TypedObjectRef1, ...],
    pair: tuple[str, str],
    budget: PolicyReadBudget1,
) -> tuple[TypedObjectRef1, ...]:
    """Require exact immutable sorted unique identities within one owning format."""
    if type(value) is not tuple or len(value) > budget.max_references:
        raise ValueError("selected assessment requires bounded immutable reference tuples")
    refs = tuple(policy_reference(item, allowed=frozenset({pair})) for item in value)
    identities = tuple(ref.object_id for ref in refs)
    if identities != tuple(sorted(set(identities))):
        raise ValueError("selected assessment references must be sorted and unique")
    return refs


@dataclass(frozen=True)
class SelectedControlAssessment2:
    """A complete selected assessment declaration, with no implicit admission.

    Its declared status cannot authenticate evidence, reviews, applicability,
    a source exception or the enclosing selected generation. Installed consuming
    owners must resolve these exact inputs and evaluate the actual contracts.
    Accepted risk never substitutes for a mandatory source floor's pass.
    """

    lock_digest: str
    quality_projection_digest: str
    task_context_digest: str
    event_request_digest: str
    control: TypedObjectRef1
    contract_case: ContractCase
    applicability: AssessmentApplicability
    status: AssessmentStatus
    evidence: tuple[TypedObjectRef1, ...]
    reviews: tuple[TypedObjectRef1, ...]
    assessor: str
    assessed_at: str
    reason_code: str
    assessment_digest: str

    schema_version: ClassVar[str] = SELECTED_CONTROL_ASSESSMENT_V2_SCHEMA_VERSION
    object_kind: ClassVar[str] = "selected-control-assessment"

    def _body(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Validate closed cases, explicit tri-state strings and complete bounded references."""
        limits = checked_policy_budget(budget)
        case = require_string(self.contract_case, "selected assessment contract case")
        if case not in {"legacy1", "qualitative2"}:
            raise ValueError("unsupported selected assessment contract case")
        applicability = require_string(self.applicability, "selected assessment applicability")
        status = require_string(self.status, "selected assessment status")
        if applicability not in {"true", "false", "unknown"} or status not in _STATUSES:
            raise ValueError("unsupported selected assessment applicability or status")
        if applicability == "unknown" and status == "pass":
            raise ValueError("unknown selected applicability cannot pass")
        if applicability == "false" and status != "unassessed":
            raise ValueError("not-applicable selected controls remain explicitly unassessed")
        version = "1.0" if case == "legacy1" else "2.0"
        control = policy_reference(
            self.control, allowed=frozenset({("control-definition", version)})
        )
        evidence = _references(self.evidence, ("evidence-reference", version), limits)
        reviews = _references(self.reviews, ("review-attestation", "2.0"), limits)
        if 1 + len(evidence) + len(reviews) > limits.max_references:
            raise ValueError("selected assessment exceeds the aggregate reference budget")
        instant = require_utc_timestamp(self.assessed_at, "selected assessment instant")
        if instant != self.assessed_at:
            raise ValueError("selected assessment timestamp wire must remain unchanged")
        body: dict[str, object] = {
            "schema_version": SELECTED_CONTROL_ASSESSMENT_V2_SCHEMA_VERSION,
            "object_kind": "selected-control-assessment",
            "lock_digest": require_digest(self.lock_digest, "selected lock digest"),
            "quality_projection_digest": require_digest(
                self.quality_projection_digest, "selected quality projection digest"
            ),
            "task_context_digest": require_digest(
                self.task_context_digest, "selected task digest"
            ),
            "event_request_digest": require_digest(
                self.event_request_digest, "selected request digest"
            ),
            "control": control.to_dict(),
            "contract_case": case,
            "applicability": applicability,
            "status": status,
            "evidence": [item.to_dict() for item in evidence],
            "reviews": [item.to_dict() for item in reviews],
            "assessor": require_identifier(self.assessor, "selected assessor identity"),
            "assessed_at": instant,
            "reason_code": require_identifier(self.reason_code, "selected assessment reason"),
        }
        policy_wire_size(body, budget=limits)
        return body

    @classmethod
    def build(
        cls,
        *,
        lock_digest: str,
        quality_projection_digest: str,
        task_context_digest: str,
        event_request_digest: str,
        control: TypedObjectRef1,
        contract_case: ContractCase,
        applicability: AssessmentApplicability,
        status: AssessmentStatus,
        evidence: tuple[TypedObjectRef1, ...],
        reviews: tuple[TypedObjectRef1, ...],
        assessor: str,
        assessed_at: str,
        reason_code: str,
        budget: PolicyReadBudget1,
    ) -> SelectedControlAssessment2:
        """Bind explicit inputs without selecting a host or creating a legacy profile lock."""
        candidate = cls(
            lock_digest,
            quality_projection_digest,
            task_context_digest,
            event_request_digest,
            control,
            contract_case,
            applicability,
            status,
            evidence,
            reviews,
            assessor,
            assessed_at,
            reason_code,
            "",
        )
        body = candidate._body(budget=budget)
        return cls.from_dict({**body, "assessment_digest": canonical_digest(body)}, budget=budget)

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Revalidate every direct field and owning digest before returning the exact wire."""
        body = self._body(budget=budget)
        digest = require_digest(self.assessment_digest, "selected assessment digest")
        if digest != canonical_digest(body):
            raise ValueError("selected assessment digest differs")
        result = {**body, "assessment_digest": digest}
        policy_wire_size(result, budget=budget)
        return result

    def review_body_digest(self, *, budget: PolicyReadBudget1) -> str:
        """Derive the independent body to be reviewed before adding any review references.

        This body contains every assessment field except ``reviews`` and the
        final ``assessment_digest``. Original attestations can sign this exact
        independent input using their unchanged original signature domain.
        Deriving a digest authenticates no reviewer, contract or selected root.
        """
        body = self.to_dict(budget=budget)
        body.pop("assessment_digest")
        body.pop("reviews")
        return canonical_digest(body)

    def verify_quality_binding(
        self, row: object, control: object, *, budget: PolicyReadBudget1
    ) -> None:
        """Check this exact row and actual control without authenticating the enclosing selection.

        Parameters
        ----------
        row : object
            Actual complete ``QualityProjectionRowV3`` from the selected projection.
        control : object
            Actual original or qualitative owning control for that row.
        budget : PolicyReadBudget1
            Explicit bounds for all three complete records.

        Raises
        ------
        ValueError
            The row, contract case or actual control differs. Full selected root,
            task/request bindings and evidence/review verification remain required.
        """
        self.to_dict(budget=budget)
        if type(row) is not QualityProjectionRowV3:
            raise ValueError("selected assessment requires an actual complete quality row")
        row.verify_control_binding(control, budget=budget)
        if self.control != row.control or self.contract_case != row.contract_case:
            raise ValueError("selected assessment differs from its exact quality row")

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> SelectedControlAssessment2:
        """Parse exact fields and allocation counts before constructing reference children."""
        data = policy_record_mapping(
            value,
            fields=_FIELDS,
            object_kind="selected-control-assessment",
            schema_version=SELECTED_CONTROL_ASSESSMENT_V2_SCHEMA_VERSION,
            budget=budget,
        )
        count = 1
        for name in ("evidence", "reviews"):
            rows = data[name]
            if type(rows) is not list:
                raise ValueError("selected assessment requires exact reference arrays")
            count += len(rows)
            if count > budget.max_references:
                raise ValueError("selected assessment exceeds the reference allocation budget")
        result = cls(
            require_digest(data["lock_digest"], "selected lock digest"),
            require_digest(
                data["quality_projection_digest"], "selected quality projection digest"
            ),
            require_digest(data["task_context_digest"], "selected task digest"),
            require_digest(data["event_request_digest"], "selected request digest"),
            TypedObjectRef1.from_dict(data["control"]),
            cast(ContractCase, data["contract_case"]),
            cast(AssessmentApplicability, data["applicability"]),
            cast(AssessmentStatus, data["status"]),
            tuple(
                TypedObjectRef1.from_dict(item) for item in cast(list[object], data["evidence"])
            ),
            tuple(TypedObjectRef1.from_dict(item) for item in cast(list[object], data["reviews"])),
            require_identifier(data["assessor"], "selected assessor identity"),
            require_utc_timestamp(data["assessed_at"], "selected assessment instant"),
            require_identifier(data["reason_code"], "selected assessment reason"),
            require_digest(data["assessment_digest"], "selected assessment digest"),
        )
        result.to_dict(budget=budget)
        if result.to_dict(budget=budget) != data:
            raise ValueError("selected assessment wire must remain unchanged")
        return result


def validate_selected_legacy_pass(
    assessment: SelectedControlAssessment2,
    row: QualityProjectionRowV3,
    control: ControlDefinition,
    *,
    adapters: tuple[AdapterLock, ...],
    evidence: tuple[EvidenceReference, ...],
    reviews: tuple[ReviewerAttestation, ...],
    review_trust_store: VerificationTrustStore | None,
    instant: datetime,
    budget: PolicyReadBudget1,
) -> None:
    """Apply exact original evidence and signed-review predicates to a selected legacy pass.

    Parameters
    ----------
    assessment : SelectedControlAssessment2
        Complete legacy pass declaration, with explicit true applicability.
    row : QualityProjectionRowV3
        Actual row from the entire selected quality projection.
    control : ControlDefinition
        Actual complete original control, retaining its positive numeric contract.
    adapters : tuple[AdapterLock, ...]
        Actual complete selected original adapter custody cohort.
    evidence : tuple[EvidenceReference, ...]
        Entire original evidence cohort, exactly matching the declared references.
    reviews : tuple[ReviewerAttestation, ...]
        Entire original attestation cohort, exactly matching the declared references.
    review_trust_store : VerificationTrustStore or None
        Explicit original public-key selection. An absent store cannot qualify.
    instant : datetime
        Actual aware evaluation time, including current evidence and review expiry.
    budget : PolicyReadBudget1
        Explicit bounds for complete children and aggregate metadata allocations.

    Raises
    ------
    ValueError
        Any actual owner, reference, budget, original freshness/coverage, signature,
        independent identity or positive reviewer requirement does not qualify.

    Notes
    -----
    This verifies the original pure predicates without constructing a v1 lock.
    The enclosing installed owner still must derive and authenticate the selected
    root, complete source scope, applicability, actual artifacts/results, current
    public-key lifecycle and closing checks. This function supplies no gate receipt.
    """
    limits = checked_policy_budget(budget)
    if type(assessment) is not SelectedControlAssessment2:
        raise ValueError("legacy pass requires an actual selected assessment")
    assessment.verify_quality_binding(row, control, budget=limits)
    if (
        assessment.contract_case != "legacy1"
        or assessment.status != "pass"
        or assessment.applicability != "true"
    ):
        raise ValueError("legacy pass requires its exact legacy case, pass and true applicability")
    if type(instant) is not datetime or instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("legacy pass evaluation requires an actual aware instant")
    count = 0
    size = 2
    emitted = 0
    for group, owner in (
        (adapters, AdapterLock),
        (evidence, EvidenceReference),
        (reviews, ReviewerAttestation),
    ):
        if type(group) is not tuple:
            raise ValueError("legacy pass requires immutable original owner cohorts")
        count += len(group)
        if count > limits.max_references:
            raise ValueError("legacy pass exceeds its aggregate owner reference budget")
        identities: set[str] = set()
        for item in group:
            if type(item) is not owner:
                raise ValueError("legacy pass requires actual complete original owners")
            source = PolicyComponent1(item, limits)
            identity = source.reference().object_id
            if identity in identities:
                raise ValueError("legacy pass original cohort contains a duplicate identity")
            identities.add(identity)
            size += policy_wire_size(source.to_dict(), budget=limits) + bool(emitted)
            if size > limits.max_document_bytes:
                raise ValueError("legacy pass exceeds its aggregate owner byte budget")
            emitted += 1
    for actual, declared in ((evidence, assessment.evidence), (reviews, assessment.reviews)):
        refs = tuple(
            sorted(
                (PolicyComponent1(item, limits).reference() for item in actual),
                key=lambda item: item.object_id,
            )
        )
        if refs != declared:
            raise ValueError("legacy pass differs from its complete declared evidence or reviews")
    if review_trust_store is not None:
        if (
            type(review_trust_store) is not VerificationTrustStore
            or type(review_trust_store.keys) is not tuple
            or any(type(key) is not TrustedPublicKey for key in review_trust_store.keys)
        ):
            raise ValueError(
                "legacy pass requires an actual immutable original public trust store"
            )
        if count + len(review_trust_store.keys) > limits.max_references:
            raise ValueError("legacy pass public keys exceed the aggregate reference budget")
        if VerificationTrustStore.build(review_trust_store.keys) != review_trust_store:
            raise ValueError("legacy pass original public trust store integrity differs")
        policy_wire_size(review_trust_store.to_dict(), budget=limits)
    missing = tuple(
        sorted(
            set(control.evidence.required_adapters).difference(
                adapter.adapter_id for adapter in adapters
            )
        )
    )
    validate_original_evidence_bindings(
        domain=control.domain, adapters=adapters, evidence=evidence
    )
    validate_original_pass_evidence(
        contract=control.evidence, missing_adapter_ids=missing, instant=instant, evidence=evidence
    )
    validate_original_reviewers(
        contract=control.evidence,
        instant=instant,
        reviews=reviews,
        assessor=assessment.assessor,
        decision=assessment.status,
        review_body_digest=assessment.review_body_digest(budget=limits),
        review_trust_store=review_trust_store,
    )
