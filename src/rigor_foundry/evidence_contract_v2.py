# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — qualitative evidence requirement contracts
"""Bind actual adapter custody, qualitative freshness and explicit review policy references."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from .audit_primitives import canonical_digest
from .model_primitives import require_digest, require_identifier
from .policy_model_inputs import (
    checked_policy_budget,
    policy_record_mapping,
    policy_reference,
    policy_wire_size,
)
from .policy_read_budget import PolicyReadBudget1
from .review_policy import REVIEW_POLICY_SCHEMA_VERSION
from .source_component_reader import ADAPTER_LOCK_REFERENCE_FORMAT
from .typed_object_reference import TypedObjectRef1

EVIDENCE_REQUIREMENT_SCHEMA_VERSION = "1.0"
EVIDENCE_CONTRACT_V2_SCHEMA_VERSION = "2.0"
_ADAPTER_FORMATS = frozenset({("adapter-lock", ADAPTER_LOCK_REFERENCE_FORMAT)})
_FRESHNESS_FORMATS = frozenset({("freshness-policy", "2.0")})
_REVIEW_FORMATS = frozenset({("review-policy", REVIEW_POLICY_SCHEMA_VERSION)})
_REQUIREMENT_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "evidence_type",
        "adapter",
        "subject_class",
        "freshness_policy",
        "requirement_digest",
    }
)
_CONTRACT_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "contract_id",
        "requirements",
        "review_policy",
        "contract_digest",
    }
)


@dataclass(frozen=True)
class EvidenceRequirement1:
    """One explicit evidence type, adapter custody, subject domain and freshness policy.

    These are exact structural references. The installed adapter and evidence
    owners still must verify the actual result, source/configuration/toolchain/
    cohort, selected freshness policy, current state and invalidators.
    """

    evidence_type: str
    adapter: TypedObjectRef1
    subject_class: str
    freshness_policy: TypedObjectRef1
    requirement_digest: str

    schema_version: ClassVar[str] = EVIDENCE_REQUIREMENT_SCHEMA_VERSION
    object_kind: ClassVar[str] = "evidence-requirement"

    def _body(self) -> dict[str, object]:
        """Check actual reference classes and the exact supported owning formats."""
        adapter = policy_reference(self.adapter, allowed=_ADAPTER_FORMATS)
        freshness = policy_reference(self.freshness_policy, allowed=_FRESHNESS_FORMATS)
        return {
            "schema_version": EVIDENCE_REQUIREMENT_SCHEMA_VERSION,
            "object_kind": "evidence-requirement",
            "evidence_type": require_identifier(self.evidence_type, "evidence requirement type"),
            "adapter": adapter.to_dict(),
            "subject_class": require_identifier(self.subject_class, "evidence subject class"),
            "freshness_policy": freshness.to_dict(),
        }

    @classmethod
    def build(
        cls,
        *,
        evidence_type: str,
        adapter: TypedObjectRef1,
        subject_class: str,
        freshness_policy: TypedObjectRef1,
        budget: PolicyReadBudget1,
    ) -> EvidenceRequirement1:
        """Build exact requirements without numeric freshness or review-count substitutes."""
        limits = checked_policy_budget(budget)
        if limits.max_references < 2:
            raise ValueError("evidence requirement exceeds the reference budget")
        candidate = cls(evidence_type, adapter, subject_class, freshness_policy, "")
        result = cls(
            evidence_type,
            adapter,
            subject_class,
            freshness_policy,
            canonical_digest(candidate._body()),
        )
        result.to_dict(budget=limits)
        return result

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Revalidate direct records and both complete original component references."""
        limits = checked_policy_budget(budget)
        if limits.max_references < 2:
            raise ValueError("evidence requirement exceeds the reference budget")
        body = self._body()
        digest = require_digest(self.requirement_digest, "evidence requirement digest")
        if digest != canonical_digest(body):
            raise ValueError("evidence requirement digest differs")
        result = {**body, "requirement_digest": digest}
        policy_wire_size(result, budget=limits)
        return result

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> EvidenceRequirement1:
        """Parse exactly the declared requirement fields and original owning references."""
        data = policy_record_mapping(
            value,
            fields=_REQUIREMENT_FIELDS,
            object_kind="evidence-requirement",
            schema_version=EVIDENCE_REQUIREMENT_SCHEMA_VERSION,
            budget=budget,
        )
        result = cls(
            require_identifier(data["evidence_type"], "evidence requirement type"),
            TypedObjectRef1.from_dict(data["adapter"]),
            require_identifier(data["subject_class"], "evidence subject class"),
            TypedObjectRef1.from_dict(data["freshness_policy"]),
            require_digest(data["requirement_digest"], "evidence requirement digest"),
        )
        result.to_dict(budget=budget)
        return result


@dataclass(frozen=True)
class EvidenceContract2:
    """A nonempty exact evidence set and source-bound qualitative review policy.

    Requirements sort uniquely by (evidence_type, adapter.object_id,
    subject_class, freshness_policy.object_id). Changed digests cannot give one
    requirement identity two meanings. Parsing creates no trusted evidence,
    source acceptance, review fallback or current-freshness verdict.
    """

    contract_id: str
    requirements: tuple[EvidenceRequirement1, ...]
    review_policy: TypedObjectRef1
    contract_digest: str

    schema_version: ClassVar[str] = EVIDENCE_CONTRACT_V2_SCHEMA_VERSION
    object_kind: ClassVar[str] = "evidence-contract"

    def _body(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Validate complete requirements and their aggregate reference allocation."""
        limits = checked_policy_budget(budget)
        if (
            type(self.requirements) is not tuple
            or not self.requirements
            or len(self.requirements) > limits.max_references
        ):
            raise ValueError("evidence contract requires a bounded nonempty immutable tuple")
        if 2 * len(self.requirements) + 1 > limits.max_references:
            raise ValueError("evidence contract exceeds the aggregate reference budget")
        rows: list[dict[str, object]] = []
        identities: list[tuple[str, str, str, str]] = []
        for requirement in self.requirements:
            if type(requirement) is not EvidenceRequirement1:
                raise ValueError("evidence contract requires actual evidence requirements")
            rows.append(requirement.to_dict(budget=limits))
            identities.append(
                (
                    requirement.evidence_type,
                    requirement.adapter.object_id,
                    requirement.subject_class,
                    requirement.freshness_policy.object_id,
                )
            )
        if identities != sorted(set(identities)):
            raise ValueError("evidence requirement identities must be sorted and unique")
        review = policy_reference(self.review_policy, allowed=_REVIEW_FORMATS)
        body: dict[str, object] = {
            "schema_version": EVIDENCE_CONTRACT_V2_SCHEMA_VERSION,
            "object_kind": "evidence-contract",
            "contract_id": require_identifier(self.contract_id, "evidence contract identity"),
            "requirements": rows,
            "review_policy": review.to_dict(),
        }
        policy_wire_size(body, budget=limits)
        return body

    @classmethod
    def build(
        cls,
        *,
        contract_id: str,
        requirements: tuple[EvidenceRequirement1, ...],
        review_policy: TypedObjectRef1,
        budget: PolicyReadBudget1,
    ) -> EvidenceContract2:
        """Bind a complete nonempty declaration with its exact qualitative review source."""
        candidate = cls(contract_id, requirements, review_policy, "")
        body = candidate._body(budget=budget)
        result = cls(contract_id, requirements, review_policy, canonical_digest(body))
        result.to_dict(budget=budget)
        return result

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Serialize exact version2 requirements after revalidating all direct values."""
        body = self._body(budget=budget)
        digest = require_digest(self.contract_digest, "qualitative evidence contract digest")
        if digest != canonical_digest(body):
            raise ValueError("qualitative evidence contract digest differs")
        result = {**body, "contract_digest": digest}
        policy_wire_size(result, budget=budget)
        return result

    def reference(self, *, budget: PolicyReadBudget1) -> TypedObjectRef1:
        """Identify the exact complete contract for its actual owning consumer to resolve."""
        self.to_dict(budget=budget)
        return TypedObjectRef1.build(
            kind="evidence-contract",
            format_version=EVIDENCE_CONTRACT_V2_SCHEMA_VERSION,
            object_id=self.contract_id,
            object_digest=self.contract_digest,
        )

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> EvidenceContract2:
        """Parse closed version2 fields without treating the old numeric contract as new."""
        data = policy_record_mapping(
            value,
            fields=_CONTRACT_FIELDS,
            object_kind="evidence-contract",
            schema_version=EVIDENCE_CONTRACT_V2_SCHEMA_VERSION,
            budget=budget,
        )
        rows = data["requirements"]
        if type(rows) is not list or not rows or len(rows) > budget.max_references:
            raise ValueError("evidence contract requires a bounded nonempty array")
        if 2 * len(rows) + 1 > budget.max_references:
            raise ValueError("evidence contract exceeds the aggregate reference budget")
        result = cls(
            require_identifier(data["contract_id"], "evidence contract identity"),
            tuple(EvidenceRequirement1.from_dict(item, budget=budget) for item in rows),
            TypedObjectRef1.from_dict(data["review_policy"]),
            require_digest(data["contract_digest"], "qualitative evidence contract digest"),
        )
        result.to_dict(budget=budget)
        return result
