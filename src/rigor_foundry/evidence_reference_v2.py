# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — exact qualitative evidence subjects and references
"""Bind artifact/source/configuration identities before including producer and freshness proofs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Literal, cast

from .audit_primitives import canonical_digest, require_integer, require_string
from .context_owner_proof import OwnerProof1
from .control_assessment import Classification
from .evidence_contract_v2 import EvidenceRequirement1
from .freshness_proof import FreshnessProof1, freshness_reference_count
from .model_primitives import require_digest, require_identifier, require_utc_timestamp
from .policy_model_inputs import (
    checked_policy_budget,
    policy_owner_proof,
    policy_record_mapping,
    policy_reference,
    policy_wire_size,
)
from .policy_read_budget import PolicyReadBudget1
from .rule_chain_pack_v2 import FreshnessPolicyV2
from .source_component_reader import ADAPTER_LOCK_REFERENCE_FORMAT
from .typed_object_reference import TypedObjectRef1

EVIDENCE_REFERENCE_V2_SCHEMA_VERSION = "2.0"
EVIDENCE_SUBJECT_SCHEMA_VERSION = "1.0"
EvidenceResult = Literal["pass", "fail", "unavailable", "refused"]
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "evidence_id",
        "evidence_type",
        "adapter",
        "artifact_digest",
        "artifact_size",
        "classification",
        "reference",
        "observed_at",
        "subject_digest",
        "configuration_digest",
        "toolchain_digest",
        "cohort_digest",
        "source_objects",
        "result",
        "producer_proof",
        "freshness",
        "evidence_digest",
    }
)
_ADAPTER_FORMATS = frozenset({("adapter-lock", ADAPTER_LOCK_REFERENCE_FORMAT)})


def _source_objects(values: object, budget: PolicyReadBudget1) -> tuple[TypedObjectRef1, ...]:
    """Recheck a bounded immutable source identity set before sorting or subject hashing."""
    if type(values) is not tuple or len(values) + 1 > budget.max_references:
        raise ValueError("evidence source objects exceed the immutable reference budget")
    if len(values) > budget.max_sources:
        raise ValueError("evidence source objects exceed the source budget")
    result: list[TypedObjectRef1] = []
    for value in values:
        if type(value) is not TypedObjectRef1:
            raise ValueError("evidence source objects require actual typed references")
        result.append(TypedObjectRef1.from_dict(value.to_dict()))
    identities = tuple((ref.kind, ref.format_version, ref.object_id) for ref in result)
    if identities != tuple(sorted(set(identities))):
        raise ValueError("evidence source identities must be sorted and unique")
    return tuple(result)


def evidence_subject_digest(
    *,
    adapter: TypedObjectRef1,
    artifact_digest: str,
    artifact_size: int,
    configuration_digest: str,
    toolchain_digest: str,
    cohort_digest: str,
    source_objects: tuple[TypedObjectRef1, ...],
    budget: PolicyReadBudget1,
) -> str:
    """Derive the independent evidence subject before either included proof exists.

    Parameters
    ----------
    adapter : TypedObjectRef1
        Exact original adapter custody reference.
    artifact_digest : str
        SHA256 of the complete artifact bytes, rather than a caller result string.
    artifact_size : int
        Actual nonnegative artifact byte count.
    configuration_digest, toolchain_digest, cohort_digest : str
        Exact independent configuration, toolchain and tested-cohort identities.
    source_objects : tuple[TypedObjectRef1, ...]
        Complete declared source set, sorted by kind/version/ID and unique.
    budget : PolicyReadBudget1
        Explicit structural byte, depth and reference bounds.

    Returns
    -------
    str
        Digest of the closed evidence-subject1.0 body. It contains no producer
        proof, freshness proof or enclosing evidence-reference digest.
    """
    limits = checked_policy_budget(budget)
    actual_adapter = policy_reference(adapter, allowed=_ADAPTER_FORMATS)
    sources = _source_objects(source_objects, limits)
    body: dict[str, object] = {
        "schema_version": EVIDENCE_SUBJECT_SCHEMA_VERSION,
        "object_kind": "evidence-subject",
        "adapter": actual_adapter.to_dict(),
        "artifact_digest": require_digest(artifact_digest, "evidence artifact digest"),
        "artifact_size": require_integer(artifact_size, "evidence artifact size", minimum=0),
        "configuration_digest": require_digest(
            configuration_digest, "evidence configuration digest"
        ),
        "toolchain_digest": require_digest(toolchain_digest, "evidence toolchain digest"),
        "cohort_digest": require_digest(cohort_digest, "evidence cohort digest"),
        "source_objects": [ref.to_dict() for ref in sources],
    }
    policy_wire_size(body, budget=limits)
    return canonical_digest(body)


@dataclass(frozen=True)
class EvidenceReference2:
    """Classified opaque evidence metadata bound to an independent exact subject.

    Producer and freshness proof subjects must agree with the independently
    computed artifact/source/configuration/toolchain/cohort body. Result text
    remains a declaration until the installed adapter reads the actual artifact
    and current owners verify all proofs. Parsing establishes no gate verdict.
    """

    evidence_id: str
    evidence_type: str
    adapter: TypedObjectRef1
    artifact_digest: str
    artifact_size: int
    classification: Classification
    reference: str
    observed_at: str
    subject_digest: str
    configuration_digest: str
    toolchain_digest: str
    cohort_digest: str
    source_objects: tuple[TypedObjectRef1, ...]
    result: EvidenceResult
    producer_proof: OwnerProof1
    freshness: FreshnessProof1
    evidence_digest: str

    schema_version: ClassVar[str] = EVIDENCE_REFERENCE_V2_SCHEMA_VERSION
    object_kind: ClassVar[str] = "evidence-reference"

    def _body(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Verify independent subjects and full aggregate allocations before nested serialization."""
        limits = checked_policy_budget(budget)
        sources = _source_objects(self.source_objects, limits)
        if type(self.freshness) is not FreshnessProof1:
            raise ValueError("evidence requires an actual freshness proof")
        count = 3 + len(sources) + freshness_reference_count(self.freshness, budget=limits)
        if count > limits.max_references:
            raise ValueError("evidence exceeds the aggregate reference budget")
        freshness = self.freshness.to_dict(budget=limits)
        adapter = policy_reference(self.adapter, allowed=_ADAPTER_FORMATS)
        subject = evidence_subject_digest(
            adapter=adapter,
            artifact_digest=self.artifact_digest,
            artifact_size=self.artifact_size,
            configuration_digest=self.configuration_digest,
            toolchain_digest=self.toolchain_digest,
            cohort_digest=self.cohort_digest,
            source_objects=sources,
            budget=limits,
        )
        producer = policy_owner_proof(self.producer_proof, budget=limits)
        if (
            subject != require_digest(self.subject_digest, "evidence subject digest")
            or producer.subject_digest != subject
            or self.freshness.subject_digest != subject
        ):
            raise ValueError(
                "evidence or included proof differs from the independent evidence subject"
            )
        classification = require_string(self.classification, "evidence classification")
        result = require_string(self.result, "evidence result")
        reference = require_string(self.reference, "opaque evidence reference")
        if classification not in {"public", "internal", "confidential", "secret"}:
            raise ValueError("unsupported evidence classification")
        if result not in {"pass", "fail", "unavailable", "refused"}:
            raise ValueError("unsupported evidence result")
        if any(character.isspace() for character in reference):
            raise ValueError("evidence reference must be opaque whitespace-free text")
        body: dict[str, object] = {
            "schema_version": EVIDENCE_REFERENCE_V2_SCHEMA_VERSION,
            "object_kind": "evidence-reference",
            "evidence_id": require_identifier(self.evidence_id, "evidence identity"),
            "evidence_type": require_identifier(self.evidence_type, "evidence type"),
            "adapter": adapter.to_dict(),
            "artifact_digest": self.artifact_digest,
            "artifact_size": self.artifact_size,
            "classification": classification,
            "reference": reference,
            "observed_at": require_utc_timestamp(self.observed_at, "evidence observation time"),
            "subject_digest": subject,
            "configuration_digest": self.configuration_digest,
            "toolchain_digest": self.toolchain_digest,
            "cohort_digest": self.cohort_digest,
            "source_objects": [ref.to_dict() for ref in sources],
            "result": result,
            "producer_proof": producer.to_dict(),
            "freshness": freshness,
        }
        policy_wire_size(body, budget=limits)
        return body

    @classmethod
    def build(
        cls,
        *,
        evidence_id: str,
        evidence_type: str,
        adapter: TypedObjectRef1,
        artifact_digest: str,
        artifact_size: int,
        classification: Classification,
        reference: str,
        observed_at: str,
        subject_digest: str,
        configuration_digest: str,
        toolchain_digest: str,
        cohort_digest: str,
        source_objects: tuple[TypedObjectRef1, ...],
        result: EvidenceResult,
        producer_proof: OwnerProof1,
        freshness: FreshnessProof1,
        budget: PolicyReadBudget1,
    ) -> EvidenceReference2:
        """Build complete evidence metadata after independent subjects and proof inputs are available."""
        candidate = cls(
            evidence_id,
            evidence_type,
            adapter,
            artifact_digest,
            artifact_size,
            classification,
            reference,
            observed_at,
            subject_digest,
            configuration_digest,
            toolchain_digest,
            cohort_digest,
            source_objects,
            result,
            producer_proof,
            freshness,
            "",
        )
        body = candidate._body(budget=budget)
        return cls.from_dict({**body, "evidence_digest": canonical_digest(body)}, budget=budget)

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Revalidate complete direct metadata and all included original proof identities."""
        body = self._body(budget=budget)
        digest = require_digest(self.evidence_digest, "evidence digest")
        if digest != canonical_digest(body):
            raise ValueError("evidence digest differs")
        result = {**body, "evidence_digest": digest}
        policy_wire_size(result, budget=budget)
        return result

    def object_reference(self, *, budget: PolicyReadBudget1) -> TypedObjectRef1:
        """Return the exact evidence identity, distinct from its opaque artifact reference field."""
        self.to_dict(budget=budget)
        return TypedObjectRef1.build(
            kind="evidence-reference",
            format_version=EVIDENCE_REFERENCE_V2_SCHEMA_VERSION,
            object_id=self.evidence_id,
            object_digest=self.evidence_digest,
        )

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> EvidenceReference2:
        """Parse exact complete fields without replacing old numeric evidence or rewriting input."""
        data = policy_record_mapping(
            value,
            fields=_FIELDS,
            object_kind="evidence-reference",
            schema_version=EVIDENCE_REFERENCE_V2_SCHEMA_VERSION,
            budget=budget,
        )
        limits = checked_policy_budget(budget)
        rows = data["source_objects"]
        if type(rows) is not list or len(rows) + 6 > limits.max_references:
            raise ValueError("evidence sources require a bounded array")
        if len(rows) > limits.max_sources:
            raise ValueError("evidence source objects exceed the source budget")
        count = 3 + len(rows) + freshness_reference_count(data["freshness"], budget=limits)
        if count > limits.max_references:
            raise ValueError("evidence exceeds the aggregate reference budget")
        parsed_freshness = FreshnessProof1.from_dict(data["freshness"], budget=limits)
        result = cls(
            require_identifier(data["evidence_id"], "evidence identity"),
            require_identifier(data["evidence_type"], "evidence type"),
            TypedObjectRef1.from_dict(data["adapter"]),
            require_digest(data["artifact_digest"], "evidence artifact digest"),
            require_integer(data["artifact_size"], "evidence artifact size", minimum=0),
            cast(
                Classification, require_string(data["classification"], "evidence classification")
            ),
            require_string(data["reference"], "opaque evidence reference"),
            require_string(data["observed_at"], "evidence observation time"),
            require_digest(data["subject_digest"], "evidence subject digest"),
            require_digest(data["configuration_digest"], "evidence configuration digest"),
            require_digest(data["toolchain_digest"], "evidence toolchain digest"),
            require_digest(data["cohort_digest"], "evidence cohort digest"),
            tuple(TypedObjectRef1.from_dict(row) for row in rows),
            cast(EvidenceResult, require_string(data["result"], "evidence result")),
            OwnerProof1.from_dict(data["producer_proof"], budget=limits),
            parsed_freshness,
            require_digest(data["evidence_digest"], "evidence digest"),
        )
        if result.to_dict(budget=limits) != data:
            raise ValueError("evidence wire must remain unchanged")
        return result

    def verify_requirement_binding(
        self,
        requirement: object,
        policy: object,
        *,
        budget: PolicyReadBudget1,
    ) -> None:
        """Check exact declared requirement and original policy relations without assessing results.

        Parameters
        ----------
        requirement : object
            Actual ``EvidenceRequirement1``, including adapter and subject class.
        policy : object
            Actual original ``FreshnessPolicyV2`` with unchanged invalidators.
        budget : PolicyReadBudget1
            Explicit bounds for all complete records.
        """
        self.to_dict(budget=budget)
        if type(requirement) is not EvidenceRequirement1 or type(policy) is not FreshnessPolicyV2:
            raise ValueError(
                "evidence binding requires actual requirement and original freshness policy"
            )
        expected = EvidenceRequirement1.from_dict(
            requirement.to_dict(budget=budget), budget=budget
        )
        self.freshness.verify_policy_binding(policy, budget=budget)
        if (
            expected.evidence_type != self.evidence_type
            or expected.adapter != self.adapter
            or expected.freshness_policy != self.freshness.policy
            or expected.subject_class != policy.subject_class
        ):
            raise ValueError(
                "evidence differs from the exact requirement, adapter or subject class"
            )
