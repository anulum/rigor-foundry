# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — independent source-owner observations
"""Build the independent observation preimage before any enclosing proof digest."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from .audit_primitives import (
    canonical_digest,
    require_exact_fields,
    require_mapping,
    require_string,
)
from .condition_facts import ConditionFact, ObservationState
from .condition_language import ConditionExpression, ConditionValue
from .context_owner_proof import OwnerProof1
from .model_primitives import require_digest, require_identifier
from .policy_read_budget import PolicyReadBudget1

CONTEXT_PRODUCER_OBSERVATION_SCHEMA_VERSION = "1.0"
_OBSERVATION_FIELDS = frozenset({"reference", "state", "value", "subject_digest"})
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "owner_id",
        "owner_contract_ref_digest",
        "source_object_ref_digest",
        "snapshot_id",
        "subject_kind",
        "subject_digest",
        "observations",
    }
)
_MAX_REFERENCES = 65536


@dataclass(frozen=True, eq=False)
class OwnerObservation:
    """Inline finite fact state, still requiring its actual source-owner check."""

    reference: str
    state: ObservationState
    value: ConditionValue
    subject_digest: str

    def __post_init__(self) -> None:
        """Check exact reference syntax and scalar/state relationships."""
        self.to_dict()

    def __eq__(self, other: object) -> bool:
        """Compare exact scalar wire identities without Boolean/integer aliasing."""
        if not isinstance(other, OwnerObservation):
            return False
        return canonical_digest(self.to_dict()) == canonical_digest(other.to_dict())

    def __hash__(self) -> int:
        """Hash the same type-preserving data used by observation equality."""
        return hash(canonical_digest(self.to_dict()))

    def to_dict(self) -> dict[str, object]:
        """Retain observed null and empty arrays without fabricating absence."""
        reference = require_string(self.reference, "owner observation reference")
        ConditionExpression.build("exists", reference=reference)
        fact = ConditionFact(self.state, self.value)
        return {
            "reference": reference,
            **fact.to_dict(),
            "subject_digest": require_digest(self.subject_digest, "observation subject digest"),
        }

    @classmethod
    def from_dict(cls, value: object) -> OwnerObservation:
        """Parse a closed inline observation using the existing operand semantics."""
        data = require_mapping(value, "owner observation")
        require_exact_fields(data, _OBSERVATION_FIELDS, "owner observation")
        fact = ConditionFact.from_dict({"state": data["state"], "value": data["value"]})
        return cls(
            require_string(data["reference"], "owner observation reference"),
            fact.state,
            fact.value,
            require_digest(data["subject_digest"], "observation subject digest"),
        )


@dataclass(frozen=True)
class ContextProducerObservation1:
    """Independent closed preimage whose hash becomes OwnerProof.observation_digest.

    This mapping deliberately contains no final proof, fact-observation or
    context digest. Its header and inline observations are hashed together.
    Matching metadata is not installed source authentication.
    """

    owner_id: str
    owner_contract_ref_digest: str
    source_object_ref_digest: str
    snapshot_id: str
    subject_kind: str
    subject_digest: str
    observations: tuple[OwnerObservation, ...]

    schema_version: ClassVar[str] = CONTEXT_PRODUCER_OBSERVATION_SCHEMA_VERSION
    object_kind: ClassVar[str] = "context-producer-observation"

    def __post_init__(self) -> None:
        """Check hard reference ceilings and exact noncircular subjects."""
        self.to_dict()

    def to_dict(self) -> dict[str, object]:
        """Validate and serialize the independent mapping without an own digest."""
        subject = require_digest(self.subject_digest, "producer subject digest")
        if (
            not isinstance(self.observations, tuple)
            or len(self.observations) + 2 > _MAX_REFERENCES
        ):
            raise ValueError("producer observations require bounded immutable records")
        if any(type(item) is not OwnerObservation for item in self.observations):
            raise ValueError("producer observations require actual inline records")
        values = [item.to_dict() for item in self.observations]
        names = tuple(item.reference for item in self.observations)
        if names != tuple(sorted(set(names))):
            raise ValueError("producer observations must be sorted and unique")
        if any(item.subject_digest != subject for item in self.observations):
            raise ValueError("producer observation subject differs")
        return {
            "schema_version": CONTEXT_PRODUCER_OBSERVATION_SCHEMA_VERSION,
            "object_kind": "context-producer-observation",
            "owner_id": require_identifier(self.owner_id, "producer identity"),
            "owner_contract_ref_digest": require_digest(
                self.owner_contract_ref_digest, "producer contract reference digest"
            ),
            "source_object_ref_digest": require_digest(
                self.source_object_ref_digest, "producer source reference digest"
            ),
            "snapshot_id": require_identifier(self.snapshot_id, "producer snapshot identity"),
            "subject_kind": require_identifier(self.subject_kind, "producer subject kind"),
            "subject_digest": subject,
            "observations": values,
        }

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> ContextProducerObservation1:
        """Bound the observation array before parsing its exact inline values."""
        if type(budget) is not PolicyReadBudget1:
            raise ValueError("policy read budget is required")
        limits = PolicyReadBudget1.from_dict(budget.to_dict())
        data = require_mapping(value, "producer observation preimage")
        require_exact_fields(data, _FIELDS, "producer observation preimage")
        if (
            data["schema_version"] != CONTEXT_PRODUCER_OBSERVATION_SCHEMA_VERSION
            or data["object_kind"] != "context-producer-observation"
        ):
            raise ValueError("unsupported producer observation preimage")
        raw = data["observations"]
        if not isinstance(raw, list) or len(raw) + 2 > limits.max_references:
            raise ValueError(
                "producer observations exceed the reference budget or have invalid type"
            )
        return cls(
            require_identifier(data["owner_id"], "producer identity"),
            require_digest(
                data["owner_contract_ref_digest"], "producer contract reference digest"
            ),
            require_digest(data["source_object_ref_digest"], "producer source reference digest"),
            require_identifier(data["snapshot_id"], "producer snapshot identity"),
            require_identifier(data["subject_kind"], "producer subject kind"),
            require_digest(data["subject_digest"], "producer subject digest"),
            tuple(OwnerObservation.from_dict(item) for item in raw),
        )

    def digest(self, *, budget: PolicyReadBudget1) -> str:
        """Hash only independently defined fields after applying the caller's budget."""
        checked = ContextProducerObservation1.from_dict(self.to_dict(), budget=budget)
        return canonical_digest(checked.to_dict())

    def verify_proof_binding(self, proof: OwnerProof1, *, budget: PolicyReadBudget1) -> None:
        """Check metadata agreement without asserting installed owner authentication."""
        if type(proof) is not OwnerProof1:
            raise ValueError("actual owner proof record is required")
        checked = OwnerProof1.from_dict(proof.to_dict(), budget=budget)
        if (
            checked.owner_id != self.owner_id
            or checked.owner_contract.ref_digest != self.owner_contract_ref_digest
            or checked.source_object.ref_digest != self.source_object_ref_digest
            or checked.snapshot_id != self.snapshot_id
            or checked.subject_digest != self.subject_digest
            or checked.observation_digest != self.digest(budget=budget)
        ):
            raise ValueError("owner proof differs from its independent observation")
