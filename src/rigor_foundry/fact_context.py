# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — provenance-bound fact context data
"""Bind explicit fact states without turning a parsed owner envelope into authority."""

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

FACT_OBSERVATION_SCHEMA_VERSION = "1.0"
FACT_CONTEXT_SCHEMA_VERSION = "1.0"
_OBSERVATION_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "reference",
        "state",
        "value",
        "subject_digest",
        "provenance",
        "observation_digest",
    }
)
_CONTEXT_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "task_identity_digest",
        "registry_generation_id",
        "registry_sha256",
        "inventory_digest",
        "producer_proofs",
        "observations",
        "context_digest",
    }
)


def _limits(budget: PolicyReadBudget1) -> PolicyReadBudget1:
    if type(budget) is not PolicyReadBudget1:
        raise ValueError("policy read budget is required")
    return PolicyReadBudget1.from_dict(budget.to_dict())


@dataclass(frozen=True, eq=False)
class FactObservation1:
    """Explicit known/absent/unknown value with independently defined provenance.

    Parameters
    ----------
    reference : str
        Exact bounded dotted reference, without descendant absence inference.
    state, value : str, scalar or tuple or None
        Existing finite ConditionFact semantics, including known null/empty tuple.
    subject_digest : str
        Independent input subject shared with the selected producer proof.
    provenance : OwnerProof1 or None
        Required for known/absent, forbidden for unknown; still unauthenticated data.
    observation_digest : str
        Canonical identity of all other closed fields.
    """

    reference: str
    state: ObservationState
    value: ConditionValue
    subject_digest: str
    provenance: OwnerProof1 | None
    observation_digest: str

    schema_version: ClassVar[str] = FACT_OBSERVATION_SCHEMA_VERSION
    object_kind: ClassVar[str] = "fact-observation"

    def __post_init__(self) -> None:
        """Validate state/provenance relations and the complete direct-instance digest."""
        self.to_dict()

    def __eq__(self, other: object) -> bool:
        """Compare canonical scalar identities without Boolean/integer aliasing."""
        return isinstance(other, FactObservation1) and self.to_dict() == other.to_dict()

    def __hash__(self) -> int:
        """Hash the type-preserving canonical record used by the wire identity."""
        return hash(canonical_digest(self.to_dict()))

    def _body(self) -> dict[str, object]:
        if isinstance(self.value, tuple) and len(self.value) + 3 > 65536:
            raise ValueError("fact values exceed the hard reference budget")
        reference = require_string(self.reference, "fact observation reference")
        ConditionExpression.build("exists", reference=reference)
        fact = ConditionFact(self.state, self.value)
        subject = require_digest(self.subject_digest, "fact observation subject")
        if fact.state == "unknown":
            if self.provenance is not None:
                raise ValueError("unknown facts cannot claim producer provenance")
        elif type(self.provenance) is not OwnerProof1 or self.provenance.subject_digest != subject:
            raise ValueError("known/absent facts require an independently bound producer proof")
        return {
            "schema_version": FACT_OBSERVATION_SCHEMA_VERSION,
            "object_kind": "fact-observation",
            "reference": reference,
            **fact.to_dict(),
            "subject_digest": subject,
            "provenance": None if self.provenance is None else self.provenance.to_dict(),
        }

    @classmethod
    def build(
        cls,
        *,
        reference: str,
        state: ObservationState,
        value: ConditionValue,
        subject_digest: str,
        provenance: OwnerProof1 | None,
        budget: PolicyReadBudget1,
    ) -> FactObservation1:
        """Bind exact fact states through the bounded closed parser.

        Parameters
        ----------
        reference, state, value, subject_digest, provenance : object
            Original declared fact fields, with no source authentication inferred.
        budget : PolicyReadBudget1
            Explicit value/reference allocation limits.

        Returns
        -------
        FactObservation1
            Integrity-checked original state, subject and proof metadata.

        Raises
        ------
        ValueError
            If state, finite values, proof relation or budgets are invalid.
        """
        limits = _limits(budget)
        if isinstance(value, tuple) and len(value) + 3 > limits.max_references:
            raise ValueError("fact values exceed the reference budget")
        if provenance is not None and type(provenance) is not OwnerProof1:
            raise ValueError("fact provenance requires an actual owner proof")
        fact = ConditionFact(state, value)
        body = {
            "schema_version": FACT_OBSERVATION_SCHEMA_VERSION,
            "object_kind": "fact-observation",
            "reference": reference,
            **fact.to_dict(),
            "subject_digest": subject_digest,
            "provenance": None if provenance is None else provenance.to_dict(),
        }
        return cls.from_dict({**body, "observation_digest": canonical_digest(body)}, budget=limits)

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> FactObservation1:
        """Parse a closed observed state without choosing an owner implementation.

        Parameters
        ----------
        value : object
            Complete decoded fact mapping.
        budget : PolicyReadBudget1
            Explicit finite-array and nested-proof reference ceiling.

        Returns
        -------
        FactObservation1
            Checked original fact; installed source verification remains required.

        Raises
        ------
        ValueError
            If version, finite values, allocation or provenance relations fail.
        """
        limits = _limits(budget)
        data = require_mapping(value, "fact observation")
        require_exact_fields(data, _OBSERVATION_FIELDS, "fact observation")
        if (
            data["schema_version"] != FACT_OBSERVATION_SCHEMA_VERSION
            or data["object_kind"] != "fact-observation"
        ):
            raise ValueError("unsupported fact observation")
        if (
            isinstance(data["value"], (list, tuple))
            and len(data["value"]) + 3 > limits.max_references
        ):
            raise ValueError("fact values exceed the reference budget")
        fact = ConditionFact.from_dict({"state": data["state"], "value": data["value"]})
        return cls(
            require_string(data["reference"], "fact observation reference"),
            fact.state,
            fact.value,
            require_digest(data["subject_digest"], "fact observation subject"),
            None
            if data["provenance"] is None
            else OwnerProof1.from_dict(data["provenance"], budget=limits),
            require_digest(data["observation_digest"], "fact observation digest"),
        )

    def to_dict(self) -> dict[str, object]:
        """Revalidate state/subject/proof data and the complete observation identity.

        Returns
        -------
        dict of str to object
            All original fields with immutable arrays rendered as JSON arrays.

        Raises
        ------
        ValueError
            If direct or later field mutation breaks state/integrity semantics.
        """
        body = self._body()
        digest = require_digest(self.observation_digest, "fact observation digest")
        if digest != canonical_digest(body):
            raise ValueError("fact observation digest differs")
        return {**body, "observation_digest": digest}


@dataclass(frozen=True)
class FactContext1:
    """Closed complete producer/fact mapping bound to task/registry/inventory inputs.

    Parameters
    ----------
    task_identity_digest, registry_generation_id, registry_sha256, inventory_digest : str
        Independent current source identities, preceding this enclosing context.
    producer_proofs : tuple of OwnerProof1
        Sorted unique source-owner envelopes, requiring installed verification.
    observations : tuple of FactObservation1
        Sorted unique exact references, preserving unknown rather than absence.
    context_digest : str
        Canonical identity of every other complete field.
    """

    task_identity_digest: str
    registry_generation_id: str
    registry_sha256: str
    inventory_digest: str
    producer_proofs: tuple[OwnerProof1, ...]
    observations: tuple[FactObservation1, ...]
    context_digest: str

    schema_version: ClassVar[str] = FACT_CONTEXT_SCHEMA_VERSION
    object_kind: ClassVar[str] = "fact-context"

    def __post_init__(self) -> None:
        """Reject contradictory references, unbound observations and complete digest drift."""
        self.to_dict()

    def _body(self) -> dict[str, object]:
        if (
            type(self.producer_proofs) is not tuple
            or type(self.observations) is not tuple
            or len(self.producer_proofs) * 2 + len(self.observations) * 3 > 65536
            or any(type(item) is not OwnerProof1 for item in self.producer_proofs)
            or any(type(item) is not FactObservation1 for item in self.observations)
        ):
            raise ValueError("fact context requires bounded actual immutable proof/fact records")
        if (
            2 * len(self.producer_proofs)
            + 3 * len(self.observations)
            + sum(len(item.value) for item in self.observations if isinstance(item.value, tuple))
            > 65536
        ):
            raise ValueError("fact values exceed the hard aggregate context reference budget")
        digests = tuple(item.proof_digest for item in self.producer_proofs)
        refs = tuple(item.reference for item in self.observations)
        if digests != tuple(sorted(set(digests))) or refs != tuple(sorted(set(refs))):
            raise ValueError("context proofs and fact references must be sorted and unique")
        proofs = {item.proof_digest: item for item in self.producer_proofs}
        observed = {item.reference: item for item in self.observations}
        for item in self.observations:
            if (
                item.provenance is not None
                and proofs.get(item.provenance.proof_digest) != item.provenance
            ):
                raise ValueError("fact provenance is outside the selected producer proof set")
            if item.state == "known":
                segments = item.reference.split(".")
                for index in range(1, len(segments)):
                    parent = observed.get(".".join(segments[:index]))
                    if parent is not None and parent.state != "unknown":
                        raise ValueError("fact references contradict an observed parent")
        return {
            "schema_version": FACT_CONTEXT_SCHEMA_VERSION,
            "object_kind": "fact-context",
            "task_identity_digest": require_digest(
                self.task_identity_digest, "fact task identity"
            ),
            "registry_generation_id": require_identifier(
                self.registry_generation_id, "fact registry generation"
            ),
            "registry_sha256": require_digest(self.registry_sha256, "fact registry digest"),
            "inventory_digest": require_digest(self.inventory_digest, "fact inventory digest"),
            "producer_proofs": [item.to_dict() for item in self.producer_proofs],
            "observations": [item.to_dict() for item in self.observations],
        }

    @classmethod
    def build(
        cls,
        *,
        task_identity_digest: str,
        registry_generation_id: str,
        registry_sha256: str,
        inventory_digest: str,
        producer_proofs: tuple[OwnerProof1, ...],
        observations: tuple[FactObservation1, ...],
        budget: PolicyReadBudget1,
    ) -> FactContext1:
        """Bind complete source/fact records through the same bounded context parser.

        Parameters
        ----------
        task_identity_digest, registry_generation_id, registry_sha256, inventory_digest : str
            Independently derived original source identities.
        producer_proofs, observations : tuple
            Immutable complete sorted proof and fact records.
        budget : PolicyReadBudget1
            Explicit aggregate reference/value allocation ceiling.

        Returns
        -------
        FactContext1
            Closed integrity-checked metadata, without producer authentication.

        Raises
        ------
        ValueError
            If records, proof membership, field relations or budgets disagree.
        """
        limits = _limits(budget)
        if (
            type(producer_proofs) is not tuple
            or type(observations) is not tuple
            or any(type(item) is not OwnerProof1 for item in producer_proofs)
            or any(type(item) is not FactObservation1 for item in observations)
            or 2 * len(producer_proofs) + 3 * len(observations) > limits.max_references
        ):
            raise ValueError("fact context exceeds its actual record/reference budget")
        if (
            2 * len(producer_proofs)
            + 3 * len(observations)
            + sum(len(item.value) for item in observations if isinstance(item.value, tuple))
            > limits.max_references
        ):
            raise ValueError("fact values exceed the aggregate context reference budget")
        body = {
            "schema_version": FACT_CONTEXT_SCHEMA_VERSION,
            "object_kind": "fact-context",
            "task_identity_digest": task_identity_digest,
            "registry_generation_id": registry_generation_id,
            "registry_sha256": registry_sha256,
            "inventory_digest": inventory_digest,
            "producer_proofs": [item.to_dict() for item in producer_proofs],
            "observations": [item.to_dict() for item in observations],
        }
        return cls.from_dict({**body, "context_digest": canonical_digest(body)}, budget=limits)

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> FactContext1:
        """Bound complete arrays before parsing any nested proof or fact allocation.

        Parameters
        ----------
        value : object
            Exact complete decoded context mapping.
        budget : PolicyReadBudget1
            Aggregate nested-reference and scalar-array allocation ceiling.

        Returns
        -------
        FactContext1
            Original checked data; actual owner verification remains separate.

        Raises
        ------
        ValueError
            If shape, version, budgets, relationships or complete integrity fail.
        """
        limits = _limits(budget)
        data = require_mapping(value, "fact context")
        require_exact_fields(data, _CONTEXT_FIELDS, "fact context")
        if (
            data["schema_version"] != FACT_CONTEXT_SCHEMA_VERSION
            or data["object_kind"] != "fact-context"
        ):
            raise ValueError("unsupported fact context")
        proofs, observations = data["producer_proofs"], data["observations"]
        if (
            not isinstance(proofs, list)
            or not isinstance(observations, list)
            or 2 * len(proofs) + 3 * len(observations) > limits.max_references
        ):
            raise ValueError("fact context exceeds its actual record/reference budget")
        total = 2 * len(proofs) + 3 * len(observations)
        for item in observations:
            row = require_mapping(item, "fact observation")
            raw = row.get("value")
            if isinstance(raw, (list, tuple)):
                total += len(raw)
                if total > limits.max_references:
                    raise ValueError("fact values exceed the aggregate context reference budget")
        return cls(
            require_digest(data["task_identity_digest"], "fact task identity"),
            require_identifier(data["registry_generation_id"], "fact registry generation"),
            require_digest(data["registry_sha256"], "fact registry digest"),
            require_digest(data["inventory_digest"], "fact inventory digest"),
            tuple(OwnerProof1.from_dict(item, budget=limits) for item in proofs),
            tuple(FactObservation1.from_dict(item, budget=limits) for item in observations),
            require_digest(data["context_digest"], "fact context digest"),
        )

    def to_dict(self) -> dict[str, object]:
        """Validate original proof/fact relations and the complete context identity.

        Returns
        -------
        dict of str to object
            Every original field, with no manufactured absence or authority.

        Raises
        ------
        ValueError
            If direct or later mutation contradicts the closed context contract.
        """
        body = self._body()
        digest = require_digest(self.context_digest, "fact context digest")
        if digest != canonical_digest(body):
            raise ValueError("fact context digest differs")
        return {**body, "context_digest": digest}
