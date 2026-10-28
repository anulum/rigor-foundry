# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete source-bound task contexts
"""Keep declared event context separate from verified source identity and operational authority."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from .audit_primitives import canonical_digest, require_exact_fields, require_mapping
from .context_owner_proof import OwnerProof1
from .fact_context import FactContext1
from .maintained_inventory import MaintainedInventory1
from .model_primitives import require_digest, require_identifier
from .policy_read_budget import PolicyReadBudget1
from .remediation_task_binding import RemediationTaskBinding1
from .task_definition import TASK_IDENTITY_SCHEMA_VERSION
from .typed_object_reference import TypedObjectRef1

TASK_CONTEXT_SCHEMA_VERSION = "1.0"
TASK_CONTEXT_EVENTS = frozenset(
    {
        "claim",
        "start",
        "scope-change",
        "dependency-change",
        "mutation",
        "verification",
        "review",
        "commit",
        "publication",
        "process",
        "closure",
        "audit",
    }
)
_IDENTITIES = (
    "task_id",
    "actor_id",
    "project_id",
    "group_id",
    "root_id",
    "registry_generation_id",
    "lifecycle",
)
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        *_IDENTITIES,
        "task_definition",
        "task_proof",
        "registry_sha256",
        "event",
        "inventory",
        "facts",
        "claim_proof",
        "remediation",
        "task_identity_digest",
        "context_digest",
    }
)
_REGISTRY_REFS = frozenset(
    {
        "project.id",
        "project.group",
        "project.lifecycle",
        "project.target_kind",
        "project.visibility",
        "project.memory_state",
        "registry.generation",
        "registry.digest",
    }
)
_INVENTORY_REFS = frozenset(
    {
        "inventory.roots",
        "inventory.languages",
        "inventory.roles",
        "inventory.changed_paths",
        "inventory.repository_state",
    }
)


def _limits(value: PolicyReadBudget1) -> PolicyReadBudget1:
    if type(value) is not PolicyReadBudget1:
        raise ValueError("policy read budget is required")
    return PolicyReadBudget1.from_dict(value.to_dict())


def _model_count(
    inventory: MaintainedInventory1,
    facts: FactContext1,
    claim: OwnerProof1 | None,
    remediation: RemediationTaskBinding1 | None,
) -> int:
    if (
        type(inventory) is not MaintainedInventory1
        or type(facts) is not FactContext1
        or (claim is not None and type(claim) is not OwnerProof1)
        or (remediation is not None and type(remediation) is not RemediationTaskBinding1)
    ):
        raise ValueError("task context requires actual inventory/fact/proof/binding records")
    return (
        7
        + len(inventory.root_ids)
        + 3 * len(inventory.surfaces)
        + 2 * len(facts.producer_proofs)
        + 3 * len(facts.observations)
        + sum(len(row.value) for row in facts.observations if isinstance(row.value, tuple))
        + (2 if claim is not None else 0)
        + (
            0
            if remediation is None
            else sum(
                ref is not None
                for ref in (remediation.task, remediation.record, remediation.closure)
            )
        )
    )


def _check_wire_budget(data: dict[str, object], maximum: int) -> None:
    inventory = require_mapping(data["inventory"], "task inventory")
    facts = require_mapping(data["facts"], "task facts")
    roots, surfaces = inventory.get("root_ids"), inventory.get("surfaces")
    proofs, observations = facts.get("producer_proofs"), facts.get("observations")
    if (
        not isinstance(roots, list)
        or not isinstance(surfaces, list)
        or not isinstance(proofs, list)
        or not isinstance(observations, list)
    ):
        raise ValueError("task context nested collections must be arrays")
    count = 7 + len(roots) + 3 * len(surfaces) + 2 * len(proofs) + 3 * len(observations)
    if data["claim_proof"] is not None:
        count += 2
    if data["remediation"] is not None:
        binding = require_mapping(data["remediation"], "task remediation")
        count += sum(binding.get(name) is not None for name in ("task", "record", "closure"))
    if count > maximum:
        raise ValueError("task context exceeds the aggregate reference budget")
    for row in observations:
        value = require_mapping(row, "task fact observation").get("value")
        if isinstance(value, (list, tuple)):
            count += len(value)
            if count > maximum:
                raise ValueError("task fact values exceed the aggregate reference budget")


@dataclass(frozen=True)
class TaskContext1:
    """Closed source-bound task data, without authenticating a declared event or claim.

    Parameters
    ----------
    task_id, task_definition, task_proof : str, TypedObjectRef1, OwnerProof1
        Original general task and independently observed identity proof.
    actor_id, project_id, group_id, root_id : str
        Declared task member and exact current registered source scope.
    registry_generation_id, registry_sha256 : str
        Original selected registry generation and owning digest.
    lifecycle, event : str
        Original task lifecycle and explicit declared event; no occurrence proof.
    inventory, facts : MaintainedInventory1, FactContext1
        Complete independent source observations and their provenance.
    claim_proof : OwnerProof1 or None
        Optional claim metadata, requiring actual enclosing claim-owner verification.
    remediation : RemediationTaskBinding1 or None
        Optional original remediation references; general work needs none.
    task_identity_digest, context_digest : str
        Independent identity-only hash and complete enclosing context hash.
    """

    task_id: str
    task_definition: TypedObjectRef1
    task_proof: OwnerProof1
    actor_id: str
    project_id: str
    group_id: str
    root_id: str
    registry_generation_id: str
    registry_sha256: str
    lifecycle: str
    event: str
    inventory: MaintainedInventory1
    facts: FactContext1
    claim_proof: OwnerProof1 | None
    remediation: RemediationTaskBinding1 | None
    task_identity_digest: str
    context_digest: str
    schema_version: ClassVar[str] = TASK_CONTEXT_SCHEMA_VERSION
    object_kind: ClassVar[str] = "task-context"

    def __post_init__(self) -> None:
        """Validate the complete immutable model and independent identity relationships."""
        self.to_dict()

    def _body(self) -> dict[str, object]:
        if _model_count(self.inventory, self.facts, self.claim_proof, self.remediation) > 65536:
            raise ValueError("task context exceeds the hard aggregate reference budget")
        if (
            type(self.task_definition) is not TypedObjectRef1
            or type(self.task_proof) is not OwnerProof1
        ):
            raise ValueError("actual task definition reference and proof are required")
        identifiers = {name: require_identifier(getattr(self, name), name) for name in _IDENTITIES}
        event = require_identifier(self.event, "task event")
        if event not in TASK_CONTEXT_EVENTS:
            raise ValueError("unsupported task context event")
        reference, proof = self.task_definition, self.task_proof
        if (
            (reference.kind, reference.format_version, reference.object_id)
            != ("task-definition", "1.0", self.task_id)
            or proof.owner_class != "task"
            or proof.source_object != reference
        ):
            raise ValueError("task proof differs from the original definition source")
        identity = canonical_digest(
            {
                "schema_version": TASK_IDENTITY_SCHEMA_VERSION,
                "object_kind": "task-identity",
                "task_id": self.task_id,
                "task_definition": reference.to_dict(),
                "actor_id": self.actor_id,
                "project_id": self.project_id,
                "group_id": self.group_id,
                "root_id": self.root_id,
            }
        )
        registry = require_digest(self.registry_sha256, "task registry digest")
        if (
            require_digest(self.task_identity_digest, "task identity digest") != identity
            or proof.subject_digest != identity
            or self.facts.task_identity_digest != identity
            or self.root_id not in self.inventory.root_ids
            or self.inventory.project_id != self.project_id
            or self.facts.inventory_digest != self.inventory.inventory_digest
            or (self.inventory.registry_generation_id, self.facts.registry_generation_id)
            != (self.registry_generation_id, self.registry_generation_id)
            or (self.inventory.registry_sha256, self.facts.registry_sha256) != (registry, registry)
        ):
            raise ValueError("task context independent source identities disagree")
        selected = {row.proof_digest: row for row in self.facts.producer_proofs}
        if (
            selected.get(proof.proof_digest) != proof
            or selected.get(self.inventory.change_inventory_proof.proof_digest)
            != self.inventory.change_inventory_proof
        ):
            raise ValueError("task/inventory proofs are outside the complete source fact context")
        observations = {row.reference: row for row in self.facts.observations}
        task_values = {
            "task.id": self.task_id,
            "task.actor": self.actor_id,
            "task.project": self.project_id,
            "task.group": self.group_id,
            "task.root": self.root_id,
            "task.lifecycle": self.lifecycle,
        }
        for name in (*task_values, "task.revision"):
            row = observations.get(name)
            if (
                row is None
                or row.state != "known"
                or row.provenance != proof
                or not isinstance(row.value, str)
                or (name in task_values and row.value != task_values[name])
            ):
                raise ValueError("task context omits or contradicts original task facts")
        registry_values = {
            "project.id": self.project_id,
            "project.group": self.group_id,
            "registry.generation": self.registry_generation_id,
            "registry.digest": registry,
        }
        registry_proofs: set[str] = set()
        registry_owners: set[str] = set()
        for name in sorted(_REGISTRY_REFS):
            row = observations.get(name)
            if (
                row is None
                or row.state != "known"
                or row.provenance is None
                or row.provenance.owner_class != "registry"
                or row.subject_digest != registry
                or row.provenance.source_object.kind != "project-registry"
                or (
                    row.provenance.source_object.object_id,
                    row.provenance.source_object.object_digest,
                )
                != (self.registry_generation_id, registry)
                or not isinstance(row.value, str)
                or (name in registry_values and row.value != registry_values[name])
            ):
                raise ValueError("task context omits or contradicts original registry facts")
            registry_proofs.add(row.provenance.proof_digest)
            registry_owners.add(row.provenance.owner_id)
        if (
            len(registry_proofs) != 1
            or len(
                {
                    proof.owner_id,
                    self.inventory.change_inventory_proof.owner_id,
                    *registry_owners,
                }
            )
            != 3
        ):
            raise ValueError("task context must use one registry proof and distinct source owners")
        for name in sorted(_INVENTORY_REFS):
            row = observations.get(name)
            if (
                row is None
                or row.state != "known"
                or row.provenance != self.inventory.change_inventory_proof
            ):
                raise ValueError("task context omits original complete inventory facts")
        if (
            observations["inventory.roots"].value != self.inventory.root_ids
            or observations["inventory.repository_state"].value
            != self.inventory.repository_state_digest
        ):
            raise ValueError("task inventory facts differ from the independent complete inventory")
        if self.claim_proof is not None and self.claim_proof.owner_class != "claim":
            raise ValueError("task claim metadata has the wrong owner class")
        if self.remediation is not None and self.remediation.task.object_id != self.task_id:
            raise ValueError("remediation binding differs from the original general task identity")
        return {
            "schema_version": TASK_CONTEXT_SCHEMA_VERSION,
            "object_kind": "task-context",
            **identifiers,
            "task_definition": reference.to_dict(),
            "task_proof": proof.to_dict(),
            "registry_sha256": registry,
            "event": event,
            "inventory": self.inventory.to_dict(),
            "facts": self.facts.to_dict(),
            "claim_proof": None if self.claim_proof is None else self.claim_proof.to_dict(),
            "remediation": None if self.remediation is None else self.remediation.to_dict(),
            "task_identity_digest": identity,
        }

    @classmethod
    def build(
        cls,
        *,
        task_id: str,
        task_definition: TypedObjectRef1,
        task_proof: OwnerProof1,
        actor_id: str,
        project_id: str,
        group_id: str,
        root_id: str,
        registry_generation_id: str,
        registry_sha256: str,
        lifecycle: str,
        event: str,
        inventory: MaintainedInventory1,
        facts: FactContext1,
        claim_proof: OwnerProof1 | None,
        remediation: RemediationTaskBinding1 | None,
        task_identity_digest: str,
        budget: PolicyReadBudget1,
    ) -> TaskContext1:
        """Build complete source data under the explicit whole nested-reference budget.

        Parameters
        ----------
        task_id, actor_id, project_id, group_id, root_id : str
            Exact original task member and source scope.
        task_definition, task_proof : TypedObjectRef1, OwnerProof1
            Original task source and its independent identity proof.
        registry_generation_id, registry_sha256, lifecycle, event : str
            Current registry/task fields and declared event.
        inventory, facts : MaintainedInventory1, FactContext1
            Complete independent observations to join.
        claim_proof, remediation : OwnerProof1 or None, RemediationTaskBinding1 or None
            Optional integrity-only metadata requiring actual owning verification.
        task_identity_digest : str
            Independently derived original task identity.
        budget : PolicyReadBudget1
            Explicit aggregate nested-reference allocation ceiling.

        Returns
        -------
        TaskContext1
            Closed source-bound data, without permission or event authentication.

        Raises
        ------
        ValueError
            If budgets, complete source relations or exact fields disagree.
        """
        limits = _limits(budget)
        if _model_count(inventory, facts, claim_proof, remediation) > limits.max_references:
            raise ValueError("task context exceeds the aggregate reference budget")
        if type(task_definition) is not TypedObjectRef1 or type(task_proof) is not OwnerProof1:
            raise ValueError("actual task definition reference and proof are required")
        body = {
            "schema_version": TASK_CONTEXT_SCHEMA_VERSION,
            "object_kind": "task-context",
            "task_id": task_id,
            "task_definition": task_definition.to_dict(),
            "task_proof": task_proof.to_dict(),
            "actor_id": actor_id,
            "project_id": project_id,
            "group_id": group_id,
            "root_id": root_id,
            "registry_generation_id": registry_generation_id,
            "registry_sha256": registry_sha256,
            "lifecycle": lifecycle,
            "event": event,
            "inventory": inventory.to_dict(),
            "facts": facts.to_dict(),
            "claim_proof": None if claim_proof is None else claim_proof.to_dict(),
            "remediation": None if remediation is None else remediation.to_dict(),
            "task_identity_digest": task_identity_digest,
        }
        return cls.from_dict({**body, "context_digest": canonical_digest(body)}, budget=limits)

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> TaskContext1:
        """Bound every nested collection before parsing any source/proof child.

        Parameters
        ----------
        value : object
            Complete decoded source-context record.
        budget : PolicyReadBudget1
            Explicit aggregate nested-reference allocation ceiling.

        Returns
        -------
        TaskContext1
            Original integrity-checked data; an actual owner must still verify it.

        Raises
        ------
        ValueError
            If fields, version, allocation or independent source relationships fail.
        """
        limits = _limits(budget)
        data = require_mapping(value, "task context")
        require_exact_fields(data, _FIELDS, "task context")
        if data["schema_version"] != "1.0" or data["object_kind"] != "task-context":
            raise ValueError("unsupported task context")
        _check_wire_budget(data, limits.max_references)
        return cls(
            task_id=require_identifier(data["task_id"], "task identity"),
            task_definition=TypedObjectRef1.from_dict(data["task_definition"]),
            task_proof=OwnerProof1.from_dict(data["task_proof"], budget=limits),
            actor_id=require_identifier(data["actor_id"], "task actor"),
            project_id=require_identifier(data["project_id"], "task project"),
            group_id=require_identifier(data["group_id"], "task group"),
            root_id=require_identifier(data["root_id"], "task root"),
            registry_generation_id=require_identifier(
                data["registry_generation_id"], "task registry"
            ),
            registry_sha256=require_digest(data["registry_sha256"], "task registry digest"),
            lifecycle=require_identifier(data["lifecycle"], "task lifecycle"),
            event=require_identifier(data["event"], "task event"),
            inventory=MaintainedInventory1.from_dict(data["inventory"], budget=limits),
            facts=FactContext1.from_dict(data["facts"], budget=limits),
            claim_proof=None
            if data["claim_proof"] is None
            else OwnerProof1.from_dict(data["claim_proof"], budget=limits),
            remediation=None
            if data["remediation"] is None
            else RemediationTaskBinding1.from_dict(data["remediation"], budget=limits),
            task_identity_digest=require_digest(
                data["task_identity_digest"], "task identity digest"
            ),
            context_digest=require_digest(data["context_digest"], "task context digest"),
        )

    def to_dict(self) -> dict[str, object]:
        """Revalidate and serialize complete source bindings without granting authority.

        Returns
        -------
        dict of str to object
            Every closed original field and the verified enclosing digest.

        Raises
        ------
        ValueError
            If direct or later mutation breaks source relationships or hard limits.
        """
        body = self._body()
        digest = require_digest(self.context_digest, "task context digest")
        if digest != canonical_digest(body):
            raise ValueError("task context digest differs")
        return {**body, "context_digest": digest}
