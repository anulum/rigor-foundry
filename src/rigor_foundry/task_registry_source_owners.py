# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — fixed task and registry source owners
"""Generate and verify actual source observations under one held host selection."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import TracebackType
from uuid import uuid4

from .audit_primitives import canonical_digest
from .context_owner_implementation import OwnerImplementationSnapshot, observe_owner_implementation
from .context_owner_observations import ContextProducerObservation1, OwnerObservation
from .context_owner_proof import OwnerProof1
from .context_producer_contract import ContextProducerContract1, ContextRootBinding
from .context_source_lease import RetainedContextSource
from .policy_read_budget import PolicyReadBudget1
from .project_registry_models import ProjectRegistration, ProjectRegistry
from .task_definition import TaskDefinition1


@dataclass(frozen=True)
class OwnedSourceObservations:
    """Independent source observations and their exact resulting metadata envelope."""

    observation: ContextProducerObservation1
    proof: OwnerProof1


class TaskRegistrySourceOwners:
    """Fixed owning implementations selected by trusted host composition.

    Four actual retained source objects and a prior complete implementation
    observation are required. There is no request-wire constructor, parser
    callback, code-root argument or metadata-driven implementation loader.
    Initiating user/event/claim authority, global revocation custody, complete
    inventory and root3 admission remain the enclosing host's obligations.
    """

    def __init__(
        self,
        *,
        task_source: RetainedContextSource,
        registry_source: RetainedContextSource,
        task_contract: RetainedContextSource,
        registry_contract: RetainedContextSource,
        implementation: OwnerImplementationSnapshot,
        budget: PolicyReadBudget1,
    ) -> None:
        """Pin actual source objects and validate the fixed installed implementation selection."""
        if type(budget) is not PolicyReadBudget1:
            raise ValueError("policy read budget is required")
        self._budget = PolicyReadBudget1.from_dict(budget.to_dict())
        if any(
            type(item) is not RetainedContextSource
            for item in (task_source, registry_source, task_contract, registry_contract)
        ):
            raise ValueError("fixed owners require actual retained source selections")
        if type(implementation) is not OwnerImplementationSnapshot:
            raise ValueError("fixed owners require a complete implementation observation")
        implementation.__post_init__()
        self._implementation = implementation
        self._sources = (task_source, registry_source, task_contract, registry_contract)
        self._selection_id = uuid4().hex
        self._closed = False
        self._read()

    def _read(
        self,
    ) -> tuple[
        TaskDefinition1, ProjectRegistry, ContextProducerContract1, ContextProducerContract1
    ]:
        """Revalidate the same code and original source objects before each observation."""
        if self._closed:
            raise ValueError("source owner selection is closed")
        actual = observe_owner_implementation(
            Path(__file__).absolute().parent, budget=self._budget
        )
        if actual != self._implementation:
            raise ValueError("selected owner implementation or source identity changed")
        task, registry, task_contract, registry_contract = (
            source.read() for source in self._sources
        )
        if (
            type(task) is not TaskDefinition1
            or type(registry) is not ProjectRegistry
            or type(task_contract) is not ContextProducerContract1
            or type(registry_contract) is not ContextProducerContract1
        ):
            raise ValueError("fixed owner source kind differs from its installed role")
        for contract, owner_class, implementation_id in (
            (task_contract, "task", "builtin.task-definition.v1"),
            (registry_contract, "registry", "builtin.project-registry.v1"),
        ):
            if (
                contract.owner_class,
                contract.implementation_id,
                contract.implementation_digest,
            ) != (owner_class, implementation_id, actual.implementation_digest):
                raise ValueError("producer contract differs from the fixed actual implementation")
            registry_ref = self._sources[1].reference
            if (registry_ref.kind, registry_ref.format_version) not in contract.source_formats:
                raise ValueError("producer contract excludes the actual selected registry format")
            for root in contract.root_bindings:
                project = self._project(registry, root.project_id)
                if (
                    root.group_id not in {group.group_id for group in registry.groups}
                    or project.owning_group_id != root.group_id
                    or not PurePosixPath(root.canonical_path).is_relative_to(
                        PurePosixPath(project.canonical_path)
                    )
                ):
                    raise ValueError("producer root differs from the actual registry ownership")
        if (
            task_contract.owner_id == registry_contract.owner_id
            or task_contract.root_bindings != registry_contract.root_bindings
        ):
            raise ValueError(
                "source owners require distinct identities and one consistent root selection"
            )
        project = self._project(registry, task.project_id)
        if project.owning_group_id != task.group_id:
            raise ValueError("task owning group differs from the selected registry")
        bindings = {root.root_id: root for root in task_contract.root_bindings}
        if any(
            root not in bindings
            or (bindings[root].project_id, bindings[root].group_id)
            != (task.project_id, task.group_id)
            for root in task.root_ids
        ):
            raise ValueError("task root is outside its actual selected registry binding")
        return task, registry, task_contract, registry_contract

    @staticmethod
    def _project(registry: ProjectRegistry, identity: str) -> ProjectRegistration:
        """Select exact registered ownership without affiliation or retired-alias fallback."""
        for project in registry.projects:
            if project.project_id == identity:
                return project
        raise ValueError("source project is absent from the selected registry")

    def root_bindings(self) -> tuple[ContextRootBinding, ...]:
        """Read the complete root selection from the original actual owner contracts.

        Returns
        -------
        tuple of ContextRootBinding
            All original task/registry contract roots, without request filtering.

        Raises
        ------
        ValueError, RuntimeError, OSError
            If the original sources, implementation or owner lifetime changed.
        """
        return self._read()[2].root_bindings

    def _snapshot(self, contract: ContextProducerContract1) -> str:
        """Bind the actual owning entry, full source selection and code snapshot."""
        return canonical_digest(
            {
                "selection_id": self._selection_id,
                "owner_id": contract.owner_id,
                "owner_class": contract.owner_class,
                "implementation_snapshot": self._implementation.snapshot_digest,
                "sources": [
                    {"reference": source.reference.to_dict(), "snapshot_id": source.snapshot_id}
                    for source in self._sources
                ],
            }
        )

    def observe(self, *, actor_id: str, root_id: str, owner_class: str) -> OwnedSourceObservations:
        """Generate exact source-owned values after current definition/registry/code checks.

        Actor membership here is source identity, not authentication of a user
        instruction. A task-selected root cannot reduce the enclosing host's
        maintained inventory or configured-language completeness requirements.
        """
        if not isinstance(owner_class, str) or owner_class not in {"task", "registry"}:
            raise ValueError("source owner implementation is unavailable")
        task, registry, task_contract, registry_contract = self._read()
        identity = task.identity_digest(actor_id=actor_id, root_id=root_id, budget=self._budget)
        project = self._project(registry, task.project_id)
        if owner_class == "task":
            contract, source, subject, subject_kind = (
                task_contract,
                self._sources[0],
                identity,
                "task-identity",
            )
            values = {
                "task.id": task.task_id,
                "task.revision": task.revision,
                "task.actor": actor_id,
                "task.project": task.project_id,
                "task.group": task.group_id,
                "task.root": root_id,
                "task.lifecycle": task.lifecycle,
            }
            contract_source = self._sources[2]
        else:
            contract, source, subject, subject_kind = (
                registry_contract,
                self._sources[1],
                registry.registry_sha256,
                "registry-generation",
            )
            values = {
                "project.id": project.project_id,
                "project.group": project.owning_group_id,
                "project.lifecycle": project.lifecycle_state,
                "project.target_kind": project.target_kind,
                "project.visibility": project.visibility,
                "project.memory_state": project.memory_state,
                "registry.generation": registry.generation_id,
                "registry.digest": registry.registry_sha256,
            }
            contract_source = self._sources[3]
        observed = ContextProducerObservation1(
            contract.owner_id,
            contract_source.reference.ref_digest,
            source.reference.ref_digest,
            self._snapshot(contract),
            subject_kind,
            subject,
            tuple(
                OwnerObservation(name, "known", values[name], subject)
                for name in contract.fact_references
            ),
        )
        proof = OwnerProof1.build(
            owner_id=contract.owner_id,
            owner_class=contract.owner_class,
            owner_contract=contract_source.reference,
            subject_digest=subject,
            source_object=source.reference,
            snapshot_id=observed.snapshot_id,
            observation_digest=observed.digest(budget=self._budget),
            budget=self._budget,
        )
        self._read()
        return OwnedSourceObservations(observed, proof)

    def verify(
        self, value: OwnedSourceObservations, *, actor_id: str, root_id: str, owner_class: str
    ) -> None:
        """Recompute the actual owning observations rather than accepting caller metadata."""
        if (
            type(value) is not OwnedSourceObservations
            or type(value.observation) is not ContextProducerObservation1
            or type(value.proof) is not OwnerProof1
        ):
            raise ValueError("actual owned source observations are required")
        value.observation.verify_proof_binding(value.proof, budget=self._budget)
        expected = self.observe(actor_id=actor_id, root_id=root_id, owner_class=owner_class)
        if value != expected:
            raise ValueError("observations differ from the actual selected source owner")

    def close(self) -> None:
        """Revalidate at closure without releasing the host's borrowed source leases."""
        if self._closed:
            return
        try:
            self._read()
        finally:
            self._closed = True

    def __enter__(self) -> TaskRegistrySourceOwners:
        """Validate before using this fixed owning selection."""
        self._read()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Revalidate the same source/code selection at the enclosing closing boundary."""
        self.close()
