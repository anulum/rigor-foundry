# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — source-derived verified fact context
"""Join only actual fixed source owners before evaluating existing tri-state conditions."""

from __future__ import annotations

from .condition_evaluation import evaluate_condition_state
from .condition_facts import ConditionFact, ConditionTruth
from .condition_language import ConditionExpression, ConditionValue
from .context_producer_contract import ContextRootBinding
from .fact_context import FactContext1, FactObservation1
from .inventory_source_owner import InventorySourceOwner
from .model_primitives import require_digest, require_identifier
from .policy_read_budget import PolicyReadBudget1
from .task_registry_source_owners import OwnedSourceObservations, TaskRegistrySourceOwners

_TASK_REFERENCES = frozenset(
    {
        "task.id",
        "task.revision",
        "task.actor",
        "task.project",
        "task.group",
        "task.root",
        "task.lifecycle",
    }
)
_REGISTRY_REFERENCES = frozenset(
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
_INVENTORY_REFERENCES = frozenset(
    {
        "inventory.roots",
        "inventory.languages",
        "inventory.roles",
        "inventory.changed_paths",
        "inventory.repository_state",
    }
)


def _facts(
    source: OwnedSourceObservations,
    *,
    references: frozenset[str],
    budget: PolicyReadBudget1,
) -> dict[str, ConditionValue]:
    source.observation.verify_proof_binding(source.proof, budget=budget)
    values = {item.reference: item.value for item in source.observation.observations}
    if set(values) != references:
        raise ValueError("source owner omits the complete required fact domain")
    return values


def observe_source_fact_context(
    *,
    task_owners: TaskRegistrySourceOwners,
    inventory_owner: InventorySourceOwner,
    actor_id: str,
    root_id: str,
    budget: PolicyReadBudget1,
) -> FactContext1:
    """Derive current task/registry/inventory facts and verify their actual owners.

    Parameters
    ----------
    task_owners : TaskRegistrySourceOwners
        Actual fixed task/registry entry chosen by trusted host composition.
    inventory_owner : InventorySourceOwner
        Actual complete inventory entry with independently retained state/history.
    actor_id, root_id : str
        Declared task member and selected root, verified by the original task owner.
    budget : PolicyReadBudget1
        Explicit context allocation ceiling; no source-access or effect permission.

    Returns
    -------
    FactContext1
        Complete original source facts bound to actual task/registry/inventory
        identities. Missing other exact references remain unobserved, not absent.

    Raises
    ------
    ValueError
        If actual owner types, full domains, source identities or closing checks fail.
    RuntimeError, OSError
        If an original source owner cannot complete its safe observation.

    Notes
    -----
    This authenticates selected source observations through fixed actual entries.
    It does not authenticate an initiating user/event/claim or admit a root3/native
    operation, generated lineage, atomic snapshot or host-required-root authority.
    """
    if (
        type(task_owners) is not TaskRegistrySourceOwners
        or type(inventory_owner) is not InventorySourceOwner
    ):
        raise ValueError("fact context requires actual fixed source owner entries")
    if type(budget) is not PolicyReadBudget1:
        raise ValueError("policy read budget is required")
    limits = PolicyReadBudget1.from_dict(budget.to_dict())
    task = task_owners.observe(actor_id=actor_id, root_id=root_id, owner_class="task")
    registry = task_owners.observe(actor_id=actor_id, root_id=root_id, owner_class="registry")
    inventory = inventory_owner.observe()
    task_values = _facts(task, references=_TASK_REFERENCES, budget=limits)
    registry_values = _facts(registry, references=_REGISTRY_REFERENCES, budget=limits)
    _facts(inventory.change, references=_INVENTORY_REFERENCES, budget=limits)
    selected = inventory.inventory
    expected_roots = tuple(
        ContextRootBinding(
            item.root.root_id,
            selected.project_id,
            require_identifier(task_values["task.group"], "actual task group"),
            item.root.canonical_path,
            inventory.capture.state.configured_roots_digest,
        )
        for item in inventory.capture.inputs.roots
    )
    if (
        root_id not in selected.root_ids
        or task_owners.root_bindings() != expected_roots
        or task_values["task.project"] != selected.project_id
        or registry_values["registry.generation"] != selected.registry_generation_id
        or registry_values["registry.digest"] != selected.registry_sha256
        or len({task.proof.owner_id, registry.proof.owner_id, inventory.change.proof.owner_id})
        != 3
    ):
        raise ValueError("actual task, registry and complete inventory owner selections disagree")
    sources = (task, registry, inventory.change)
    observations = tuple(
        sorted(
            (
                FactObservation1.build(
                    reference=item.reference,
                    state=item.state,
                    value=item.value,
                    subject_digest=item.subject_digest,
                    provenance=source.proof,
                    budget=limits,
                )
                for source in sources
                for item in source.observation.observations
            ),
            key=lambda item: item.reference,
        )
    )
    context = FactContext1.build(
        task_identity_digest=task.proof.subject_digest,
        registry_generation_id=require_identifier(
            registry_values["registry.generation"], "actual registry generation"
        ),
        registry_sha256=require_digest(
            registry_values["registry.digest"], "actual registry digest"
        ),
        inventory_digest=selected.inventory_digest,
        producer_proofs=tuple(
            sorted((source.proof for source in sources), key=lambda item: item.proof_digest)
        ),
        observations=observations,
        budget=limits,
    )
    task_owners.verify(task, actor_id=actor_id, root_id=root_id, owner_class="task")
    task_owners.verify(registry, actor_id=actor_id, root_id=root_id, owner_class="registry")
    inventory_owner.verify(inventory)
    return context


def verify_source_fact_context(
    value: FactContext1,
    *,
    task_owners: TaskRegistrySourceOwners,
    inventory_owner: InventorySourceOwner,
    actor_id: str,
    root_id: str,
    budget: PolicyReadBudget1,
) -> None:
    """Compare complete supplied data with newly derived actual source-owner facts.

    Parameters
    ----------
    value : FactContext1
        Earlier complete context from this exact actual owner selection.
    task_owners, inventory_owner : object
        Original fixed actual task/registry and complete inventory entries.
    actor_id, root_id : str
        Exact original task member and root identities.
    budget : PolicyReadBudget1
        Explicit unchanged context allocation ceiling.

    Raises
    ------
    ValueError
        If metadata, current sources, owner selection or source identities differ.
    RuntimeError, OSError
        If an original safe source observation refuses.
    """
    if type(value) is not FactContext1:
        raise ValueError("actual fact context record is required")
    checked = FactContext1.from_dict(value.to_dict(), budget=budget)
    actual = observe_source_fact_context(
        task_owners=task_owners,
        inventory_owner=inventory_owner,
        actor_id=actor_id,
        root_id=root_id,
        budget=budget,
    )
    if checked != actual:
        raise ValueError("fact context differs from the actual selected source owners")


def evaluate_source_fact_condition(
    expression: ConditionExpression,
    *,
    context: FactContext1,
    task_owners: TaskRegistrySourceOwners,
    inventory_owner: InventorySourceOwner,
    actor_id: str,
    root_id: str,
    budget: PolicyReadBudget1,
) -> ConditionTruth:
    """Verify whole source completeness before and after real tri-state evaluation.

    Parameters
    ----------
    expression : ConditionExpression
        Existing exact version1.1 condition syntax, without Boolean coercion.
    context : FactContext1
        Complete prior current-source context to verify through actual owners.
    task_owners, inventory_owner : object
        Original actual fixed source entries, not request-selected callbacks.
    actor_id, root_id : str
        Exact original task member and root identities.
    budget : PolicyReadBudget1
        Explicit source-context allocation ceiling, never an operational grant.

    Returns
    -------
    ConditionTruth
        True, false or unknown using existing finite operand and complete-child
        semantics. No decisive sibling excuses missing maintained scope.

    Raises
    ------
    ValueError
        If source authentication, completeness or a known operand domain fails.
    RuntimeError, OSError
        If original safe source verification refuses.
    """
    verify_source_fact_context(
        context,
        task_owners=task_owners,
        inventory_owner=inventory_owner,
        actor_id=actor_id,
        root_id=root_id,
        budget=budget,
    )
    truth = evaluate_condition_state(
        expression,
        {item.reference: ConditionFact(item.state, item.value) for item in context.observations},
    )
    verify_source_fact_context(
        context,
        task_owners=task_owners,
        inventory_owner=inventory_owner,
        actor_id=actor_id,
        root_id=root_id,
        budget=budget,
    )
    return truth
