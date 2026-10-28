# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual task context source composition
"""Join actual original task, inventory, fact and optional remediation source entries."""

from __future__ import annotations

from .condition_evaluation import evaluate_condition_state
from .condition_facts import ConditionFact, ConditionTruth
from .condition_language import ConditionExpression
from .inventory_source_owner import InventorySourceOwner
from .model_primitives import require_identifier
from .policy_read_budget import PolicyReadBudget1
from .remediation_task_binding import RemediationSources
from .source_fact_context import observe_source_fact_context
from .task_context import TASK_CONTEXT_EVENTS, TaskContext1
from .task_registry_source_owners import TaskRegistrySourceOwners


def observe_source_task_context(
    *,
    task_owners: TaskRegistrySourceOwners,
    inventory_owner: InventorySourceOwner,
    actor_id: str,
    root_id: str,
    event: str,
    budget: PolicyReadBudget1,
    remediation_sources: RemediationSources | None = None,
) -> TaskContext1:
    """Bind complete current source identity without authenticating a declared event.

    Parameters
    ----------
    task_owners, inventory_owner : TaskRegistrySourceOwners, InventorySourceOwner
        Actual fixed entries selected by trusted host composition.
    actor_id, root_id : str
        Original declared task member and exact selected root.
    event : str
        Explicit supported event label, requiring separate actual initiating authority.
    budget : PolicyReadBudget1
        Explicit unchanged source/context allocation ceiling.
    remediation_sources : RemediationSources or None
        Optional host-held original remediation sources; none for general work.

    Returns
    -------
    TaskContext1
        Source-verified context data with no claim proof or permission grant.

    Raises
    ------
    ValueError
        If owner types, scope, full domains, declared event or sources disagree.
    RuntimeError, OSError
        If an original source or closing verification refuses.

    Notes
    -----
    This entry cannot authenticate an initiating user, event, audit request or
    claim. Enclosing selected policy still owns claim requirements and admission.
    Nonnull caller claim metadata cannot become verified through this source entry.
    """
    declared = require_identifier(event, "declared task event")
    if declared not in TASK_CONTEXT_EVENTS:
        raise ValueError("unsupported declared task context event")
    if remediation_sources is not None and type(remediation_sources) is not RemediationSources:
        raise ValueError("actual retained remediation source selections are required")
    facts = observe_source_fact_context(
        task_owners=task_owners,
        inventory_owner=inventory_owner,
        actor_id=actor_id,
        root_id=root_id,
        budget=budget,
    )
    task = task_owners.observe(actor_id=actor_id, root_id=root_id, owner_class="task")
    inventory = inventory_owner.observe()
    observations = {row.reference: row for row in facts.observations}
    remediation = (
        None if remediation_sources is None else remediation_sources.observe(budget=budget)
    )
    result = TaskContext1.build(
        task_id=task.proof.source_object.object_id,
        task_definition=task.proof.source_object,
        task_proof=task.proof,
        actor_id=actor_id,
        project_id=inventory.inventory.project_id,
        group_id=require_identifier(observations["task.group"].value, "actual task group"),
        root_id=root_id,
        registry_generation_id=inventory.inventory.registry_generation_id,
        registry_sha256=inventory.inventory.registry_sha256,
        lifecycle=require_identifier(
            observations["task.lifecycle"].value, "actual task lifecycle"
        ),
        event=declared,
        inventory=inventory.inventory,
        facts=facts,
        claim_proof=None,
        remediation=remediation,
        task_identity_digest=task.proof.subject_digest,
        budget=budget,
    )
    task_owners.verify(task, actor_id=actor_id, root_id=root_id, owner_class="task")
    inventory_owner.verify(inventory)
    if remediation_sources is not None:
        remediation_sources.observe(budget=budget)
    return result


def verify_source_task_context(
    value: TaskContext1,
    *,
    task_owners: TaskRegistrySourceOwners,
    inventory_owner: InventorySourceOwner,
    actor_id: str,
    root_id: str,
    event: str,
    budget: PolicyReadBudget1,
    remediation_sources: RemediationSources | None = None,
) -> None:
    """Rebuild complete source data with the exact declared event and actual entries.

    Parameters
    ----------
    value : TaskContext1
        Earlier complete context whose metadata alone supplies no authority.
    task_owners, inventory_owner : TaskRegistrySourceOwners, InventorySourceOwner
        Actual original fixed owner entries.
    actor_id, root_id, event : str
        Exact declared task member, root and event; event occurrence is separate.
    budget : PolicyReadBudget1
        Explicit whole allocation ceiling.
    remediation_sources : RemediationSources or None
        Original optional source entries held through use and closing checks.

    Raises
    ------
    ValueError
        If metadata, original sources, entry selection or declared event differs.
    RuntimeError, OSError
        If actual retained-source verification refuses.
    """
    if type(value) is not TaskContext1:
        raise ValueError("actual complete task context is required")
    checked = TaskContext1.from_dict(value.to_dict(), budget=budget)
    actual = observe_source_task_context(
        task_owners=task_owners,
        inventory_owner=inventory_owner,
        actor_id=actor_id,
        root_id=root_id,
        event=event,
        budget=budget,
        remediation_sources=remediation_sources,
    )
    if checked != actual:
        raise ValueError("task context differs from actual original source selections")


def evaluate_source_task_condition(
    expression: ConditionExpression,
    *,
    context: TaskContext1,
    task_owners: TaskRegistrySourceOwners,
    inventory_owner: InventorySourceOwner,
    actor_id: str,
    root_id: str,
    event: str,
    budget: PolicyReadBudget1,
    remediation_sources: RemediationSources | None = None,
) -> ConditionTruth:
    """Verify the complete task context before and after original tri-state evaluation.

    Parameters
    ----------
    expression : ConditionExpression
        Existing bounded condition syntax with exact finite operand semantics.
    context : TaskContext1
        Complete source-derived task context; no operational admission token.
    task_owners, inventory_owner : TaskRegistrySourceOwners, InventorySourceOwner
        Original actual fixed task/registry and full inventory entries.
    actor_id, root_id, event : str
        Explicit original member, root and declared event.
    budget : PolicyReadBudget1
        Explicit whole source/context ceiling, not an effect budget.
    remediation_sources : RemediationSources or None
        Original optional borrowed remediation source selections.

    Returns
    -------
    ConditionTruth
        Existing TRUE/FALSE/UNKNOWN semantics after full source verification.

    Raises
    ------
    ValueError, RuntimeError, OSError
        If complete sources, current metadata or known operand semantics refuse.
    """
    verify_source_task_context(
        context,
        task_owners=task_owners,
        inventory_owner=inventory_owner,
        actor_id=actor_id,
        root_id=root_id,
        event=event,
        budget=budget,
        remediation_sources=remediation_sources,
    )
    truth = evaluate_condition_state(
        expression,
        {row.reference: ConditionFact(row.state, row.value) for row in context.facts.observations},
    )
    verify_source_task_context(
        context,
        task_owners=task_owners,
        inventory_owner=inventory_owner,
        actor_id=actor_id,
        root_id=root_id,
        event=event,
        budget=budget,
        remediation_sources=remediation_sources,
    )
    return truth
