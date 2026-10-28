# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual fixed source fact context tests
"""Compose real retained task/registry/inventory entries before evaluating conditions."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
from test_fact_context import context as declared_context
from test_inventory_source_owner import owner_selection

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.condition_facts import ConditionTruth
from rigor_foundry.condition_language import ConditionExpression, ConditionValue
from rigor_foundry.fact_context import FactContext1
from rigor_foundry.inventory_source_owner import InventorySourceOwner
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.source_fact_context import (
    evaluate_source_fact_condition,
    observe_source_fact_context,
    verify_source_fact_context,
)
from rigor_foundry.task_registry_source_owners import TaskRegistrySourceOwners


def test_actual_source_context_and_three_valued_evaluation_keep_independent_subjects(
    tmp_path: Path,
) -> None:
    """Real owner verification precedes actual true/false/unknown condition evaluation."""
    with owner_selection(tmp_path / "case") as chosen:
        context = observe_source_fact_context(
            task_owners=chosen.tasks,
            inventory_owner=chosen.owner,
            actor_id="actor",
            root_id="core",
            budget=chosen.budget,
        )
        assert len(context.observations) == 20
        assert len(context.producer_proofs) == 3
        assert FactContext1.from_dict(context.to_dict(), budget=chosen.budget) == context
        cases: tuple[tuple[str, ConditionValue, ConditionTruth], ...] = (
            ("project.id", "PROJECT-A", ConditionTruth.TRUE),
            ("task.actor", "another", ConditionTruth.FALSE),
            ("runtime.permission", True, ConditionTruth.UNKNOWN),
        )
        for reference, literal, expected in cases:
            expression = ConditionExpression.build("eq", reference=reference, value=literal)
            actual = evaluate_source_fact_condition(
                expression,
                context=context,
                task_owners=chosen.tasks,
                inventory_owner=chosen.owner,
                actor_id="actor",
                root_id="core",
                budget=chosen.budget,
            )
            assert actual is expected
        verify_source_fact_context(
            context,
            task_owners=chosen.tasks,
            inventory_owner=chosen.owner,
            actor_id="actor",
            root_id="core",
            budget=chosen.budget,
        )
        assert all(
            proof.subject_digest != context.context_digest for proof in context.producer_proofs
        )
        invalid = ConditionExpression.build(
            "all",
            children=(
                ConditionExpression.build("eq", reference="task.actor", value="another"),
                ConditionExpression.build("lt", reference="task.id", value=1),
            ),
        )
        with pytest.raises(ValueError):
            evaluate_source_fact_condition(
                invalid,
                context=context,
                task_owners=chosen.tasks,
                inventory_owner=chosen.owner,
                actor_id="actor",
                root_id="core",
                budget=chosen.budget,
            )


@pytest.mark.parametrize(
    "fault",
    (
        "task-facts",
        "registry-facts",
        "inventory-facts",
        "owner-collision",
        "root-path",
        "root-scope",
    ),
)
def test_incomplete_source_domains_or_overlapping_owner_identities_refuse(
    tmp_path: Path, fault: str
) -> None:
    """Valid descriptive contracts cannot omit a mandatory actual source fact domain."""
    with (
        owner_selection(tmp_path / "case", fault=fault) as chosen,
        pytest.raises(ValueError, match=r"(required fact domain|selections disagree)"),
    ):
        observe_source_fact_context(
            task_owners=chosen.tasks,
            inventory_owner=chosen.owner,
            actor_id="actor",
            root_id="core",
            budget=chosen.budget,
        )


def test_unclassified_actual_scope_cannot_be_waived_by_a_false_sibling(tmp_path: Path) -> None:
    """Completeness refuses before any condition can manufacture a ready result."""
    with owner_selection(tmp_path / "case", fault="unclassified") as chosen:
        with pytest.raises(ValueError, match="classification is unresolved"):
            observe_source_fact_context(
                task_owners=chosen.tasks,
                inventory_owner=chosen.owner,
                actor_id="actor",
                root_id="core",
                budget=chosen.budget,
            )
        false = ConditionExpression.build("eq", reference="task.id", value="different")
        with pytest.raises(ValueError, match="classification is unresolved"):
            evaluate_source_fact_condition(
                false,
                context=declared_context(),
                task_owners=chosen.tasks,
                inventory_owner=chosen.owner,
                actor_id="actor",
                root_id="core",
                budget=chosen.budget,
            )
        with pytest.raises(ValueError, match="classification is unresolved"):
            chosen.owner.close()


def test_actual_owner_types_budget_and_rehashed_context_identity_are_required(
    tmp_path: Path,
) -> None:
    """Only the current actual fixed source entries can verify a context's claims."""
    with owner_selection(tmp_path / "case") as chosen:
        for tasks, inventory in [
            (cast(TaskRegistrySourceOwners, {}), chosen.owner),
            (chosen.tasks, cast(InventorySourceOwner, {})),
        ]:
            with pytest.raises(ValueError, match="actual fixed source owner"):
                observe_source_fact_context(
                    task_owners=tasks,
                    inventory_owner=inventory,
                    actor_id="actor",
                    root_id="core",
                    budget=chosen.budget,
                )
        with pytest.raises(ValueError, match="policy read budget"):
            observe_source_fact_context(
                task_owners=chosen.tasks,
                inventory_owner=chosen.owner,
                actor_id="actor",
                root_id="core",
                budget=cast(PolicyReadBudget1, {}),
            )
        with pytest.raises(ValueError, match="actual fact context"):
            verify_source_fact_context(
                cast(FactContext1, {}),
                task_owners=chosen.tasks,
                inventory_owner=chosen.owner,
                actor_id="actor",
                root_id="core",
                budget=chosen.budget,
            )
        value = observe_source_fact_context(
            task_owners=chosen.tasks,
            inventory_owner=chosen.owner,
            actor_id="actor",
            root_id="core",
            budget=chosen.budget,
        )
        data = value.to_dict()
        data.pop("context_digest")
        data["registry_generation_id"] = "foreign-generation"
        data["context_digest"] = canonical_digest(data)
        forged = FactContext1.from_dict(data, budget=chosen.budget)
        with pytest.raises(ValueError, match="actual selected source owners"):
            verify_source_fact_context(
                forged,
                task_owners=chosen.tasks,
                inventory_owner=chosen.owner,
                actor_id="actor",
                root_id="core",
                budget=chosen.budget,
            )
