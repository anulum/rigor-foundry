# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual task context composition tests
"""Exercise fixed owners, retained remediation files and real tri-state consumers."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
from test_context_owner_implementation import implementation_budget
from test_inventory_source_owner import owner_arguments, owner_selection
from test_maintained_surface import rehashed
from test_remediation_task_binding import retained
from test_work_models import source_records

from rigor_foundry.condition_facts import ConditionTruth
from rigor_foundry.condition_language import ConditionExpression, ConditionValue
from rigor_foundry.inventory_source_owner import InventorySourceOwner
from rigor_foundry.remediation_task_binding import RemediationSources
from rigor_foundry.source_task_context import (
    evaluate_source_task_condition,
    observe_source_task_context,
    verify_source_task_context,
)
from rigor_foundry.task_context import TaskContext1
from rigor_foundry.task_registry_source_owners import TaskRegistrySourceOwners
from rigor_foundry.work_models import WorkTask


def remediation_task() -> WorkTask:
    """Build an explicit actual remediation fixture for the same declared general task."""
    report, review = source_records()
    return WorkTask.build(
        report,
        review,
        task_id="source-work",
        production_impact="Verify original remediation source relationships.",
        affected_surfaces=("src/module.py",),
        prohibited_shortcuts=("no source substitution",),
        required_verifier="independent-verifier",
        created_by="implementation-owner",
        created_at="2026-07-15T10:05:00Z",
    )


def test_real_general_task_context_has_no_invented_remediation_or_claim(tmp_path: Path) -> None:
    """Actual original source owners join full scope before TRUE/FALSE/UNKNOWN evaluation."""
    with owner_selection(tmp_path / "case") as chosen:
        value = observe_source_task_context(
            task_owners=chosen.tasks,
            inventory_owner=chosen.owner,
            actor_id="actor",
            root_id="core",
            event="verification",
            budget=chosen.budget,
        )
        assert value.task_id == "source-work" and value.remediation is None
        assert value.claim_proof is None
        assert TaskContext1.from_dict(value.to_dict(), budget=chosen.budget) == value
        verify_source_task_context(
            value,
            task_owners=chosen.tasks,
            inventory_owner=chosen.owner,
            actor_id="actor",
            root_id="core",
            event="verification",
            budget=chosen.budget,
        )
        cases: tuple[tuple[str, ConditionValue, ConditionTruth], ...] = (
            ("task.id", "source-work", ConditionTruth.TRUE),
            ("task.actor", "another", ConditionTruth.FALSE),
            ("runtime.permission", True, ConditionTruth.UNKNOWN),
        )
        for reference, literal, expected in cases:
            assert (
                evaluate_source_task_condition(
                    ConditionExpression.build("eq", reference=reference, value=literal),
                    context=value,
                    task_owners=chosen.tasks,
                    inventory_owner=chosen.owner,
                    actor_id="actor",
                    root_id="core",
                    event="verification",
                    budget=chosen.budget,
                )
                is expected
            )
        with pytest.raises(ValueError, match="differs from actual original"):
            verify_source_task_context(
                value,
                task_owners=chosen.tasks,
                inventory_owner=chosen.owner,
                actor_id="actor",
                root_id="core",
                event="commit",
                budget=chosen.budget,
            )
        with pytest.raises(ValueError):
            evaluate_source_task_condition(
                ConditionExpression.build(
                    "all",
                    children=(
                        ConditionExpression.build("eq", reference="task.actor", value="different"),
                        ConditionExpression.build("lt", reference="task.id", value=1),
                    ),
                ),
                context=value,
                task_owners=chosen.tasks,
                inventory_owner=chosen.owner,
                actor_id="actor",
                root_id="core",
                event="verification",
                budget=chosen.budget,
            )


def test_actual_optional_remediation_source_is_verified_through_task_use(tmp_path: Path) -> None:
    """An explicit existing remediation is optional, source-bound and never manufactured."""
    with (
        owner_selection(tmp_path / "case") as chosen,
        retained(tmp_path / "remediation/source.json", remediation_task()) as task,
    ):
        selected = RemediationSources(task)
        value = observe_source_task_context(
            task_owners=chosen.tasks,
            inventory_owner=chosen.owner,
            actor_id="actor",
            root_id="core",
            event="review",
            remediation_sources=selected,
            budget=chosen.budget,
        )
        assert value.remediation is not None and value.remediation.task == task.reference
        verify_source_task_context(
            value,
            task_owners=chosen.tasks,
            inventory_owner=chosen.owner,
            actor_id="actor",
            root_id="core",
            event="review",
            remediation_sources=selected,
            budget=chosen.budget,
        )
        assert task.read() == remediation_task()
        with pytest.raises(ValueError, match="differs from actual original"):
            verify_source_task_context(
                value,
                task_owners=chosen.tasks,
                inventory_owner=chosen.owner,
                actor_id="actor",
                root_id="core",
                event="review",
                budget=chosen.budget,
            )


def test_caller_claim_metadata_and_foreign_actual_entries_cannot_be_upgraded(
    tmp_path: Path,
) -> None:
    """Parsed claim data cannot become an authenticated claim through source-only composition."""
    with owner_selection(tmp_path / "case") as chosen:
        value = observe_source_task_context(
            task_owners=chosen.tasks,
            inventory_owner=chosen.owner,
            actor_id="actor",
            root_id="core",
            event="mutation",
            budget=chosen.budget,
        )
        data = value.task_proof.to_dict()
        data["owner_class"] = "claim"
        supplied = value.to_dict()
        supplied["claim_proof"] = rehashed(data, "proof_digest")
        claimed = TaskContext1.from_dict(
            rehashed(supplied, "context_digest"), budget=chosen.budget
        )
        with pytest.raises(ValueError, match="differs from actual original"):
            evaluate_source_task_condition(
                ConditionExpression.build("eq", reference="task.id", value="different"),
                context=claimed,
                task_owners=chosen.tasks,
                inventory_owner=chosen.owner,
                actor_id="actor",
                root_id="core",
                event="mutation",
                budget=chosen.budget,
            )
        with (
            InventorySourceOwner(**owner_arguments(chosen)) as other,
            pytest.raises(ValueError, match="differs from actual original"),
        ):
            verify_source_task_context(
                value,
                task_owners=chosen.tasks,
                inventory_owner=other,
                actor_id="actor",
                root_id="core",
                event="mutation",
                budget=chosen.budget,
            )


@pytest.mark.parametrize("fault", ("unclassified", "root-path", "root-scope"))
def test_incomplete_or_conflicting_actual_scope_cannot_make_a_task_context(
    tmp_path: Path, fault: str
) -> None:
    """Whole actual inventory completeness and physical root bindings precede task data."""
    with owner_selection(tmp_path / "case", fault=fault) as chosen:
        with pytest.raises(ValueError):
            observe_source_task_context(
                task_owners=chosen.tasks,
                inventory_owner=chosen.owner,
                actor_id="actor",
                root_id="core",
                event="audit",
                budget=chosen.budget,
            )
        if fault == "unclassified":
            with pytest.raises(ValueError):
                chosen.owner.close()


def test_declared_events_metadata_owners_and_malformed_contexts_have_no_fallback() -> None:
    """Caller labels or malformed data never appoint a source reader or claim authority."""
    for event, remediation in [
        ("unsupported", None),
        ("start", cast(RemediationSources, {})),
    ]:
        with pytest.raises(ValueError):
            observe_source_task_context(
                task_owners=cast(TaskRegistrySourceOwners, {}),
                inventory_owner=cast(InventorySourceOwner, {}),
                actor_id="actor",
                root_id="core",
                event=event,
                budget=implementation_budget(),
                remediation_sources=remediation,
            )
    with pytest.raises(ValueError, match="actual complete task context"):
        verify_source_task_context(
            cast(TaskContext1, {}),
            task_owners=cast(TaskRegistrySourceOwners, {}),
            inventory_owner=cast(InventorySourceOwner, {}),
            actor_id="actor",
            root_id="core",
            event="start",
            budget=implementation_budget(),
        )


def test_actual_changed_root_refuses_task_verification_and_closure(tmp_path: Path) -> None:
    """The same original entries refuse after actual maintained bytes change."""
    with pytest.raises(ValueError), owner_selection(tmp_path / "case") as chosen:
        value = observe_source_task_context(
            task_owners=chosen.tasks,
            inventory_owner=chosen.owner,
            actor_id="actor",
            root_id="core",
            event="verification",
            budget=chosen.budget,
        )
        chosen.private_file.write_bytes(b"changed actual maintained bytes\n")
        with pytest.raises(ValueError):
            verify_source_task_context(
                value,
                task_owners=chosen.tasks,
                inventory_owner=chosen.owner,
                actor_id="actor",
                root_id="core",
                event="verification",
                budget=chosen.budget,
            )
        chosen.owner.close()
