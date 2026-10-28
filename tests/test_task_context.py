# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete task context wire tests
"""Join explicit source protocol vectors and reject conflicting independent identities."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_context_owner_implementation import implementation_budget
from test_context_producer_contract import contract
from test_maintained_inventory import inventory
from test_maintained_surface import rehashed
from test_remediation_task_binding import binding

from rigor_foundry.condition_language import ConditionValue
from rigor_foundry.context_owner_proof import OwnerProof1
from rigor_foundry.fact_context import FactContext1, FactObservation1
from rigor_foundry.maintained_inventory import MaintainedInventory1
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_reads import read_policy_document
from rigor_foundry.remediation_task_binding import RemediationTaskBinding1
from rigor_foundry.task_context import TASK_CONTEXT_EVENTS, TaskContext1
from rigor_foundry.task_definition import TaskDefinition1
from rigor_foundry.typed_object_reference import TypedObjectRef1


def context(
    *,
    budget: PolicyReadBudget1 | None = None,
    task_reference: TypedObjectRef1 | None = None,
    task_proof: OwnerProof1 | None = None,
    remediation: RemediationTaskBinding1 | None = None,
) -> TaskContext1:
    """Build inert exact wire vectors; real owner authentication has dedicated source tests."""
    limits = implementation_budget()
    maintained = inventory()
    identity = "source-work" if remediation is None else remediation.task.object_id
    task = TaskDefinition1.build(
        task_id=identity,
        revision="1",
        actor_ids=("actor",),
        project_id=maintained.project_id,
        group_id="engineering",
        root_ids=("code",),
        statement="Verify complete source context contracts.",
        lifecycle="active",
        budget=limits,
    )
    task_ref = TypedObjectRef1.from_dict(task.reference())
    subject = task.identity_digest(actor_id="actor", root_id="code", budget=limits)
    task_owner = OwnerProof1.build(
        owner_id="task-owner",
        owner_class="task",
        owner_contract=TypedObjectRef1.from_dict(contract().reference()),
        subject_digest=subject,
        source_object=task_ref,
        snapshot_id="task-vector",
        observation_digest="b" * 64,
        budget=limits,
    )
    registry_owner = OwnerProof1.build(
        owner_id="registry-owner",
        owner_class="registry",
        owner_contract=TypedObjectRef1.from_dict(contract("registry").reference()),
        subject_digest=maintained.registry_sha256,
        source_object=TypedObjectRef1.build(
            kind="project-registry",
            format_version="gotm-project-registry.v1",
            object_id=maintained.registry_generation_id,
            object_digest=maintained.registry_sha256,
        ),
        snapshot_id="registry-vector",
        observation_digest="c" * 64,
        budget=limits,
    )
    task_values: dict[str, ConditionValue] = {
        "task.id": identity,
        "task.revision": "1",
        "task.actor": "actor",
        "task.project": maintained.project_id,
        "task.group": "engineering",
        "task.root": "code",
        "task.lifecycle": "active",
    }
    registry_values: dict[str, ConditionValue] = {
        "project.id": maintained.project_id,
        "project.group": "engineering",
        "project.lifecycle": "active",
        "project.target_kind": "git-repository",
        "project.visibility": "private",
        "project.memory_state": "scaffold-only",
        "registry.generation": maintained.registry_generation_id,
        "registry.digest": maintained.registry_sha256,
    }
    inventory_values: dict[str, ConditionValue] = {
        "inventory.roots": maintained.root_ids,
        "inventory.languages": ("python",),
        "inventory.roles": ("source",),
        "inventory.changed_paths": (),
        "inventory.repository_state": maintained.repository_state_digest,
    }
    rows = tuple(
        sorted(
            (
                FactObservation1.build(
                    reference=name,
                    state="known",
                    value=value,
                    subject_digest=owner.subject_digest,
                    provenance=owner,
                    budget=limits,
                )
                for owner, values in (
                    (task_owner, task_values),
                    (registry_owner, registry_values),
                    (maintained.change_inventory_proof, inventory_values),
                )
                for name, value in values.items()
            ),
            key=lambda row: row.reference,
        )
    )
    facts = FactContext1.build(
        task_identity_digest=subject,
        registry_generation_id=maintained.registry_generation_id,
        registry_sha256=maintained.registry_sha256,
        inventory_digest=maintained.inventory_digest,
        producer_proofs=tuple(
            sorted(
                (task_owner, registry_owner, maintained.change_inventory_proof),
                key=lambda proof: proof.proof_digest,
            )
        ),
        observations=rows,
        budget=limits,
    )
    return TaskContext1.build(
        task_id=identity,
        task_definition=task_ref if task_reference is None else task_reference,
        task_proof=task_owner if task_proof is None else task_proof,
        actor_id="actor",
        project_id=maintained.project_id,
        group_id="engineering",
        root_id="code",
        registry_generation_id=maintained.registry_generation_id,
        registry_sha256=maintained.registry_sha256,
        lifecycle="active",
        event="verification",
        inventory=maintained,
        facts=facts,
        claim_proof=None,
        remediation=remediation,
        task_identity_digest=subject,
        budget=limits if budget is None else budget,
    )


def replace_fact(
    value: TaskContext1,
    reference: str,
    *,
    literal: ConditionValue = None,
    omit: bool = False,
    unknown: bool = False,
) -> FactContext1:
    """Create another integrity-valid fact vector without pretending it was observed."""
    rows = tuple(
        row
        if row.reference != reference
        else FactObservation1.build(
            reference=reference,
            state="unknown" if unknown else "known",
            value=literal,
            subject_digest=row.subject_digest,
            provenance=None if unknown else row.provenance,
            budget=implementation_budget(),
        )
        for row in value.facts.observations
        if not (omit and row.reference == reference)
    )
    data = value.facts.to_dict()
    data["observations"] = [row.to_dict() for row in rows]
    return FactContext1.from_dict(rehashed(data, "context_digest"), budget=implementation_budget())


def test_complete_task_json_round_trip_keeps_independent_identity_and_event(
    tmp_path: Path,
) -> None:
    """Every accepted event remains data, with no fabricated remediation or claim."""
    value = context()
    path = tmp_path / "task-context.json"
    path.write_text(json.dumps(value.to_dict()))
    assert (
        TaskContext1.from_dict(
            read_policy_document(path, budget=implementation_budget()),
            budget=implementation_budget(),
        )
        == value
    )
    assert value.remediation is None and value.claim_proof is None
    assert value.task_identity_digest != value.context_digest
    for event in sorted(TASK_CONTEXT_EVENTS):
        data = value.to_dict()
        data["event"] = event
        changed = TaskContext1.from_dict(
            rehashed(data, "context_digest"), budget=implementation_budget()
        )
        assert (
            changed.event == event and changed.task_identity_digest == value.task_identity_digest
        )
    actual_remediation = context(remediation=binding())
    assert actual_remediation.remediation == binding()
    claim_data = value.task_proof.to_dict()
    claim_data["owner_class"] = "claim"
    data = value.to_dict()
    data["claim_proof"] = rehashed(claim_data, "proof_digest")
    parsed = TaskContext1.from_dict(
        rehashed(data, "context_digest"), budget=implementation_budget()
    )
    assert parsed.claim_proof is not None
    assert not {"authenticated", "guard_admissible", "permission"}.intersection(parsed.to_dict())


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("schema_version", "2.0"),
        ("object_kind", "other"),
        ("event", "execute"),
        ("task_id", "foreign"),
        ("actor_id", "foreign"),
        ("project_id", "foreign"),
        ("group_id", "foreign"),
        ("root_id", "foreign"),
        ("registry_generation_id", "foreign"),
        ("registry_sha256", "f" * 64),
        ("task_identity_digest", "f" * 64),
        ("lifecycle", "different"),
        ("task_definition", {}),
        ("task_proof", {}),
    ],
)
def test_rehashed_context_cannot_change_independent_sources(field: str, invalid: object) -> None:
    """An outer digest never makes conflicting task/source identities equivalent."""
    data = context().to_dict()
    data[field] = invalid
    with pytest.raises(ValueError):
        TaskContext1.from_dict(rehashed(data, "context_digest"), budget=implementation_budget())


@pytest.mark.parametrize(
    "reference", ("task.id", "task.revision", "project.id", "project.lifecycle", "inventory.roles")
)
@pytest.mark.parametrize("omitted", (False, True))
def test_mandatory_original_fact_domains_cannot_be_unknown_or_omitted(
    reference: str, omitted: bool
) -> None:
    """Complete context data requires the original known task/registry/inventory observations."""
    value = context()
    with pytest.raises(ValueError):
        replace(value, facts=replace_fact(value, reference, omit=omitted, unknown=not omitted))


@pytest.mark.parametrize(
    ("reference", "literal"),
    [
        ("task.id", True),
        ("task.actor", "other"),
        ("project.id", "other"),
        ("project.lifecycle", True),
        ("inventory.roots", ("code",)),
        ("inventory.repository_state", "f" * 64),
    ],
)
def test_integrity_valid_fact_values_must_agree_with_the_original_context(
    reference: str, literal: ConditionValue
) -> None:
    """Finite values alone do not prove original identity, complete roots or state."""
    value = context()
    with pytest.raises(ValueError):
        replace(value, facts=replace_fact(value, reference, literal=literal))


def test_direct_types_claim_roles_remediation_identity_and_budgets_refuse() -> None:
    """Direct instances use the same closed type and complete-allocation boundaries."""
    value = context()
    with pytest.raises(ValueError):
        replace(value, inventory=cast(MaintainedInventory1, {}))
    with pytest.raises(ValueError):
        replace(value, facts=cast(FactContext1, {}))
    with pytest.raises(ValueError):
        replace(value, claim_proof=cast(OwnerProof1, {}))
    with pytest.raises(ValueError):
        replace(value, remediation=cast(RemediationTaskBinding1, {}))
    with pytest.raises(ValueError):
        replace(value, task_definition=cast(TypedObjectRef1, {}))
    with pytest.raises(ValueError):
        replace(value, task_proof=cast(OwnerProof1, {}))
    with pytest.raises(ValueError, match="claim metadata"):
        replace(value, claim_proof=value.task_proof)
    with pytest.raises(ValueError, match="remediation binding differs"):
        replace(value, remediation=binding())
    with pytest.raises(ValueError, match="context digest differs"):
        replace(value, context_digest="f" * 64)
    with pytest.raises(ValueError):
        context(task_reference=cast(TypedObjectRef1, {}))
    with pytest.raises(ValueError):
        context(task_proof=cast(OwnerProof1, {}))
    with pytest.raises(ValueError, match="budget is required"):
        context(budget=cast(PolicyReadBudget1, {}))
    with pytest.raises(ValueError, match="aggregate reference"):
        context(budget=implementation_budget(max_references=8))
    for data in [
        {**value.to_dict(), "loader": "caller"},
        {**value.to_dict(), "inventory": {}},
        {**value.to_dict(), "facts": []},
    ]:
        with pytest.raises(ValueError):
            TaskContext1.from_dict(data, budget=implementation_budget())


def test_complete_nested_task_budget_includes_fact_arrays_before_allocation() -> None:
    """A valid child context cannot exceed the enclosing task's aggregate allocation."""
    value = context()
    for count in (1024, 65452):
        entries = ("entry",) * count
        row = FactObservation1.build(
            reference="extra.values",
            state="known",
            value=entries,
            subject_digest=value.task_identity_digest,
            provenance=value.task_proof,
            budget=implementation_budget(),
        )
        data = value.facts.to_dict()
        data["observations"] = [
            item.to_dict()
            for item in sorted((*value.facts.observations, row), key=lambda item: item.reference)
        ]
        facts = FactContext1.from_dict(
            rehashed(data, "context_digest"), budget=implementation_budget()
        )
        if count == 65452:
            with pytest.raises(ValueError, match="hard aggregate"):
                replace(value, facts=facts)
        else:
            payload = value.to_dict()
            payload["facts"] = facts.to_dict()
            payload = rehashed(payload, "context_digest")
            assert TaskContext1.from_dict(payload, budget=implementation_budget()).facts == facts
            for array in (list(entries), entries):
                records = cast(
                    list[dict[str, object]],
                    cast(dict[str, object], payload["facts"])["observations"],
                )
                records[0]["value"] = array
                with pytest.raises(ValueError, match="fact values exceed"):
                    TaskContext1.from_dict(
                        payload, budget=implementation_budget(max_references=150)
                    )


def test_task_and_inventory_proofs_must_belong_to_the_same_full_fact_context() -> None:
    """Equal subjects and labels cannot substitute a different selected proof envelope."""
    value = context()
    data = value.task_proof.to_dict()
    data["owner_id"] = "other-task-owner"
    other = OwnerProof1.from_dict(rehashed(data, "proof_digest"), budget=implementation_budget())
    with pytest.raises(ValueError, match="outside the complete"):
        replace(value, task_proof=other)
    data = value.inventory.change_inventory_proof.to_dict()
    data["observation_digest"] = "f" * 64
    changed = OwnerProof1.from_dict(rehashed(data, "proof_digest"), budget=implementation_budget())
    inventory_data = value.inventory.to_dict()
    inventory_data["change_inventory_proof"] = changed.to_dict()
    surfaces = cast(list[dict[str, object]], inventory_data["surfaces"])
    for index, surface in enumerate(surfaces):
        surface["inventory_proof"] = changed.to_dict()
        surfaces[index] = rehashed(surface, "surface_digest")
    maintained = MaintainedInventory1.from_dict(
        rehashed(inventory_data, "inventory_digest"), budget=implementation_budget()
    )
    fact_data = value.facts.to_dict()
    fact_data["inventory_digest"] = maintained.inventory_digest
    facts = FactContext1.from_dict(
        rehashed(fact_data, "context_digest"), budget=implementation_budget()
    )
    with pytest.raises(ValueError, match="outside the complete"):
        replace(value, inventory=maintained, facts=facts)


@pytest.mark.parametrize("collision", (False, True))
def test_registry_domain_cannot_mix_entries_or_alias_another_source_owner(collision: bool) -> None:
    """One original registry proof and distinct actual producer roles remain required."""
    value = context()
    original = next(
        proof for proof in value.facts.producer_proofs if proof.owner_class == "registry"
    )
    data = original.to_dict()
    data["owner_id"] = value.task_proof.owner_id if collision else "another-registry-owner"
    alternate = OwnerProof1.from_dict(
        rehashed(data, "proof_digest"), budget=implementation_budget()
    )
    facts_data = value.facts.to_dict()
    proofs = (
        tuple(proof for proof in value.facts.producer_proofs if proof != original)
        if collision
        else value.facts.producer_proofs
    )
    facts_data["producer_proofs"] = [
        proof.to_dict()
        for proof in sorted((*proofs, alternate), key=lambda proof: proof.proof_digest)
    ]
    facts_data["observations"] = [
        FactObservation1.build(
            reference=row.reference,
            state=row.state,
            value=row.value,
            subject_digest=row.subject_digest,
            provenance=alternate,
            budget=implementation_budget(),
        ).to_dict()
        if row.provenance == original and (collision or row.reference == "project.id")
        else row.to_dict()
        for row in value.facts.observations
    ]
    facts = FactContext1.from_dict(
        rehashed(facts_data, "context_digest"), budget=implementation_budget()
    )
    with pytest.raises(ValueError, match="one registry proof and distinct"):
        replace(value, facts=facts)

    with pytest.raises(ValueError):
        TaskContext1.from_dict(value.to_dict(), budget=cast(PolicyReadBudget1, {}))
    with pytest.raises(ValueError, match="aggregate reference"):
        TaskContext1.from_dict(value.to_dict(), budget=implementation_budget(max_references=8))
    for parent, name in [
        ("inventory", "root_ids"),
        ("inventory", "surfaces"),
        ("facts", "producer_proofs"),
        ("facts", "observations"),
    ]:
        data = value.to_dict()
        nested = cast(dict[str, object], data[parent])
        nested[name] = None
        with pytest.raises(ValueError, match="nested collections"):
            TaskContext1.from_dict(data, budget=implementation_budget())
