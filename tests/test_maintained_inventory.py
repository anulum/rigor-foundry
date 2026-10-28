# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete maintained inventory wire tests
"""Retain empty roots and reject contradictory complete surface/proof metadata."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import TypedDict, cast

import pytest
from test_context_owner_implementation import implementation_budget
from test_maintained_surface import inventory_proofs, rehashed, surface
from test_repository_state import state

from rigor_foundry.context_owner_proof import OwnerProof1
from rigor_foundry.maintained_inventory import MaintainedInventory1
from rigor_foundry.maintained_surface import MaintainedSurface1
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_reads import read_policy_document


class InventoryArguments(TypedDict):
    """Exact public builder fields before deliberate invalid-input boundary checks."""

    project_id: str
    registry_generation_id: str
    registry_sha256: str
    repository_state_digest: str
    baseline_inventory_digest: str
    root_ids: tuple[str, ...]
    surfaces: tuple[MaintainedSurface1, ...]
    change_inventory_proof: OwnerProof1
    completeness_proof: OwnerProof1


def inventory() -> MaintainedInventory1:
    """Declare an integrity-valid full inventory vector, without actual owner authentication."""
    current = state()
    change, complete = inventory_proofs()
    return MaintainedInventory1.build(
        project_id=current.project_id,
        registry_generation_id=current.registry_generation_id,
        registry_sha256=current.registry_sha256,
        repository_state_digest=current.repository_state_digest,
        baseline_inventory_digest=current.baseline_inventory_digest,
        root_ids=("code", "empty"),
        surfaces=(surface(),),
        change_inventory_proof=change,
        completeness_proof=complete,
        budget=implementation_budget(),
    )


def test_complete_inventory_json_round_trip_preserves_empty_roots(tmp_path: Path) -> None:
    """A root with no files remains in the complete enclosing source identity."""
    value = inventory()
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(value.to_dict()))
    actual = MaintainedInventory1.from_dict(
        read_policy_document(path, budget=implementation_budget()), budget=implementation_budget()
    )
    assert actual == value
    assert actual.root_ids == ("code", "empty")
    assert actual.inventory_digest not in {
        actual.change_inventory_proof.subject_digest,
        actual.completeness_proof.subject_digest,
    }


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("schema_version", "2.0"),
        ("object_kind", "inventory"),
        ("root_ids", []),
        ("root_ids", ["empty", "code"]),
        ("root_ids", ["code", "code"]),
        ("root_ids", ["empty"]),
        ("root_ids", {}),
        ("surfaces", {}),
        ("project_id", "bad project"),
        ("repository_state_digest", "f" * 64),
        ("baseline_inventory_digest", "f" * 64),
    ],
)
def test_rehashed_inventory_cannot_omit_roots_or_relabel_subjects(
    field: str, invalid: object
) -> None:
    """Closed versions, complete root relations and independent proof subjects remain required."""
    data = inventory().to_dict()
    data[field] = invalid
    with pytest.raises(ValueError):
        MaintainedInventory1.from_dict(
            rehashed(data, "inventory_digest"), budget=implementation_budget()
        )


@pytest.mark.parametrize("fault", ("owner", "class", "contract", "snapshot", "kind", "subject"))
def test_baseline_completeness_proof_must_share_the_exact_selected_owner(fault: str) -> None:
    """A self-consistent foreign envelope cannot supply this inventory's completeness."""
    value = inventory()
    data = value.completeness_proof.to_dict()
    if fault == "owner":
        data["owner_id"] = "other"
    elif fault == "class":
        data["owner_class"] = "task"
    elif fault == "snapshot":
        data["snapshot_id"] = "other-entry"
    elif fault == "kind":
        data["source_object"] = value.change_inventory_proof.source_object.to_dict()
    elif fault == "subject":
        data["subject_digest"] = "f" * 64
    else:
        ref = value.change_inventory_proof.owner_contract.to_dict()
        ref["object_id"] = "other-contract"
        data["owner_contract"] = rehashed(ref, "ref_digest")
    wrong = OwnerProof1.from_dict(rehashed(data, "proof_digest"), budget=implementation_budget())
    with pytest.raises(ValueError):
        replace(value, completeness_proof=wrong)


def test_inventory_direct_collections_proofs_and_aggregate_budgets() -> None:
    """Count/type checks precede allocation and later semantic or hash acceptance."""
    value = inventory()
    for roots in [[], (), ("bad root",), ("code",) * 4097]:
        with pytest.raises(ValueError):
            replace(value, root_ids=cast(tuple[str, ...], roots))
    for rows in [
        [],
        (None,),
        (surface(), surface()),
        (surface(),) * 22000,
        (surface(path="z.py"), surface(path="a.py")),
    ]:
        with pytest.raises(ValueError):
            replace(value, surfaces=cast(tuple[MaintainedSurface1, ...], rows))
    with pytest.raises(ValueError, match="actual change"):
        replace(value, change_inventory_proof=cast(OwnerProof1, {}))
    with pytest.raises(ValueError, match="actual change"):
        replace(value, completeness_proof=cast(OwnerProof1, {}))
    with pytest.raises(ValueError, match="digest differs"):
        replace(value, registry_generation_id="new-generation")
    for limits in [implementation_budget(max_sources=1), implementation_budget(max_references=8)]:
        with pytest.raises(ValueError, match="reference budget"):
            MaintainedInventory1.from_dict(value.to_dict(), budget=limits)
    with pytest.raises(ValueError, match="policy read budget"):
        MaintainedInventory1.from_dict(value.to_dict(), budget=cast(PolicyReadBudget1, {}))
    data = value.to_dict()
    data["surfaces"] = [surface().to_dict(), surface().to_dict()]
    with pytest.raises(ValueError, match="sorted, unique"):
        MaintainedInventory1.from_dict(
            rehashed(data, "inventory_digest"), budget=implementation_budget()
        )


def test_inventory_builder_applies_its_actual_types_and_explicit_budgets() -> None:
    """Builder validation precedes serialization just as direct/parser validation does."""
    value = inventory()
    args: InventoryArguments = {
        "project_id": value.project_id,
        "registry_generation_id": value.registry_generation_id,
        "registry_sha256": value.registry_sha256,
        "repository_state_digest": value.repository_state_digest,
        "baseline_inventory_digest": value.baseline_inventory_digest,
        "root_ids": value.root_ids,
        "surfaces": value.surfaces,
        "change_inventory_proof": value.change_inventory_proof,
        "completeness_proof": value.completeness_proof,
    }
    for field in ("root_ids", "surfaces", "change_inventory_proof", "completeness_proof"):
        invalid = cast(InventoryArguments, {**args, field: []})
        with pytest.raises(ValueError, match="immutable actual"):
            MaintainedInventory1.build(**invalid, budget=implementation_budget())
    with pytest.raises(ValueError, match="policy read budget"):
        MaintainedInventory1.build(**args, budget=cast(PolicyReadBudget1, {}))
    with pytest.raises(ValueError, match="reference budget"):
        MaintainedInventory1.build(**args, budget=implementation_budget(max_references=8))
    foreign_data = value.change_inventory_proof.to_dict()
    foreign_data["snapshot_id"] = "other-entry"
    foreign = OwnerProof1.from_dict(
        rehashed(foreign_data, "proof_digest"), budget=implementation_budget()
    )
    changed = surface().to_dict()
    changed["inventory_proof"] = foreign.to_dict()
    wrong_surface = MaintainedSurface1.from_dict(
        rehashed(changed, "surface_digest"), budget=implementation_budget()
    )
    with pytest.raises(ValueError, match="surface proof differs"):
        replace(value, surfaces=(wrong_surface,))
