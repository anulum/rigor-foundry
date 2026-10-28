# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — maintained surface wire contract tests
"""Exercise closed protocol vectors and real JSON reads without claiming authentication."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_context_owner_implementation import implementation_budget
from test_context_producer_contract import contract
from test_repository_state import state

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.context_owner_proof import OwnerProof1
from rigor_foundry.maintained_surface import MaintainedSurface1
from rigor_foundry.policy_source_reads import read_policy_document
from rigor_foundry.typed_object_reference import TypedObjectRef1


def rehashed(data: dict[str, object], field: str) -> dict[str, object]:
    """Recompute only wire integrity so semantic mutations remain independently tested."""
    body = dict(data)
    body.pop(field)
    return {**body, field: canonical_digest(body)}


def inventory_proofs() -> tuple[OwnerProof1, OwnerProof1]:
    """Declare independent state/baseline proof envelopes as inert protocol vectors."""
    current = state()
    sources = (
        TypedObjectRef1.from_dict(current.reference()),
        TypedObjectRef1.build(
            kind="inventory-baseline",
            format_version="1.0",
            object_id="before",
            object_digest=current.baseline_inventory_digest,
        ),
    )
    first, second = tuple(
        OwnerProof1.build(
            owner_id="inventory-owner",
            owner_class="inventory",
            owner_contract=TypedObjectRef1.from_dict(contract("inventory").reference()),
            subject_digest=source.object_digest,
            source_object=source,
            snapshot_id="selected-entry",
            observation_digest="c" * 64,
            budget=implementation_budget(),
        )
        for source in sources
    )
    return first, second


def surface(*, path: str = "src/module.py") -> MaintainedSurface1:
    """Bind a complete maintained path vector with separately named source subjects."""
    return MaintainedSurface1.build(
        surface_id=canonical_digest(path),
        root_id="code",
        relative_path=path,
        role="source",
        language="python",
        content_digest="d" * 64,
        baseline_content_digest="e" * 64,
        inventory_proof=inventory_proofs()[0],
        budget=implementation_budget(),
    )


def test_surface_round_trip_through_real_json_keeps_deleted_before_bytes(tmp_path: Path) -> None:
    """The public parser preserves every original field and nullable earlier identity."""
    value = surface()
    path = tmp_path / "surface.json"
    path.write_text(json.dumps(value.to_dict()))
    assert (
        MaintainedSurface1.from_dict(
            read_policy_document(path, budget=implementation_budget()),
            budget=implementation_budget(),
        )
        == value
    )
    assert value.surface_digest != value.inventory_proof.subject_digest
    data = value.to_dict()
    data["baseline_content_digest"] = None
    new = MaintainedSurface1.from_dict(
        rehashed(data, "surface_digest"), budget=implementation_budget()
    )
    assert new.baseline_content_digest is None
    assert "verified" not in new.to_dict()


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("schema_version", "2.0"),
        ("object_kind", "surface"),
        ("relative_path", "../outside"),
        ("role", "omitted"),
        ("language", ""),
        ("surface_id", "bad identity"),
        ("content_digest", "short"),
    ],
)
def test_rehashed_surface_semantic_changes_refuse(field: str, invalid: object) -> None:
    """Integrity recalculation cannot bless unknown versions, roles or unsafe paths."""
    data = surface().to_dict()
    data[field] = invalid
    with pytest.raises(ValueError):
        MaintainedSurface1.from_dict(
            rehashed(data, "surface_digest"), budget=implementation_budget()
        )


@pytest.mark.parametrize("fault", ("class", "kind", "subject"))
def test_surface_proof_must_name_the_independent_repository_state(fault: str) -> None:
    """Other source types and equal-width digest labels cannot replace the state subject."""
    value = surface()
    data = value.inventory_proof.to_dict()
    if fault == "class":
        data["owner_class"] = "task"
    elif fault == "kind":
        data["source_object"] = inventory_proofs()[1].source_object.to_dict()
    else:
        data["subject_digest"] = "f" * 64
    proof = OwnerProof1.from_dict(rehashed(data, "proof_digest"), budget=implementation_budget())
    with pytest.raises(ValueError, match="independent repository state"):
        replace(value, inventory_proof=proof)


def test_surface_closed_fields_direct_proof_types_and_digest_refuse() -> None:
    """Direct construction and decoding apply the same complete contract."""
    value = surface()
    with pytest.raises(ValueError):
        MaintainedSurface1.from_dict(
            {**value.to_dict(), "verified": True}, budget=implementation_budget()
        )
    with pytest.raises(ValueError, match="digest differs"):
        replace(value, content_digest="f" * 64)
    with pytest.raises(ValueError, match="actual inventory proof"):
        replace(value, inventory_proof=cast(OwnerProof1, {}))
    with pytest.raises(ValueError, match="actual inventory proof"):
        MaintainedSurface1.build(
            surface_id="surface",
            root_id="code",
            relative_path="src/module.py",
            role="source",
            language="python",
            content_digest="a" * 64,
            baseline_content_digest=None,
            inventory_proof=cast(OwnerProof1, {}),
            budget=implementation_budget(),
        )
    with pytest.raises(ValueError, match="reference budget"):
        MaintainedSurface1.from_dict(
            value.to_dict(), budget=implementation_budget(max_references=1)
        )
