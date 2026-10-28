# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — closed fact context protocol tests
"""Preserve explicit finite states and reject unbound or contradictory provenance."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_context_owner_implementation import implementation_budget
from test_context_owner_proof import proof
from test_maintained_surface import rehashed

from rigor_foundry.condition_facts import ObservationState
from rigor_foundry.condition_language import ConditionValue
from rigor_foundry.context_owner_proof import OwnerProof1
from rigor_foundry.fact_context import FactContext1, FactObservation1
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_reads import read_policy_document


def observation(
    *,
    reference: str = "task.id",
    state: ObservationState = "known",
    value: ConditionValue = "task",
) -> FactObservation1:
    """Declare one closed fact vector; actual source authentication has separate real tests."""
    return FactObservation1.build(
        reference=reference,
        state=state,
        value=value,
        subject_digest=proof().subject_digest,
        provenance=None if state == "unknown" else proof(),
        budget=implementation_budget(),
    )


def context(
    *,
    observations: tuple[FactObservation1, ...] | None = None,
    budget: PolicyReadBudget1 | None = None,
) -> FactContext1:
    """Bind complete original protocol vectors to independent task/registry/inventory IDs."""
    return FactContext1.build(
        task_identity_digest=proof().subject_digest,
        registry_generation_id="generation",
        registry_sha256="b" * 64,
        inventory_digest="c" * 64,
        producer_proofs=(proof(),),
        observations=(observation(),) if observations is None else observations,
        budget=implementation_budget() if budget is None else budget,
    )


def test_real_json_round_trip_preserves_null_empty_absent_and_unknown(tmp_path: Path) -> None:
    """Observed null/empty are distinct from authoritative absence and missing knowledge."""
    rows = (
        observation(reference="task.absent", state="absent", value=None),
        observation(reference="task.empty", value=()),
        observation(reference="task.null", value=None),
        observation(reference="task.unknown", state="unknown", value=None),
    )
    value = context(observations=rows)
    path = tmp_path / "facts.json"
    path.write_text(json.dumps(value.to_dict()))
    actual = FactContext1.from_dict(
        read_policy_document(path, budget=implementation_budget()), budget=implementation_budget()
    )
    assert actual == value
    assert actual.observations[0].provenance is not None
    assert actual.observations[1].value == ()
    assert actual.observations[2].state == "known"
    assert actual.observations[3].provenance is None
    assert "authenticated" not in actual.to_dict()
    assert observation(value=True) != observation(value=1)
    assert observation(value=False) != observation(value=0)
    assert observation(value=True) != object()
    assert len({observation(value=True), observation(value=1), observation(value=None)}) == 3


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("schema_version", "2.0"),
        ("object_kind", "fact"),
        ("reference", "bad reference"),
        ("state", "missing"),
        ("value", {"nested": True}),
        ("subject_digest", "b" * 64),
        ("provenance", None),
    ],
)
def test_rehashed_fact_semantics_and_provenance_refuse(field: str, invalid: object) -> None:
    """A caller cannot replace finite state/provenance semantics by recomputing a hash."""
    data = observation().to_dict()
    data[field] = invalid
    with pytest.raises(ValueError):
        FactObservation1.from_dict(
            rehashed(data, "observation_digest"), budget=implementation_budget()
        )


def test_direct_fact_types_integrity_and_allocation_bounds() -> None:
    """Direct records retain exact unknown/provenance relations and explicit limits."""
    value = observation()
    with pytest.raises(ValueError, match="unknown facts"):
        replace(value, state="unknown", value=None)
    with pytest.raises(ValueError, match="fact provenance"):
        FactObservation1.build(
            reference="task.id",
            state="known",
            value="task",
            subject_digest="a" * 64,
            provenance=cast(OwnerProof1, {}),
            budget=implementation_budget(),
        )
    with pytest.raises(ValueError, match="digest differs"):
        replace(value, value="changed")
    with pytest.raises(ValueError, match="hard reference"):
        replace(value, value=(0,) * 65534)
    with pytest.raises(ValueError, match="reference budget"):
        FactObservation1.from_dict(
            observation(value=(1, 2, 3)).to_dict(), budget=implementation_budget(max_references=5)
        )
    with pytest.raises(ValueError, match="policy read budget"):
        FactObservation1.from_dict(value.to_dict(), budget=cast(PolicyReadBudget1, {}))
    with pytest.raises(ValueError):
        FactObservation1.from_dict(
            {**value.to_dict(), "verified": True}, budget=implementation_budget()
        )


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("schema_version", "2.0"),
        ("object_kind", "context"),
        ("producer_proofs", {}),
        ("observations", {}),
        ("registry_generation_id", "bad generation"),
        ("inventory_digest", "short"),
    ],
)
def test_rehashed_context_headers_and_closed_fields_refuse(field: str, invalid: object) -> None:
    """Context structure is checked independently of the nested data's valid hashes."""
    data = context().to_dict()
    data[field] = invalid
    with pytest.raises(ValueError):
        FactContext1.from_dict(rehashed(data, "context_digest"), budget=implementation_budget())


def test_observed_parent_conflicts_and_foreign_provenance_refuse() -> None:
    """Exact reference state never manufactures descendant absence or another owner."""
    for parent in [
        observation(reference="task", value=None),
        observation(reference="task", state="absent", value=None),
    ]:
        with pytest.raises(ValueError, match="observed parent"):
            context(observations=(parent, observation()))
    allowed = context(
        observations=(observation(reference="task", state="unknown", value=None), observation())
    )
    assert allowed.observations[0].state == "unknown"
    assert context(
        observations=(
            observation(reference="task", value=None),
            observation(state="unknown", value=None),
        )
    )
    for parent in (
        observation(reference="task", value=None),
        observation(reference="task", state="absent", value=None),
    ):
        absent = context(observations=(parent, observation(state="absent", value=None)))
        assert absent.observations[1].state == "absent"
    data = proof().to_dict()
    data["owner_id"] = "foreign-owner"
    foreign = OwnerProof1.from_dict(rehashed(data, "proof_digest"), budget=implementation_budget())
    changed = observation().to_dict()
    changed["provenance"] = foreign.to_dict()
    foreign_fact = FactObservation1.from_dict(
        rehashed(changed, "observation_digest"), budget=implementation_budget()
    )
    with pytest.raises(ValueError, match="outside the selected"):
        context(observations=(foreign_fact,))


def test_context_immutable_collections_digests_and_aggregate_limits() -> None:
    """Direct and parser boundaries reject duplicate records and combined value overflow."""
    value = context()
    for proofs in [[], (None,), (proof(), proof()), (proof(),) * 32769]:
        with pytest.raises(ValueError):
            replace(value, producer_proofs=cast(tuple[OwnerProof1, ...], proofs))
    for rows in [
        [],
        (None,),
        (observation(), observation()),
        (observation(reference="z"), observation(reference="a")),
    ]:
        with pytest.raises(ValueError):
            replace(value, observations=cast(tuple[FactObservation1, ...], rows))
    with pytest.raises(ValueError, match="digest differs"):
        replace(value, registry_generation_id="changed-generation")
    with pytest.raises(ValueError, match="reference budget"):
        FactContext1.from_dict(value.to_dict(), budget=implementation_budget(max_references=4))
    with pytest.raises(ValueError, match="aggregate context"):
        FactContext1.from_dict(
            context(observations=(observation(value=(1, 2, 3, 4)),)).to_dict(),
            budget=implementation_budget(max_references=8),
        )
    with pytest.raises(ValueError, match="hard aggregate"):
        replace(
            value,
            observations=tuple(
                observation(reference=f"values.x{i}", value=(0,) * 10000) for i in range(7)
            ),
        )
    with pytest.raises(ValueError):
        FactContext1.from_dict(
            {**value.to_dict(), "verified": True}, budget=implementation_budget()
        )
    with pytest.raises(ValueError, match="record/reference budget"):
        context(observations=cast(tuple[FactObservation1, ...], []))


def test_immutable_array_inputs_cannot_bypass_builder_or_parser_budgets() -> None:
    """The same finite tuple arrays consume references before any new wire allocation."""
    value = observation(value=(1, 2, 3))
    data = value.to_dict()
    data["value"] = (1, 2, 3)
    with pytest.raises(ValueError, match="reference budget"):
        FactObservation1.from_dict(data, budget=implementation_budget(max_references=5))
    with pytest.raises(ValueError, match="reference budget"):
        FactObservation1.build(
            reference="task.id",
            state="known",
            value=(1, 2, 3),
            subject_digest=proof().subject_digest,
            provenance=proof(),
            budget=implementation_budget(max_references=5),
        )
    row = observation(value=(1, 2, 3, 4))
    with pytest.raises(ValueError, match="aggregate context"):
        context(observations=(row,), budget=implementation_budget(max_references=8))
    data = context(observations=(row,)).to_dict()
    raw_observations = cast(list[dict[str, object]], data["observations"])
    raw_observations[0]["value"] = (1, 2, 3, 4)
    with pytest.raises(ValueError, match="aggregate context"):
        FactContext1.from_dict(data, budget=implementation_budget(max_references=8))
