# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — independent observation preimage tests
"""Exercise noncircular observations before their actual containing proof exists."""

from __future__ import annotations

from typing import cast

import pytest
from test_context_owner_proof import proof
from test_task_definition import budget
from test_typed_object_reference import reference

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.condition_language import ConditionValue
from rigor_foundry.context_owner_observations import ContextProducerObservation1, OwnerObservation
from rigor_foundry.context_owner_proof import OwnerProof1
from rigor_foundry.policy_read_budget import PolicyReadBudget1


def preimage(observations: tuple[OwnerObservation, ...] = ()) -> ContextProducerObservation1:
    """Construct the independent mapping without any final proof or context digest."""
    declared = proof()
    return ContextProducerObservation1(
        declared.owner_id,
        declared.owner_contract.ref_digest,
        declared.source_object.ref_digest,
        declared.snapshot_id,
        "task-identity",
        declared.subject_digest,
        observations,
    )


def bound_proof(observed: ContextProducerObservation1) -> OwnerProof1:
    """Bind the completed preimage only after its independent digest is available."""
    declared = proof()
    data = declared.to_dict()
    data.pop("proof_digest")
    data["observation_digest"] = observed.digest(budget=budget())
    return OwnerProof1.from_dict({**data, "proof_digest": canonical_digest(data)}, budget=budget())


def test_independent_observations_then_proof_have_no_digest_cycle() -> None:
    """Known null/empty, exact absence and unknown preserve distinct wire meanings."""
    rows = (
        OwnerObservation("task.absent", "absent", None, "a" * 64),
        OwnerObservation("task.empty", "known", (), "a" * 64),
        OwnerObservation("task.null", "known", None, "a" * 64),
        OwnerObservation("task.unknown", "unknown", None, "a" * 64),
    )
    observed = preimage(rows)
    body = observed.to_dict()
    assert observed.digest(budget=budget()) == canonical_digest(body)
    assert ContextProducerObservation1.from_dict(body, budget=budget()) == observed
    assert not {"proof_digest", "context_digest", "observation_digest", "provenance"}.intersection(
        body
    )
    declared = bound_proof(observed)
    assert declared.proof_digest != observed.digest(budget=budget())
    observed.verify_proof_binding(declared, budget=budget())
    assert preimage().to_dict()["observations"] == []


@pytest.mark.parametrize(("first", "second"), [(True, 1), (False, 0), ((True,), (1,))])
def test_observation_identity_preserves_boolean_numeric_separation(
    first: ConditionValue, second: ConditionValue
) -> None:
    """Valid scalar/array observations retain distinct equality, hashes and preimages."""
    flag = OwnerObservation("task.value", "known", first, "a" * 64)
    count = OwnerObservation("task.value", "known", second, "a" * 64)
    assert flag != count
    assert len({flag, count}) == 2
    assert flag != object()
    assert preimage((flag,)) != preimage((count,))
    assert preimage((flag,)).digest(budget=budget()) != preimage((count,)).digest(budget=budget())


@pytest.mark.parametrize(
    "field",
    [
        "owner_id",
        "owner_contract",
        "source_object",
        "snapshot_id",
        "subject_digest",
        "observation_digest",
    ],
)
def test_rehashed_foreign_proof_refuses(field: str) -> None:
    """Valid enclosing metadata cannot replace the selected source, snapshot or owner."""
    observed = preimage()
    data = bound_proof(observed).to_dict()
    data.pop("proof_digest")
    if field in {"owner_contract", "source_object"}:
        kind = "context-producer-contract" if field == "owner_contract" else "task-definition"
        data[field] = reference(kind, identity="foreign").to_dict()
    else:
        data[field] = "b" * 64 if field.endswith("digest") else "foreign"
    changed = OwnerProof1.from_dict(
        {**data, "proof_digest": canonical_digest(data)}, budget=budget()
    )
    with pytest.raises(ValueError, match="differs"):
        observed.verify_proof_binding(changed, budget=budget())
    with pytest.raises(ValueError, match="actual owner proof"):
        observed.verify_proof_binding(cast(OwnerProof1, {}), budget=budget())


@pytest.mark.parametrize(
    "data",
    [
        None,
        {"reference": "task.id", "state": "known", "value": "x"},
        {"reference": "task.*", "state": "known", "value": 1, "subject_digest": "a" * 64},
        {
            "reference": "task.id",
            "state": "absent",
            "value": "invented",
            "subject_digest": "a" * 64,
        },
        {"reference": "task.id", "state": "known", "value": [[1]], "subject_digest": "a" * 64},
    ],
)
def test_malformed_inline_observation_refuses(data: object) -> None:
    """Inline data has no wildcard domain, nested operands or inferred absence."""
    with pytest.raises(ValueError):
        OwnerObservation.from_dict(data)


def test_subject_order_collections_headers_and_budgets_refuse() -> None:
    """Complete preimages refuse omitted/extra fields, repeated names and foreign subjects."""
    row = OwnerObservation("task.id", "known", "task", "a" * 64)
    for bad in [
        cast(tuple[OwnerObservation, ...], []),
        cast(tuple[OwnerObservation, ...], ({},)),
        (row,) * 65535,
        (row, row),
        (row, OwnerObservation("task.a", "known", "task", "a" * 64)),
        (OwnerObservation("task.id", "known", "task", "b" * 64),),
    ]:
        with pytest.raises(ValueError):
            preimage(bad)
    data = preimage((row,)).to_dict()
    invalid: list[object] = [
        None,
        {**data, "proof_digest": "b" * 64},
        {k: v for k, v in data.items() if k != "owner_id"},
        {**data, "schema_version": "2.0"},
        {**data, "object_kind": "other"},
        {**data, "observations": None},
    ]
    for bad_value in invalid:
        with pytest.raises(ValueError):
            ContextProducerObservation1.from_dict(bad_value, budget=budget())
    with pytest.raises(ValueError, match="reference budget"):
        ContextProducerObservation1.from_dict(data, budget=budget(max_references=2))
    with pytest.raises(ValueError, match="budget is required"):
        ContextProducerObservation1.from_dict(data, budget=cast(PolicyReadBudget1, {}))
