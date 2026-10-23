# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — exact owner proof metadata tests
"""Exercise independent source/contract references without declaring authentication."""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest
from test_context_producer_contract import contract
from test_task_definition import budget, definition
from test_typed_object_reference import reference

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.context_owner_proof import OwnerProof1
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.typed_object_reference import TypedObjectRef1


def proof() -> OwnerProof1:
    """Bind declared independently named subjects and references for parser cases."""
    return OwnerProof1.build(
        owner_id="fixed-owner",
        owner_class="task",
        owner_contract=TypedObjectRef1.from_dict(contract().reference()),
        subject_digest="a" * 64,
        source_object=TypedObjectRef1.from_dict(definition().reference()),
        snapshot_id="selected-snapshot",
        observation_digest="b" * 64,
        budget=budget(),
    )


def test_exact_proof_round_trip_has_independent_subject() -> None:
    """A parsed proof binds its whole body but never manufactures a verified status."""
    actual = proof()
    assert OwnerProof1.from_dict(actual.to_dict(), budget=budget()) == actual
    body = actual.to_dict()
    assert body.pop("proof_digest") == canonical_digest(body)
    assert actual.subject_digest != actual.proof_digest
    assert not {"verified", "guard_admissible", "context_digest", "source_path"}.intersection(body)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("owner_id", "bad owner"),
        ("owner_class", "caller"),
        ("owner_class", 1),
        ("subject_digest", "a" * 40),
        ("snapshot_id", ""),
        ("observation_digest", "short"),
        ("owner_contract", reference().to_dict()),
        ("source_object", {}),
        ("schema_version", "2.0"),
        ("object_kind", "task-proof"),
    ],
)
def test_rehashed_malformed_proof_refuses(field: str, invalid: object) -> None:
    """Rehashing cannot legitimize a wrong owner class, source kind or header."""
    data = proof().to_dict()
    data.pop("proof_digest")
    data[field] = invalid
    with pytest.raises(ValueError):
        OwnerProof1.from_dict({**data, "proof_digest": canonical_digest(data)}, budget=budget())


def test_closed_fields_direct_forgery_and_explicit_budget_refuse() -> None:
    """Later consumers reject changed records and cannot substitute a caller budget."""
    actual = proof()
    data = actual.to_dict()
    for bad in [
        None,
        {**data, "verified": True},
        {k: v for k, v in data.items() if k != "owner_id"},
    ]:
        with pytest.raises(ValueError):
            OwnerProof1.from_dict(bad, budget=budget())
    with pytest.raises(ValueError, match="reference budget"):
        OwnerProof1.from_dict(data, budget=budget(max_references=1))
    with pytest.raises(ValueError, match="budget is required"):
        OwnerProof1.from_dict(data, budget=cast(PolicyReadBudget1, {}))
    with pytest.raises(ValueError, match="actual typed"):
        replace(actual, source_object=cast(TypedObjectRef1, {}))
    with pytest.raises(ValueError, match="actual typed"):
        OwnerProof1.build(
            owner_id="owner",
            owner_class="task",
            owner_contract=cast(TypedObjectRef1, {}),
            subject_digest="a" * 64,
            source_object=actual.source_object,
            snapshot_id="snapshot",
            observation_digest="b" * 64,
            budget=budget(),
        )
    with pytest.raises(ValueError, match="differs"):
        replace(actual, subject_digest="c" * 64)
    object.__setattr__(actual, "proof_digest", "0" * 64)
    with pytest.raises(ValueError, match="differs"):
        actual.to_dict()
