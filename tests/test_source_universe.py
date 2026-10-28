# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — closed source universe entry tests
"""Exercise inert complete source entry wires without fabricating source observation."""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest
from test_context_owner_implementation import implementation_budget
from test_context_producer_contract import contract
from test_source_provenance import capture
from test_typed_object_reference import reference

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.context_owner_proof import OwnerProof1
from rigor_foundry.control_assessment import Classification
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_records import PolicySourceRecord1
from rigor_foundry.source_universe import SourceDisposition, SourceReadState, SourceUniverseEntry1
from rigor_foundry.typed_object_reference import TypedObjectRef1


def entry(
    state: SourceReadState = "verified",
    disposition: SourceDisposition = "included",
    classification: Classification = "internal",
) -> SourceUniverseEntry1:
    """Build a declared parser vector, explicitly not an actual source-owner observation."""
    source = TypedObjectRef1.from_dict(
        PolicySourceRecord1(capture(), implementation_budget()).reference()
    )
    proof = OwnerProof1.build(
        owner_id="source-owner",
        owner_class="source",
        owner_contract=TypedObjectRef1.from_dict(contract("source").reference()),
        subject_digest="b" * 64 if state == "verified" else source.object_digest,
        source_object=source,
        snapshot_id="declared-snapshot",
        observation_digest="c" * 64,
        budget=implementation_budget(),
    )
    return SourceUniverseEntry1.build(
        source_id="policy",
        existing_source=source,
        classification=classification,
        locator="opaque:policy",
        byte_digest="b" * 64 if state == "verified" else None,
        byte_count=0 if state == "verified" else None,
        read_state=state,
        disposition=disposition,
        disposition_decision="exclusion" if disposition == "excluded" else None,
        provenance=proof,
        budget=implementation_budget(),
    )


@pytest.mark.parametrize("state", ["verified", "unread", "unavailable", "protected"])
@pytest.mark.parametrize("disposition", ["included", "excluded"])
@pytest.mark.parametrize("classification", ["public", "internal", "confidential", "secret"])
def test_all_explicit_source_states_and_dispositions_remain_metadata(
    state: SourceReadState, disposition: SourceDisposition, classification: Classification
) -> None:
    """Closed entry round trips retain held sources and do not claim semantic acceptance."""
    declared = entry(state, disposition, classification)
    assert (
        SourceUniverseEntry1.from_dict(declared.to_dict(), budget=implementation_budget())
        == declared
    )
    body = declared.to_dict()
    assert body.pop("entry_digest") == canonical_digest(body)
    assert body["read_state"] == state and body["disposition"] == disposition
    assert body["classification"] == classification
    assert declared.provenance.subject_digest != declared.entry_digest
    assert not {"source_path", "accepted", "ready_boot", "verified_by_parser"}.intersection(body)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "2.0"),
        ("object_kind", "source-capture"),
        ("source_id", "bad identity"),
        ("classification", "caller"),
        ("locator", "has whitespace"),
        ("locator", "a\0b"),
        ("locator", "a" * 4097),
        ("read_state", "accepted"),
        ("disposition", "omitted"),
        ("byte_digest", "bad"),
        ("byte_digest", None),
        ("byte_count", None),
        ("byte_count", True),
        ("byte_count", -1),
        ("disposition_decision", "bad identity"),
        ("existing_source", reference().to_dict()),
        ("provenance", {}),
        ("entry_digest", "f" * 64),
    ],
)
def test_rehashed_unknown_fields_and_false_original_binding_refuse(
    field: str, value: object
) -> None:
    """Hashing a different declaration cannot repair a wrong entry state or source role."""
    data = entry().to_dict()
    data[field] = value
    if field != "entry_digest":
        data.pop("entry_digest")
        data["entry_digest"] = canonical_digest(data)
    with pytest.raises(ValueError):
        SourceUniverseEntry1.from_dict(data, budget=implementation_budget())


def test_verified_bytes_and_exclusion_decisions_are_required() -> None:
    """A fully rehashed null pair cannot claim actual bytes or silently exclude a source."""
    actual = entry()
    data = actual.to_dict()
    data.pop("entry_digest")
    data.update(byte_digest=None, byte_count=None)
    with pytest.raises(ValueError, match="paired and present"):
        SourceUniverseEntry1.from_dict(
            {**data, "entry_digest": canonical_digest(data)}, budget=implementation_budget()
        )
    data = entry("protected", "excluded").to_dict()
    data.pop("entry_digest")
    data["disposition_decision"] = None
    with pytest.raises(ValueError, match="exact disposition decision"):
        SourceUniverseEntry1.from_dict(
            {**data, "entry_digest": canonical_digest(data)}, budget=implementation_budget()
        )


def test_source_proof_subject_class_and_original_reference_must_agree() -> None:
    """Proof and enclosing-entry hashes cannot substitute a foreign independent subject."""
    actual = entry()
    for changes in (
        {"owner_class": "task"},
        {"subject_digest": "d" * 64},
        {"source_object": reference("source-capture").to_dict()},
    ):
        data = actual.to_dict()
        proof = cast(dict[str, object], data["provenance"])
        proof.pop("proof_digest")
        proof.update(changes)
        proof["proof_digest"] = canonical_digest(proof)
        data.pop("entry_digest")
        with pytest.raises(ValueError, match="independent subject"):
            SourceUniverseEntry1.from_dict(
                {**data, "entry_digest": canonical_digest(data)}, budget=implementation_budget()
            )


def test_direct_runtime_types_closed_fields_and_explicit_limits_refuse() -> None:
    """Actual child classes and bounded nested parsing remain mandatory for builders too."""
    actual = entry()
    invalid_children: tuple[dict[str, object], ...] = ({"existing_source": {}}, {"provenance": {}})
    for changes in invalid_children:
        with pytest.raises(ValueError, match="actual reference"):
            SourceUniverseEntry1(**{**actual.__dict__, **changes})
    data = actual.to_dict()
    for malformed in (
        None,
        {**data, "accepted": True},
        {k: v for k, v in data.items() if k != "locator"},
    ):
        with pytest.raises(ValueError):
            SourceUniverseEntry1.from_dict(malformed, budget=implementation_budget())
    for limits in (implementation_budget(max_references=3), implementation_budget(max_depth=2)):
        with pytest.raises(ValueError, match="parser budget"):
            SourceUniverseEntry1.from_dict(data, budget=limits)
    with pytest.raises(ValueError, match="budget is required"):
        SourceUniverseEntry1.from_dict(data, budget=cast(PolicyReadBudget1, {}))
    with pytest.raises(ValueError, match="actual reference"):
        SourceUniverseEntry1.build(
            source_id=actual.source_id,
            existing_source=cast(TypedObjectRef1, {}),
            classification=actual.classification,
            locator=actual.locator,
            byte_digest=actual.byte_digest,
            byte_count=actual.byte_count,
            read_state=actual.read_state,
            disposition=actual.disposition,
            disposition_decision=actual.disposition_decision,
            provenance=actual.provenance,
            budget=implementation_budget(),
        )
    with pytest.raises(ValueError, match="digest differs"):
        replace(actual, entry_digest="0" * 64)
