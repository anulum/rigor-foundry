# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete policy hold declaration tests
"""Exercise bounded hold wires against actual original control and evidence owners."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_policy_model_inputs import budget
from test_standard_pack import control

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.policy_hold import PolicyHold1
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_reads import read_policy_document
from rigor_foundry.source_component_reader import PolicyComponent1, resolve_policy_component
from rigor_foundry.typed_object_reference import TypedObjectRef1


def declared_hold(*, empty: bool = False) -> PolicyHold1:
    """Bind the actual original numeric control and its exact evidence contract."""
    original = control()
    return PolicyHold1.build(
        code="evidence-unavailable",
        subject=PolicyComponent1(original, budget()).reference(),
        affected_rule_ids=() if empty else ("module-responsibility",),
        evidence=() if empty else (PolicyComponent1(original.evidence, budget()).reference(),),
        budget=budget(),
    )


@pytest.mark.parametrize("empty", [False, True])
def test_complete_hold_roundtrips_through_actual_bounded_file_reader(
    tmp_path: Path, empty: bool
) -> None:
    """Exact original references and explicit empty arrays survive a real serialized read."""
    value = declared_hold(empty=empty)
    wire = value.to_dict(budget=budget())
    assert len(wire) == 7
    assert wire["schema_version"] == "1.0" and wire["object_kind"] == "policy-hold"
    assert value.hold_digest == canonical_digest(
        {key: item for key, item in wire.items() if key != "hold_digest"}
    )
    path = tmp_path / "held-policy.json"
    path.write_text(json.dumps(wire), encoding="utf-8")
    parsed = PolicyHold1.from_dict(read_policy_document(path, budget=budget()), budget=budget())
    assert parsed == value
    original = control()
    owner = PolicyComponent1(original, budget())
    assert resolve_policy_component(parsed.subject, (owner,), budget=budget()) == owner
    assert parsed.subject.object_digest == original.control_digest
    if empty:
        assert parsed.affected_rule_ids == ()
        assert parsed.evidence == ()
    else:
        evidence = PolicyComponent1(original.evidence, budget())
        assert (
            resolve_policy_component(parsed.evidence[0], (evidence,), budget=budget()) == evidence
        )
        assert original.evidence.minimum_independent_reviewers == 1


def test_different_declared_reason_or_subject_changes_complete_identity() -> None:
    """The owning digest covers the exact reason and actual complete component target."""
    value = declared_hold()
    other = PolicyHold1.build(
        code="source-unavailable",
        subject=PolicyComponent1(control(control_id="other/module"), budget()).reference(),
        affected_rule_ids=value.affected_rule_ids,
        evidence=value.evidence,
        budget=budget(),
    )
    assert value.hold_digest != other.hold_digest
    assert PolicyHold1.from_dict(other.to_dict(budget=budget()), budget=budget()) == other
    for changed in (replace(value, code=other.code), replace(value, subject=other.subject)):
        with pytest.raises(ValueError, match="hold digest differs"):
            changed.to_dict(budget=budget())


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "2.0"),
        ("schema_version", 1),
        ("object_kind", "selected-policy-binding"),
        ("code", "raw exception: /private/path"),
        ("affected_rule_ids", ["z", "a"]),
        ("affected_rule_ids", ["a", "a"]),
        ("affected_rule_ids", [True]),
        ("affected_rule_ids", {}),
        ("evidence", {}),
        ("subject", {}),
    ],
)
def test_recomputed_digest_cannot_admit_wrong_fields_or_collections(
    field: str, value: object
) -> None:
    """Rehashing malformed input supplies no supported schema, order or reference."""
    wire = declared_hold().to_dict(budget=budget())
    wire[field] = value
    wire["hold_digest"] = canonical_digest(
        {key: item for key, item in wire.items() if key != "hold_digest"}
    )
    with pytest.raises(ValueError):
        PolicyHold1.from_dict(wire, budget=budget())


def test_unknown_and_missing_fields_and_stale_digest_refuse() -> None:
    """No field is discarded and direct or wire digest substitutions refuse."""
    value = declared_hold()
    wire = value.to_dict(budget=budget())
    for changed in (
        {**wire, "resolution_status": "effective"},
        {key: item for key, item in wire.items() if key != "evidence"},
        {**wire, "hold_digest": "0" * 64},
    ):
        with pytest.raises(ValueError):
            PolicyHold1.from_dict(changed, budget=budget())
    with pytest.raises(ValueError, match="hold digest differs"):
        replace(value, hold_digest="0" * 64).to_dict(budget=budget())


def test_direct_mutable_or_nonowner_children_refuse() -> None:
    """Direct construction must satisfy the same complete collection and child-owner checks."""
    value = declared_hold()
    for changed in (
        replace(value, evidence=cast(tuple[TypedObjectRef1, ...], list(value.evidence))),
        replace(value, affected_rule_ids=cast(tuple[str, ...], ["module-responsibility"])),
        replace(value, subject=cast(TypedObjectRef1, {})),
        replace(value, evidence=(cast(TypedObjectRef1, {}),)),
    ):
        with pytest.raises(ValueError):
            changed.to_dict(budget=budget())


def test_evidence_order_and_identity_uniqueness_are_not_digest_order() -> None:
    """Supporting targets have typed identity ordering and cannot declare conflicting digests."""
    first = PolicyComponent1(control(control_id="a/module"), budget()).reference()
    last = PolicyComponent1(control(control_id="z/module"), budget()).reference()
    value = PolicyHold1.build(
        code="source-unavailable",
        subject=first,
        affected_rule_ids=("a-rule", "z-rule"),
        evidence=(first, last),
        budget=budget(),
    )
    assert PolicyHold1.from_dict(value.to_dict(budget=budget()), budget=budget()) == value
    conflicting = TypedObjectRef1.build(
        kind=first.kind,
        format_version=first.format_version,
        object_id=first.object_id,
        object_digest="f" * 64,
    )
    for refs in ((last, first), (first, first), (first, conflicting)):
        with pytest.raises(ValueError, match="sorted and unique"):
            replace(value, evidence=refs).to_dict(budget=budget())


def test_exact_aggregate_rule_reference_byte_and_depth_limits() -> None:
    """The subject, rules and evidence all consume the declared complete input budget."""
    value = declared_hold()
    wire = value.to_dict(budget=budget())
    assert PolicyHold1.from_dict(wire, budget=budget(references=3)) == value
    for limits in (budget(references=2), budget(size=1), budget(depth=1)):
        with pytest.raises(ValueError):
            value.to_dict(budget=limits)
        with pytest.raises(ValueError):
            PolicyHold1.from_dict(wire, budget=limits)
    body = {key: item for key, item in budget().to_dict().items() if key != "budget_digest"}
    body["max_rules"] = 1
    small = PolicyReadBudget1.from_dict({**body, "budget_digest": canonical_digest(body)})
    two_rules = replace(value, affected_rule_ids=("a-rule", "z-rule"))
    with pytest.raises(ValueError, match="affected rule budget"):
        two_rules.to_dict(budget=small)
    large_wire = {**wire, "affected_rule_ids": ["a-rule", "z-rule"]}
    with pytest.raises(ValueError, match="allocation budget"):
        PolicyHold1.from_dict(large_wire, budget=small)
    exact_size = len(json.dumps(wire, ensure_ascii=False, separators=(",", ":")).encode())
    assert value.to_dict(budget=budget(size=exact_size)) == wire
    with pytest.raises(ValueError, match="byte budget"):
        value.to_dict(budget=budget(size=exact_size - 1))


def test_reference_child_digest_and_file_duplicate_keys_are_rechecked(tmp_path: Path) -> None:
    """Neither a mutated child nor a duplicate JSON key survives the real public boundary."""
    value = declared_hold()
    object.__setattr__(value.evidence[0], "object_digest", "0" * 64)
    with pytest.raises(ValueError, match="reference digest differs"):
        value.to_dict(budget=budget())
    raw = json.dumps(declared_hold().to_dict(budget=budget()))
    path = tmp_path / "duplicate.json"
    path.write_text(raw[:-1] + ', "code": "source-unavailable"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        read_policy_document(path, budget=budget())
