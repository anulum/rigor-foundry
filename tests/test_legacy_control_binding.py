# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — original legacy control binding tests
"""Preserve actual signed-pack membership and every original numeric control obligation."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_component_source_resolution import original_pack
from test_control_definition_v2 import qualitative_control
from test_policy_model_inputs import budget
from test_standard_pack import control
from test_typed_object_reference import reference

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.component_source_resolution import StandardPackSource2
from rigor_foundry.legacy_control_binding import LegacyControlBinding1
from rigor_foundry.policy_source_reads import read_policy_document
from rigor_foundry.source_component_reader import PolicyComponent1


def legacy_binding() -> LegacyControlBinding1:
    """Bind an exact original architecture control without generating a legacy lock."""
    pack = original_pack()
    return LegacyControlBinding1.build(
        rule_id="rule",
        pack=StandardPackSource2(pack, budget(size=65536)).reference(),
        control=PolicyComponent1(pack.controls[0], budget()).reference(),
        source_decision_ids=("adopt-original", "preserve-review"),
        budget=budget(),
    )


def test_original_member_keeps_all_numeric_evidence_applicability_and_remediation() -> None:
    """Actual public binding returns the whole original selected control, with no lossy conversion."""
    binding = legacy_binding()
    actual = binding.verify_pack(original_pack(), budget=budget(size=65536))
    assert actual == control()
    assert actual.evidence.to_dict() == control().evidence.to_dict()
    assert actual.evidence.freshness_seconds == 3600
    assert actual.evidence.minimum_independent_reviewers == 1
    assert actual.default_applicable and actual.condition is not None
    expected = control()
    assert expected.condition is not None
    assert actual.condition.to_dict() == expected.condition.to_dict()
    assert actual.target_level == "production" and actual.remediation == control().remediation
    data = binding.to_dict(budget=budget())
    assert LegacyControlBinding1.from_dict(data, budget=budget()) == binding
    assert data.pop("binding_digest") == canonical_digest(data)
    assert not {"lock", "waiver", "override", "freshness_seconds"}.intersection(data)


def test_actual_file_reader_preserves_exact_source_decisions(tmp_path: Path) -> None:
    """The bounded file API retains the complete explicit original relation and rejects duplicate keys."""
    binding = legacy_binding()
    path = tmp_path / "legacy-binding.json"
    path.write_text(json.dumps(binding.to_dict(budget=budget())), encoding="utf-8")
    assert (
        LegacyControlBinding1.from_dict(
            read_policy_document(path, budget=budget()), budget=budget()
        )
        == binding
    )
    path.write_text('{"rule_id":"rule","rule_id":"other"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        read_policy_document(path, budget=budget())


def test_pack_identity_membership_and_complete_owning_digest_are_mandatory() -> None:
    """A missing member, changed pack or same-looking control digest cannot stand in for the original."""
    value = legacy_binding()
    empty = original_pack(controls=())
    with pytest.raises(ValueError, match="complete original pack"):
        value.verify_pack(empty, budget=budget(size=65536))
    data = value.to_dict(budget=budget())
    data["pack"] = StandardPackSource2(empty, budget(size=65536)).reference().to_dict()
    data.pop("binding_digest")
    data["binding_digest"] = canonical_digest(data)
    missing = LegacyControlBinding1.from_dict(data, budget=budget())
    with pytest.raises(ValueError, match="exact member"):
        missing.verify_pack(empty, budget=budget(size=65536))
    for changed in [
        reference("standard-pack", "2.0", "other-pack"),
        reference("control-definition", "1.0", value.control.object_id, "0" * 64),
    ]:
        data = value.to_dict(budget=budget())
        data["pack" if changed.kind == "standard-pack" else "control"] = changed.to_dict()
        data.pop("binding_digest")
        data["binding_digest"] = canonical_digest(data)
        modified = LegacyControlBinding1.from_dict(data, budget=budget())
        with pytest.raises(ValueError, match=r"original pack|exact member"):
            modified.verify_pack(original_pack(), budget=budget(size=65536))
    with pytest.raises(ValueError, match="actual original pack2"):
        value.verify_pack({}, budget=budget())


@pytest.mark.parametrize(
    "field,bad",
    [
        ("schema_version", "2.0"),
        ("object_kind", "other"),
        ("rule_id", "bad identity"),
        ("source_decision_ids", ["z", "a"]),
        ("source_decision_ids", ["a", "a"]),
        ("source_decision_ids", [1]),
        ("source_decision_ids", {}),
        ("pack", reference().to_dict()),
        ("control", qualitative_control().reference(budget=budget()).to_dict()),
    ],
)
def test_rehashed_wrong_versions_pairs_and_decision_sets_refuse(field: str, bad: object) -> None:
    """Rehashing cannot permit a new pack generation, qualitative cast or reordered source obligations."""
    data = legacy_binding().to_dict(budget=budget())
    data.pop("binding_digest")
    data[field] = bad
    with pytest.raises(ValueError):
        LegacyControlBinding1.from_dict(
            {**data, "binding_digest": canonical_digest(data)}, budget=budget()
        )


def test_direct_instances_closed_fields_and_aggregate_counts_refuse() -> None:
    """Direct mutation, malformed arrays and unbounded complete references are rechecked at use."""
    value = legacy_binding()
    for changed in [
        replace(value, binding_digest="0" * 64),
        replace(value, source_decision_ids=cast(tuple[str, ...], [])),
    ]:
        with pytest.raises(ValueError):
            changed.to_dict(budget=budget())
    data = value.to_dict(budget=budget())
    for changed_wire in [
        {**data, "override": True},
        {key: row for key, row in data.items() if key != "control"},
    ]:
        with pytest.raises(ValueError):
            LegacyControlBinding1.from_dict(changed_wire, budget=budget())
    for maximum in [1, 3]:
        limits = budget(references=maximum)
        with pytest.raises(ValueError, match="reference budget"):
            value.to_dict(budget=limits)
        with pytest.raises(ValueError, match="source-decision array"):
            LegacyControlBinding1.from_dict(data, budget=limits)
    empty = LegacyControlBinding1.build(
        rule_id=value.rule_id,
        pack=value.pack,
        control=value.control,
        source_decision_ids=(),
        budget=budget(references=2),
    )
    assert empty.source_decision_ids == ()
