# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — source-bound qualitative control tests
"""Exercise exact rule/evidence binding and the unchanged original remediation owner."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_atomic_rule import rule
from test_evidence_contract_v2 import evidence_contract
from test_policy_model_inputs import budget
from test_review_policy import review_policy
from test_standard_pack import control

from rigor_foundry.atomic_rule import AtomicRule1
from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.control_definition_v2 import ControlDefinition2
from rigor_foundry.evidence_contract_v2 import EvidenceContract2
from rigor_foundry.policy_source_reads import read_policy_document
from rigor_foundry.rule_scope import RuleScope1
from rigor_foundry.standard_pack import RemediationContract


def qualitative_control(*, conditional: bool = True) -> ControlDefinition2:
    """Build an actual qualitative control with complete original remediation semantics."""
    return ControlDefinition2.build(
        control_id="qualitative/source-quality",
        version="1.0.0",
        title="Preserve exact source quality obligations",
        domain="architecture-and-wiring",
        severity="P1",
        target_level="production",
        mode="require",
        rule_id="rule",
        scope=rule(conditional=conditional).scope,
        evidence=evidence_contract(),
        remediation=control().remediation,
        budget=budget(),
    )


def bound_rule(value: ControlDefinition2) -> AtomicRule1:
    """Join exact current rule metadata to actual new control and review component references."""
    actual = rule(conditional=value.scope.scope_kind == "scoped")
    refs = (
        *actual.component_refs,
        value.reference(budget=budget()),
        review_policy().reference(budget=budget()),
    )
    refs = tuple(sorted(refs, key=lambda ref: (ref.kind, ref.format_version, ref.object_id)))
    data = actual.to_dict(budget=budget())
    data["component_refs"] = [ref.to_dict() for ref in refs]
    data.pop("rule_digest")
    data["rule_digest"] = canonical_digest(data)
    return AtomicRule1.from_dict(data, budget=budget())


@pytest.mark.parametrize("conditional", [False, True])
def test_complete_new_control_preserves_original_remediation_and_exact_rule_binding(
    conditional: bool,
) -> None:
    """Public new control/rule parsers retain exact scope/mode and original child bytes."""
    value = qualitative_control(conditional=conditional)
    data = value.to_dict(budget=budget())
    assert ControlDefinition2.from_dict(data, budget=budget()) == value
    assert data["remediation"] == control().remediation.to_dict()
    assert data["evidence"] == value.evidence.to_dict(budget=budget())
    assert "default_applicable" not in data and "condition" not in data
    assert data.pop("control_digest") == canonical_digest(data)
    ref = value.reference(budget=budget())
    assert (ref.kind, ref.format_version, ref.object_id, ref.object_digest) == (
        "control-definition",
        "2.0",
        "qualitative/source-quality@1.0.0",
        value.control_digest,
    )
    actual = bound_rule(value)
    value.verify_rule_binding(actual, budget=budget())
    assert value.reference(budget=budget()) in actual.component_refs


def test_actual_file_reader_and_original_remediation_order_and_text_are_preserved(
    tmp_path: Path,
) -> None:
    """Original non-normalized remediation strings/order stay byte-identical under the new owner."""
    value = qualitative_control()
    data = value.to_dict(budget=budget())
    remediation = cast(dict[str, object], data["remediation"])
    remediation["dependencies"] = ["z first", "a second"]
    remediation["procedure_ids"] = ["  exact original procedure text  "]
    remediation.pop("contract_digest")
    remediation["contract_digest"] = canonical_digest(remediation)
    data.pop("control_digest")
    data["control_digest"] = canonical_digest(data)
    path = tmp_path / "control.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    parsed = ControlDefinition2.from_dict(
        read_policy_document(path, budget=budget()), budget=budget()
    )
    assert parsed.remediation.to_dict() == remediation
    assert parsed.to_dict(budget=budget()) == data
    with pytest.raises(ValueError):
        ControlDefinition2.from_dict(control().to_dict(), budget=budget())


def test_rule_identity_mode_scope_and_component_relation_are_all_exact() -> None:
    """Rehashing a valid but different rule cannot repair the selected control relation."""
    value = qualitative_control()
    actual = bound_rule(value)
    changes: tuple[dict[str, object], ...] = (
        {"rule_id": "other"},
        {"mode": "deny"},
        {"scope": rule().scope.to_dict(budget=budget())},
        {
            "component_refs": [
                ref.to_dict()
                for ref in actual.component_refs
                if ref != value.reference(budget=budget())
            ]
        },
    )
    for changed in changes:
        data = actual.to_dict(budget=budget())
        data.pop("rule_digest")
        data.update(changed)
        data["rule_digest"] = canonical_digest(data)
        different = AtomicRule1.from_dict(data, budget=budget())
        with pytest.raises(ValueError, match="exact source rule binding"):
            value.verify_rule_binding(different, budget=budget())
    with pytest.raises(ValueError, match="actual atomic rule"):
        value.verify_rule_binding(cast(AtomicRule1, {}), budget=budget())


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("schema_version", "1.0"),
        ("object_kind", "legacy-control"),
        ("control_id", "bad identity"),
        ("version", "latest"),
        ("title", " "),
        ("domain", "caller"),
        ("severity", "P5"),
        ("target_level", "complete"),
        ("mode", "observe"),
        ("rule_id", "bad identity"),
        ("scope", {}),
        ("evidence", {}),
        ("remediation", {}),
        ("control_digest", "0" * 64),
    ],
)
def test_rehashed_malformed_fields_never_become_qualitative_controls(
    field: str, invalid: object
) -> None:
    """Existing domain/severity/maturity and exact child contracts cannot be relaxed by hashing."""
    data = qualitative_control().to_dict(budget=budget())
    data.pop("control_digest")
    data[field] = invalid
    digest = "0" * 64 if field == "control_digest" else canonical_digest(data)
    with pytest.raises(ValueError):
        ControlDefinition2.from_dict({**data, "control_digest": digest}, budget=budget())


def test_direct_child_types_original_immutable_arrays_and_whole_reference_budget_refuse() -> None:
    """Direct dataclasses revalidate every child and complete original remediation allocation."""
    value = qualitative_control()
    for invalid in [
        replace(value, scope=cast(RuleScope1, {})),
        replace(value, evidence=cast(EvidenceContract2, {})),
        replace(value, remediation=cast(RemediationContract, {})),
    ]:
        with pytest.raises(ValueError, match="actual scope, evidence and original remediation"):
            invalid.to_dict(budget=budget())
    with pytest.raises(ValueError, match="aggregate reference budget"):
        value.to_dict(budget=budget(references=10))
    with pytest.raises(ValueError, match="immutable child sequences"):
        replace(
            value, remediation=replace(value.remediation, dependencies=cast(tuple[str, ...], []))
        ).to_dict(budget=budget())
    with pytest.raises(ValueError, match="remediation exceeds"):
        replace(
            value,
            remediation=replace(
                value.remediation,
                dependencies=tuple(f"dependency-{index}" for index in range(129)),
            ),
        ).to_dict(budget=budget())
    with pytest.raises(ValueError, match="control digest"):
        replace(value, control_digest="0" * 64).to_dict(budget=budget())


def test_original_remediation_wire_is_closed_before_its_unchanged_legacy_parser() -> None:
    """Unknown fields, wrong collection types and excessive rows refuse before original allocation."""
    changes: tuple[dict[str, object], ...] = (
        {"extension": True},
        {"dependencies": "named"},
        {"dependencies": [f"dependency-{index}" for index in range(129)]},
    )
    for changed in changes:
        data = qualitative_control().to_dict(budget=budget())
        remediation = cast(dict[str, object], data["remediation"])
        remediation.update(changed)
        with pytest.raises(ValueError):
            ControlDefinition2.from_dict(data, budget=budget())
    data = qualitative_control().to_dict(budget=budget())
    remediation = cast(dict[str, object], data["remediation"])
    remediation["schema_version"] = "2.0"
    with pytest.raises(ValueError, match="unsupported remediation"):
        ControlDefinition2.from_dict(data, budget=budget())


def test_closed_new_control_has_no_extension_or_omitted_default() -> None:
    """The explicit new applicability owner never falls back to a legacy Boolean/default."""
    data = qualitative_control().to_dict(budget=budget())
    for invalid in [
        None,
        {**data, "default_applicable": False},
        {key: item for key, item in data.items() if key != "scope"},
    ]:
        with pytest.raises(ValueError):
            ControlDefinition2.from_dict(invalid, budget=budget())
