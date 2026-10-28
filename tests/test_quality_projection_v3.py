# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — original and qualitative projection tests
"""Exercise exact owning control relations without a fabricated legacy profile lock."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_atomic_rule import rule
from test_control_definition_v2 import qualitative_control
from test_policy_model_inputs import budget
from test_semantic_decision import decision
from test_standard_pack import control
from test_typed_object_reference import reference

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.condition_language import ConditionExpression
from rigor_foundry.control_definition_v2 import ControlDefinition2
from rigor_foundry.policy_source_reads import read_policy_document
from rigor_foundry.quality_projection_v3 import (
    ContractCase,
    QualityProjectionRowV3,
    validate_quality_projection,
)
from rigor_foundry.rule_scope import RuleScope1
from rigor_foundry.source_component_reader import PolicyComponent1
from rigor_foundry.standard_pack import ControlDefinition, TargetLevel
from rigor_foundry.typed_object_reference import TypedObjectRef1


def projection(*, qualitative: bool = True, conditional: bool = True) -> QualityProjectionRowV3:
    """Build complete actual owner relations while leaving selection and fact evaluation separate."""
    if qualitative:
        selected = qualitative_control(conditional=conditional)
        control_ref = selected.reference(budget=budget())
        evidence_ref = selected.evidence.reference(budget=budget())
        review = selected.evidence.review_policy
        default = None
        expression = None
        case: ContractCase = "qualitative2"
    else:
        original = control()
        control_ref = PolicyComponent1(original, budget()).reference()
        evidence_ref = PolicyComponent1(original.evidence, budget()).reference()
        review = None
        default = original.default_applicable
        expression = original.condition
        case = "legacy1"
    return QualityProjectionRowV3.build(
        control=control_ref,
        source_rule_ids=("rule",),
        scope=rule(conditional=conditional).scope,
        contract_case=case,
        evidence_contract=evidence_ref,
        review_policy=review,
        target_level="production",
        default_applicable=default,
        condition=expression,
        applicability_decisions=(decision("adoption").reference(budget=budget()),),
        budget=budget(),
    )


@pytest.mark.parametrize("qualitative", [False, True])
@pytest.mark.parametrize("conditional", [False, True])
def test_both_actual_control_generations_keep_complete_obligations(
    qualitative: bool, conditional: bool
) -> None:
    """The exact same public binding retains original fields or explicit qualitative scope."""
    value = projection(qualitative=qualitative, conditional=conditional)
    wire = value.to_dict(budget=budget())
    assert QualityProjectionRowV3.from_dict(wire, budget=budget()) == value
    selected = qualitative_control(conditional=conditional) if qualitative else control()
    value.verify_control_binding(selected, budget=budget())
    assert wire.pop("row_digest") == canonical_digest(wire)
    if qualitative:
        assert value.default_applicable is None and value.condition is None
        assert value.review_policy is not None
    else:
        assert value.default_applicable is control().default_applicable
        assert value.condition == control().condition
        assert value.review_policy is None
        assert (
            value.evidence_contract == PolicyComponent1(control().evidence, budget()).reference()
        )


def test_retained_json_has_exact_wire_and_no_implicit_applicability(tmp_path: Path) -> None:
    """Actual file reads preserve both closed rows and reject duplicate field names."""
    path = tmp_path / "quality.json"
    for qualitative in [False, True]:
        value = projection(qualitative=qualitative)
        path.write_text(json.dumps(value.to_dict(budget=budget())), encoding="utf-8")
        assert (
            QualityProjectionRowV3.from_dict(
                read_policy_document(path, budget=budget()), budget=budget()
            )
            == value
        )
    path.write_text('{"contract_case":"legacy1","contract_case":"qualitative2"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        read_policy_document(path, budget=budget())


@pytest.mark.parametrize(
    "field,invalid",
    [
        ("schema_version", "2.0"),
        ("object_kind", "quality"),
        ("control", {}),
        ("contract_case", "automatic"),
        ("contract_case", 1),
        ("source_rule_ids", []),
        ("source_rule_ids", ["z", "a"]),
        ("source_rule_ids", ["rule", "rule"]),
        ("source_rule_ids", ["bad identity"]),
        ("scope", {}),
        ("evidence_contract", {}),
        ("review_policy", None),
        ("target_level", "complete"),
        ("default_applicable", False),
        ("condition", cast(ConditionExpression, control().condition).to_dict()),
        ("applicability_decisions", {}),
        ("row_digest", "0" * 64),
    ],
)
def test_rehashing_cannot_rewrite_closed_qualitative_relations(
    field: str, invalid: object
) -> None:
    """Unknown cases, legacy defaults, invalid identities and malformed children refuse."""
    wire = projection().to_dict(budget=budget())
    wire.pop("row_digest")
    wire[field] = invalid
    digest = "0" * 64 if field == "row_digest" else canonical_digest(wire)
    with pytest.raises(ValueError):
        QualityProjectionRowV3.from_dict({**wire, "row_digest": digest}, budget=budget())


def test_legacy_default_and_absent_condition_remain_explicit_original_values() -> None:
    """A false original default or absent old condition is never inferred from a qualitative scope."""
    source = control().to_dict()
    source["condition"] = None
    source["default_applicable"] = False
    source.pop("control_digest")
    source["control_digest"] = canonical_digest(source)
    original = ControlDefinition.from_dict(source)
    value = projection(qualitative=False)
    body = value.to_dict(budget=budget())
    body.update(
        control=PolicyComponent1(original, budget()).reference().to_dict(),
        condition=None,
        default_applicable=False,
    )
    body.pop("row_digest")
    actual = QualityProjectionRowV3.from_dict(
        {**body, "row_digest": canonical_digest(body)}, budget=budget()
    )
    actual.verify_control_binding(original, budget=budget())
    assert actual.default_applicable is False and actual.condition is None
    for changed in [
        replace(actual, default_applicable=None),
        replace(actual, review_policy=reference("review-policy", "1.0")),
    ]:
        with pytest.raises(ValueError):
            changed.to_dict(budget=budget())


def test_closed_reference_generations_and_decision_identities_refuse() -> None:
    """Same-looking targets and duplicate semantic identities cannot alter the selected generation."""
    value = projection()
    legacy = projection(qualitative=False)
    ref = value.applicability_decisions[0]
    changes = [
        replace(value, control=legacy.control),
        replace(value, evidence_contract=legacy.evidence_contract),
        replace(value, review_policy=reference()),
        replace(value, applicability_decisions=(reference(),)),
        replace(value, applicability_decisions=(ref, ref)),
        replace(value, applicability_decisions=(reference("semantic-decision", "1.0", "z"), ref)),
        replace(value, applicability_decisions=cast(tuple[TypedObjectRef1, ...], [ref])),
        replace(value, source_rule_ids=cast(tuple[str, ...], ["rule"])),
        replace(value, scope=cast(RuleScope1, {})),
    ]
    for changed in changes:
        with pytest.raises(ValueError):
            changed.to_dict(budget=budget())


def test_complete_projection_to_control_binding_rejects_rehashed_obligation_changes() -> None:
    """An internally valid row must still match the owning control's exact complete semantics."""
    for qualitative in [False, True]:
        value = projection(qualitative=qualitative)
        selected = qualitative_control() if qualitative else control()
        replacements: list[dict[str, object]] = [
            {
                "control": reference(
                    "control-definition", "2.0" if qualitative else "1.0"
                ).to_dict()
            },
            {
                "evidence_contract": reference(
                    "evidence-contract", "2.0" if qualitative else "1.0"
                ).to_dict()
            },
            {"target_level": "enterprise"},
        ]
        if qualitative:
            replacements.extend(
                [
                    {"scope": rule().scope.to_dict(budget=budget())},
                    {"source_rule_ids": ["other-rule"]},
                    {"review_policy": reference("review-policy", "1.0").to_dict()},
                ]
            )
        else:
            replacements.extend([{"default_applicable": False}, {"condition": None}])
        for changes in replacements:
            body = value.to_dict(budget=budget())
            body.pop("row_digest")
            body.update(changes)
            changed = QualityProjectionRowV3.from_dict(
                {**body, "row_digest": canonical_digest(body)}, budget=budget()
            )
            with pytest.raises(ValueError, match="complete owning control"):
                changed.verify_control_binding(selected, budget=budget())
        with pytest.raises(ValueError, match="owning control generation"):
            value.verify_control_binding(
                qualitative_control() if not qualitative else control(), budget=budget()
            )
        with pytest.raises(ValueError, match="owning control generation"):
            value.verify_control_binding({}, budget=budget())


def test_row_allocation_and_complete_bytes_are_bounded_before_child_construction() -> None:
    """Direct and parsed rows enforce aggregate counts, immutable arrays, bytes and integrity."""
    value = projection()
    wire = value.to_dict(budget=budget())
    for key in ["source_rule_ids", "applicability_decisions"]:
        bad = {**wire, key: [None] * 129}
        with pytest.raises(ValueError, match="reference allocation budget"):
            QualityProjectionRowV3.from_dict(bad, budget=budget(size=65536))
    with pytest.raises(ValueError, match="exact arrays"):
        QualityProjectionRowV3.from_dict({**wire, "source_rule_ids": {}}, budget=budget())
    with pytest.raises(ValueError, match="aggregate reference budget"):
        value.to_dict(budget=budget(references=5))
    with pytest.raises(ValueError, match="reference allocation budget"):
        QualityProjectionRowV3.from_dict(wire, budget=budget(references=4))
    with pytest.raises(ValueError, match="immutable decision references"):
        replace(value, applicability_decisions=value.applicability_decisions * 129).to_dict(
            budget=budget()
        )
    with pytest.raises(ValueError, match="row digest differs"):
        replace(value, row_digest="0" * 64).to_dict(budget=budget())
    with pytest.raises(ValueError):
        replace(value, condition=cast(ConditionExpression, {})).to_dict(budget=budget())
    with pytest.raises(ValueError):
        replace(value, target_level=cast(TargetLevel, "unsupported")).to_dict(budget=budget())
    for invalid in [
        None,
        {**wire, "extension": True},
        {key: item for key, item in wire.items() if key != "scope"},
    ]:
        with pytest.raises(ValueError):
            QualityProjectionRowV3.from_dict(invalid, budget=budget())


@pytest.mark.parametrize("conditional", [False, True])
def test_complete_mixed_projection_preserves_every_selected_control(conditional: bool) -> None:
    """One complete row for each real selected generation passes without a legacy lock."""
    rows = tuple(
        sorted(
            (
                projection(qualitative=False, conditional=conditional),
                projection(conditional=conditional),
            ),
            key=lambda row: row.control.object_id,
        )
    )
    selected = (control(), qualitative_control(conditional=conditional))
    validate_quality_projection(rows, selected, budget=budget(size=65536))
    validate_quality_projection((), (), budget=budget())


def test_missing_extra_duplicate_or_reordered_rows_cannot_hide_a_selected_control() -> None:
    """The complete supplied selected cohort is validated, including unselected malformed children."""
    old, new = projection(qualitative=False), projection()
    rows = (old, new)
    selected = (control(), qualitative_control())
    for submitted, owners in [
        ((old,), selected),
        ((), selected),
        (rows, (control(),)),
        ((new, old), selected),
        ((old, old), selected),
        (rows, (*selected, control())),
    ]:
        with pytest.raises(
            ValueError, match=r"missing|no actual selected|sorted and unique|duplicate identity"
        ):
            validate_quality_projection(submitted, owners, budget=budget(size=65536))
    for bad_rows, bad_controls in [
        (cast(tuple[QualityProjectionRowV3, ...], list(rows)), selected),
        (rows, cast(tuple[ControlDefinition | ControlDefinition2, ...], list(selected))),
        (cast(tuple[QualityProjectionRowV3, ...], ({},)), selected),
        (rows, cast(tuple[ControlDefinition | ControlDefinition2, ...], ({},))),
    ]:
        with pytest.raises(ValueError, match=r"bounded immutable|actual complete"):
            validate_quality_projection(bad_rows, bad_controls, budget=budget(size=65536))
    corrupted = replace(control(), evidence=replace(control().evidence, freshness_seconds=0))
    with pytest.raises(ValueError):
        validate_quality_projection(
            rows, (corrupted, qualitative_control()), budget=budget(size=65536)
        )


def test_complete_projection_enforces_row_count_reference_and_encoded_array_bounds() -> None:
    """Each row can fit individually while its complete mixed projection still exceeds a bound."""
    rows = (projection(qualitative=False), projection())
    selected = (control(), qualitative_control())
    for submitted, owners in [(rows * 17, selected), (rows, selected * 17)]:
        with pytest.raises(ValueError, match="bounded immutable"):
            validate_quality_projection(submitted, owners, budget=budget(size=65536))
    with pytest.raises(ValueError, match="cohort exceeds the aggregate reference"):
        validate_quality_projection(rows, selected, budget=budget(size=65536, references=11))
    encoded = json.dumps(
        [row.to_dict(budget=budget()) for row in rows],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    validate_quality_projection(rows, selected, budget=budget(size=len(encoded)))
    with pytest.raises(ValueError, match="cohort exceeds the aggregate byte"):
        validate_quality_projection(rows, selected, budget=budget(size=len(encoded) - 1))
    with pytest.raises(ValueError, match="byte budget"):
        validate_quality_projection((), (), budget=budget(size=1))
