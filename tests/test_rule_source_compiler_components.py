# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete real retained source compilation tests
"""Verify full target and original pack/component/source-rule compilation relations."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
from test_rule_source_compiler import (
    Targets,
    changed_document,
    changed_rule,
    compiled_document,
    rehashed,
    verify,
    with_control,
)
from test_source_component_reader import components
from test_source_universe_owner import owner, universe_selection

from rigor_foundry.control_definition_v2 import ControlDefinition2
from rigor_foundry.legacy_control_binding import LegacyControlBinding1
from rigor_foundry.rule_chain_pack_v2 import FreshnessPolicyV2
from rigor_foundry.rule_source_compiler import verify_rule_source_document
from rigor_foundry.source_component_reader import PolicyComponent1
from rigor_foundry.typed_object_reference import TypedObjectRef1


def test_invalid_complete_target_cohorts_and_global_identity_changes_refuse(
    tmp_path: Path,
) -> None:
    """Unused targets are still parsed, exact duplicate identities refuse and no loader is appointed."""
    with universe_selection(tmp_path / "selected") as selected, owner(selected) as actual:
        doc, targets = compiled_document(selected, actual)
        malformed_targets: list[object] = [
            list(targets),
            (None,),
            ((targets[0][0],),),
            (({}, {}),),
            (*targets, targets[0]),
        ]
        for wrong in malformed_targets:
            with pytest.raises(
                ValueError, match=r"immutable external|complete target pairs|duplicated"
            ):
                verify(doc, cast(Targets, wrong), selected, actual)
        with pytest.raises(ValueError, match="unresolved exact"):
            verify(doc, targets[1:], selected, actual)
        control = doc.qualitative_controls[0]
        wire = rehashed(
            control.to_dict(budget=selected.budget),
            "control_digest",
            title="Changed full original control identity",
        )
        changed = ControlDefinition2.from_dict(wire, budget=selected.budget)
        with pytest.raises(ValueError, match="inconsistent global"):
            verify(
                doc,
                (*targets, (changed.reference(budget=selected.budget), wire)),
                selected,
                actual,
            )
        extra = PolicyComponent1(components()[1].record, selected.budget)
        malformed = {**extra.to_dict(), "unknown": True}
        with pytest.raises(ValueError):
            verify(doc, (*targets, (extra.reference(), malformed)), selected, actual)
        for omitted in [targets[:1], (targets[0], targets[1])]:
            with pytest.raises(ValueError, match="unresolved exact"):
                verify(doc, omitted, selected, actual)


def test_original_pack_enumeration_source_ownership_and_component_sets_are_complete(
    tmp_path: Path,
) -> None:
    """Valid signatures and source bytes cannot excuse dropped original controls or owning relations."""
    with universe_selection(tmp_path / "selected") as selected, owner(selected) as actual:
        doc, targets = compiled_document(selected, actual)
        cases: list[tuple[str, list[dict[str, object]], str]] = [
            (
                "legacy_control_bindings",
                [doc.legacy_control_bindings[0].to_dict(budget=selected.budget)],
                "original selected pack control",
            ),
            ("authority_bindings", [], "original selected pack authority"),
            (
                "freshness_policies",
                [
                    p.to_dict()
                    for p in doc.freshness_policies
                    if not p.policy_id.startswith("core/")
                ],
                "original selected pack freshness",
            ),
        ]
        for field, wires, pattern in cases:
            changed = changed_document(doc, selected, **{field: wires})
            with pytest.raises(ValueError, match=pattern):
                verify(changed, targets, selected, actual)
        binding = doc.legacy_control_bindings[0]
        binding_updates: list[dict[str, object]] = [
            {"rule_id": "missing"},
            {"source_decision_ids": ["missing"]},
        ]
        for updates in binding_updates:
            wrong = LegacyControlBinding1.from_dict(
                rehashed(binding.to_dict(budget=selected.budget), "binding_digest", **updates),
                budget=selected.budget,
            )
            changed = changed_document(
                doc,
                selected,
                legacy_control_bindings=[
                    wrong.to_dict(budget=selected.budget),
                    doc.legacy_control_bindings[1].to_dict(budget=selected.budget),
                ],
            )
            with pytest.raises(ValueError, match=r"owning source rule|unresolved or unrelated"):
                verify(changed, targets, selected, actual)
        extra_rule = changed_rule(
            doc,
            selected,
            rule_id="another",
            component_refs=[],
            dependency_rule_ids=[],
            decision_ids=[],
            lifecycle="retired",
        )
        wrong_control = ControlDefinition2.from_dict(
            rehashed(
                doc.qualitative_controls[0].to_dict(budget=selected.budget),
                "control_digest",
                rule_id="missing",
            ),
            budget=selected.budget,
        )
        changed = with_control(doc, selected, wrong_control)
        with pytest.raises(ValueError, match="unresolved source rule"):
            verify(changed, targets, selected, actual)
        ref = doc.review_policies[0].reference(budget=selected.budget)
        without_review = changed_rule(
            doc,
            selected,
            component_refs=[item.to_dict() for item in doc.rules[0].component_refs if item != ref],
        )
        changed = changed_document(
            doc, selected, rules=[without_review.to_dict(budget=selected.budget)]
        )
        with pytest.raises(ValueError, match="review source-rule bindings"):
            verify(changed, targets, selected, actual)
        changed = changed_document(doc, selected, qualitative_controls=[])
        extra_target = (
            doc.qualitative_controls[0].reference(budget=selected.budget),
            doc.qualitative_controls[0].to_dict(budget=selected.budget),
        )
        with pytest.raises(ValueError, match="component cohorts differ"):
            verify(changed, (*targets, extra_target), selected, actual)
        naked = changed_rule(doc, selected, component_refs=[])
        changed = changed_document(
            doc,
            selected,
            rules=[naked.to_dict(budget=selected.budget)],
            qualitative_controls=[],
            review_policies=[],
            legacy_control_bindings=[],
            authority_bindings=[],
            freshness_policies=[],
        )
        with pytest.raises(ValueError, match="active rule lacks enforcement"):
            verify(changed, (), selected, actual)
        changed = changed_document(
            doc,
            selected,
            rules=[
                extra_rule.to_dict(budget=selected.budget),
                doc.rules[0].to_dict(budget=selected.budget),
            ],
            regions=[
                rehashed(
                    doc.regions[0].to_dict(), "region_digest", rule_ids=["another", "review-rule"]
                )
            ],
        )
        assert verify(changed, targets, selected, actual) == ("another", "review-rule")


def test_control_review_and_freshness_targets_must_be_exact_inline_source_components(
    tmp_path: Path,
) -> None:
    """An otherwise valid external substitute cannot silently change the document's inline policies."""
    with universe_selection(tmp_path / "selected") as selected, owner(selected) as actual:
        doc, targets = compiled_document(selected, actual)
        control = doc.qualitative_controls[0]
        evidence = control.evidence.to_dict(budget=selected.budget)
        review = doc.review_policies[0]
        from rigor_foundry.review_policy import ReviewPolicy1

        outside_review = ReviewPolicy1.from_dict(
            rehashed(
                review.to_dict(budget=selected.budget), "policy_digest", policy_id="outside-review"
            ),
            budget=selected.budget,
        )
        changed_evidence = rehashed(
            evidence,
            "contract_digest",
            review_policy=outside_review.reference(budget=selected.budget).to_dict(),
        )
        changed_control = ControlDefinition2.from_dict(
            rehashed(
                control.to_dict(budget=selected.budget),
                "control_digest",
                evidence=changed_evidence,
            ),
            budget=selected.budget,
        )
        with pytest.raises(ValueError, match="review policy is outside"):
            verify(
                with_control(doc, selected, changed_control),
                (
                    *targets,
                    (
                        outside_review.reference(budget=selected.budget),
                        outside_review.to_dict(budget=selected.budget),
                    ),
                ),
                selected,
                actual,
            )
        requirements = cast(list[dict[str, object]], evidence["requirements"])
        freshness = next(p for p in doc.freshness_policies if not p.policy_id.startswith("core/"))
        outside_freshness = FreshnessPolicyV2.from_dict(
            rehashed(freshness.to_dict(), "policy_digest", policy_id="outside-freshness")
        )
        outside_ref = PolicyComponent1(outside_freshness, selected.budget).reference()
        requirement_cases: list[tuple[dict[str, object], Targets, str]] = [
            (
                {"freshness_policy": outside_ref.to_dict()},
                ((outside_ref, outside_freshness.to_dict()),),
                "freshness is outside",
            ),
            ({"subject_class": "unrelated-domain"}, (), "subject classes differ"),
        ]
        for updates, extras, pattern in requirement_cases:
            first = rehashed(requirements[0], "requirement_digest", **updates)
            changed_evidence = rehashed(
                evidence, "contract_digest", requirements=[first, *requirements[1:]]
            )
            changed_control = ControlDefinition2.from_dict(
                rehashed(
                    control.to_dict(budget=selected.budget),
                    "control_digest",
                    evidence=changed_evidence,
                ),
                budget=selected.budget,
            )
            with pytest.raises(ValueError, match=pattern):
                verify(
                    with_control(doc, selected, changed_control),
                    (*targets, *extras),
                    selected,
                    actual,
                )


def test_complete_external_bytes_and_typed_reference_allocations_are_bounded(
    tmp_path: Path,
) -> None:
    """Individually valid unused full targets cannot evade aggregate compiler limits."""
    import json

    from test_evidence_contract_v2 import requirement
    from test_policy_model_inputs import budget

    from rigor_foundry.evidence_contract_v2 import EvidenceContract2

    with universe_selection(tmp_path / "selected") as selected, owner(selected) as actual:
        doc, targets = compiled_document(selected, actual)

        def size(value: object) -> int:
            """Count actual canonical UTF8 bytes for the complete public inputs."""
            return len(
                json.dumps(
                    value,
                    ensure_ascii=False,
                    sort_keys=True,
                    allow_nan=False,
                    separators=(",", ":"),
                ).encode()
            )

        wire = doc.to_dict(budget=selected.budget)
        target_wires = [{"reference": ref.to_dict(), "target": value} for ref, value in targets]
        complete = size({"document": wire, "targets": target_wires})
        assert verify_rule_source_document(
            doc,
            source_owner=actual,
            targets=targets,
            budget=budget(size=complete, references=2048),
        ) == ("review-rule",)
        for maximum in [complete - 1, size(wire) + size(target_wires[0]) - 1]:
            with pytest.raises(ValueError, match="byte budget"):
                verify_rule_source_document(
                    doc,
                    source_owner=actual,
                    targets=targets,
                    budget=budget(size=maximum, references=2048),
                )
        extras: list[tuple[TypedObjectRef1, object]] = []
        for identity in ["extra-a", "extra-b"]:
            contract = EvidenceContract2.build(
                contract_id=identity,
                requirements=tuple(requirement(f"type-{number:02}") for number in range(40)),
                review_policy=doc.review_policies[0].reference(budget=selected.budget),
                budget=selected.budget,
            )
            extras.append(
                (
                    contract.reference(budget=selected.budget),
                    contract.to_dict(budget=selected.budget),
                )
            )
        with pytest.raises(ValueError, match="typed references exceed"):
            verify_rule_source_document(
                doc,
                source_owner=actual,
                targets=(*targets, *extras),
                budget=budget(size=262144, references=100),
            )
        with pytest.raises(ValueError, match="immutable external targets"):
            verify_rule_source_document(
                doc,
                source_owner=actual,
                targets=targets * 101,
                budget=budget(size=262144, references=100),
            )


def test_original_nested_evidence_identity_is_registered_from_the_entire_original_pack(
    tmp_path: Path,
) -> None:
    """Unused external evidence cannot assign a second meaning to a nested original contract ID."""
    from test_component_source_resolution import original_pack

    from rigor_foundry.standard_pack import EvidenceContract

    with universe_selection(tmp_path / "selected") as selected, owner(selected) as actual:
        doc, targets = compiled_document(selected, actual)
        original = PolicyComponent1(original_pack().controls[0].evidence, selected.budget)
        assert verify(
            doc, (*targets, (original.reference(), original.to_dict())), selected, actual
        ) == ("review-rule",)
        changed = EvidenceContract.from_dict(
            rehashed(original.to_dict(), "contract_digest", freshness_seconds=3601)
        )
        wrong = PolicyComponent1(changed, selected.budget)
        with pytest.raises(ValueError, match="inconsistent global typed"):
            verify(doc, (*targets, (wrong.reference(), wrong.to_dict())), selected, actual)
