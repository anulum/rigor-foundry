# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete real retained source compilation tests
"""Compile actual retained source cohorts and complete original pack/component relations."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest
from test_atomic_rule import rule
from test_component_source_resolution import original_pack
from test_control_definition_v2 import qualitative_control
from test_review_policy import review_policy
from test_source_component_reader import adapter_source, components, reviewer_source
from test_source_universe_owner import UniverseSelection, owner, regions_for, universe_selection

from rigor_foundry.atomic_rule import AtomicRule1
from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.component_source_resolution import StandardPackSource2
from rigor_foundry.control_definition_v2 import ControlDefinition2
from rigor_foundry.legacy_control_binding import LegacyControlBinding1
from rigor_foundry.policy_source_regions import SourceRegion1
from rigor_foundry.policy_source_spans import SourceSpan1
from rigor_foundry.rule_chain_pack_v2 import FreshnessPolicyV2
from rigor_foundry.rule_source_compiler import (
    compile_rule_source_document,
    rule_source_compiler_contract_digest,
    verify_rule_source_document,
)
from rigor_foundry.rule_source_document import RuleSourceDocument1
from rigor_foundry.semantic_decision import SemanticDecision1
from rigor_foundry.source_component_reader import PolicyComponent1
from rigor_foundry.source_universe_owner import SourceUniverseOwner
from rigor_foundry.typed_object_reference import TypedObjectRef1

Targets = tuple[tuple[TypedObjectRef1, object], ...]


def compiled_document(
    selected: UniverseSelection, actual: SourceUniverseOwner
) -> tuple[RuleSourceDocument1, Targets]:
    """Build complete explicit declarations against real source bytes, not a mocked source owner."""
    limits = selected.budget
    source = selected.sources[0]
    assert source.payload is not None
    payload = source.payload.read()
    span = SourceSpan1.build(
        span_id="original",
        source_id=source.source_id,
        start_byte=0,
        end_byte=len(payload),
        payload=payload,
    )
    pack = original_pack()
    pack_ref = StandardPackSource2(pack, limits).reference()
    review = review_policy()
    control_wire = qualitative_control(conditional=False).to_dict(budget=limits)
    control_wire["rule_id"] = "review-rule"
    control_wire.pop("control_digest")
    control = ControlDefinition2.from_dict(
        {**control_wire, "control_digest": canonical_digest(control_wire)}, budget=limits
    )
    freshness = cast(FreshnessPolicyV2, components()[2].record)
    policies = tuple(
        sorted((*pack.freshness_policies, freshness), key=lambda item: item.policy_id)
    )
    authorities = tuple(
        PolicyComponent1(item, limits).reference() for item in pack.authority_clauses
    )
    legacy = tuple(
        LegacyControlBinding1.build(
            rule_id="review-rule",
            pack=pack_ref,
            control=PolicyComponent1(item, limits).reference(),
            source_decision_ids=("adopt-original",),
            budget=limits,
        )
        for item in pack.controls
    )
    refs = (
        *authorities,
        *(item.control for item in legacy),
        control.reference(budget=limits),
        review.reference(budget=limits),
        *(PolicyComponent1(item, limits).reference() for item in policies),
    )
    rule_wire = rule().to_dict(budget=limits)
    rule_wire.update(
        rule_id="review-rule",
        source_spans=[span.to_dict()],
        dependency_rule_ids=[],
        decision_ids=["adopt-original"],
        component_refs=[
            ref.to_dict()
            for ref in sorted(refs, key=lambda ref: (ref.kind, ref.format_version, ref.object_id))
        ],
    )
    rule_wire.pop("rule_digest")
    declared = AtomicRule1.from_dict(
        {**rule_wire, "rule_digest": canonical_digest(rule_wire)}, budget=limits
    )
    decision = SemanticDecision1.build(
        decision_id="adopt-original",
        relation="adoption",
        issuer_id=declared.issuer_id,
        issuer_class=declared.issuer_class,
        source_spans=(span,),
        affected_rule_ids=(declared.rule_id,),
        successor_rule_ids=(),
        condition=None,
        rationale="Declared preservation of all original components; independent acceptance required.",
        authority_proof=actual.observe()[0].provenance,
        budget=limits,
    )
    regions = list(regions_for(selected))
    regions[0] = SourceRegion1.build(
        source_id=source.source_id,
        start_byte=0,
        end_byte=len(payload),
        payload=payload,
        disposition="normative",
        rule_ids=(declared.rule_id,),
        decision_ids=(decision.decision_id,),
        reason_code="declared-normative",
    )
    externals = (adapter_source(), reviewer_source())
    targets: Targets = (
        (pack_ref, pack.to_dict()),
        *((item.reference(), item.to_dict()) for item in externals),
    )
    doc = compile_rule_source_document(
        corpus_id="complete-corpus",
        source_owner=actual,
        regions=tuple(regions),
        rules=(declared,),
        decisions=(decision,),
        qualitative_controls=(control,),
        review_policies=(review,),
        legacy_control_bindings=legacy,
        authority_bindings=authorities,
        freshness_policies=policies,
        targets=targets,
        budget=limits,
    )
    return doc, targets


@pytest.mark.parametrize("kind", ["capture", "native", "discovery"])
def test_compile_and_verify_use_complete_actual_original_owners_and_retained_bytes(
    tmp_path: Path, kind: str
) -> None:
    """Actual captures/native host pins/discovery cohorts feed one complete deterministic document."""
    with universe_selection(tmp_path / "selected", kind) as selected, owner(selected) as actual:
        document, targets = compiled_document(selected, actual)
        assert document.universe == actual.observe()
        assert verify_rule_source_document(
            document, source_owner=actual, targets=targets, budget=selected.budget
        ) == ("review-rule",)
        repeated, _ = compiled_document(selected, actual)
        assert repeated == document
        assert document.compiler_contract_digest == rule_source_compiler_contract_digest()
        assert document.compiler_contract_digest != document.document_digest
        assert len(document.legacy_control_bindings) == 2
        assert not {
            "signature",
            "accepted",
            "pack_digest",
            "lock_digest",
            "observed_at",
        }.intersection(document.to_dict(budget=selected.budget))


def rehashed(value: dict[str, object], digest: str, **changes: object) -> dict[str, object]:
    """Change explicit public wire inputs while keeping only their owning structural digest valid."""
    wire = {**value, **changes}
    wire.pop(digest)
    return {**wire, digest: canonical_digest(wire)}


def changed_document(
    document: RuleSourceDocument1, selected: UniverseSelection, **changes: object
) -> RuleSourceDocument1:
    """Reparse altered public document wire, never call private production helpers."""
    return RuleSourceDocument1.from_dict(
        rehashed(document.to_dict(budget=selected.budget), "document_digest", **changes),
        budget=selected.budget,
    )


def changed_rule(
    document: RuleSourceDocument1, selected: UniverseSelection, **changes: object
) -> AtomicRule1:
    """Retain the actual full rule owner while changing a declared semantic relation."""
    return AtomicRule1.from_dict(
        rehashed(document.rules[0].to_dict(budget=selected.budget), "rule_digest", **changes),
        budget=selected.budget,
    )


def verify(
    document: RuleSourceDocument1,
    targets: Targets,
    selected: UniverseSelection,
    actual: SourceUniverseOwner,
) -> tuple[str, ...]:
    """Exercise the public actual source/target consumer with unchanged retained ownership."""
    return verify_rule_source_document(
        document, source_owner=actual, targets=targets, budget=selected.budget
    )


def with_control(
    document: RuleSourceDocument1, selected: UniverseSelection, control: ControlDefinition2
) -> RuleSourceDocument1:
    """Rebind one changed complete control in both its source rule and document output cohort."""
    previous = document.qualitative_controls[0].reference(budget=selected.budget)
    current = control.reference(budget=selected.budget)
    rule = changed_rule(
        document,
        selected,
        component_refs=[
            (current if ref == previous else ref).to_dict()
            for ref in document.rules[0].component_refs
        ],
    )
    return changed_document(
        document,
        selected,
        rules=[rule.to_dict(budget=selected.budget)],
        qualitative_controls=[control.to_dict(budget=selected.budget)],
    )
