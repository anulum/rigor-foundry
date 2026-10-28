# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete source input document tests
"""Exercise closed complete arrays without claiming authenticated extraction acceptance."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_atomic_rule import rule
from test_control_definition_v2 import qualitative_control
from test_legacy_control_binding import legacy_binding
from test_policy_model_inputs import budget
from test_review_policy import review_policy
from test_semantic_decision import decision
from test_source_component_reader import components
from test_source_universe import entry
from test_typed_object_reference import reference

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.legacy_control_binding import LegacyControlBinding1
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_reads import read_policy_document
from rigor_foundry.policy_source_regions import SourceRegion1
from rigor_foundry.rule_chain_pack_v2 import FreshnessPolicyV2
from rigor_foundry.rule_source_document import RuleSourceDocument1


def document_budget(*, size: int = 262144, references: int = 2048) -> PolicyReadBudget1:
    """Allow complete nested original records while keeping every limit explicit."""
    return budget(size=size, references=references)


def source_document(*, conditional: bool = False) -> RuleSourceDocument1:
    """Collect actual owning parser vectors, not an authenticated or semantically joined corpus."""
    originals = components()
    authority = next(
        item.reference() for item in originals if item.reference().kind == "authority-clause"
    )
    freshness = next(item.record for item in originals if type(item.record) is FreshnessPolicyV2)
    assert type(freshness) is FreshnessPolicyV2
    return RuleSourceDocument1.build(
        corpus_id="corpus",
        universe=(entry(),),
        regions=(
            SourceRegion1.build(
                source_id="policy",
                start_byte=0,
                end_byte=3,
                payload=b"raw",
                disposition="normative",
                rule_ids=("rule",),
                decision_ids=(),
                reason_code="declared-normative",
            ),
        ),
        rules=(rule(conditional=conditional),),
        decisions=(decision(),),
        qualitative_controls=(qualitative_control(conditional=conditional),),
        review_policies=(review_policy(),),
        legacy_control_bindings=(legacy_binding(),),
        authority_bindings=(authority,),
        freshness_policies=(freshness,),
        compiler_contract_digest="a" * 64,
        budget=document_budget(),
    )


@pytest.mark.parametrize("conditional", [False, True])
def test_all_closed_arrays_retain_exact_original_children_and_deterministic_identity(
    conditional: bool,
) -> None:
    """No output generation or observation is invented while serializing source declarations."""
    value = source_document(conditional=conditional)
    wire = value.to_dict(budget=document_budget())
    parsed = RuleSourceDocument1.from_dict(json.loads(json.dumps(wire)), budget=document_budget())
    assert parsed == value == source_document(conditional=conditional)
    assert wire["freshness_policies"] == [row.to_dict() for row in value.freshness_policies]
    assert wire["regions"] == [row.to_dict() for row in value.regions]
    assert wire["universe"] == [row.to_dict() for row in value.universe]
    assert wire["legacy_control_bindings"] == [
        row.to_dict(budget=document_budget()) for row in value.legacy_control_bindings
    ]
    assert not {
        "signature",
        "acceptance_digest",
        "pack_digest",
        "profile_digest",
        "lock_digest",
        "observed_at",
        "accepted",
    }.intersection(wire)
    assert wire.pop("document_digest") == canonical_digest(wire)
    assert value.compiler_contract_digest != value.document_digest


def test_real_bounded_document_file_read_and_duplicate_json_refusal(tmp_path: Path) -> None:
    """The actual public retained-file parser feeds the fixed document owner, with no callback."""
    value = source_document()
    path = tmp_path / "document.json"
    path.write_text(json.dumps(value.to_dict(budget=document_budget())), encoding="utf-8")
    assert (
        RuleSourceDocument1.from_dict(
            read_policy_document(path, budget=document_budget()), budget=document_budget()
        )
        == value
    )
    path.write_text('{"corpus_id":"corpus","corpus_id":"other"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        read_policy_document(path, budget=document_budget())


_ARRAYS = (
    "universe",
    "regions",
    "rules",
    "decisions",
    "qualitative_controls",
    "review_policies",
    "legacy_control_bindings",
    "authority_bindings",
    "freshness_policies",
)


@pytest.mark.parametrize("name", _ARRAYS)
def test_every_collection_requires_actual_immutable_sorted_unique_complete_rows(name: str) -> None:
    """Arrays cannot silently sort duplicates, accept mutable tuples or substitute unknown owners."""
    value = source_document()
    rows = getattr(value, name)
    for wrong in [list(rows), ({},), (*rows, *rows)]:
        with pytest.raises(
            ValueError, match=r"immutable cohorts|actual fixed inline owners|sorted unique"
        ):
            candidate = replace(value)
            object.__setattr__(candidate, name, wrong)
            candidate.to_dict(budget=document_budget())
    data = value.to_dict(budget=document_budget())
    data[name] = None
    with pytest.raises(ValueError, match="bounded complete arrays"):
        RuleSourceDocument1.from_dict(data, budget=document_budget())


def test_legacy_identity_is_composite_not_digest_or_rule_only_order() -> None:
    """Many bindings per rule and many rules per control retain the documented exact triple."""
    original = source_document()
    binding = original.legacy_control_bindings[0]
    other_pack = reference("standard-pack", "2.0", "z-pack")
    other_control = reference("control-definition", "1.0", "z-control")
    second = LegacyControlBinding1.build(
        rule_id="rule",
        pack=binding.pack,
        control=other_control,
        source_decision_ids=(),
        budget=document_budget(),
    )
    third = LegacyControlBinding1.build(
        rule_id="rule",
        pack=other_pack,
        control=binding.control,
        source_decision_ids=(),
        budget=document_budget(),
    )
    fourth = LegacyControlBinding1.build(
        rule_id="z-rule",
        pack=binding.pack,
        control=binding.control,
        source_decision_ids=(),
        budget=document_budget(),
    )
    rows = (binding, second, third, fourth)
    candidate = replace(original, legacy_control_bindings=rows)
    data = original.to_dict(budget=document_budget())
    data["legacy_control_bindings"] = [row.to_dict(budget=document_budget()) for row in rows]
    data.pop("document_digest")
    data["document_digest"] = canonical_digest(data)
    assert (
        RuleSourceDocument1.from_dict(data, budget=document_budget()).legacy_control_bindings
        == rows
    )
    with pytest.raises(ValueError, match="sorted unique"):
        replace(candidate, legacy_control_bindings=tuple(reversed(rows))).to_dict(
            budget=document_budget()
        )
    same_triple = LegacyControlBinding1.build(
        rule_id=binding.rule_id,
        pack=binding.pack,
        control=binding.control,
        source_decision_ids=(),
        budget=document_budget(),
    )
    assert same_triple.binding_digest != binding.binding_digest
    with pytest.raises(ValueError, match="sorted unique"):
        replace(original, legacy_control_bindings=(binding, same_triple)).to_dict(
            budget=document_budget()
        )


@pytest.mark.parametrize(
    ("field", "wrong"),
    [
        ("schema_version", "2.0"),
        ("object_kind", "standard-pack"),
        ("corpus_id", "bad identity"),
        ("compiler_contract_digest", "bad"),
        ("document_digest", "f" * 64),
        ("signature", {}),
    ],
)
def test_wrong_identity_fields_output_cycles_and_tampered_digests_refuse(
    field: str, wrong: object
) -> None:
    """Even rehashed input cannot extend the document with output or self-acceptance fields."""
    wire = source_document().to_dict(budget=document_budget())
    wire[field] = wrong
    with pytest.raises(ValueError):
        RuleSourceDocument1.from_dict(wire, budget=document_budget())
    for name in ["compiler_contract_digest", "corpus_id", "document_digest"]:
        with pytest.raises(ValueError):
            candidate = source_document()
            object.__setattr__(candidate, name, wrong)
            candidate.to_dict(budget=document_budget())


def test_unchanged_original_freshness_owner_and_authority_reference_subset_are_closed() -> None:
    """Original freshness digests cannot be repaired by hashing only the new enclosing input."""
    value = source_document()
    wrong = replace(value.freshness_policies[0], policy_digest="f" * 64)
    with pytest.raises(ValueError, match="policy digest"):
        replace(value, freshness_policies=(wrong,)).to_dict(budget=document_budget())
    with pytest.raises(ValueError, match="wrong policy component"):
        replace(value, authority_bindings=(reference(),)).to_dict(budget=document_budget())
    wire = value.to_dict(budget=document_budget())
    rows = cast(list[dict[str, object]], wire["freshness_policies"])
    rows[0]["numeric_ttl"] = 100
    wire.pop("document_digest")
    wire["document_digest"] = canonical_digest(wire)
    with pytest.raises(ValueError, match="fields"):
        RuleSourceDocument1.from_dict(wire, budget=document_budget())


def test_region_relations_are_bounded_before_original_sequence_serialization() -> None:
    """Mutated direct original rows cannot allocate an oversized or mutable reference set."""
    value = source_document()
    for name, wrong in [
        ("rule_ids", ["rule"]),
        ("decision_ids", []),
        ("rule_ids", tuple("r" for _ in range(2048))),
    ]:
        region = replace(value.regions[0])
        object.__setattr__(region, name, wrong)
        with pytest.raises(ValueError, match="region relations"):
            replace(value, regions=(region,)).to_dict(budget=document_budget())


def test_whole_reference_budget_counts_all_valid_cohorts_together() -> None:
    """Individually valid original and new children do not evade an aggregate limit."""
    value = source_document(conditional=True)
    with pytest.raises(ValueError, match="aggregate reference budget"):
        value.to_dict(budget=document_budget(references=32))
    wire = value.to_dict(budget=document_budget())
    with pytest.raises(ValueError, match="bounded complete arrays"):
        RuleSourceDocument1.from_dict(
            {**wire, "authority_bindings": [wire["authority_bindings"]] * 2049},
            budget=document_budget(size=8 * 1024**2),
        )
    budget_wire = document_budget().to_dict()
    budget_wire["max_rules"] = 1
    budget_wire.pop("budget_digest")
    too_few = PolicyReadBudget1.from_dict(
        {**budget_wire, "budget_digest": canonical_digest(budget_wire)}
    )
    rules = (value.rules[0], value.rules[0])
    with pytest.raises(ValueError, match="bounded immutable cohorts"):
        replace(value, rules=rules).to_dict(budget=too_few)


def test_complete_encoded_byte_bound_includes_enclosing_fields_and_digest() -> None:
    """Exact canonical bytes pass; one fewer byte refuses without truncation or normalization."""
    value = source_document()
    wire = value.to_dict(budget=document_budget())
    count = len(
        json.dumps(
            wire, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")
        ).encode()
    )
    assert value.to_dict(budget=document_budget(size=count)) == wire
    with pytest.raises(ValueError, match="byte budget"):
        value.to_dict(budget=document_budget(size=count - 1))
    with pytest.raises(ValueError, match="byte budget"):
        value.to_dict(budget=document_budget(size=count - 150))
    largest_child = max(
        len(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode())
        for name in _ARRAYS
        for row in cast(list[object], wire[name])
    )
    with pytest.raises(ValueError, match="aggregate byte budget"):
        value.to_dict(budget=document_budget(size=largest_child + 100))


def test_original_array_limits_apply_before_their_owner_allocates_nested_records() -> None:
    """Bound source counts, original region links and original invalidators before parsing."""
    wire = source_document().to_dict(budget=document_budget())
    with pytest.raises(ValueError, match="bounded complete arrays"):
        RuleSourceDocument1.from_dict(
            {**wire, "universe": cast(list[object], wire["universe"]) * 17},
            budget=document_budget(),
        )
    for name in ["rule_ids", "decision_ids"]:
        region = cast(list[dict[str, object]], wire["regions"])[0]
        for wrong in [None, ["rule"] * 2048]:
            with pytest.raises(ValueError, match="region relations"):
                RuleSourceDocument1.from_dict(
                    {**wire, "regions": [{**region, name: wrong}]}, budget=document_budget()
                )
    with pytest.raises(ValueError, match="original region mapping"):
        RuleSourceDocument1.from_dict({**wire, "regions": [None]}, budget=document_budget())
    freshness = cast(list[dict[str, object]], wire["freshness_policies"])[0]
    with pytest.raises(ValueError, match="reference budget"):
        RuleSourceDocument1.from_dict(
            {
                **wire,
                "freshness_policies": [{**freshness, "invalidator_ids": ["invalidator"] * 2049}],
            },
            budget=document_budget(),
        )
