# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — fixed policy component target tests
"""Resolve complete real owning records without relaxing original child versions."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest
from signing_fixtures import sign_message
from test_assessment_evidence_validation import attestation
from test_control_assessment import evidence as original_evidence
from test_control_definition_v2 import qualitative_control
from test_evidence_contract_v2 import evidence_contract
from test_evidence_reference_v2 import evidence_record
from test_policy_model_inputs import budget
from test_review_policy import review_policy
from test_semantic_decision import decision
from test_source_component_reader import adapter_source, components, reviewer_source
from test_standard_pack import control
from test_typed_object_reference import reference

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.component_source_resolution import (
    PolicyComponentTarget,
    StandardPackSource2,
    parse_policy_component_target,
)
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_reads import read_policy_document
from rigor_foundry.rule_chain_pack_v2 import AuthorityClauseV2, FreshnessPolicyV2, StandardPackV2
from rigor_foundry.signed_rule_chain_v2 import RuleChainV2Signature, rule_chain_v2_payload_digest
from rigor_foundry.source_component_reader import PolicyComponent1
from rigor_foundry.standard_pack import ControlDefinition
from rigor_foundry.typed_object_reference import TypedObjectRef1


def original_pack(*, controls: tuple[ControlDefinition, ...] | None = None) -> StandardPackV2:
    """Sign an actual original pack containing complete legacy numeric controls."""
    original = components()
    authority = original[1].to_dict()
    authority["clause_id"] = "core/authority"
    authority.pop("clause_digest")
    authority["clause_digest"] = canonical_digest(authority)
    freshness = original[2].to_dict()
    freshness["policy_id"] = "core/freshness"
    freshness.pop("policy_digest")
    freshness["policy_digest"] = canonical_digest(freshness)
    body = StandardPackV2.body(
        pack_id="core",
        version="2.0.0",
        source_uri="https://standards.example/core/2",
        source_digest=sha256(b"Retain every selected architecture control.\n").hexdigest(),
        transition_digest=cast(str, authority["transition_digest"]),
        licence="MIT",
        controls=(control(), control(control_id="core/second")) if controls is None else controls,
        authority_clauses=(AuthorityClauseV2.from_dict(authority),),
        freshness_policies=(FreshnessPolicyV2.from_dict(freshness),),
    )
    signed_at = "2026-10-28T12:00:00Z"
    payload = rule_chain_v2_payload_digest(
        object_kind="standard-pack",
        body_digest=canonical_digest(body),
        signed_at=signed_at,
    )
    signature = RuleChainV2Signature.build(
        object_kind="standard-pack",
        key_id="common-policy-legacy-pack",
        body_digest=canonical_digest(body),
        signed_at=signed_at,
        signature_hex=sign_message(
            "common-policy-legacy-pack", "rigor-foundry.standard-pack.v2", payload
        ),
    )
    complete = {**body, "signature": signature.to_dict()}
    return StandardPackV2.from_dict({**complete, "pack_digest": canonical_digest(complete)})


def target_records() -> tuple[
    tuple[TypedObjectRef1, dict[str, object], PolicyComponentTarget], ...
]:
    """Enumerate actual complete owners for every supported component target pair."""
    originals = (
        *components(),
        adapter_source(),
        reviewer_source(),
        PolicyComponent1(control().evidence, budget()),
        PolicyComponent1(original_evidence(), budget()),
        PolicyComponent1(attestation(reviewer_id="Exact Original Reviewer"), budget()),
    )
    rows: list[tuple[TypedObjectRef1, dict[str, object], PolicyComponentTarget]] = [
        (item.reference(), item.to_dict(), item.record) for item in originals
    ]
    for new in (qualitative_control(), evidence_contract(), review_policy(), decision()):
        rows.append((new.reference(budget=budget()), new.to_dict(budget=budget()), new))
    pack = StandardPackSource2(original_pack(), budget(size=65536))
    rows.append((pack.reference(), pack.to_dict(), pack.record))
    evidence = evidence_record()
    rows.append(
        (evidence.object_reference(budget=budget()), evidence.to_dict(budget=budget()), evidence)
    )
    return tuple(rows)


@pytest.mark.parametrize("index", range(14))
def test_fixed_pairs_resolve_actual_owning_models_with_complete_identity(index: int) -> None:
    """Every implemented target uses its actual parser, original ID and owning digest."""
    ref, data, actual = target_records()[index]
    assert parse_policy_component_target(ref, data, budget=budget(size=65536)) == actual
    for wrong in (
        reference(ref.kind, ref.format_version, "other-target", ref.object_digest),
        reference(ref.kind, ref.format_version, ref.object_id, "0" * 64),
    ):
        with pytest.raises(ValueError, match="identity or owning digest"):
            parse_policy_component_target(wrong, data, budget=budget(size=65536))


def test_unsupported_pair_and_nonreference_refuse_before_target_interpretation() -> None:
    """A closed context reference cannot appoint a policy parser or inspect a hostile target."""
    with pytest.raises(ValueError, match="unsupported policy component target pair"):
        parse_policy_component_target(reference(), object(), budget=budget())
    with pytest.raises(ValueError, match="actual typed policy target"):
        parse_policy_component_target(cast(TypedObjectRef1, {}), object(), budget=budget())


def test_complete_original_pack_file_and_signature_bytes_remain_unchanged(tmp_path: Path) -> None:
    """Actual file parsing retains both controls, original child fields and full detached signature."""
    actual = original_pack()
    source = StandardPackSource2(actual, budget(size=65536))
    data = source.to_dict()
    assert data == actual.to_dict()
    assert StandardPackSource2.from_dict(data, budget=budget(size=65536)) == source
    assert source.reference().object_id == actual.pack_id
    assert source.reference().object_digest == actual.pack_digest
    assert len(actual.controls) == 2 and actual.controls[0].evidence.freshness_seconds == 3600
    assert data["signature"] == actual.signature.to_dict()
    path = tmp_path / "original-pack.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    retained = read_policy_document(path, budget=budget(size=65536))
    assert (
        parse_policy_component_target(source.reference(), retained, budget=budget(size=65536))
        == actual
    )
    path.write_text('{"schema_version":"2.0","schema_version":"2.0"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        read_policy_document(path, budget=budget(size=65536))


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "1.0"),
        ("object_kind", "other"),
        ("controls", ()),
        ("authority_clauses", None),
        ("freshness_policies", {}),
        ("pack_digest", "0" * 64),
    ],
)
def test_original_pack_refuses_wrong_version_arrays_and_owning_digest(
    field: str, value: object
) -> None:
    """No pack coercion, permissive list alias or forged complete digest survives the owner."""
    data = original_pack().to_dict()
    data[field] = value
    with pytest.raises(ValueError):
        StandardPackSource2.from_dict(data, budget=budget(size=65536))


def test_original_pack_rejects_unselected_child_corruption_and_ignored_extensions() -> None:
    """A later malformed control or silently discarded legacy child field cannot hide in a pack."""
    original = original_pack().to_dict()
    for name in ["control_digest", "extra"]:
        data = deepcopy(original)
        children = cast(list[dict[str, object]], data["controls"])
        children[-1][name] = "0" * 64
        with pytest.raises(ValueError):
            StandardPackSource2.from_dict(data, budget=budget(size=65536))
    with pytest.raises(ValueError):
        StandardPackSource2.from_dict(
            {**original, "loader": "appointed"}, budget=budget(size=65536)
        )


def test_original_signature_timestamp_normalization_cannot_change_retained_pack_input() -> None:
    """The original parser's accepted timestamp alias cannot rewrite the new boundary's exact wire."""
    actual = original_pack()
    data = actual.to_dict()
    signature = cast(dict[str, object], data["signature"])
    signature["signed_at"] = actual.signature.signed_at.replace("Z", "+00:00")
    assert StandardPackV2.from_dict(data) == actual
    assert StandardPackV2.from_dict(data).to_dict() != data
    with pytest.raises(ValueError, match="wire must remain unchanged"):
        StandardPackSource2.from_dict(data, budget=budget(size=65536))


def test_original_pack_enforces_aggregate_child_and_control_budgets() -> None:
    """Complete allocations include references across every original control and policy."""
    actual = original_pack()
    data = actual.to_dict()
    limits = budget(size=65536)
    control_limits = limits.to_dict()
    control_limits["max_rules"] = 1
    control_limits.pop("budget_digest")
    control_limits["budget_digest"] = canonical_digest(control_limits)
    small = PolicyReadBudget1.from_dict(control_limits)
    with pytest.raises(ValueError, match="control budget"):
        StandardPackSource2(actual, small)
    with pytest.raises(ValueError, match="control budget"):
        StandardPackSource2.from_dict(data, budget=small)
    assert StandardPackSource2(actual, budget(size=65536, references=20)).to_dict() == data
    for maximum in [1, 10, 19]:
        small = budget(size=65536, references=maximum)
        with pytest.raises(ValueError, match="reference budget"):
            StandardPackSource2(actual, small)
        with pytest.raises(ValueError, match="reference budget"):
            StandardPackSource2.from_dict(data, budget=small)


def test_direct_pack_guards_precede_original_recursive_serialization() -> None:
    """Mutable and foreign original child objects refuse before their methods can be invoked."""
    actual = original_pack()
    malformed: tuple[object, ...] = (
        {},
        replace(actual, signature=cast(RuleChainV2Signature, {})),
        replace(actual, controls=cast(tuple[ControlDefinition, ...], list(actual.controls))),
        replace(actual, controls=cast(tuple[ControlDefinition, ...], ({},))),
    )
    for value in malformed:
        with pytest.raises(ValueError, match=r"actual original|immutable component"):
            StandardPackSource2(cast(StandardPackV2, value), budget(size=65536))
    data = actual.to_dict()
    data.pop("pack_digest")
    with pytest.raises(ValueError):
        StandardPackSource2.from_dict(data, budget=budget(size=65536))
