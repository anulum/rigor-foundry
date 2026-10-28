# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete qualitative pack ownership tests
"""Exercise actual qualitative/original children, real signatures and closed parent3 parsing."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from test_control_definition_v2 import qualitative_control
from test_policy_model_inputs import budget
from test_rule_chain_trust_v3 import selected_roles
from test_rule_corpus_acceptance import corpus_signature
from test_source_component_reader import components
from test_standard_pack import control

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.control_definition_v2 import ControlDefinition2
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_reads import read_policy_document
from rigor_foundry.rule_chain_pack_v2 import AuthorityClauseV2, FreshnessPolicyV2, StandardPackV2
from rigor_foundry.rule_chain_pack_v3 import StandardPackV3
from rigor_foundry.signed_rule_chain_v3 import RuleChainV3Signature


def qualitative_pack(
    *,
    conditional: bool = False,
    original_children: bool = True,
    controls: bool = True,
    bad_crypto: bool = False,
) -> StandardPackV3:
    """Build a complete actual new pack with real deterministic TEST Ed25519 bytes."""
    limits = budget(size=30000)
    clauses = (cast(AuthorityClauseV2, components()[1].record),) if original_children else ()
    freshness = (cast(FreshnessPolicyV2, components()[2].record),) if original_children else ()
    fields = StandardPackV3.body(
        pack_id="example-quality",
        version="1.0.0",
        source_uri="opaque:source-locator-α",
        source_digest="a" * 64,
        corpus_acceptance_digest="b" * 64,
        licence="Apache-2.0",
        controls=(qualitative_control(conditional=conditional),) if controls else (),
        authority_clauses=clauses,
        freshness_policies=freshness,
        budget=limits,
    )
    signature = corpus_signature(
        "standard-pack", canonical_digest(fields), budget=limits, fault=bad_crypto
    )
    return StandardPackV3.build(
        pack_id="example-quality",
        version="1.0.0",
        source_uri="opaque:source-locator-α",
        source_digest="a" * 64,
        corpus_acceptance_digest="b" * 64,
        licence="Apache-2.0",
        controls=(qualitative_control(conditional=conditional),) if controls else (),
        authority_clauses=clauses,
        freshness_policies=freshness,
        signature=signature,
        budget=limits,
    )


@pytest.mark.parametrize(
    "conditional,original,controls",
    [(False, True, True), (True, True, True), (False, False, True), (False, True, False)],
)
def test_complete_pack_keeps_exact_children_and_real_signature_bound_to_full_body(
    tmp_path: Path,
    conditional: bool,
    original: bool,
    controls: bool,
) -> None:
    """New parent preserves original children and authenticates the entire actual new body."""
    value = qualitative_pack(
        conditional=conditional, original_children=original, controls=controls
    )
    limits = budget(size=30000)
    wire = value.to_dict(budget=limits)
    assert len(wire) == 13 and wire["schema_version"] == "3.0"
    assert "transition_digest" not in wire
    if original:
        assert wire["authority_clauses"] == [components()[1].record.to_dict()]
        assert wire["freshness_policies"] == [components()[2].record.to_dict()]
    path = tmp_path / "pack.json"
    path.write_text(json.dumps(wire, ensure_ascii=False), encoding="utf-8")
    assert (
        StandardPackV3.from_dict(read_policy_document(path, budget=limits), budget=limits) == value
    )
    roles = selected_roles()
    assert value.signature.verify(
        object_kind="standard-pack",
        body_schema_version="3.0",
        body_digest=canonical_digest(value.unsigned_body(budget=limits)),
        roles=roles,
        trust_roles_digest=roles.trust_roles_digest,
        now=datetime(2026, 10, 28, tzinfo=UTC),
        budget=limits,
    )
    with pytest.raises(ValueError):
        StandardPackV2.from_dict(wire)


def test_structural_integrity_does_not_claim_crypto_or_source_acceptance() -> None:
    """A well-formed signature made by another real TEST key parses but fails actual crypto."""
    value = qualitative_pack(bad_crypto=True)
    limits, roles = budget(size=30000), selected_roles()
    assert StandardPackV3.from_dict(value.to_dict(budget=limits), budget=limits) == value
    assert not value.signature.verify(
        object_kind="standard-pack",
        body_schema_version="3.0",
        body_digest=canonical_digest(value.unsigned_body(budget=limits)),
        roles=roles,
        trust_roles_digest=roles.trust_roles_digest,
        now=datetime(2026, 10, 28, tzinfo=UTC),
        budget=limits,
    )


@pytest.mark.parametrize("whitespace", [" ", "\t", "\n", "\r", "\v", "\f", "\u00a0", "\u2003"])
def test_validly_signed_pack_rejects_whitespace_in_opaque_source_uri(whitespace: str) -> None:
    """A valid actual signature cannot admit whitespace at any position in an opaque URI."""
    limits, roles = budget(size=30000), selected_roles()
    value = qualitative_pack()
    assert value.source_uri == "opaque:source-locator-α"
    for uri in (
        whitespace + value.source_uri,
        "opaque:source" + whitespace + "locator-α",
        value.source_uri + whitespace,
    ):
        body = {**value.unsigned_body(budget=limits), "source_uri": uri}
        signature = corpus_signature("standard-pack", canonical_digest(body), budget=limits)
        assert signature.verify(
            object_kind="standard-pack",
            body_schema_version="3.0",
            body_digest=canonical_digest(body),
            roles=roles,
            trust_roles_digest=roles.trust_roles_digest,
            now=datetime(2026, 10, 28, tzinfo=UTC),
            budget=limits,
        )
        signed = {**body, "signature": signature.to_dict(budget=limits)}
        with pytest.raises(ValueError, match="whitespace"):
            StandardPackV3.from_dict(
                {**signed, "pack_digest": canonical_digest(signed)}, budget=limits
            )
        with pytest.raises(ValueError, match="whitespace"):
            replace(value, source_uri=uri).unsigned_body(budget=limits)


def test_complete_pack_preserves_typed_versioned_component_identities() -> None:
    """Distinct versions and component kinds retain their actual identities without collision."""
    limits, roles = budget(size=30000), selected_roles()
    value = qualitative_pack()
    control_data = value.controls[0].to_dict(budget=limits)
    control_data.pop("control_digest")
    control_data["version"] = "2.0.0"
    second = ControlDefinition2.from_dict(
        {**control_data, "control_digest": canonical_digest(control_data)}, budget=limits
    )
    clause_data = value.authority_clauses[0].to_dict()
    clause_data.pop("clause_digest")
    clause_data["clause_id"] = value.controls[0].control_id
    clause = AuthorityClauseV2.from_dict(
        {**clause_data, "clause_digest": canonical_digest(clause_data)}
    )
    freshness_data = value.freshness_policies[0].to_dict()
    freshness_data.pop("policy_digest")
    freshness_data["policy_id"] = value.controls[0].control_id
    freshness = FreshnessPolicyV2.from_dict(
        {**freshness_data, "policy_digest": canonical_digest(freshness_data)}
    )
    changed = replace(
        value,
        controls=(value.controls[0], second),
        authority_clauses=(clause,),
        freshness_policies=(freshness,),
    )
    body = changed.unsigned_body(budget=limits)
    signature = corpus_signature("standard-pack", canonical_digest(body), budget=limits)
    assert signature.verify(
        object_kind="standard-pack",
        body_schema_version="3.0",
        body_digest=canonical_digest(body),
        roles=roles,
        trust_roles_digest=roles.trust_roles_digest,
        now=datetime(2026, 10, 28, tzinfo=UTC),
        budget=limits,
    )
    signed = {**body, "signature": signature.to_dict(budget=limits)}
    parsed = StandardPackV3.from_dict(
        {**signed, "pack_digest": canonical_digest(signed)}, budget=limits
    )
    assert parsed.controls == changed.controls
    assert parsed.authority_clauses == (clause,)
    assert parsed.freshness_policies == (freshness,)
    for duplicate in (
        replace(parsed, controls=(second, second)),
        replace(parsed, authority_clauses=(clause, clause)),
        replace(parsed, freshness_policies=(freshness, freshness)),
    ):
        with pytest.raises(ValueError, match="identities must be distinct"):
            duplicate.unsigned_body(budget=limits)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "2.0"),
        ("object_kind", "project-profile"),
        ("extra", True),
        ("pack_digest", "c" * 64),
        ("source_digest", "c" * 64),
        ("controls", None),
        ("authority_clauses", ()),
        ("freshness_policies", {}),
    ],
)
def test_closed_pack_wire_refuses_mixed_versions_unknown_fields_and_detached_body(
    field: str,
    value: object,
) -> None:
    """Version and complete-body checks precede any admission claim or source lookup."""
    limits = budget(size=30000)
    wire = qualitative_pack().to_dict(budget=limits)
    with pytest.raises(ValueError):
        StandardPackV3.from_dict({**wire, field: value}, budget=limits)
    if field in wire:
        wire.pop(field)
        with pytest.raises(ValueError):
            StandardPackV3.from_dict(wire, budget=limits)


def test_direct_child_owner_and_complete_identity_invariants_refuse_before_serialization() -> None:
    """Direct constructors cannot inject legacy controls, duplicate IDs or mutable cohorts."""
    value = qualitative_pack()
    limits = budget(size=30000)
    invalid = (
        replace(value, controls=cast(tuple[ControlDefinition2, ...], [value.controls[0]])),
        replace(value, controls=cast(tuple[ControlDefinition2, ...], (control(),))),
        replace(value, controls=(), authority_clauses=(), freshness_policies=()),
        replace(value, controls=(value.controls[0], value.controls[0])),
        replace(value, signature=cast(RuleChainV3Signature, "caller-signature")),
        replace(
            value,
            signature=corpus_signature(
                "project-profile",
                canonical_digest(value.unsigned_body(budget=limits)),
                budget=limits,
            ),
        ),
        replace(value, pack_digest="d" * 64),
    )
    for changed in invalid:
        with pytest.raises(ValueError):
            changed.to_dict(budget=limits)


def test_complete_pack_allocation_bounds_cover_arrays_nested_references_and_full_wire() -> None:
    """Bounds apply to entire actual children and parent rather than one individually small row."""
    value = qualitative_pack()
    limits = budget(size=30000)
    wire = value.to_dict(budget=limits)
    failures: tuple[tuple[StandardPackV3, PolicyReadBudget1], ...] = (
        (replace(value, controls=(value.controls[0],) * 129), limits),
        (replace(value, controls=(value.controls[0],) * 33), limits),
        (value, budget(size=30000, references=2)),
        (qualitative_pack(controls=False), budget(size=30000, references=3)),
        (qualitative_pack(original_children=False), budget(size=30000, references=1)),
        (value, budget(size=1)),
    )
    for changed, bounds in failures:
        with pytest.raises(ValueError):
            changed.to_dict(budget=bounds)
    for name in ("controls", "authority_clauses", "freshness_policies"):
        with pytest.raises(ValueError, match="reference budget"):
            StandardPackV3.from_dict({**wire, name: [None] * 129}, budget=limits)
