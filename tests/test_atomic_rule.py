# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — exact atomic rule declaration tests
"""Bind real original statements and components without fabricating policy admission."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_policy_model_inputs import budget
from test_rule_scope import scoped
from test_source_component_reader import components
from test_typed_object_reference import reference

from rigor_foundry.atomic_rule import AtomicRule1
from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.control_assessment import Classification
from rigor_foundry.policy_source_spans import SourceSpan1, verify_policy_source_spans
from rigor_foundry.rule_scope import RuleScope1
from rigor_foundry.source_component_reader import resolve_policy_component
from rigor_foundry.task_context import TASK_CONTEXT_EVENTS
from rigor_foundry.typed_object_reference import TypedObjectRef1

STATEMENT = "  Retain žiadny changed original byte.\r\n"


def rule(
    *,
    lifecycle: str = "active",
    mode: str = "require",
    classification: Classification = "internal",
    conditional: bool = False,
) -> AtomicRule1:
    """Build declared rule metadata using actual original enforcement component parsers."""
    payload = STATEMENT.encode("utf-8")
    span = SourceSpan1.build(
        span_id="statement",
        source_id="policy",
        start_byte=0,
        end_byte=len(payload),
        payload=payload,
    )
    refs = tuple(
        sorted(
            (item.reference() for item in components()),
            key=lambda item: (item.kind, item.format_version, item.object_id),
        )
    )
    scope = (
        scoped()
        if conditional
        else RuleScope1.build(
            scope_kind="global",
            condition=None,
            events=tuple(sorted(TASK_CONTEXT_EVENTS)),
            budget=budget(),
        )
    )
    return AtomicRule1.build(
        rule_id="rule",
        revision="original-revision",
        statement=STATEMENT,
        issuer_id="declared-issuer",
        issuer_class="source-owner",
        source_spans=(span,),
        scope=scope,
        lifecycle=lifecycle,
        mode=mode,
        mandatory_floor=True,
        dependency_rule_ids=("prerequisite",),
        decision_ids=("decision",),
        component_refs=refs,
        classification=classification,
        budget=budget(),
    )


@pytest.mark.parametrize(
    ("lifecycle", "mode", "classification"),
    [
        ("proposed", "require", "public"),
        ("active", "deny", "internal"),
        ("held", "require", "confidential"),
        ("superseded", "deny", "secret"),
        ("retired", "require", "public"),
    ],
)
def test_explicit_history_modes_and_classifications_remain_exact_metadata(
    lifecycle: str, mode: str, classification: Classification
) -> None:
    """Historical/held rows never become active or admitted merely through parsing."""
    value = rule(lifecycle=lifecycle, mode=mode, classification=classification)
    data = value.to_dict(budget=budget())
    assert AtomicRule1.from_dict(data, budget=budget()) == value
    assert data["lifecycle"] == lifecycle
    assert data["mode"] == mode
    assert data["classification"] == classification
    assert data["statement"] == STATEMENT
    assert data["statement_digest"] == hashlib.sha256(STATEMENT.encode("utf-8")).hexdigest()
    assert not {"admitted", "accepted", "ready", "verdict"}.intersection(data)
    assert data.pop("rule_digest") == canonical_digest(data)


def test_real_source_spans_original_components_and_json_are_resolved_through_public_owners(
    tmp_path: Path,
) -> None:
    """The exact parsed rule joins real original bytes and original component digests."""
    value = rule(conditional=True)
    parsed = AtomicRule1.from_dict(
        json.loads(json.dumps(value.to_dict(budget=budget()))), budget=budget()
    )
    assert parsed == value
    path = tmp_path / "source.txt"
    path.write_bytes(STATEMENT.encode("utf-8"))
    assert (
        verify_policy_source_spans({"policy": path}, parsed.source_spans, budget=budget())
        == parsed.source_spans
    )
    cohort = components()
    resolved = tuple(
        resolve_policy_component(ref, cohort, budget=budget()).reference()
        for ref in parsed.component_refs
    )
    assert resolved == parsed.component_refs
    path.write_bytes(STATEMENT.replace("original", "ORIGINAL").encode("utf-8"))
    with pytest.raises(ValueError, match="byte digest"):
        verify_policy_source_spans({"policy": path}, parsed.source_spans, budget=budget())


def test_scoped_aggregate_reference_limits_and_direct_scope_types_refuse() -> None:
    """An exact scope and all original rule references count before consumer serialization."""
    value = rule(conditional=True)
    with pytest.raises(ValueError, match="aggregate reference budget"):
        value.to_dict(budget=budget(references=6))
    with pytest.raises(ValueError, match="actual explicit scope"):
        replace(value, scope=cast(RuleScope1, {})).to_dict(budget=budget())
    with pytest.raises(ValueError, match="depend on itself"):
        replace(value, dependency_rule_ids=("rule",)).to_dict(budget=budget())


def test_component_set_requires_actual_sorted_unique_supported_original_references() -> None:
    """Source metadata, a duplicated target or caller list cannot become an enforcement component."""
    value = rule()
    for invalid in [
        tuple(reversed(value.component_refs)),
        (value.component_refs[0],) * 2,
        (reference(),),
        ({},),
        list(value.component_refs),
    ]:
        with pytest.raises(ValueError):
            replace(value, component_refs=cast(tuple[TypedObjectRef1, ...], invalid)).to_dict(
                budget=budget()
            )
    with pytest.raises(ValueError, match="bounded immutable"):
        replace(value, component_refs=(value.component_refs[0],) * 129).to_dict(budget=budget())
    data = value.to_dict(budget=budget())
    data["component_refs"] = []
    data.pop("rule_digest")
    data["rule_digest"] = canonical_digest(data)
    parsed = AtomicRule1.from_dict(data, budget=budget())
    assert parsed.component_refs == ()
    assert "accepted" not in parsed.to_dict(budget=budget())


@pytest.mark.parametrize(
    "kind,version",
    [
        ("evidence-contract", "1.0"),
        ("evidence-contract", "2.0"),
        ("evidence-reference", "2.0"),
        ("evidence-reference", "1.0"),
        ("review-attestation", "2.0"),
        ("adapter-lock", "1.0"),
        ("reviewer-identity-policy", "semantic-reviewer-identity-policy.v1"),
        ("semantic-decision", "1.0"),
    ],
)
def test_supporting_policy_targets_cannot_become_atomic_enforcement(
    kind: str, version: str
) -> None:
    """Adding a fixed supporting reader never broadens the closed enforcement component subset."""
    body = rule().to_dict(budget=budget())
    body["component_refs"] = [reference(kind, version).to_dict()]
    body.pop("rule_digest")
    body["rule_digest"] = canonical_digest(body)
    with pytest.raises(ValueError, match="unsupported atomic enforcement"):
        AtomicRule1.from_dict(body, budget=budget())


def test_statement_bytes_and_original_component_resolution_cannot_be_replaced_by_rehashing() -> (
    None
):
    """Structural integrity alone never repairs an altered statement or unresolved component."""
    value = rule()
    data = value.to_dict(budget=budget())
    data["statement"] = STATEMENT.replace("\r\n", "\n")
    data.pop("rule_digest")
    data["rule_digest"] = canonical_digest(data)
    with pytest.raises(ValueError, match="exact UTF8 bytes"):
        AtomicRule1.from_dict(data, budget=budget())
    ref = value.component_refs[0]
    different = TypedObjectRef1.build(
        kind=ref.kind,
        format_version=ref.format_version,
        object_id=ref.object_id,
        object_digest="0" * 64,
    )
    refs = (different, *value.component_refs[1:])
    # This is a structurally valid declaration. The actual owner still refuses
    # its different original target; parsing does not approve semantic binding.
    data = value.to_dict(budget=budget())
    data["component_refs"] = [item.to_dict() for item in refs]
    data.pop("rule_digest")
    data["rule_digest"] = canonical_digest(data)
    parsed = AtomicRule1.from_dict(data, budget=budget())
    with pytest.raises(ValueError, match="original owning digest"):
        resolve_policy_component(parsed.component_refs[0], components(), budget=budget())


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("schema_version", "2.0"),
        ("object_kind", "active-rule"),
        ("revision", ""),
        ("rule_id", "bad identity"),
        ("statement", " "),
        ("statement_digest", "bad"),
        ("issuer_id", "bad identity"),
        ("issuer_class", ""),
        ("lifecycle", "ready"),
        ("mode", "observe"),
        ("classification", "unclassified"),
        ("mandatory_floor", 1),
        ("source_spans", {}),
        ("source_spans", [{}]),
        ("scope", {}),
        ("dependency_rule_ids", ["z", "a"]),
        ("decision_ids", ["same", "same"]),
        ("component_refs", [{}]),
        ("rule_digest", "0" * 64),
    ],
)
def test_rehashed_unsupported_fields_and_direct_digest_forgery_refuse(
    field: str, invalid: object
) -> None:
    """A recomputed outer hash cannot relax the original scope, field or child contracts."""
    data = rule().to_dict(budget=budget())
    data.pop("rule_digest")
    data[field] = invalid
    digest = "0" * 64 if field == "rule_digest" else canonical_digest(data)
    with pytest.raises(ValueError):
        AtomicRule1.from_dict({**data, "rule_digest": digest}, budget=budget())


def test_closed_top_level_and_oversized_arrays_refuse_before_allocation() -> None:
    """No missing field, extension bag or overly large child cohort is accepted."""
    data = rule().to_dict(budget=budget())
    for invalid in [
        None,
        {**data, "ready": True},
        {key: item for key, item in data.items() if key != "scope"},
    ]:
        with pytest.raises(ValueError):
            AtomicRule1.from_dict(invalid, budget=budget())
    with pytest.raises(ValueError, match="bounded arrays"):
        AtomicRule1.from_dict({**data, "source_spans": [{}] * 129}, budget=budget())
    with pytest.raises(ValueError, match="atomic rule digest"):
        replace(rule(), rule_digest="0" * 64).to_dict(budget=budget())
