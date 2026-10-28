# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — source-bound semantic declaration tests
"""Exercise original source records and decision wires without appointing semantic issuers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_context_producer_contract import contract
from test_policy_model_inputs import budget
from test_source_provenance import capture

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.condition_language import ConditionExpression
from rigor_foundry.context_owner_proof import OwnerProof1
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_records import PolicySourceRecord1
from rigor_foundry.policy_source_spans import SourceSpan1, verify_policy_source_spans
from rigor_foundry.semantic_decision import SemanticDecision1
from rigor_foundry.typed_object_reference import TypedObjectRef1

PAYLOAD = b'{"previous":"Keep exact bytes.","successor":"Retain original sources.\\r\\n"}'


def decision(
    relation: str = "supersedes",
    *,
    condition: ConditionExpression | None = None,
    limits: PolicyReadBudget1 | None = None,
) -> SemanticDecision1:
    """Build actual original capture/span metadata, explicitly without issuer authentication."""
    limits = budget() if limits is None else limits
    span = SourceSpan1.build(
        span_id="statement",
        source_id="policy",
        start_byte=0,
        end_byte=len(PAYLOAD),
        payload=PAYLOAD,
    )
    source = TypedObjectRef1.from_dict(PolicySourceRecord1(capture(PAYLOAD), limits).reference())
    proof = OwnerProof1.build(
        owner_id="fixed-owner",
        owner_class="source",
        owner_contract=TypedObjectRef1.from_dict(contract("source").reference()),
        subject_digest=hashlib.sha256(PAYLOAD).hexdigest(),
        source_object=source,
        snapshot_id="declared-snapshot",
        observation_digest=canonical_digest(span.to_dict()),
        budget=limits,
    )
    return SemanticDecision1.build(
        decision_id="declared-change",
        relation=relation,
        issuer_id="declared-issuer",
        issuer_class="source-owner",
        source_spans=(span,),
        affected_rule_ids=("previous",),
        successor_rule_ids=("successor",),
        condition=condition,
        rationale="Retain the exact independently accepted source interpretation.",
        authority_proof=proof,
        budget=limits,
    )


@pytest.mark.parametrize(
    "relation", ["supersedes", "exception", "exclusion", "interpretation", "adoption"]
)
def test_every_explicit_relation_round_trips_original_inputs_without_acceptance(
    relation: str,
) -> None:
    """A supported relation retains source and issuer declarations with no ready status."""
    value = decision(relation)
    data = value.to_dict(budget=budget())
    assert SemanticDecision1.from_dict(data, budget=budget()) == value
    assert data["source_spans"] == [span.to_dict() for span in value.source_spans]
    assert data["authority_proof"] == value.authority_proof.to_dict()
    assert value.authority_proof.subject_digest != value.decision_digest
    assert not {"accepted", "effective", "ready", "observed_at"}.intersection(data)
    assert data.pop("decision_digest") == canonical_digest(data)


def test_real_retained_source_read_and_json_round_trip_preserve_original_identity(
    tmp_path: Path,
) -> None:
    """A real source-byte edit refuses through the original public span-verification boundary."""
    path = tmp_path / "source.json"
    path.write_bytes(PAYLOAD)
    value = decision(condition=ConditionExpression.build("exists", reference="project.id"))
    assert (
        verify_policy_source_spans({"policy": path}, value.source_spans, budget=budget())
        == value.source_spans
    )
    path.write_bytes(PAYLOAD.replace(b"bytes", b"BYTES"))
    with pytest.raises(ValueError, match="byte digest"):
        verify_policy_source_spans({"policy": path}, value.source_spans, budget=budget())
    parsed = SemanticDecision1.from_dict(
        json.loads(json.dumps(value.to_dict(budget=budget()))), budget=budget()
    )
    assert parsed == value
    assert parsed.condition == value.condition


@pytest.mark.parametrize(
    ("affected", "successors"),
    [((), ("next",)), (("previous",), ()), (("same",), ("same",))],
)
def test_supersession_has_explicit_nonempty_directed_nonself_edges(
    affected: tuple[str, ...], successors: tuple[str, ...]
) -> None:
    """Neither reversed defaults nor self-supersession can be silently interpreted."""
    value = replace(decision(), affected_rule_ids=affected, successor_rule_ids=successors)
    with pytest.raises(ValueError, match="directed distinct"):
        value.to_dict(budget=budget())


def test_direct_proof_types_integrity_and_aggregate_reference_budget_refuse() -> None:
    """Actual original proof records and complete input bounds apply at each public consumer."""
    value = decision()
    with pytest.raises(ValueError, match="original owner proof"):
        replace(value, authority_proof=cast(OwnerProof1, {})).to_dict(budget=budget())
    with pytest.raises(ValueError, match="aggregate reference budget"):
        value.to_dict(budget=budget(references=4))
    with pytest.raises(ValueError, match="aggregate reference budget"):
        decision(condition=ConditionExpression.build("exists", reference="project.id")).to_dict(
            budget=budget(references=5)
        )
    with pytest.raises(ValueError, match="decision digest"):
        replace(value, decision_digest="0" * 64).to_dict(budget=budget())
    with pytest.raises(ValueError):
        replace(value, decision_digest="bad").to_dict(budget=budget())
    object.__setattr__(value.authority_proof, "proof_digest", "0" * 64)
    with pytest.raises(ValueError, match="proof digest"):
        value.to_dict(budget=budget())


@pytest.mark.parametrize(
    ("name", "invalid"),
    [
        ("schema_version", "2.0"),
        ("object_kind", "effective-decision"),
        ("decision_id", "bad identity"),
        ("relation", "latest-date"),
        ("issuer_id", "bad identity"),
        ("issuer_class", ""),
        ("source_spans", "statement"),
        ("source_spans", [{}]),
        ("source_spans", []),
        ("affected_rule_ids", ["z", "a"]),
        ("successor_rule_ids", ["same", "same"]),
        ("rationale", " "),
        ("authority_proof", {}),
        ("condition", {}),
        ("decision_digest", "0" * 64),
    ],
)
def test_rehashed_malformed_declarations_do_not_become_supported(
    name: str, invalid: object
) -> None:
    """Self-consistent hashes cannot repair unsupported identity, syntax or directed sets."""
    data = decision().to_dict(budget=budget())
    data.pop("decision_digest")
    data[name] = invalid
    digest = "0" * 64 if name == "decision_digest" else canonical_digest(data)
    with pytest.raises(ValueError):
        SemanticDecision1.from_dict({**data, "decision_digest": digest}, budget=budget())


def test_closed_input_and_collection_allocation_limits_apply_before_nested_parsing() -> None:
    """Unknown/missing keys and oversized arrays refuse without selecting nested readers."""
    data = decision().to_dict(budget=budget())
    for invalid in [
        None,
        {**data, "accepted": True},
        {k: v for k, v in data.items() if k != "condition"},
    ]:
        with pytest.raises(ValueError):
            SemanticDecision1.from_dict(invalid, budget=budget())
    with pytest.raises(ValueError, match="bounded arrays"):
        SemanticDecision1.from_dict({**data, "source_spans": [{}] * 129}, budget=budget())
