# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — qualitative evidence contract tests
"""Join actual adapter/freshness/review identities without replacing original legacy evidence."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_policy_model_inputs import budget
from test_review_policy import review_policy
from test_source_component_reader import adapter_source, components
from test_standard_pack import control
from test_typed_object_reference import reference

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.evidence_contract_v2 import EvidenceContract2, EvidenceRequirement1
from rigor_foundry.policy_source_reads import read_policy_document
from rigor_foundry.source_component_reader import resolve_policy_component
from rigor_foundry.typed_object_reference import TypedObjectRef1


def requirement(evidence_type: str = "lint-report") -> EvidenceRequirement1:
    """Bind actual unchanged adapter custody and original qualitative freshness policy."""
    return EvidenceRequirement1.build(
        evidence_type=evidence_type,
        adapter=adapter_source().reference(),
        subject_class="source",
        freshness_policy=components()[2].reference(),
        budget=budget(),
    )


def evidence_contract() -> EvidenceContract2:
    """Retain all declared evidence owners and a complete exact qualitative review identity."""
    return EvidenceContract2.build(
        contract_id="source-quality",
        requirements=(requirement(), requirement("test-report")),
        review_policy=review_policy().reference(budget=budget()),
        budget=budget(),
    )


def test_requirement_resolves_original_adapter_and_freshness_without_numeric_placeholders() -> (
    None
):
    """Original source identities and digest fields survive both owning parser boundaries."""
    value = requirement()
    data = value.to_dict(budget=budget())
    assert EvidenceRequirement1.from_dict(data, budget=budget()) == value
    sources = (*components(), adapter_source())
    assert (
        resolve_policy_component(value.adapter, sources, budget=budget()).reference()
        == value.adapter
    )
    assert (
        resolve_policy_component(value.freshness_policy, sources, budget=budget()).reference()
        == value.freshness_policy
    )
    assert not {
        "freshness_seconds",
        "expires_at",
        "minimum_independent_reviewers",
        "accepted",
    }.intersection(data)
    assert data.pop("requirement_digest") == canonical_digest(data)


def test_complete_contract_round_trip_and_reference_keep_all_source_requirements() -> None:
    """Exact nonempty sorted requirements and qualitative review identity define the digest."""
    value = evidence_contract()
    data = value.to_dict(budget=budget())
    assert EvidenceContract2.from_dict(data, budget=budget()) == value
    assert data["requirements"] == [item.to_dict(budget=budget()) for item in value.requirements]
    assert data["review_policy"] == review_policy().reference(budget=budget()).to_dict()
    ref = value.reference(budget=budget())
    assert (ref.kind, ref.format_version, ref.object_id, ref.object_digest) == (
        "evidence-contract",
        "2.0",
        value.contract_id,
        value.contract_digest,
    )
    assert data.pop("contract_digest") == canonical_digest(data)
    assert not {"freshness_seconds", "reviewer_count", "accepted", "pass"}.intersection(data)


def test_actual_file_parser_preserves_version2_and_duplicate_key_refusal(tmp_path: Path) -> None:
    """File parsing uses the real retained-byte reader before exact owning contract validation."""
    path = tmp_path / "evidence.json"
    value = evidence_contract()
    encoded = json.dumps(value.to_dict(budget=budget()))
    path.write_text(encoded, encoding="utf-8")
    assert (
        EvidenceContract2.from_dict(read_policy_document(path, budget=budget()), budget=budget())
        == value
    )
    path.write_text('{"contract_id":"substitute",' + encoded[1:], encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate keys"):
        read_policy_document(path, budget=budget())
    original = control().evidence
    with pytest.raises(ValueError):
        EvidenceContract2.from_dict(original.to_dict(), budget=budget())
    assert original.freshness_seconds == 3600
    assert original.minimum_independent_reviewers == 1


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("schema_version", "2.0"),
        ("object_kind", "other"),
        ("evidence_type", "bad identity"),
        ("subject_class", ""),
        ("adapter", reference().to_dict()),
        ("freshness_policy", adapter_source().reference().to_dict()),
        ("requirement_digest", "0" * 64),
    ],
)
def test_rehashed_wrong_requirement_identity_and_source_format_refuse(
    field: str, invalid: object
) -> None:
    """The actual selected component roles cannot be replaced by other supported source kinds."""
    data = requirement().to_dict(budget=budget())
    data.pop("requirement_digest")
    data[field] = invalid
    digest = "0" * 64 if field == "requirement_digest" else canonical_digest(data)
    with pytest.raises(ValueError):
        EvidenceRequirement1.from_dict({**data, "requirement_digest": digest}, budget=budget())


def test_requirement_direct_children_limits_closed_fields_and_late_mutations_refuse() -> None:
    """Both references and their parser allocations remain mandatory at every public boundary."""
    value = requirement()
    with pytest.raises(ValueError, match="actual typed"):
        replace(value, adapter=cast(TypedObjectRef1, {})).to_dict(budget=budget())
    with pytest.raises(ValueError, match="reference budget"):
        EvidenceRequirement1.build(
            evidence_type=value.evidence_type,
            adapter=value.adapter,
            subject_class=value.subject_class,
            freshness_policy=value.freshness_policy,
            budget=budget(references=1),
        )
    with pytest.raises(ValueError, match="reference budget"):
        value.to_dict(budget=budget(references=1))
    with pytest.raises(ValueError, match="requirement digest"):
        replace(value, requirement_digest="0" * 64).to_dict(budget=budget())
    data = value.to_dict(budget=budget())
    for invalid in [
        None,
        {**data, "freshness_seconds": 1},
        {key: item for key, item in data.items() if key != "subject_class"},
    ]:
        with pytest.raises(ValueError):
            EvidenceRequirement1.from_dict(invalid, budget=budget())
    object.__setattr__(value.freshness_policy, "ref_digest", "0" * 64)
    with pytest.raises(ValueError, match="digest"):
        value.to_dict(budget=budget())


def test_nonempty_exact_requirement_set_and_whole_contract_reference_budget_apply() -> None:
    """Incomplete, mutable, reordered, duplicated or oversized evidence sets cannot weaken a contract."""
    value = evidence_contract()
    for requirements in [
        (),
        cast(tuple[EvidenceRequirement1, ...], []),
        (value.requirements[0],) * 2,
        tuple(reversed(value.requirements)),
        (cast(EvidenceRequirement1, {}),),
        (value.requirements[0],) * 129,
    ]:
        with pytest.raises(ValueError):
            replace(value, requirements=requirements).to_dict(budget=budget())
    with pytest.raises(ValueError, match="aggregate reference budget"):
        value.to_dict(budget=budget(references=4))
    with pytest.raises(ValueError, match="wrong policy component format"):
        replace(value, review_policy=reference()).to_dict(budget=budget())
    data = value.to_dict(budget=budget())
    with pytest.raises(ValueError, match="aggregate reference budget"):
        EvidenceContract2.from_dict(data, budget=budget(references=4))
    with pytest.raises(ValueError, match="contract digest"):
        replace(value, contract_digest="0" * 64).to_dict(budget=budget())


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("schema_version", "1.0"),
        ("object_kind", "legacy-evidence"),
        ("contract_id", "bad identity"),
        ("requirements", []),
        ("requirements", {}),
        ("requirements", [{}]),
        ("review_policy", reference().to_dict()),
        ("contract_digest", "0" * 64),
    ],
)
def test_rehashed_unsupported_contract_is_not_implicitly_migrated(
    field: str, invalid: object
) -> None:
    """Old versions, malformed nested inputs and different review owners stay typed refusals."""
    data = evidence_contract().to_dict(budget=budget())
    data.pop("contract_digest")
    data[field] = invalid
    digest = "0" * 64 if field == "contract_digest" else canonical_digest(data)
    with pytest.raises(ValueError):
        EvidenceContract2.from_dict({**data, "contract_digest": digest}, budget=budget())


def test_contract_closed_fields_and_array_limits_refuse_before_child_parsers() -> None:
    """An extension cannot reintroduce numeric substitutes or silently omit the qualitative review policy."""
    data = evidence_contract().to_dict(budget=budget())
    for invalid in [
        None,
        {**data, "minimum_independent_reviewers": 0},
        {key: item for key, item in data.items() if key != "review_policy"},
    ]:
        with pytest.raises(ValueError):
            EvidenceContract2.from_dict(invalid, budget=budget())
    with pytest.raises(ValueError, match="bounded nonempty array"):
        EvidenceContract2.from_dict({**data, "requirements": [{}] * 129}, budget=budget())
