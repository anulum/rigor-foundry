# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — source-bound qualitative review policy tests
"""Exercise exact role/source declarations and original enrolled public identity policies."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from test_policy_model_inputs import budget
from test_source_component_reader import reviewer_source
from test_typed_object_reference import reference

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_reads import read_policy_document
from rigor_foundry.review_policy import ReviewPolicy1, ReviewRoleRequirement1
from rigor_foundry.source_component_reader import resolve_policy_component
from rigor_foundry.typed_object_reference import TypedObjectRef1


def role(
    *, role_id: str = "independent-reviewer", independent: bool = True
) -> ReviewRoleRequirement1:
    """Bind a real original public identity-policy record without granting role authority."""
    return ReviewRoleRequirement1.build(
        role_id=role_id,
        identity_policy=reviewer_source().reference(),
        independent_from_author=independent,
        budget=budget(),
    )


def review_policy(mode: str = "independent") -> ReviewPolicy1:
    """Declare source-required roles and explicit unknown-capable availability references."""
    return ReviewPolicy1.build(
        policy_id="review",
        mode=mode,
        required_roles=(role(),),
        source_rule_ids=("review-rule",),
        unavailability_fact_refs=("review.manager_unavailable",),
        budget=budget(),
    )


@pytest.mark.parametrize("independent", [True, False])
def test_exact_roles_keep_their_original_identity_policy_and_boolean_obligation(
    independent: bool,
) -> None:
    """An actual public identity source resolves without manufacturing enrollment or review PASS."""
    value = role(independent=independent)
    data = value.to_dict(budget=budget())
    assert ReviewRoleRequirement1.from_dict(data, budget=budget()) == value
    assert (
        resolve_policy_component(
            value.identity_policy, (reviewer_source(),), budget=budget()
        ).reference()
        == value.identity_policy
    )
    assert data["independent_from_author"] is independent
    assert data.pop("requirement_digest") == canonical_digest(data)


@pytest.mark.parametrize("mode", ["independent", "self-review", "conditional-self-review"])
def test_each_mode_retains_all_source_requirements_without_activating_fallback(mode: str) -> None:
    """SelfReview and unknown availability are metadata until actual owning verification."""
    value = review_policy(mode)
    data = value.to_dict(budget=budget())
    assert ReviewPolicy1.from_dict(data, budget=budget()) == value
    assert value.reference(budget=budget()).object_digest == value.policy_digest
    assert data["required_roles"] == [role().to_dict(budget=budget())]
    assert data["source_rule_ids"] == ["review-rule"]
    assert data["unavailability_fact_refs"] == ["review.manager_unavailable"]
    assert not {"accepted", "pass", "self_review_authorized", "reviewer_count"}.intersection(data)
    assert data.pop("policy_digest") == canonical_digest(data)


def test_file_input_uses_the_actual_bounded_original_reader_and_rejects_duplicate_keys(
    tmp_path: Path,
) -> None:
    """The real retained-file boundary preserves exact closed review policy JSON."""
    value = review_policy("conditional-self-review")
    path = tmp_path / "review.json"
    encoded = json.dumps(value.to_dict(budget=budget()))
    path.write_text(encoded, encoding="utf-8")
    assert (
        ReviewPolicy1.from_dict(read_policy_document(path, budget=budget()), budget=budget())
        == value
    )
    path.write_text('{"policy_id":"other",' + encoded[1:], encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate keys"):
        read_policy_document(path, budget=budget())


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("schema_version", "2.0"),
        ("object_kind", "review-role"),
        ("role_id", "bad role"),
        ("identity_policy", reference().to_dict()),
        ("independent_from_author", 1),
        ("requirement_digest", "0" * 64),
    ],
)
def test_rehashed_malformed_roles_never_become_source_requirements(
    field: str, invalid: object
) -> None:
    """Closed identity, exact Boolean and actual owning-reference format remain mandatory."""
    data = role().to_dict(budget=budget())
    data.pop("requirement_digest")
    data[field] = invalid
    digest = "0" * 64 if field == "requirement_digest" else canonical_digest(data)
    with pytest.raises(ValueError):
        ReviewRoleRequirement1.from_dict({**data, "requirement_digest": digest}, budget=budget())


def test_role_closed_fields_late_mutation_and_actual_reference_type_refuse() -> None:
    """The public serializer revalidates direct role records as well as parsed input."""
    data = role().to_dict(budget=budget())
    for invalid in [
        None,
        {**data, "accepted": True},
        {key: value for key, value in data.items() if key != "role_id"},
    ]:
        with pytest.raises(ValueError):
            ReviewRoleRequirement1.from_dict(invalid, budget=budget())
    with pytest.raises(ValueError, match="actual typed"):
        replace(role(), identity_policy=cast(TypedObjectRef1, {})).to_dict(budget=budget())
    with pytest.raises(ValueError, match="requirement digest"):
        replace(role(), requirement_digest="0" * 64).to_dict(budget=budget())
    changed = role()
    object.__setattr__(changed.identity_policy, "ref_digest", "0" * 64)
    with pytest.raises(ValueError, match="digest"):
        changed.to_dict(budget=budget())


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("schema_version", "2.0"),
        ("object_kind", "accepted-review"),
        ("policy_id", "bad identity"),
        ("mode", "automatic-self-review"),
        ("required_roles", {}),
        ("required_roles", [{}]),
        ("source_rule_ids", ["z", "a"]),
        ("unavailability_fact_refs", ["review.*"]),
        ("policy_digest", "0" * 64),
    ],
)
def test_rehashed_review_policy_does_not_weaken_exact_source_requirements(
    field: str, invalid: object
) -> None:
    """A self-consistent outer hash cannot enroll a role, derive fallback or normalize IDs."""
    data = review_policy().to_dict(budget=budget())
    data.pop("policy_digest")
    data[field] = invalid
    digest = "0" * 64 if field == "policy_digest" else canonical_digest(data)
    with pytest.raises(ValueError):
        ReviewPolicy1.from_dict({**data, "policy_digest": digest}, budget=budget())


def test_role_and_availability_arrays_are_immutable_sorted_unique_and_bounded() -> None:
    """No duplicate assignment or reordered source/availability set is silently rewritten."""
    value = review_policy()
    for roles in [
        (role(), role()),
        (role(role_id="z"), role(role_id="a")),
        (cast(ReviewRoleRequirement1, {}),),
        cast(tuple[ReviewRoleRequirement1, ...], []),
    ]:
        with pytest.raises(ValueError):
            replace(value, required_roles=roles).to_dict(budget=budget())
    with pytest.raises(ValueError, match="bounded immutable tuple"):
        replace(value, required_roles=(role(),) * 129).to_dict(budget=budget())
    for refs in [
        cast(tuple[str, ...], []),
        ("review.a",) * 129,
        ("review.z", "review.a"),
        ("review.a", "review.a"),
    ]:
        with pytest.raises(ValueError):
            replace(value, unavailability_fact_refs=refs).to_dict(budget=budget())
    with pytest.raises(ValueError, match="aggregate reference budget"):
        value.to_dict(budget=budget(references=2))
    limits = budget().to_dict()
    limits.pop("budget_digest")
    limits["max_rules"] = 1
    with pytest.raises(ValueError, match="source rule budget"):
        replace(value, source_rule_ids=("first", "second")).to_dict(
            budget=PolicyReadBudget1.from_dict(
                {**limits, "budget_digest": canonical_digest(limits)}
            )
        )


def test_empty_declarations_stay_declarations_and_closed_fields_remain_exact() -> None:
    """A structurally empty declaration never supplies an approved review or fallback."""
    value = ReviewPolicy1.build(
        policy_id="declared-empty",
        mode="conditional-self-review",
        required_roles=(),
        source_rule_ids=(),
        unavailability_fact_refs=(),
        budget=budget(),
    )
    assert ReviewPolicy1.from_dict(value.to_dict(budget=budget()), budget=budget()) == value
    assert not {"accepted", "pass", "fallback_allowed"}.intersection(
        value.to_dict(budget=budget())
    )
    data = review_policy().to_dict(budget=budget())
    for invalid in [
        None,
        {**data, "extra": True},
        {key: item for key, item in data.items() if key != "source_rule_ids"},
    ]:
        with pytest.raises(ValueError):
            ReviewPolicy1.from_dict(invalid, budget=budget())
    with pytest.raises(ValueError, match="bounded arrays"):
        ReviewPolicy1.from_dict({**data, "required_roles": [{}] * 129}, budget=budget())
    with pytest.raises(ValueError, match="policy digest"):
        replace(review_policy(), policy_digest="0" * 64).to_dict(budget=budget())
