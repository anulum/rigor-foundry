# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete mixed-format profile tests
"""Exercise complete signed selections, explicit rule dispositions and original version refusal."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import cast

import pytest
from test_policy_model_inputs import budget
from test_rule_chain_pack_v3 import qualitative_pack
from test_rule_chain_trust_v3 import selected_roles
from test_rule_corpus_acceptance import corpus_signature

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.rule_chain_profile_v2 import ProjectProfileV2
from rigor_foundry.rule_chain_profile_v3 import (
    PackSelectionV3,
    ProfileRuleDisposition1,
    ProjectProfileV3,
)
from rigor_foundry.signed_rule_chain_v3 import RuleChainV3Signature
from rigor_foundry.standard_pack import TargetLevel


def selection(*, legacy: bool = False) -> PackSelectionV3:
    """Select an exact actual new pack or a separately identified unchanged original child."""
    actual = qualitative_pack()
    return PackSelectionV3.build(
        pack_id="original" if legacy else actual.pack_id,
        pack_format="2.0" if legacy else "3.0",
        pack_digest="c" * 64 if legacy else actual.pack_digest,
        source_digest="d" * 64 if legacy else actual.source_digest,
        transition_digest="e" * 64 if legacy else None,
        corpus_acceptance_digest=None if legacy else actual.corpus_acceptance_digest,
        pack_signer_key_id="original-pack-issuer" if legacy else actual.signature.key_id,
        budget=budget(size=30000),
    )


def disposition(*, excluded: bool = False, identity: str = "rule") -> ProfileRuleDisposition1:
    """Retain an explicit decision identity for declarative exclusions without accepting it."""
    return ProfileRuleDisposition1.build(
        rule_id=identity,
        disposition="excluded" if excluded else "included",
        decision_id="exact-decision" if excluded else None,
        budget=budget(size=30000),
    )


def project_profile(*, legacy: bool = False, excluded: bool = False) -> ProjectProfileV3:
    """Sign one complete TEST selection under the actual project-selector3 crypto domain."""
    packs = (selection(legacy=True), selection()) if legacy else (selection(),)
    rows = (
        (disposition(), disposition(excluded=True, identity="secondary"))
        if excluded
        else (disposition(),)
    )
    limits = budget(size=30000)
    body = ProjectProfileV3.body(
        project_id="example",
        profile_id="complete",
        selector_scope_digest="1" * 64,
        selected_packs=packs,
        corpus_acceptance_digest="b" * 64,
        mandatory_rule_ids=("rule",),
        rule_dispositions=rows,
        target_maturity="production",
        legacy_fact_context_digest="2" * 64 if legacy else None,
        local_constraint_digests=("3" * 64, "4" * 64),
        budget=limits,
    )
    return ProjectProfileV3.build(
        project_id="example",
        profile_id="complete",
        selector_scope_digest="1" * 64,
        selected_packs=packs,
        corpus_acceptance_digest="b" * 64,
        mandatory_rule_ids=("rule",),
        rule_dispositions=rows,
        target_maturity="production",
        legacy_fact_context_digest="2" * 64 if legacy else None,
        local_constraint_digests=("3" * 64, "4" * 64),
        signature=corpus_signature("project-profile", canonical_digest(body), budget=limits),
        budget=limits,
    )


@pytest.mark.parametrize("legacy,excluded", [(False, False), (True, False), (True, True)])
def test_complete_profile_retains_pack_order_old_null_and_full_signed_body(
    legacy: bool,
    excluded: bool,
) -> None:
    """One new signed profile can select both actual formats without a second effective root."""
    actual, limits, roles = (
        project_profile(legacy=legacy, excluded=excluded),
        budget(size=30000),
        selected_roles(),
    )
    wire = actual.to_dict(budget=limits)
    assert len(wire) == 14 and wire["schema_version"] == "3.0"
    assert ProjectProfileV3.from_dict(wire, budget=limits) == actual
    assert actual.signature.verify(
        object_kind="project-profile",
        body_schema_version="3.0",
        body_digest=canonical_digest(actual.unsigned_body(budget=limits)),
        roles=roles,
        trust_roles_digest=roles.trust_roles_digest,
        now=datetime(2026, 10, 28, tzinfo=UTC),
        budget=limits,
    )
    assert [row.pack_id for row in actual.selected_packs] == (
        ["original", "example-quality"] if legacy else ["example-quality"]
    )
    for row in actual.selected_packs:
        assert PackSelectionV3.from_dict(row.to_dict(budget=limits), budget=limits) == row
    for rule_row in actual.rule_dispositions:
        assert (
            ProfileRuleDisposition1.from_dict(rule_row.to_dict(budget=limits), budget=limits)
            == rule_row
        )
    with pytest.raises(ValueError):
        ProjectProfileV2.from_dict(wire)


@pytest.mark.parametrize("legacy", [False, True])
def test_pack_selection_requires_exact_supported_format_acceptance_and_owning_digest(
    legacy: bool,
) -> None:
    """Caller metadata cannot mix old transitions and complete new corpus acceptance."""
    actual, limits = selection(legacy=legacy), budget(size=30000)
    bad = (
        replace(actual, pack_format="1.0"),
        replace(actual, corpus_acceptance_digest="f" * 64)
        if legacy
        else replace(actual, transition_digest="f" * 64),
        replace(actual, transition_digest=None)
        if legacy
        else replace(actual, corpus_acceptance_digest=None),
        replace(actual, selection_digest="0" * 64),
    )
    for value in bad:
        with pytest.raises(ValueError):
            value.to_dict(budget=limits)
    wire = actual.to_dict(budget=limits)
    for changed in ({**wire, "extra": True}, {**wire, "schema_version": "2.0"}):
        with pytest.raises(ValueError):
            PackSelectionV3.from_dict(changed, budget=limits)


def test_exclusion_requires_decision_and_never_proves_its_acceptance() -> None:
    """Exclusion declaration retains its decision relation without granting issuer authority."""
    actual, limits = disposition(excluded=True), budget(size=30000)
    for changed in (
        replace(actual, disposition="held"),
        replace(actual, decision_id=None),
        replace(actual, disposition_digest="0" * 64),
    ):
        with pytest.raises(ValueError):
            changed.to_dict(budget=limits)
    wire = actual.to_dict(budget=limits)
    for changed_wire in ({**wire, "extra": True}, {**wire, "schema_version": "3.0"}):
        with pytest.raises(ValueError):
            ProfileRuleDisposition1.from_dict(changed_wire, budget=limits)
    included_with_decision = ProfileRuleDisposition1.build(
        rule_id="rule",
        disposition="included",
        decision_id="adopt-original",
        budget=limits,
    )
    assert (
        ProfileRuleDisposition1.from_dict(
            included_with_decision.to_dict(budget=limits), budget=limits
        )
        == included_with_decision
    )


def test_mandatory_floor_full_identity_and_current_corpus_cannot_be_weakened_by_profile() -> None:
    """A fresh signature cannot repair ambiguous metadata, duplicate rules or declared floor removal."""
    actual, limits = project_profile(), budget(size=30000)
    invalid = (
        replace(actual, selected_packs=()),
        replace(actual, selected_packs=(selection(), selection())),
        replace(actual, corpus_acceptance_digest="f" * 64),
        replace(actual, rule_dispositions=(disposition(excluded=True),)),
        replace(actual, rule_dispositions=()),
        replace(actual, rule_dispositions=(disposition(), disposition())),
        replace(actual, rule_dispositions=(disposition(identity="z"), disposition(identity="a"))),
        replace(actual, target_maturity=cast(TargetLevel, "caller-choice")),
        replace(actual, local_constraint_digests=("4" * 64, "3" * 64)),
        replace(actual, local_constraint_digests=("3" * 64, "3" * 64)),
        replace(actual, signature=cast(RuleChainV3Signature, "caller-signature")),
        replace(
            actual,
            signature=corpus_signature(
                "standard-pack",
                canonical_digest(actual.unsigned_body(budget=limits)),
                budget=limits,
            ),
        ),
        replace(actual, profile_digest="0" * 64),
    )
    for invalid_profile in invalid:
        with pytest.raises(ValueError):
            invalid_profile.to_dict(budget=limits)


def test_closed_profile_refuses_unknown_fields_body_changes_and_mutable_or_excessive_arrays() -> (
    None
):
    """Both public parser and direct serialization apply complete fixed child owners and bounds."""
    actual, limits = project_profile(), budget(size=30000)
    wire = actual.to_dict(budget=limits)
    for changed in (
        {**wire, "extra": True},
        {**wire, "profile_digest": "0" * 64},
        {**wire, "project_id": "other"},
        {**wire, "selected_packs": None},
        {**wire, "mandatory_rule_ids": ["rule"] * 129},
    ):
        with pytest.raises(ValueError):
            ProjectProfileV3.from_dict(changed, budget=limits)
    invalid = (
        replace(actual, selected_packs=cast(tuple[PackSelectionV3, ...], [selection()])),
        replace(actual, selected_packs=cast(tuple[PackSelectionV3, ...], ("caller-pack",))),
        replace(
            actual, rule_dispositions=cast(tuple[ProfileRuleDisposition1, ...], [disposition()])
        ),
        replace(
            actual, rule_dispositions=cast(tuple[ProfileRuleDisposition1, ...], ("caller-rule",))
        ),
        replace(actual, rule_dispositions=(disposition(),) * 33),
        replace(actual, selected_packs=(selection(),) * 129),
        replace(actual, local_constraint_digests=cast(tuple[str, ...], [])),
        replace(actual, local_constraint_digests=("3" * 64,) * 129),
    )
    for invalid_profile in invalid:
        with pytest.raises(ValueError):
            invalid_profile.to_dict(budget=limits)
    for bounds in (budget(size=1), budget(size=30000, references=5)):
        with pytest.raises(ValueError):
            actual.to_dict(budget=bounds)


def test_pack_order_is_signed_without_inventing_identity_sort_precedence() -> None:
    """Explicit selection order survives serialization and participates in the full profile digest."""
    actual, limits = project_profile(legacy=True), budget(size=30000)
    other = replace(actual, selected_packs=tuple(reversed(actual.selected_packs)))
    body = other.unsigned_body(budget=limits)
    assert body != actual.unsigned_body(budget=limits)
    with pytest.raises(ValueError, match="signature metadata"):
        other.to_dict(budget=limits)
