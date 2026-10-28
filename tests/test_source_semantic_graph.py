# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — full declared rule dependency tests
"""Exercise public complete graph boundaries without treating declarations as effective decisions."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import cast

import pytest
from test_atomic_rule import rule
from test_policy_model_inputs import budget
from test_rule_scope import scoped
from test_semantic_decision import decision

from rigor_foundry.atomic_rule import AtomicRule1
from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.policy_source_spans import SourceSpan1
from rigor_foundry.semantic_decision import SemanticDecision1
from rigor_foundry.source_semantic_graph import source_rule_dependency_order


def graph_rule(
    identity: str,
    dependencies: tuple[str, ...] = (),
    decisions: tuple[str, ...] = (),
    *,
    conditional: bool = False,
    lifecycle: str = "active",
    source_id: str = "policy",
) -> AtomicRule1:
    """Derive a complete actual rule with exact retained statement bytes and original components."""
    original = rule(conditional=conditional, lifecycle=lifecycle)
    wire = original.to_dict(budget=budget())
    span = SourceSpan1.build(
        span_id="statement",
        source_id=source_id,
        start_byte=0,
        end_byte=len(original.statement.encode()),
        payload=original.statement.encode(),
    )
    wire.update(
        rule_id=identity,
        dependency_rule_ids=list(dependencies),
        decision_ids=list(decisions),
        source_spans=[span.to_dict()],
    )
    wire.pop("rule_digest")
    return AtomicRule1.from_dict({**wire, "rule_digest": canonical_digest(wire)}, budget=budget())


def graph_decision(
    identity: str = "decision",
    *,
    affected: tuple[str, ...] = ("a",),
    successors: tuple[str, ...] = ("b",),
    conditional: bool = False,
    relation: str = "interpretation",
) -> SemanticDecision1:
    """Keep the actual source/proof owner metadata while supplying explicit declared rule targets."""
    wire = decision(relation, condition=scoped().condition if conditional else None).to_dict(
        budget=budget()
    )
    wire.update(
        decision_id=identity, affected_rule_ids=list(affected), successor_rule_ids=list(successors)
    )
    wire.pop("decision_digest")
    return SemanticDecision1.from_dict(
        {**wire, "decision_digest": canonical_digest(wire)}, budget=budget()
    )


@pytest.mark.parametrize("conditional", [False, True])
def test_complete_diamond_graph_has_deterministic_dependency_first_order(
    conditional: bool,
) -> None:
    """All supplied active and historical rules survive; ID tie breaking never chooses semantic precedence."""
    rules = (
        graph_rule("a", ("b", "c"), ("decision",), conditional=conditional, lifecycle="held"),
        graph_rule("b", ("d",), conditional=conditional),
        graph_rule("c", ("d",), conditional=conditional, lifecycle="retired"),
        graph_rule("d", conditional=conditional),
        graph_rule("z", conditional=conditional),
    )
    declarations = (graph_decision(conditional=conditional),)
    before = tuple(item.to_dict(budget=budget()) for item in (*rules, *declarations))
    assert source_rule_dependency_order(rules, declarations, budget=budget(size=65536)) == (
        "d",
        "b",
        "c",
        "a",
        "z",
    )
    assert before == tuple(item.to_dict(budget=budget()) for item in (*rules, *declarations))
    assert source_rule_dependency_order((), (), budget=budget()) == ()
    source_only = graph_decision(affected=(), successors=())
    assert source_rule_dependency_order((), (source_only,), budget=budget()) == ()


def test_unknown_dependency_decision_and_all_semantic_targets_refuse() -> None:
    """Every declared reference is checked; an early dependency-ready node cannot hide a later target."""
    with pytest.raises(ValueError, match="unresolved rule dependency"):
        source_rule_dependency_order((graph_rule("a", ("missing",)),), (), budget=budget())
    with pytest.raises(ValueError, match="unresolved rule decision"):
        source_rule_dependency_order(
            (graph_rule("a", decisions=("missing",)),), (), budget=budget()
        )
    rules = (graph_rule("a"), graph_rule("b"))
    for declared in [
        graph_decision(affected=("missing",)),
        graph_decision(successors=("missing",)),
    ]:
        with pytest.raises(ValueError, match="unresolved semantic rule target"):
            source_rule_dependency_order(rules, (declared,), budget=budget())
    assert source_rule_dependency_order(
        rules, (graph_decision(affected=("a",), successors=("a",)),), budget=budget()
    ) == ("a", "b")
    supersession = graph_decision(relation="supersedes")
    object.__setattr__(supersession, "successor_rule_ids", ("a",))
    with pytest.raises(ValueError, match="supersession"):
        source_rule_dependency_order(rules, (supersession,), budget=budget())


def test_multi_rule_cycles_and_historical_cycles_cannot_be_dropped() -> None:
    """Two-node and longer cycles refuse even when an unrelated node is ready or a row is retired."""
    for rules in [
        (graph_rule("a", ("b",)), graph_rule("b", ("a",))),
        (
            graph_rule("a", ("b",)),
            graph_rule("b", ("c",), lifecycle="retired"),
            graph_rule("c", ("a",)),
            graph_rule("z"),
        ),
    ]:
        with pytest.raises(ValueError, match="rule dependency cycle"):
            source_rule_dependency_order(rules, (), budget=budget(size=65536))


@pytest.mark.parametrize("conditional", [False, True])
def test_declared_supersession_cycles_hold_without_any_backlink_or_active_selection(
    conditional: bool,
) -> None:
    """Conditional or inactive labels cannot hide a complete declared precedence cycle."""
    rules = (
        graph_rule("a", lifecycle="retired"),
        graph_rule("b", lifecycle="held"),
        graph_rule("c"),
    )
    declarations = (
        graph_decision(
            "d0",
            affected=("a",),
            successors=("b",),
            conditional=conditional,
            relation="supersedes",
        ),
        graph_decision(
            "d1",
            affected=("b",),
            successors=("c",),
            conditional=conditional,
            relation="supersedes",
        ),
        graph_decision(
            "d2",
            affected=("c",),
            successors=("a",),
            conditional=conditional,
            relation="supersedes",
        ),
    )
    assert all(not item.decision_ids for item in rules)
    with pytest.raises(ValueError, match="declared supersession cycle"):
        source_rule_dependency_order(rules, declarations, budget=budget(size=65536))


def test_resolved_endpoint_relations_need_no_invented_reciprocal_backlinks() -> None:
    """Every supersedes endpoint participates, while interpretation metadata creates no precedence edge."""
    rules = (graph_rule("a"), graph_rule("b"), graph_rule("c"))
    forks = (
        graph_decision("d0", affected=("a",), successors=("b",), relation="supersedes"),
        graph_decision("d1", affected=("a",), successors=("b", "c"), relation="supersedes"),
    )
    assert source_rule_dependency_order(rules, forks, budget=budget(size=65536)) == ("a", "b", "c")
    interpretations = (
        graph_decision("d0", affected=("a",), successors=("b",)),
        graph_decision("d1", affected=("b",), successors=("a",)),
    )
    assert source_rule_dependency_order(rules, interpretations, budget=budget(size=65536)) == (
        "a",
        "b",
        "c",
    )
    with pytest.raises(ValueError, match="unrelated semantic decision"):
        source_rule_dependency_order(
            (graph_rule("a", decisions=("decision",)), graph_rule("b"), graph_rule("c")),
            (graph_decision(affected=("b",), successors=("c",)),),
            budget=budget(size=65536),
        )
    exclusion = graph_decision(relation="exclusion", affected=(), successors=())
    assert source_rule_dependency_order((), (exclusion,), budget=budget()) == ()


def test_cartesian_supersession_allocation_is_bounded_before_edges_are_materialized() -> None:
    """Individually valid declared sets cannot cause unbounded quadratic graph allocation."""
    identities = tuple(f"r{index:02d}" for index in range(32))
    rules = tuple(graph_rule(identity) for identity in identities)
    split = graph_decision(
        affected=identities[:16], successors=identities[16:], relation="supersedes"
    )
    # Declared node/reference input fits200; the256 directed edges do not.
    with pytest.raises(ValueError, match="supersession edges exceed the allocation budget"):
        source_rule_dependency_order(rules, (split,), budget=budget(size=131072, references=200))


def test_direct_cohorts_reject_foreign_mutable_duplicate_and_reordered_owners() -> None:
    """The entire actual cohort validates before any order is returned, including unselected corrupt rows."""
    a, b = graph_rule("a"), graph_rule("b")
    d, e = graph_decision("d"), graph_decision("e")
    for rules, declarations in [
        (cast(tuple[AtomicRule1, ...], [a]), ()),
        ((a,), cast(tuple[SemanticDecision1, ...], [])),
        (cast(tuple[AtomicRule1, ...], ({},)), ()),
        ((a, b), cast(tuple[SemanticDecision1, ...], ({},))),
        ((a, a), ()),
        ((b, a), ()),
        ((a, b), (d, d)),
        ((a, b), (e, d)),
    ]:
        with pytest.raises(
            ValueError, match=r"bounded immutable|actual complete|sorted and unique"
        ):
            source_rule_dependency_order(rules, declarations, budget=budget(size=65536))
    corrupt = replace(b, rule_digest="0" * 64)
    with pytest.raises(ValueError, match="atomic rule digest"):
        source_rule_dependency_order((a, corrupt), (), budget=budget())
    corrupt_decision = replace(d, decision_digest="0" * 64)
    with pytest.raises(ValueError, match="semantic decision digest"):
        source_rule_dependency_order((a, b), (corrupt_decision,), budget=budget())


def test_complete_source_counts_and_graph_allocations_apply_before_edge_construction() -> None:
    """Each valid owner can fit while the complete supplied source/reference/byte cohort does not."""
    a, b = graph_rule("a"), graph_rule("b")
    with pytest.raises(ValueError, match="bounded immutable"):
        source_rule_dependency_order((a,) * 33, (), budget=budget())
    with pytest.raises(ValueError, match="bounded immutable"):
        source_rule_dependency_order((), (graph_decision(),) * 129, budget=budget())
    with pytest.raises(ValueError, match="aggregate reference budget"):
        source_rule_dependency_order((a, b), (), budget=budget(references=9))
    wire = budget().to_dict()
    wire.pop("budget_digest")
    wire["max_sources"] = 1
    limits = PolicyReadBudget1.from_dict({**wire, "budget_digest": canonical_digest(wire)})
    with pytest.raises(ValueError, match="complete source count budget"):
        source_rule_dependency_order(
            (a, graph_rule("b", source_id="other-policy")), (), budget=limits
        )
    encoded = json.dumps(
        [a.to_dict(budget=budget()), b.to_dict(budget=budget())],
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
    assert source_rule_dependency_order((a, b), (), budget=budget(size=len(encoded))) == ("a", "b")
    with pytest.raises(ValueError, match="aggregate byte budget"):
        source_rule_dependency_order((a, b), (), budget=budget(size=len(encoded) - 1))
    with pytest.raises(ValueError, match="document byte budget"):
        source_rule_dependency_order((), (), budget=budget(size=1))
