# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete source rule dependency validation
"""Resolve complete declared rule dependencies without appointing effective semantic decisions."""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field

from .atomic_rule import AtomicRule1
from .policy_model_inputs import checked_policy_budget, policy_wire_size
from .policy_read_budget import PolicyReadBudget1
from .semantic_decision import SemanticDecision1


@dataclass
class _GraphBounds:
    """Bound every supplied complete record before allocating dependency edges."""

    limits: PolicyReadBudget1
    references: int = 0
    size: int = 2
    records: int = 0
    sources: set[str] = field(default_factory=set)

    def add(self, wire: dict[str, object], references: int, sources: tuple[str, ...]) -> None:
        """Account for the entire encoded record, all declared relations and source identities."""
        self.references += references
        if self.references > self.limits.max_references:
            raise ValueError("source graph exceeds its aggregate reference budget")
        self.size += policy_wire_size(wire, budget=self.limits) + bool(self.records)
        if self.size > self.limits.max_document_bytes:
            raise ValueError("source graph exceeds its aggregate byte budget")
        self.sources.update(sources)
        if len(self.sources) > self.limits.max_sources:
            raise ValueError("source graph exceeds its complete source count budget")
        self.records += 1


def _dependency_order(edges: dict[str, tuple[str, ...]], cycle_error: str) -> tuple[str, ...]:
    """Order a fully resolved finite edge set without recursion or semantic precedence inference."""
    dependents: dict[str, list[str]] = {identity: [] for identity in edges}
    pending = {identity: len(targets) for identity, targets in edges.items()}
    for identity, targets in edges.items():
        for target in targets:
            dependents[target].append(identity)
    ready = [identity for identity, count in pending.items() if count == 0]
    heapq.heapify(ready)
    ordered: list[str] = []
    while ready:
        identity = heapq.heappop(ready)
        ordered.append(identity)
        for dependent in dependents[identity]:
            pending[dependent] -= 1
            if pending[dependent] == 0:
                heapq.heappush(ready, dependent)
    if len(ordered) != len(edges):
        raise ValueError(cycle_error)
    return tuple(ordered)


def _declared_supersession(
    rules: dict[str, AtomicRule1],
    decisions: tuple[SemanticDecision1, ...],
    budget: PolicyReadBudget1,
) -> None:
    """Check every declared supersedes edge, including conditional and historical decisions."""
    edges: dict[str, set[str]] = {identity: set() for identity in rules}
    allocations = 0
    for decision in decisions:
        if decision.relation == "supersedes":
            allocations += len(decision.affected_rule_ids) * len(decision.successor_rule_ids)
            if allocations > budget.max_references:
                raise ValueError("source graph supersession edges exceed the allocation budget")
            for identity in decision.affected_rule_ids:
                edges[identity].update(decision.successor_rule_ids)
    _dependency_order(
        {identity: tuple(sorted(targets)) for identity, targets in edges.items()},
        "source graph contains a declared supersession cycle",
    )


def source_rule_dependency_order(
    rules: tuple[AtomicRule1, ...],
    decisions: tuple[SemanticDecision1, ...],
    *,
    budget: PolicyReadBudget1,
) -> tuple[str, ...]:
    """Validate the complete declared graph and return deterministic dependency-first rule IDs.

    Parameters
    ----------
    rules : tuple[AtomicRule1, ...]
        Entire immutable rule cohort, sorted by exact rule ID. Historical and
        held rows remain present and undergo the same complete integrity checks.
    decisions : tuple[SemanticDecision1, ...]
        Entire immutable semantic declaration cohort, sorted by exact decision
        ID. All rule and decision targets must resolve within these cohorts.
    budget : PolicyReadBudget1
        Explicit rule/source counts and aggregate reference/encoded byte bounds.

    Returns
    -------
    tuple[str, ...]
        Every supplied rule exactly once, after its dependencies. Simultaneously
        available nodes sort by exact ID; dates, filenames and digests never
        establish precedence. This order is not semantic supersession selection.

    Raises
    ------
    ValueError
        A direct owner, duplicate/reordered identity, unknown/unrelated target,
        supersession self edge, declared dependency/supersession cycle or
        complete allocation bound is invalid.

    Notes
    -----
    Every declared supersession edge is checked before any effective selection.
    Interpretation/adoption/exclusion metadata is not a supersession edge.
    The installed owner must separately authenticate source/issuer/scope and
    conditions, derive the actual complete effective decision set and check
    simultaneous conflicts and legitimate exceptions. No lifecycle, backlink,
    authority proof or successful order grants semantic acceptance or a gate.
    """
    limits = checked_policy_budget(budget)
    if (
        type(rules) is not tuple
        or type(decisions) is not tuple
        or len(rules) > limits.max_rules
        or len(decisions) > limits.max_references
    ):
        raise ValueError("source graph requires bounded immutable rule and decision cohorts")
    bounds = _GraphBounds(limits, size=policy_wire_size([], budget=limits))
    rule_index: dict[str, AtomicRule1] = {}
    previous: str | None = None
    for rule in rules:
        if type(rule) is not AtomicRule1:
            raise ValueError("source graph requires actual complete atomic rules")
        wire = rule.to_dict(budget=limits)
        if previous is not None and rule.rule_id <= previous:
            raise ValueError("source graph rules must be sorted and unique")
        count = (
            1
            + len(rule.source_spans)
            + len(rule.dependency_rule_ids)
            + len(rule.decision_ids)
            + len(rule.component_refs)
        )
        count += 0 if rule.scope.condition is None else len(rule.scope.condition.references)
        bounds.add(wire, count, tuple(span.source_id for span in rule.source_spans))
        rule_index[rule.rule_id] = rule
        previous = rule.rule_id
    decision_index: dict[str, SemanticDecision1] = {}
    previous = None
    for decision in decisions:
        if type(decision) is not SemanticDecision1:
            raise ValueError("source graph requires actual complete semantic decisions")
        wire = decision.to_dict(budget=limits)
        if previous is not None and decision.decision_id <= previous:
            raise ValueError("source graph decisions must be sorted and unique")
        count = (
            3
            + len(decision.source_spans)
            + len(decision.affected_rule_ids)
            + len(decision.successor_rule_ids)
        )
        count += 0 if decision.condition is None else len(decision.condition.references)
        bounds.add(wire, count, tuple(span.source_id for span in decision.source_spans))
        decision_index[decision.decision_id] = decision
        previous = decision.decision_id
    for rule in rules:
        if any(identity not in rule_index for identity in rule.dependency_rule_ids):
            raise ValueError("source graph contains an unresolved rule dependency")
        if any(identity not in decision_index for identity in rule.decision_ids):
            raise ValueError("source graph contains an unresolved rule decision")
        for identity in rule.decision_ids:
            declared = decision_index[identity]
            if (
                rule.rule_id not in declared.affected_rule_ids
                and rule.rule_id not in declared.successor_rule_ids
            ):
                raise ValueError("source graph rule references an unrelated semantic decision")
    for decision in decisions:
        if any(
            identity not in rule_index
            for identity in (*decision.affected_rule_ids, *decision.successor_rule_ids)
        ):
            raise ValueError("source graph contains an unresolved semantic rule target")
    _declared_supersession(rule_index, decisions, limits)
    return _dependency_order(
        {rule.rule_id: rule.dependency_rule_ids for rule in rules},
        "source graph contains a rule dependency cycle",
    )
