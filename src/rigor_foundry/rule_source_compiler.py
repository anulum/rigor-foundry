# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete original source and component compilation
"""Join deterministic source declarations to actual retained bytes and fixed component owners."""

from __future__ import annotations

from bisect import bisect_left
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TypeAlias, cast

from .atomic_rule import AtomicRule1
from .audit_primitives import canonical_digest
from .component_source_resolution import (
    SUPPORTED_POLICY_TARGET_FORMATS,
    PolicyComponentTarget,
    parse_policy_component_target,
)
from .control_definition_v2 import ControlDefinition2
from .legacy_control_binding import LegacyControlBinding1
from .policy_model_inputs import checked_policy_budget, policy_wire_size
from .policy_read_budget import PolicyReadBudget1
from .policy_source_regions import SourceRegion1
from .policy_source_spans import SourceSpan1
from .review_policy import ReviewPolicy1
from .rule_chain_pack_v2 import AuthorityClauseV2, FreshnessPolicyV2, StandardPackV2
from .rule_source_document import RuleSourceDocument1
from .semantic_decision import SemanticDecision1
from .source_component_reader import PolicyComponent1
from .source_semantic_graph import source_rule_dependency_order
from .source_universe_owner import SourceUniverseOwner
from .standard_pack import ControlDefinition
from .typed_object_reference import TypedObjectRef1

_Key: TypeAlias = tuple[str, str, str]
_CLASSIFICATIONS = ("public", "internal", "confidential", "secret")


def rule_source_compiler_contract_digest() -> str:
    """Identify the deterministic compiler contract independently of any resulting document.

    Returns
    -------
    str
        Canonical digest binding the exact document schema, fixed target table,
        array ordering, whole declared graph and retained source/byte joins.
        Current implementation custody and semantic acceptance are separate.
    """
    return canonical_digest(
        {
            "compiler": "builtin.rule-source-compiler.v1",
            "document_schema": RuleSourceDocument1.schema_version,
            "target_formats": [list(pair) for pair in sorted(SUPPORTED_POLICY_TARGET_FORMATS)],
            "legacy_binding_order": ["rule_id", "pack.object_id", "control.object_id"],
            "graphs": "complete-declared-dependency-and-supersession-dags",
            "components": "whole-target-identity-and-bidirectional-source-joins",
            "legacy": "complete-original-pack-control-authority-freshness-cohort",
            "sources": "actual-owner-complete-cohort-initial-and-closing-byte-partitions",
            "citations": "source-region-overlap-with-exact-original-span-bytes",
            "acceptance": "independent-corpus-and-installed-competent-issuer-required",
        }
    )


@dataclass
class _Targets:
    """Keep one full owning target per versioned identity across every supplied object."""

    budget: PolicyReadBudget1
    digests: dict[_Key, str] = field(default_factory=dict)
    records: dict[_Key, PolicyComponentTarget] = field(default_factory=dict)

    def remember(self, ref: TypedObjectRef1) -> _Key:
        """Refuse a changed digest even when it occurs in an otherwise valid different object."""
        checked = TypedObjectRef1.from_dict(ref.to_dict())
        key = (checked.kind, checked.format_version, checked.object_id)
        previous = self.digests.setdefault(key, checked.object_digest)
        if previous != checked.object_digest:
            raise ValueError("source compiler has inconsistent global typed target identities")
        return key

    def add(self, ref: TypedObjectRef1, value: object) -> PolicyComponentTarget:
        """Reparse full target wire through the fixed original or new owning parser."""
        key = self.remember(ref)
        record = parse_policy_component_target(ref, value, budget=self.budget)
        self.records[key] = record
        return record

    def resolve(self, ref: TypedObjectRef1) -> PolicyComponentTarget:
        """Resolve the exact full reference, never an object ID alone."""
        key = self.remember(ref)
        if key not in self.records:
            raise ValueError("source compiler has an unresolved exact component target")
        return self.records[key]

    def check_references(self, value: object) -> None:
        """Check global identity consistency in every bounded inert nested wire record."""
        pending = [value]
        count = 0
        while pending:
            item = pending.pop()
            if type(item) is dict:
                if item.get("object_kind") == "typed-object-ref":
                    count += 1
                    if count > self.budget.max_references:
                        raise ValueError("source compiler typed references exceed the budget")
                    self.remember(TypedObjectRef1.from_dict(item))
                pending.extend(item.values())
            elif type(item) is list:
                pending.extend(item)


def _index_targets(
    document: RuleSourceDocument1,
    targets: tuple[tuple[TypedObjectRef1, object], ...],
    budget: PolicyReadBudget1,
) -> _Targets:
    """Bound and revalidate even unused supplied support targets before resolving any relation."""
    if type(targets) is not tuple or len(targets) > budget.max_references:
        raise ValueError("source compiler requires bounded immutable external targets")
    index = _Targets(budget)
    document_wire = document.to_dict(budget=budget)
    size = policy_wire_size(document_wire, budget=budget)
    wires: list[dict[str, object]] = []
    seen: set[_Key] = set()
    for pair in targets:
        if type(pair) is not tuple or len(pair) != 2 or type(pair[0]) is not TypedObjectRef1:
            raise ValueError("source compiler requires actual reference and complete target pairs")
        ref, value = pair
        key = index.remember(ref)
        if key in seen:
            raise ValueError("source compiler external target identity is duplicated")
        seen.add(key)
        wire: dict[str, object] = {"reference": ref.to_dict(), "target": value}
        size += policy_wire_size(wire, budget=budget)
        if size > budget.max_document_bytes:
            raise ValueError("source compiler complete targets exceed the aggregate byte budget")
        record = index.add(ref, value)
        if type(record) is StandardPackV2:
            components: tuple[ControlDefinition | AuthorityClauseV2 | FreshnessPolicyV2, ...] = (
                *record.controls,
                *record.authority_clauses,
                *record.freshness_policies,
            )
            for component in components:
                owner = PolicyComponent1(component, budget)
                index.add(owner.reference(), owner.to_dict())
                if type(component) is ControlDefinition:
                    evidence = PolicyComponent1(component.evidence, budget)
                    index.add(evidence.reference(), evidence.to_dict())
        wires.append(wire)
    complete: dict[str, object] = {"document": document_wire, "targets": wires}
    policy_wire_size(complete, budget=budget)
    index.check_references(complete)
    for control in document.qualitative_controls:
        index.add(control.reference(budget=budget), control.to_dict(budget=budget))
        index.add(
            control.evidence.reference(budget=budget), control.evidence.to_dict(budget=budget)
        )
    for policy in document.review_policies:
        index.add(policy.reference(budget=budget), policy.to_dict(budget=budget))
    for freshness in document.freshness_policies:
        owner = PolicyComponent1(freshness, budget)
        index.add(owner.reference(), owner.to_dict())
    return index


def _component_joins(
    document: RuleSourceDocument1, index: _Targets, budget: PolicyReadBudget1
) -> None:
    """Require complete bidirectional rule bindings and unchanged original pack enumeration."""
    rules = {rule.rule_id: rule for rule in document.rules}
    decisions = {decision.decision_id: decision for decision in document.decisions}
    emitted: set[TypedObjectRef1] = set(document.authority_bindings)
    for authority in document.authority_bindings:
        index.resolve(authority)
    for control in document.qualitative_controls:
        if control.rule_id not in rules:
            raise ValueError("source compiler qualitative control has an unresolved source rule")
        control.verify_rule_binding(rules[control.rule_id], budget=budget)
        emitted.add(control.reference(budget=budget))
        review = index.resolve(control.evidence.review_policy)
        if type(review) is not ReviewPolicy1 or review not in document.review_policies:
            raise ValueError("source compiler control review policy is outside its inline cohort")
        for requirement in control.evidence.requirements:
            index.resolve(requirement.adapter)
            freshness = index.resolve(requirement.freshness_policy)
            if (
                type(freshness) is not FreshnessPolicyV2
                or freshness not in document.freshness_policies
            ):
                raise ValueError("source compiler evidence freshness is outside its inline cohort")
            if freshness.subject_class != requirement.subject_class:
                raise ValueError("source compiler evidence and freshness subject classes differ")
    for policy in document.review_policies:
        ref = policy.reference(budget=budget)
        emitted.add(ref)
        owners = {rule.rule_id for rule in document.rules if ref in rule.component_refs}
        if not owners or owners != set(policy.source_rule_ids):
            raise ValueError("source compiler review source-rule bindings are incomplete")
        for role in policy.required_roles:
            index.resolve(role.identity_policy)
    for freshness in document.freshness_policies:
        emitted.add(PolicyComponent1(freshness, budget).reference())
    selected_packs: dict[_Key, StandardPackV2] = {}
    selected_controls: dict[_Key, set[TypedObjectRef1]] = {}
    for binding in document.legacy_control_bindings:
        if (
            binding.rule_id not in rules
            or binding.control not in rules[binding.rule_id].component_refs
        ):
            raise ValueError("source compiler legacy binding has no exact owning source rule")
        for identity in binding.source_decision_ids:
            if identity not in decisions or binding.rule_id not in (
                *decisions[identity].affected_rule_ids,
                *decisions[identity].successor_rule_ids,
            ):
                raise ValueError(
                    "source compiler legacy binding has an unresolved or unrelated decision"
                )
        pack = cast(StandardPackV2, index.resolve(binding.pack))
        binding.verify_pack(pack, budget=budget)
        key = index.remember(binding.pack)
        selected_packs[key] = pack
        selected_controls.setdefault(key, set()).add(binding.control)
        emitted.add(binding.control)
    for key, pack in selected_packs.items():
        originals = {PolicyComponent1(control, budget).reference() for control in pack.controls}
        if selected_controls[key] != originals:
            raise ValueError("source compiler omits an original selected pack control")
        if any(
            PolicyComponent1(clause, budget).reference() not in document.authority_bindings
            for clause in pack.authority_clauses
        ):
            raise ValueError("source compiler omits original selected pack authority")
        if any(policy not in document.freshness_policies for policy in pack.freshness_policies):
            raise ValueError("source compiler omits original selected pack freshness")
    referenced: set[TypedObjectRef1] = set()
    for rule in document.rules:
        if rule.lifecycle == "active" and not rule.component_refs:
            raise ValueError("source compiler active rule lacks enforcement components")
        for ref in rule.component_refs:
            index.resolve(ref)
            referenced.add(ref)
    if referenced != emitted:
        raise ValueError("source compiler emitted and rule-owned component cohorts differ")


_Intervals: TypeAlias = dict[str, tuple[tuple[int, ...], tuple[int, ...]]]


def _intervals(rows: Sequence[SourceSpan1 | SourceRegion1]) -> _Intervals:
    """Index byte intervals without changing any original source selection order."""
    grouped: dict[str, list[tuple[int, int]]] = {}
    for row in rows:
        grouped.setdefault(row.source_id, []).append((row.start_byte, row.end_byte))
    result: _Intervals = {}
    for identity, pairs in grouped.items():
        starts: list[int] = []
        ends: list[int] = []
        largest = 0
        for start, end in sorted(pairs):
            starts.append(start)
            largest = max(largest, end)
            ends.append(largest)
        result[identity] = (tuple(starts), tuple(ends))
    return result


def _overlaps(index: _Intervals, source: str, start: int, end: int) -> bool:
    """Find an actual same-source half-open overlap using finite logarithmic lookup."""
    if source not in index:
        return False
    starts, ends = index[source]
    position = bisect_left(starts, end) - 1
    return position >= 0 and ends[position] > start


def _source_joins(document: RuleSourceDocument1) -> tuple[SourceSpan1, ...]:
    """Resolve all byte-region/source relations without guessing prose meaning or issuer authority."""
    sources = {entry.source_id: entry for entry in document.universe}
    rules = {rule.rule_id: rule for rule in document.rules}
    decisions = {decision.decision_id: decision for decision in document.decisions}
    for entry in document.universe:
        if entry.disposition_decision is not None:
            if entry.disposition_decision not in decisions:
                raise ValueError("source compiler has an unresolved source disposition decision")
            if (
                entry.disposition == "excluded"
                and decisions[entry.disposition_decision].relation != "exclusion"
            ):
                raise ValueError("source compiler excluded source lacks an exclusion decision")
    rule_regions: dict[str, list[SourceRegion1]] = {}
    decision_regions: dict[str, list[SourceRegion1]] = {}
    for region in document.regions:
        if (
            region.source_id not in sources
            or any(identity not in rules for identity in region.rule_ids)
            or any(identity not in decisions for identity in region.decision_ids)
        ):
            raise ValueError(
                "source compiler region has unresolved source, rule or decision links"
            )
        for identity in region.rule_ids:
            rule_regions.setdefault(identity, []).append(region)
        for identity in region.decision_ids:
            decision_regions.setdefault(identity, []).append(region)
    spans: dict[str, SourceSpan1] = {}
    records: tuple[AtomicRule1 | SemanticDecision1, ...] = (*document.rules, *document.decisions)
    for record in records:
        identity = record.rule_id if isinstance(record, AtomicRule1) else record.decision_id
        related = (rule_regions if type(record) is AtomicRule1 else decision_regions).get(
            identity, []
        )
        region_intervals = _intervals(related)
        span_intervals = _intervals(record.source_spans)
        for span in record.source_spans:
            if span.source_id not in sources:
                raise ValueError("source compiler citation has an unresolved source")
            entry = sources[span.source_id]
            if entry.read_state != "verified" or entry.disposition != "included":
                raise ValueError(
                    "source compiler citation is outside included verified source bytes"
                )
            if type(record) is AtomicRule1 and _CLASSIFICATIONS.index(
                record.classification
            ) < _CLASSIFICATIONS.index(entry.classification):
                raise ValueError("source compiler rule classification would disclose its source")
            if not _overlaps(region_intervals, span.source_id, span.start_byte, span.end_byte):
                raise ValueError("source compiler citation lacks its exact source-region relation")
            previous = spans.setdefault(span.span_id, span)
            if previous != span:
                raise ValueError("source compiler span identity has conflicting original bytes")
        for region in related:
            if not _overlaps(span_intervals, region.source_id, region.start_byte, region.end_byte):
                raise ValueError(
                    "source compiler region relation lacks a matching original citation"
                )
        if (
            type(record) is AtomicRule1
            and record.lifecycle == "active"
            and not any(region.disposition == "normative" for region in related)
        ):
            raise ValueError("source compiler active rule lacks a normative source region")
    return tuple(spans[identity] for identity in sorted(spans))


def verify_rule_source_document(
    document: RuleSourceDocument1,
    *,
    source_owner: SourceUniverseOwner,
    targets: tuple[tuple[TypedObjectRef1, object], ...],
    budget: PolicyReadBudget1,
) -> tuple[str, ...]:
    """Verify complete source/component joins and return every dependency-first rule ID.

    Parameters
    ----------
    document : RuleSourceDocument1
        Complete deterministic declared inputs, never accepted corpus authority.
    source_owner : SourceUniverseOwner
        Actual existing owner borrowing the host's complete retained source set.
    targets : tuple of (TypedObjectRef1, object)
        Complete inert external targets for the fixed owning parser table. All
        supplied records, including unused support data, undergo full validation.
    budget : PolicyReadBudget1
        Explicit complete source/document/target allocation ceilings.

    Returns
    -------
    tuple[str, ...]
        All declared rule IDs in deterministic dependency-first order, after
        actual initial and closing source/partition/span integrity checks.

    Raises
    ------
    ValueError, OSError, StableReadError, PermissionError
        A complete record, graph, target, source relation or current owner fails.

    Notes
    -----
    Region overlap verifies declared byte joins, not adequacy of extracted prose.
    This boundary does not authenticate competent semantic issuers, current
    effective decisions, corpus/native ratification, trust lifecycle, selected
    root3, evidence or effects. Those actual installed owners remain required.
    """
    limits = checked_policy_budget(budget)
    if type(document) is not RuleSourceDocument1 or type(source_owner) is not SourceUniverseOwner:
        raise ValueError("source compiler requires the actual document and original source owner")
    document.to_dict(budget=limits)
    if document.compiler_contract_digest != rule_source_compiler_contract_digest():
        raise ValueError("source compiler contract identity differs")
    source_owner.verify(document.universe)
    order = source_rule_dependency_order(document.rules, document.decisions, budget=limits)
    index = _index_targets(document, targets, limits)
    _component_joins(document, index, limits)
    spans = _source_joins(document)
    source_owner.verify_partitions(document.universe, regions=document.regions, spans=spans)
    return order


def compile_rule_source_document(
    *,
    corpus_id: str,
    source_owner: SourceUniverseOwner,
    regions: tuple[SourceRegion1, ...],
    rules: tuple[AtomicRule1, ...],
    decisions: tuple[SemanticDecision1, ...],
    qualitative_controls: tuple[ControlDefinition2, ...],
    review_policies: tuple[ReviewPolicy1, ...],
    legacy_control_bindings: tuple[LegacyControlBinding1, ...],
    authority_bindings: tuple[TypedObjectRef1, ...],
    freshness_policies: tuple[FreshnessPolicyV2, ...],
    targets: tuple[tuple[TypedObjectRef1, object], ...],
    budget: PolicyReadBudget1,
) -> RuleSourceDocument1:
    """Compile exact explicit source declarations using the actual owner's complete universe.

    Parameters
    ----------
    corpus_id : str
        Exact declared corpus identity, without inferred applicability.
    source_owner : SourceUniverseOwner
        Actual complete retained host selections; no caller universe is accepted.
    regions, rules, decisions : tuple
        Complete exact original byte regions and explicit semantic declarations.
    qualitative_controls, review_policies, legacy_control_bindings : tuple
        Complete source-bound emitted quality components and original relations.
    authority_bindings, freshness_policies : tuple
        Exact original authority references and whole original freshness records.
    targets : tuple of (TypedObjectRef1, object)
        Full external target wires for the fixed owning parsers.
    budget : PolicyReadBudget1
        Explicit source, metadata and reference allocation limits.

    Returns
    -------
    RuleSourceDocument1
        Deterministic complete input document after all declared joins and actual
        retained byte checks, still requiring independent semantic acceptance.

    Raises
    ------
    ValueError, OSError, StableReadError, PermissionError
        A source, target, record, graph, budget or closing source check fails.
    """
    if type(source_owner) is not SourceUniverseOwner:
        raise ValueError("source compiler requires the actual original source owner")
    limits = checked_policy_budget(budget)
    document = RuleSourceDocument1.build(
        corpus_id=corpus_id,
        universe=source_owner.observe(),
        regions=regions,
        rules=rules,
        decisions=decisions,
        qualitative_controls=qualitative_controls,
        review_policies=review_policies,
        legacy_control_bindings=legacy_control_bindings,
        authority_bindings=authority_bindings,
        freshness_policies=freshness_policies,
        compiler_contract_digest=rule_source_compiler_contract_digest(),
        budget=limits,
    )
    verify_rule_source_document(
        document, source_owner=source_owner, targets=targets, budget=limits
    )
    return document
