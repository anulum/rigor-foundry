# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — deterministic complete source document inputs
"""Retain exact original source and component cohorts before compiler acceptance."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import ClassVar, TypeVar, cast

from .atomic_rule import AtomicRule1
from .audit_primitives import canonical_digest
from .control_definition_v2 import ControlDefinition2
from .legacy_control_binding import LegacyControlBinding1
from .model_primitives import require_digest, require_identifier
from .policy_model_inputs import (
    checked_policy_budget,
    policy_record_mapping,
    policy_reference,
    policy_wire_size,
)
from .policy_read_budget import PolicyReadBudget1
from .policy_source_regions import SourceRegion1
from .review_policy import ReviewPolicy1
from .rule_chain_pack_v2 import FreshnessPolicyV2
from .semantic_decision import SemanticDecision1
from .source_component_reader import PolicyComponent1
from .source_universe import SourceUniverseEntry1
from .typed_object_reference import TypedObjectRef1

RULE_SOURCE_DOCUMENT_SCHEMA_VERSION = "1.0"
_ARRAYS = (
    "universe",
    "regions",
    "rules",
    "decisions",
    "qualitative_controls",
    "review_policies",
    "legacy_control_bindings",
    "authority_bindings",
    "freshness_policies",
)
_FIELDS = frozenset(
    (
        *_ARRAYS,
        "schema_version",
        "object_kind",
        "corpus_id",
        "compiler_contract_digest",
        "document_digest",
    )
)
_T = TypeVar("_T")
_K = TypeVar("_K", str, tuple[str, int], tuple[str, str, str])


def _parse_array(value: object, parser: Callable[[object], _T], limit: int) -> tuple[_T, ...]:
    """Parse a fixed inline owner only after bounding its complete array."""
    if type(value) is not list or len(value) > limit:
        raise ValueError("source document requires bounded complete arrays")
    return tuple(parser(item) for item in value)


def _parse_region(value: object, budget: PolicyReadBudget1) -> SourceRegion1:
    """Bound original region arrays before the unchanged original parser allocates them."""
    if type(value) is not dict:
        raise ValueError("source document requires an original region mapping")
    references = 1
    for name in ("rule_ids", "decision_ids"):
        rows = value.get(name)
        if type(rows) is not list:
            raise ValueError("source document region relations require arrays")
        references += len(rows)
        if references > budget.max_references:
            raise ValueError("source document region relations exceed the reference budget")
    return SourceRegion1.from_dict(value)


def _ordered(keys: list[_K]) -> None:
    """Refuse duplicate or reordered identities without silently normalising input."""
    if keys != sorted(set(keys)):
        raise ValueError("source document cohorts must retain sorted unique identities")


@dataclass
class _DocumentArrays:
    """Accumulate complete nested references and encoded bytes before enclosing allocation."""

    budget: PolicyReadBudget1
    references: int = 0
    size: int = 0

    def add(self, wire: dict[str, object], references: int) -> dict[str, object]:
        """Charge every row and its declared nested relations to the whole document."""
        self.references += references
        if self.references > self.budget.max_references:
            raise ValueError("source document exceeds its aggregate reference budget")
        self.size += policy_wire_size(wire, budget=self.budget)
        if self.size > self.budget.max_document_bytes:
            raise ValueError("source document exceeds its aggregate byte budget")
        return wire


@dataclass(frozen=True)
class RuleSourceDocument1:
    """Complete deterministic source input, retaining original children and selection order.

    Integrity parsing does not accept extraction semantics, resolve external typed
    targets or authenticate source/issuer/corpus owners. The consuming compiler
    must verify those joins and the actual complete retained source cohort.
    No output pack/profile/lock, signature or self-acceptance is an input field.
    """

    corpus_id: str
    universe: tuple[SourceUniverseEntry1, ...]
    regions: tuple[SourceRegion1, ...]
    rules: tuple[AtomicRule1, ...]
    decisions: tuple[SemanticDecision1, ...]
    qualitative_controls: tuple[ControlDefinition2, ...]
    review_policies: tuple[ReviewPolicy1, ...]
    legacy_control_bindings: tuple[LegacyControlBinding1, ...]
    authority_bindings: tuple[TypedObjectRef1, ...]
    freshness_policies: tuple[FreshnessPolicyV2, ...]
    compiler_contract_digest: str
    document_digest: str

    schema_version: ClassVar[str] = RULE_SOURCE_DOCUMENT_SCHEMA_VERSION
    object_kind: ClassVar[str] = "rule-source-document"

    def _body(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Revalidate every direct owner before constructing bounded complete arrays."""
        limits = checked_policy_budget(budget)
        cohorts = (
            (self.universe, SourceUniverseEntry1, limits.max_sources),
            (self.regions, SourceRegion1, limits.max_references),
            (self.rules, AtomicRule1, limits.max_rules),
            (self.decisions, SemanticDecision1, limits.max_references),
            (self.qualitative_controls, ControlDefinition2, limits.max_references),
            (self.review_policies, ReviewPolicy1, limits.max_references),
            (self.legacy_control_bindings, LegacyControlBinding1, limits.max_references),
            (self.authority_bindings, TypedObjectRef1, limits.max_references),
            (self.freshness_policies, FreshnessPolicyV2, limits.max_references),
        )
        for rows, owner, count in cohorts:
            if type(rows) is not tuple or len(rows) > count:
                raise ValueError("source document requires bounded immutable cohorts")
            if any(type(row) is not owner for row in rows):
                raise ValueError("source document requires actual fixed inline owners")
        bounds = _DocumentArrays(limits)
        universe: list[dict[str, object]] = []
        for entry in self.universe:
            wire = entry.to_dict()
            policy_wire_size(wire, budget=limits)
            SourceUniverseEntry1.from_dict(wire, budget=limits)
            universe.append(bounds.add(wire, 4 + (entry.disposition_decision is not None)))
        regions: list[dict[str, object]] = []
        for region in self.regions:
            if (
                type(region.rule_ids) is not tuple
                or type(region.decision_ids) is not tuple
                or len(region.rule_ids) + len(region.decision_ids) + 1 > limits.max_references
            ):
                raise ValueError("source document region relations exceed immutable bounds")
            regions.append(
                bounds.add(region.to_dict(), 1 + len(region.rule_ids) + len(region.decision_ids))
            )
        rules = [
            bounds.add(
                rule.to_dict(budget=limits),
                1
                + len(rule.source_spans)
                + len(rule.dependency_rule_ids)
                + len(rule.decision_ids)
                + len(rule.component_refs)
                + (0 if rule.scope.condition is None else len(rule.scope.condition.references)),
            )
            for rule in self.rules
        ]
        decisions = [
            bounds.add(
                decision.to_dict(budget=limits),
                3
                + len(decision.source_spans)
                + len(decision.affected_rule_ids)
                + len(decision.successor_rule_ids)
                + (0 if decision.condition is None else len(decision.condition.references)),
            )
            for decision in self.decisions
        ]
        controls = [
            bounds.add(
                control.to_dict(budget=limits),
                2
                + 2 * len(control.evidence.requirements)
                + sum(
                    len(rows)
                    for rows in (
                        control.remediation.dependencies,
                        control.remediation.procedure_ids,
                        control.remediation.acceptance_gates,
                        control.remediation.reopen_triggers,
                    )
                )
                + (
                    0
                    if control.scope.condition is None
                    else len(control.scope.condition.references)
                ),
            )
            for control in self.qualitative_controls
        ]
        reviews = [
            bounds.add(
                policy.to_dict(budget=limits),
                len(policy.required_roles)
                + len(policy.source_rule_ids)
                + len(policy.unavailability_fact_refs),
            )
            for policy in self.review_policies
        ]
        bindings = [
            bounds.add(binding.to_dict(budget=limits), 3 + len(binding.source_decision_ids))
            for binding in self.legacy_control_bindings
        ]
        authorities = [
            bounds.add(
                policy_reference(ref, allowed=frozenset({("authority-clause", "2.0")})).to_dict(),
                1,
            )
            for ref in self.authority_bindings
        ]
        freshness = [
            bounds.add(PolicyComponent1(policy, limits).to_dict(), 1 + len(policy.invalidator_ids))
            for policy in self.freshness_policies
        ]
        _ordered([row.source_id for row in self.universe])
        _ordered([(row.source_id, row.start_byte) for row in self.regions])
        _ordered([row.rule_id for row in self.rules])
        _ordered([row.decision_id for row in self.decisions])
        _ordered([row.reference(budget=limits).object_id for row in self.qualitative_controls])
        _ordered([row.policy_id for row in self.review_policies])
        _ordered(
            [
                (row.rule_id, row.pack.object_id, row.control.object_id)
                for row in self.legacy_control_bindings
            ]
        )
        _ordered([row.object_id for row in self.authority_bindings])
        _ordered([row.policy_id for row in self.freshness_policies])
        body: dict[str, object] = {
            "schema_version": RULE_SOURCE_DOCUMENT_SCHEMA_VERSION,
            "object_kind": "rule-source-document",
            "corpus_id": require_identifier(self.corpus_id, "source corpus identity"),
            "universe": universe,
            "regions": regions,
            "rules": rules,
            "decisions": decisions,
            "qualitative_controls": controls,
            "review_policies": reviews,
            "legacy_control_bindings": bindings,
            "authority_bindings": authorities,
            "freshness_policies": freshness,
            "compiler_contract_digest": require_digest(
                self.compiler_contract_digest, "source compiler contract digest"
            ),
        }
        policy_wire_size(body, budget=limits)
        return body

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Serialize every exact input field after checking the complete owning digest."""
        body = self._body(budget=budget)
        digest = require_digest(self.document_digest, "rule source document digest")
        if digest != canonical_digest(body):
            raise ValueError("rule source document digest differs")
        result = {**body, "document_digest": digest}
        policy_wire_size(result, budget=budget)
        return result

    @classmethod
    def build(
        cls,
        *,
        corpus_id: str,
        universe: tuple[SourceUniverseEntry1, ...],
        regions: tuple[SourceRegion1, ...],
        rules: tuple[AtomicRule1, ...],
        decisions: tuple[SemanticDecision1, ...],
        qualitative_controls: tuple[ControlDefinition2, ...],
        review_policies: tuple[ReviewPolicy1, ...],
        legacy_control_bindings: tuple[LegacyControlBinding1, ...],
        authority_bindings: tuple[TypedObjectRef1, ...],
        freshness_policies: tuple[FreshnessPolicyV2, ...],
        compiler_contract_digest: str,
        budget: PolicyReadBudget1,
    ) -> RuleSourceDocument1:
        """Hash explicit source inputs without adding an observation or resulting selection."""
        candidate = cls(
            corpus_id,
            universe,
            regions,
            rules,
            decisions,
            qualitative_controls,
            review_policies,
            legacy_control_bindings,
            authority_bindings,
            freshness_policies,
            compiler_contract_digest,
            "0" * 64,
        )
        result = replace(
            candidate, document_digest=canonical_digest(candidate._body(budget=budget))
        )
        result.to_dict(budget=budget)
        return result

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> RuleSourceDocument1:
        """Parse bounded closed arrays through fixed original or explicitly new child owners."""
        limits = checked_policy_budget(budget)
        data = policy_record_mapping(
            value,
            fields=_FIELDS,
            object_kind="rule-source-document",
            schema_version=RULE_SOURCE_DOCUMENT_SCHEMA_VERSION,
            budget=limits,
        )
        count = 0
        for name in _ARRAYS:
            rows = data[name]
            if type(rows) is not list:
                raise ValueError("source document requires bounded complete arrays")
            count += len(rows)
            if count > limits.max_references:
                raise ValueError(
                    "source document requires bounded complete arrays within its reference budget"
                )
        result = cls(
            require_identifier(data["corpus_id"], "source corpus identity"),
            _parse_array(
                data["universe"],
                lambda row: SourceUniverseEntry1.from_dict(row, budget=limits),
                limits.max_sources,
            ),
            _parse_array(
                data["regions"], lambda row: _parse_region(row, limits), limits.max_references
            ),
            _parse_array(
                data["rules"],
                lambda row: AtomicRule1.from_dict(row, budget=limits),
                limits.max_rules,
            ),
            _parse_array(
                data["decisions"],
                lambda row: SemanticDecision1.from_dict(row, budget=limits),
                limits.max_references,
            ),
            _parse_array(
                data["qualitative_controls"],
                lambda row: ControlDefinition2.from_dict(row, budget=limits),
                limits.max_references,
            ),
            _parse_array(
                data["review_policies"],
                lambda row: ReviewPolicy1.from_dict(row, budget=limits),
                limits.max_references,
            ),
            _parse_array(
                data["legacy_control_bindings"],
                lambda row: LegacyControlBinding1.from_dict(row, budget=limits),
                limits.max_references,
            ),
            _parse_array(
                data["authority_bindings"], TypedObjectRef1.from_dict, limits.max_references
            ),
            _parse_array(
                data["freshness_policies"],
                lambda row: cast(
                    FreshnessPolicyV2,
                    PolicyComponent1.from_dict("freshness-policy", row, budget=limits).record,
                ),
                limits.max_references,
            ),
            require_digest(data["compiler_contract_digest"], "source compiler contract digest"),
            require_digest(data["document_digest"], "rule source document digest"),
        )
        result.to_dict(budget=limits)
        return result
