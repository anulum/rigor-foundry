# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — explicit source-bound qualitative controls
"""Bind a version2 control to exact scope, qualitative evidence and original remediation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, cast

from .audit_primitives import (
    AUDIT_DOMAINS,
    Severity,
    canonical_digest,
    require_exact_fields,
    require_mapping,
    require_string,
)
from .evidence_contract_v2 import EvidenceContract2
from .model_primitives import require_digest, require_identifier, require_semantic_version
from .policy_model_inputs import checked_policy_budget, policy_record_mapping, policy_wire_size
from .policy_read_budget import PolicyReadBudget1
from .rule_scope import RuleScope1
from .standard_pack import TARGET_LEVEL_ORDER, ControlMode, RemediationContract, TargetLevel
from .typed_object_reference import TypedObjectRef1

CONTROL_DEFINITION_V2_SCHEMA_VERSION = "2.0"
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "control_id",
        "version",
        "title",
        "domain",
        "severity",
        "target_level",
        "mode",
        "rule_id",
        "scope",
        "evidence",
        "remediation",
        "control_digest",
    }
)
_REMEDIATION_FIELDS = frozenset(
    {
        "schema_version",
        "dependencies",
        "procedure_ids",
        "acceptance_gates",
        "reopen_triggers",
        "independent_verifier_required",
        "contract_digest",
    }
)
_REMEDIATION_ARRAYS = ("dependencies", "procedure_ids", "acceptance_gates", "reopen_triggers")


def _remediation(value: object, budget: PolicyReadBudget1) -> RemediationContract:
    """Bound and close the unchanged original child before its actual owning parser."""
    if type(value) is RemediationContract:
        count = 0
        for sequence in (
            value.dependencies,
            value.procedure_ids,
            value.acceptance_gates,
            value.reopen_triggers,
        ):
            if type(sequence) is not tuple:
                raise ValueError("original remediation requires immutable child sequences")
            count += len(sequence)
            if count > budget.max_references:
                raise ValueError("original remediation exceeds the reference budget")
        value = value.to_dict()
    policy_wire_size(value, budget=budget)
    data = require_mapping(value, "original remediation contract")
    require_exact_fields(data, _REMEDIATION_FIELDS, "original remediation contract")
    count = 0
    for name in _REMEDIATION_ARRAYS:
        rows = data[name]
        if type(rows) is not list:
            raise ValueError("original remediation requires arrays")
        count += len(rows)
        if count > budget.max_references:
            raise ValueError("original remediation exceeds the reference budget")
    return RemediationContract.from_dict(data)


@dataclass(frozen=True)
class ControlDefinition2:
    """An explicit rule-bound control with qualitative evidence and original remediation.

    Rule/scope/mode relations require exact owning verification. This record
    supplies no default applicability, inferred SelfReview permission, source
    acceptance, assessment or effect authority. Legacy controls keep their
    separate original contract and numeric obligations.
    """

    control_id: str
    version: str
    title: str
    domain: str
    severity: Severity
    target_level: TargetLevel
    mode: ControlMode
    rule_id: str
    scope: RuleScope1
    evidence: EvidenceContract2
    remediation: RemediationContract
    control_digest: str

    schema_version: ClassVar[str] = CONTROL_DEFINITION_V2_SCHEMA_VERSION
    object_kind: ClassVar[str] = "control-definition"

    def _body(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Revalidate exact qualitative children, unchanged remediation and complete allocation."""
        limits = checked_policy_budget(budget)
        domain = require_string(self.domain, "qualitative control domain")
        severity = require_string(self.severity, "qualitative control severity")
        target = require_string(self.target_level, "qualitative control target")
        mode = require_string(self.mode, "qualitative control mode")
        if (
            domain not in AUDIT_DOMAINS
            or severity not in {"P0", "P1", "P2", "P3", "P4"}
            or target not in TARGET_LEVEL_ORDER
            or mode not in {"require", "deny"}
        ):
            raise ValueError("unsupported qualitative control domain, severity, maturity or mode")
        if (
            type(self.scope) is not RuleScope1
            or type(self.evidence) is not EvidenceContract2
            or type(self.remediation) is not RemediationContract
        ):
            raise ValueError(
                "qualitative control requires actual scope, evidence and original remediation"
            )
        scope = self.scope.to_dict(budget=limits)
        evidence = self.evidence.to_dict(budget=limits)
        remediation = _remediation(self.remediation, limits)
        count = 2 + 2 * len(self.evidence.requirements)
        count += sum(
            len(sequence)
            for sequence in (
                remediation.dependencies,
                remediation.procedure_ids,
                remediation.acceptance_gates,
                remediation.reopen_triggers,
            )
        )
        if self.scope.condition is not None:
            count += len(self.scope.condition.references)
        if count > limits.max_references:
            raise ValueError("qualitative control exceeds the aggregate reference budget")
        body: dict[str, object] = {
            "schema_version": CONTROL_DEFINITION_V2_SCHEMA_VERSION,
            "object_kind": "control-definition",
            "control_id": require_identifier(self.control_id, "qualitative control identity"),
            "version": require_semantic_version(self.version, "qualitative control version"),
            "title": require_string(self.title, "qualitative control title"),
            "domain": domain,
            "severity": severity,
            "target_level": target,
            "mode": mode,
            "rule_id": require_identifier(self.rule_id, "qualitative source rule identity"),
            "scope": scope,
            "evidence": evidence,
            "remediation": remediation.to_dict(),
        }
        policy_wire_size(body, budget=limits)
        return body

    @classmethod
    def build(
        cls,
        *,
        control_id: str,
        version: str,
        title: str,
        domain: str,
        severity: Severity,
        target_level: TargetLevel,
        mode: ControlMode,
        rule_id: str,
        scope: RuleScope1,
        evidence: EvidenceContract2,
        remediation: RemediationContract,
        budget: PolicyReadBudget1,
    ) -> ControlDefinition2:
        """Bind an explicit control without creating an unrelated legacy profile lock."""
        candidate = cls(
            control_id,
            version,
            title,
            domain,
            severity,
            target_level,
            mode,
            rule_id,
            scope,
            evidence,
            remediation,
            "",
        )
        body = candidate._body(budget=budget)
        result = cls(
            control_id,
            version,
            title,
            domain,
            severity,
            target_level,
            mode,
            rule_id,
            scope,
            evidence,
            remediation,
            canonical_digest(body),
        )
        result.to_dict(budget=budget)
        return result

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Serialize the complete version2 owner after rechecking direct values and integrity."""
        body = self._body(budget=budget)
        digest = require_digest(self.control_digest, "qualitative control digest")
        if digest != canonical_digest(body):
            raise ValueError("qualitative control digest differs")
        result = {**body, "control_digest": digest}
        policy_wire_size(result, budget=budget)
        return result

    def reference(self, *, budget: PolicyReadBudget1) -> TypedObjectRef1:
        """Return the exact versioned control identity for its owning compiler to resolve."""
        self.to_dict(budget=budget)
        return TypedObjectRef1.build(
            kind="control-definition",
            format_version=CONTROL_DEFINITION_V2_SCHEMA_VERSION,
            object_id=f"{self.control_id}@{self.version}",
            object_digest=self.control_digest,
        )

    def verify_rule_binding(self, rule: object, *, budget: PolicyReadBudget1) -> None:
        """Check exact original rule identity, mode, scope and emitted component relation.

        This verifies structural binding only. Complete source/semantic acceptance,
        current selected policy and authenticated assessment remain separate.

        Parameters
        ----------
        rule : object
            An actual ``AtomicRule1`` instance, checked before serialization.
        budget : PolicyReadBudget1
            Explicit bounds for both complete records.
        """
        from .atomic_rule import AtomicRule1

        self.to_dict(budget=budget)
        if type(rule) is not AtomicRule1:
            raise ValueError("control binding requires an actual atomic rule")
        actual = AtomicRule1.from_dict(rule.to_dict(budget=budget), budget=budget)
        if (
            actual.rule_id != self.rule_id
            or actual.mode != self.mode
            or actual.scope.to_dict(budget=budget) != self.scope.to_dict(budget=budget)
            or self.reference(budget=budget) not in actual.component_refs
        ):
            raise ValueError("qualitative control differs from its exact source rule binding")

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> ControlDefinition2:
        """Parse the exact new control and unchanged original remediation without migration."""
        data = policy_record_mapping(
            value,
            fields=_FIELDS,
            object_kind="control-definition",
            schema_version=CONTROL_DEFINITION_V2_SCHEMA_VERSION,
            budget=budget,
        )
        result = cls(
            require_identifier(data["control_id"], "qualitative control identity"),
            require_semantic_version(data["version"], "qualitative control version"),
            require_string(data["title"], "qualitative control title"),
            require_string(data["domain"], "qualitative control domain"),
            cast(Severity, require_string(data["severity"], "qualitative control severity")),
            cast(TargetLevel, require_string(data["target_level"], "qualitative control target")),
            cast(ControlMode, require_string(data["mode"], "qualitative control mode")),
            require_identifier(data["rule_id"], "qualitative source rule identity"),
            RuleScope1.from_dict(data["scope"], budget=budget),
            EvidenceContract2.from_dict(data["evidence"], budget=budget),
            _remediation(data["remediation"], checked_policy_budget(budget)),
            require_digest(data["control_digest"], "qualitative control digest"),
        )
        result.to_dict(budget=budget)
        return result
