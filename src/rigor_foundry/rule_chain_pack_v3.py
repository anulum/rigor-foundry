# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete source-bound signed qualitative pack
"""Retain new qualitative controls and unchanged authority/freshness children under parent3."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import ClassVar, cast

from .audit_primitives import canonical_digest, require_string
from .control_definition_v2 import ControlDefinition2
from .model_primitives import require_digest, require_identifier, require_semantic_version
from .policy_model_inputs import checked_policy_budget, policy_record_mapping, policy_wire_size
from .policy_read_budget import PolicyReadBudget1
from .rule_chain_pack_v2 import AuthorityClauseV2, FreshnessPolicyV2
from .signed_rule_chain_v3 import RuleChainV3Signature
from .source_component_reader import PolicyComponent1

STANDARD_PACK_V3_SCHEMA_VERSION = "3.0"
_ARRAYS = ("controls", "authority_clauses", "freshness_policies")
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "pack_id",
        "version",
        "source_uri",
        "source_digest",
        "corpus_acceptance_digest",
        "licence",
        *_ARRAYS,
        "signature",
        "pack_digest",
    }
)


@dataclass(frozen=True)
class StandardPackV3:
    """Complete signed parent3 without changing any original component interpretation.

    The source URI is opaque descriptive metadata, never a loader. The source
    digest names the complete canonical source document, while retained original
    file bytes have separate identities. Integrity parsing verifies neither
    crypto nor source/native/transition acceptance and cannot select a root.
    """

    pack_id: str
    version: str
    source_uri: str
    source_digest: str
    corpus_acceptance_digest: str
    licence: str
    controls: tuple[ControlDefinition2, ...]
    authority_clauses: tuple[AuthorityClauseV2, ...]
    freshness_policies: tuple[FreshnessPolicyV2, ...]
    signature: RuleChainV3Signature
    pack_digest: str

    schema_version: ClassVar[str] = STANDARD_PACK_V3_SCHEMA_VERSION
    object_kind: ClassVar[str] = "standard-pack"

    @staticmethod
    def body(
        *,
        pack_id: str,
        version: str,
        source_uri: str,
        source_digest: str,
        corpus_acceptance_digest: str,
        licence: str,
        controls: tuple[ControlDefinition2, ...],
        authority_clauses: tuple[AuthorityClauseV2, ...],
        freshness_policies: tuple[FreshnessPolicyV2, ...],
        budget: PolicyReadBudget1,
    ) -> dict[str, object]:
        """Revalidate complete bounded children before deriving the exact unsigned body.

        Parameters
        ----------
        pack_id, version, source_uri, source_digest, corpus_acceptance_digest, licence : str
            Explicit identity, version, opaque URI and canonical source/acceptance references.
        controls : tuple[ControlDefinition2, ...]
            Exact new qualitative definitions; original control1 cannot be cast.
        authority_clauses, freshness_policies : tuple
            Original unchanged typed children, retaining their original digests.
        budget : PolicyReadBudget1
            Explicit whole-body byte, nesting and aggregate reference bounds.

        Returns
        -------
        dict[str, object]
            Exact unsigned body. A signature or matching hash supplies no acceptance.
        """
        limits = checked_policy_budget(budget)
        cohorts = (
            (controls, ControlDefinition2),
            (authority_clauses, AuthorityClauseV2),
            (freshness_policies, FreshnessPolicyV2),
        )
        count = 0
        for rows, owner in cohorts:
            if type(rows) is not tuple or len(rows) > limits.max_references:
                raise ValueError("pack3 requires bounded immutable complete component arrays")
            if any(type(row) is not owner for row in rows):
                raise ValueError("pack3 requires actual versioned component owners")
            count += len(rows)
        if len(controls) > limits.max_rules:
            raise ValueError("pack3 exceeds the complete control count budget")
        if not count or count > limits.max_references:
            raise ValueError("pack3 requires nonempty bounded complete component coverage")
        identity = require_identifier(pack_id, "pack3 identity")
        controls_wire: list[dict[str, object]] = []
        for control in controls:
            controls_wire.append(control.to_dict(budget=limits))
            count += 2 + 2 * len(control.evidence.requirements)
            count += sum(
                len(rows)
                for rows in (
                    control.remediation.dependencies,
                    control.remediation.procedure_ids,
                    control.remediation.acceptance_gates,
                    control.remediation.reopen_triggers,
                )
            )
            count += (
                0 if control.scope.condition is None else len(control.scope.condition.references)
            )
        clauses_wire = [PolicyComponent1(row, limits).to_dict() for row in authority_clauses]
        freshness_wire = [PolicyComponent1(row, limits).to_dict() for row in freshness_policies]
        count += sum(len(row.grantor_classes) for row in authority_clauses)
        count += sum(len(row.invalidator_ids) for row in freshness_policies)
        if count > limits.max_references:
            raise ValueError("pack3 exceeds the aggregate reference budget")
        ids = (
            [("control-definition", f"{row.control_id}@{row.version}") for row in controls]
            + [("authority-clause", row.clause_id) for row in authority_clauses]
            + [("freshness-policy", row.policy_id) for row in freshness_policies]
        )
        if len(ids) != len(set(ids)):
            raise ValueError("pack3 component identities must be distinct")
        uri = require_string(source_uri, "pack3 opaque source URI")
        if any(character.isspace() for character in uri):
            raise ValueError("pack3 source URI must not contain whitespace")
        body: dict[str, object] = {
            "schema_version": STANDARD_PACK_V3_SCHEMA_VERSION,
            "object_kind": "standard-pack",
            "pack_id": identity,
            "version": require_semantic_version(version, "pack3 version"),
            "source_uri": uri,
            "source_digest": require_digest(source_digest, "pack3 canonical source document"),
            "corpus_acceptance_digest": require_digest(
                corpus_acceptance_digest, "pack3 complete corpus acceptance"
            ),
            "licence": require_string(licence, "pack3 licence"),
            "controls": controls_wire,
            "authority_clauses": clauses_wire,
            "freshness_policies": freshness_wire,
        }
        policy_wire_size(body, budget=limits)
        return body

    def unsigned_body(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Return the complete revalidated body under the consuming owner's explicit bounds."""
        return self.body(
            pack_id=self.pack_id,
            version=self.version,
            source_uri=self.source_uri,
            source_digest=self.source_digest,
            corpus_acceptance_digest=self.corpus_acceptance_digest,
            licence=self.licence,
            controls=self.controls,
            authority_clauses=self.authority_clauses,
            freshness_policies=self.freshness_policies,
            budget=budget,
        )

    def _signed_body(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Require the actual parent3 signature kind and complete unsigned body identity."""
        body = self.unsigned_body(budget=budget)
        if type(self.signature) is not RuleChainV3Signature:
            raise ValueError("pack3 requires an actual version3 signature")
        signature = RuleChainV3Signature.from_dict(
            self.signature.to_dict(budget=budget), budget=budget
        )
        if signature.object_kind != "standard-pack" or signature.body_digest != canonical_digest(
            body
        ):
            raise ValueError("pack3 signature metadata differs from its complete body")
        return {**body, "signature": signature.to_dict(budget=budget)}

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Serialize exact fields after rechecking complete body, signature metadata and digest."""
        body = self._signed_body(budget=budget)
        digest = require_digest(self.pack_digest, "pack3 digest")
        if digest != canonical_digest(body):
            raise ValueError("pack3 digest differs")
        result = {**body, "pack_digest": digest}
        policy_wire_size(result, budget=budget)
        return result

    @classmethod
    def build(
        cls,
        *,
        pack_id: str,
        version: str,
        source_uri: str,
        source_digest: str,
        corpus_acceptance_digest: str,
        licence: str,
        controls: tuple[ControlDefinition2, ...],
        authority_clauses: tuple[AuthorityClauseV2, ...],
        freshness_policies: tuple[FreshnessPolicyV2, ...],
        signature: RuleChainV3Signature,
        budget: PolicyReadBudget1,
    ) -> StandardPackV3:
        """Bind the full supplied body and detached signature without authenticating authority."""
        candidate = cls(
            pack_id,
            version,
            source_uri,
            source_digest,
            corpus_acceptance_digest,
            licence,
            controls,
            authority_clauses,
            freshness_policies,
            signature,
            "0" * 64,
        )
        result = replace(
            candidate, pack_digest=canonical_digest(candidate._signed_body(budget=budget))
        )
        result.to_dict(budget=budget)
        return result

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> StandardPackV3:
        """Parse exact parent3 fields through the new and original fixed child parsers."""
        limits = checked_policy_budget(budget)
        data = policy_record_mapping(
            value,
            fields=_FIELDS,
            object_kind="standard-pack",
            schema_version=STANDARD_PACK_V3_SCHEMA_VERSION,
            budget=limits,
        )
        arrays: dict[str, list[object]] = {}
        count = 0
        for name in _ARRAYS:
            rows = data[name]
            if type(rows) is not list:
                raise ValueError("pack3 components require complete arrays")
            count += len(rows)
            if count > limits.max_references:
                raise ValueError("pack3 components exceed the reference budget")
            arrays[name] = rows
        result = cls(
            require_identifier(data["pack_id"], "pack3 identity"),
            require_semantic_version(data["version"], "pack3 version"),
            require_string(data["source_uri"], "pack3 opaque source URI"),
            require_digest(data["source_digest"], "pack3 source document"),
            require_digest(data["corpus_acceptance_digest"], "pack3 corpus acceptance"),
            require_string(data["licence"], "pack3 licence"),
            tuple(ControlDefinition2.from_dict(row, budget=limits) for row in arrays["controls"]),
            tuple(
                cast(
                    AuthorityClauseV2,
                    PolicyComponent1.from_dict("authority-clause", row, budget=limits).record,
                )
                for row in arrays["authority_clauses"]
            ),
            tuple(
                cast(
                    FreshnessPolicyV2,
                    PolicyComponent1.from_dict("freshness-policy", row, budget=limits).record,
                )
                for row in arrays["freshness_policies"]
            ),
            RuleChainV3Signature.from_dict(data["signature"], budget=limits),
            require_digest(data["pack_digest"], "pack3 digest"),
        )
        result.to_dict(budget=limits)
        return result
