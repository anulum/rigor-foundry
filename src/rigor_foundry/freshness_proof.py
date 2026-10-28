# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — source-bound qualitative freshness proof metadata
"""Bind exact qualitative policy/subject/invalidators without inventing a TTL or verdict."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Literal, cast

from .audit_primitives import canonical_digest, require_mapping, require_string
from .context_owner_proof import OwnerProof1
from .model_primitives import require_digest, require_identifier
from .policy_model_inputs import (
    checked_policy_budget,
    policy_owner_proof,
    policy_record_mapping,
    policy_reference,
    policy_wire_size,
)
from .policy_read_budget import PolicyReadBudget1
from .rule_chain_pack_v2 import FreshnessMode, FreshnessPolicyV2
from .signed_rule_chain_v2 import RULE_CHAIN_V2_SCHEMA_VERSION
from .source_component_reader import PolicyComponent1
from .typed_object_reference import TypedObjectRef1

INVALIDATOR_OBSERVATION_SCHEMA_VERSION = "1.0"
FRESHNESS_PROOF_SCHEMA_VERSION = "1.0"
InvalidatorState = Literal["clear", "invalid", "unknown"]
_OBSERVATION_FIELDS = frozenset(
    {"schema_version", "object_kind", "invalidator_id", "state", "proof", "observation_digest"}
)
_PROOF_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "policy",
        "subject_digest",
        "mode",
        "subject_proof",
        "invalidators",
        "snapshot_id",
        "proof_digest",
    }
)


def freshness_reference_count(value: object, *, budget: PolicyReadBudget1) -> int:
    """Bound freshness allocations before any enclosing consumer parses its children.

    Parameters
    ----------
    value : object
        Actual ``FreshnessProof1`` or inert complete proof wire. This count
        includes policy, subject proof, invalidator IDs and optional owner proofs.
    budget : PolicyReadBudget1
        Explicit allocation limits; integrity and authentication require the
        complete owning parser and installed verifier respectively.

    Returns
    -------
    int
        Complete reference allocation, suitable for an enclosing owner's budget.
    """
    limits = checked_policy_budget(budget)
    if type(value) is FreshnessProof1:
        rows = value.invalidators
        if type(rows) is not tuple or len(rows) + 3 > limits.max_references:
            raise ValueError("freshness invalidators exceed the immutable reference budget")
        if any(type(row) is not InvalidatorObservation1 for row in rows):
            raise ValueError("freshness requires actual invalidator observations")
        count = 3 + sum(1 + (2 if row.proof is not None else 0) for row in rows)
    else:
        policy_wire_size(value, budget=limits)
        data = require_mapping(value, "freshness allocation")
        raw = data.get("invalidators")
        if type(raw) is not list or len(raw) + 3 > limits.max_references:
            raise ValueError("freshness invalidators require a bounded array")
        count = 3
        for row in raw:
            if type(row) is not dict:
                raise ValueError("freshness requires invalidator observation mappings")
            count += 1 + (2 if row.get("proof") is not None else 0)
    if count > limits.max_references:
        raise ValueError("freshness exceeds the aggregate reference budget")
    return count


@dataclass(frozen=True)
class InvalidatorObservation1:
    """One explicit invalidation state and its original independent owner-proof metadata.

    Clear requires a proof envelope. The envelope still needs actual current
    source/contract/observation authentication; parsing never establishes clear.
    Invalid and unknown remain explicit nonpassing states.
    """

    invalidator_id: str
    state: InvalidatorState
    proof: OwnerProof1 | None
    observation_digest: str

    schema_version: ClassVar[str] = INVALIDATOR_OBSERVATION_SCHEMA_VERSION
    object_kind: ClassVar[str] = "invalidator-observation"

    def _body(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Check explicit state and mandatory clear proof before deriving the record identity."""
        limits = checked_policy_budget(budget)
        state = require_string(self.state, "invalidator state")
        if state not in {"clear", "invalid", "unknown"}:
            raise ValueError("unsupported invalidator state")
        if state == "clear" and self.proof is None:
            raise ValueError("clear invalidator requires an original owner proof")
        proof = None if self.proof is None else policy_owner_proof(self.proof, budget=limits)
        body: dict[str, object] = {
            "schema_version": INVALIDATOR_OBSERVATION_SCHEMA_VERSION,
            "object_kind": "invalidator-observation",
            "invalidator_id": require_identifier(self.invalidator_id, "invalidator identity"),
            "state": state,
            "proof": None if proof is None else proof.to_dict(),
        }
        policy_wire_size(body, budget=limits)
        return body

    @classmethod
    def build(
        cls,
        *,
        invalidator_id: str,
        state: InvalidatorState,
        proof: OwnerProof1 | None,
        budget: PolicyReadBudget1,
    ) -> InvalidatorObservation1:
        """Build an explicit observation without authenticating clear or supplying a freshness verdict."""
        candidate = cls(invalidator_id, state, proof, "")
        body = candidate._body(budget=budget)
        return cls.from_dict({**body, "observation_digest": canonical_digest(body)}, budget=budget)

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Recheck complete direct records, including optional original proof integrity."""
        body = self._body(budget=budget)
        digest = require_digest(self.observation_digest, "invalidator observation digest")
        if digest != canonical_digest(body):
            raise ValueError("invalidator observation digest differs")
        result = {**body, "observation_digest": digest}
        policy_wire_size(result, budget=budget)
        return result

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> InvalidatorObservation1:
        """Parse exact state/proof fields; missing, Boolean and unsupported states refuse."""
        data = policy_record_mapping(
            value,
            fields=_OBSERVATION_FIELDS,
            object_kind="invalidator-observation",
            schema_version=INVALIDATOR_OBSERVATION_SCHEMA_VERSION,
            budget=budget,
        )
        proof = (
            None if data["proof"] is None else OwnerProof1.from_dict(data["proof"], budget=budget)
        )
        result = cls(
            require_identifier(data["invalidator_id"], "invalidator identity"),
            cast(InvalidatorState, require_string(data["state"], "invalidator state")),
            proof,
            require_digest(data["observation_digest"], "invalidator observation digest"),
        )
        result.to_dict(budget=budget)
        return result


@dataclass(frozen=True)
class FreshnessProof1:
    """Exact policy, independent subject snapshot and complete invalidation declarations.

    Subject proof metadata must bind this subject and snapshot. Invalidation
    owners retain their own independent source snapshots. Current source,
    key/revocation and state checks remain mandatory at the installed consumer;
    neither this record nor structural policy binding returns a freshness PASS.
    """

    policy: TypedObjectRef1
    subject_digest: str
    mode: FreshnessMode
    subject_proof: OwnerProof1
    invalidators: tuple[InvalidatorObservation1, ...]
    snapshot_id: str
    proof_digest: str

    schema_version: ClassVar[str] = FRESHNESS_PROOF_SCHEMA_VERSION
    object_kind: ClassVar[str] = "freshness-proof"

    def _body(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Check full immutable observations and aggregate references before child serialization."""
        limits = checked_policy_budget(budget)
        freshness_reference_count(self, budget=limits)
        names = tuple(
            require_identifier(row.invalidator_id, "invalidator identity")
            for row in self.invalidators
        )
        if names != tuple(sorted(set(names))):
            raise ValueError("freshness invalidators must be sorted and unique")
        policy = policy_reference(
            self.policy, allowed=frozenset({("freshness-policy", RULE_CHAIN_V2_SCHEMA_VERSION)})
        )
        mode = require_string(self.mode, "freshness proof mode")
        if mode not in {"immutable-object", "mutable-state"}:
            raise ValueError("unsupported freshness proof mode")
        subject = require_digest(self.subject_digest, "freshness subject digest")
        snapshot = require_identifier(self.snapshot_id, "freshness subject snapshot")
        proof = policy_owner_proof(self.subject_proof, budget=limits)
        if proof.subject_digest != subject or proof.snapshot_id != snapshot:
            raise ValueError(
                "freshness subject proof differs from its independent subject or snapshot"
            )
        body: dict[str, object] = {
            "schema_version": FRESHNESS_PROOF_SCHEMA_VERSION,
            "object_kind": "freshness-proof",
            "policy": policy.to_dict(),
            "subject_digest": subject,
            "mode": mode,
            "subject_proof": proof.to_dict(),
            "invalidators": [row.to_dict(budget=limits) for row in self.invalidators],
            "snapshot_id": snapshot,
        }
        policy_wire_size(body, budget=limits)
        return body

    @classmethod
    def build(
        cls,
        *,
        policy: TypedObjectRef1,
        subject_digest: str,
        mode: FreshnessMode,
        subject_proof: OwnerProof1,
        invalidators: tuple[InvalidatorObservation1, ...],
        snapshot_id: str,
        budget: PolicyReadBudget1,
    ) -> FreshnessProof1:
        """Bind explicit subject inputs without adding a duration or observation timestamp."""
        candidate = cls(policy, subject_digest, mode, subject_proof, invalidators, snapshot_id, "")
        body = candidate._body(budget=budget)
        return cls.from_dict({**body, "proof_digest": canonical_digest(body)}, budget=budget)

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Revalidate the complete proof metadata and its owning digest at every use."""
        body = self._body(budget=budget)
        digest = require_digest(self.proof_digest, "freshness proof digest")
        if digest != canonical_digest(body):
            raise ValueError("freshness proof digest differs")
        result = {**body, "proof_digest": digest}
        policy_wire_size(result, budget=budget)
        return result

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> FreshnessProof1:
        """Bound the full observation allocation before invoking original proof parsers."""
        data = policy_record_mapping(
            value,
            fields=_PROOF_FIELDS,
            object_kind="freshness-proof",
            schema_version=FRESHNESS_PROOF_SCHEMA_VERSION,
            budget=budget,
        )
        limits = checked_policy_budget(budget)
        freshness_reference_count(data, budget=limits)
        rows = cast(list[object], data["invalidators"])
        result = cls(
            TypedObjectRef1.from_dict(data["policy"]),
            require_digest(data["subject_digest"], "freshness subject digest"),
            cast(FreshnessMode, require_string(data["mode"], "freshness proof mode")),
            OwnerProof1.from_dict(data["subject_proof"], budget=limits),
            tuple(InvalidatorObservation1.from_dict(row, budget=limits) for row in rows),
            require_identifier(data["snapshot_id"], "freshness subject snapshot"),
            require_digest(data["proof_digest"], "freshness proof digest"),
        )
        result.to_dict(budget=limits)
        return result

    def verify_policy_binding(self, policy: object, *, budget: PolicyReadBudget1) -> None:
        """Check exact original policy/mode and complete invalidator set, without a freshness verdict.

        Parameters
        ----------
        policy : object
            Actual original ``FreshnessPolicyV2``; every original field is retained.
        budget : PolicyReadBudget1
            Explicit bounds for both complete records and original child lists.
        """
        self.to_dict(budget=budget)
        if type(policy) is not FreshnessPolicyV2:
            raise ValueError("freshness binding requires an actual original freshness policy")
        original = PolicyComponent1(policy, budget)
        if (
            original.reference() != self.policy
            or policy.mode != self.mode
            or tuple(sorted(policy.invalidator_ids))
            != tuple(row.invalidator_id for row in self.invalidators)
        ):
            raise ValueError(
                "freshness differs from its exact selected policy, mode or invalidator set"
            )
