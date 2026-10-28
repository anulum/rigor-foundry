# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — source-bound qualitative review policies
"""Retain exact review-role obligations separately from authenticated review acceptance."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, cast

from .audit_primitives import canonical_digest, require_string
from .condition_language import ConditionExpression
from .model_primitives import require_boolean, require_digest, require_identifier
from .policy_model_inputs import (
    checked_policy_budget,
    policy_identifiers,
    policy_record_mapping,
    policy_reference,
    policy_wire_size,
)
from .policy_read_budget import PolicyReadBudget1
from .semantic_acceptance_policy import REVIEWER_IDENTITY_POLICY_SCHEMA
from .typed_object_reference import TypedObjectRef1

REVIEW_ROLE_REQUIREMENT_SCHEMA_VERSION = "1.0"
REVIEW_POLICY_SCHEMA_VERSION = "1.0"
_IDENTITY_FORMATS = frozenset({("reviewer-identity-policy", REVIEWER_IDENTITY_POLICY_SCHEMA)})
_ROLE_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "role_id",
        "identity_policy",
        "independent_from_author",
        "requirement_digest",
    }
)
_POLICY_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "policy_id",
        "mode",
        "required_roles",
        "source_rule_ids",
        "unavailability_fact_refs",
        "policy_digest",
    }
)
_MODES = frozenset({"independent", "self-review", "conditional-self-review"})


@dataclass(frozen=True)
class ReviewRoleRequirement1:
    """An explicit source-required role and original reviewer identity policy reference.

    Identity policy integrity is separate from enrollment, current key lifecycle,
    role assignment, author separation and actual signed review verification.
    """

    role_id: str
    identity_policy: TypedObjectRef1
    independent_from_author: bool
    requirement_digest: str

    schema_version: ClassVar[str] = REVIEW_ROLE_REQUIREMENT_SCHEMA_VERSION
    object_kind: ClassVar[str] = "review-role-requirement"

    def _body(self) -> dict[str, object]:
        """Validate exact role inputs without inferring any provider composition."""
        identity = policy_reference(self.identity_policy, allowed=_IDENTITY_FORMATS)
        return {
            "schema_version": REVIEW_ROLE_REQUIREMENT_SCHEMA_VERSION,
            "object_kind": "review-role-requirement",
            "role_id": require_identifier(self.role_id, "review role identity"),
            "identity_policy": identity.to_dict(),
            "independent_from_author": require_boolean(
                self.independent_from_author, "review author independence"
            ),
        }

    @classmethod
    def build(
        cls,
        *,
        role_id: str,
        identity_policy: TypedObjectRef1,
        independent_from_author: bool,
        budget: PolicyReadBudget1,
    ) -> ReviewRoleRequirement1:
        """Bind the complete declared role with an explicit parser allocation budget."""
        checked_policy_budget(budget)
        candidate = cls(role_id, identity_policy, independent_from_author, "")
        result = cls(
            role_id, identity_policy, independent_from_author, canonical_digest(candidate._body())
        )
        result.to_dict(budget=budget)
        return result

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Revalidate direct records and return the complete closed role requirement."""
        limits = checked_policy_budget(budget)
        body = self._body()
        digest = require_digest(self.requirement_digest, "review role requirement digest")
        if digest != canonical_digest(body):
            raise ValueError("review role requirement digest differs")
        result = {**body, "requirement_digest": digest}
        policy_wire_size(result, budget=limits)
        return result

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> ReviewRoleRequirement1:
        """Parse the exact role fields and existing reviewer policy reference format."""
        data = policy_record_mapping(
            value,
            fields=_ROLE_FIELDS,
            object_kind="review-role-requirement",
            schema_version=REVIEW_ROLE_REQUIREMENT_SCHEMA_VERSION,
            budget=budget,
        )
        result = cls(
            require_identifier(data["role_id"], "review role identity"),
            TypedObjectRef1.from_dict(data["identity_policy"]),
            require_boolean(data["independent_from_author"], "review author independence"),
            require_digest(data["requirement_digest"], "review role requirement digest"),
        )
        result.to_dict(budget=budget)
        return result


@dataclass(frozen=True)
class ReviewPolicy1:
    """Exact qualitative review requirements, without choosing a fallback or granting PASS.

    Roles sort uniquely by role_id; source rule IDs and exact dotted availability
    references are sorted unique sets. Self-review remains distinct from
    independent approval. Empty declarations or unknown availability cannot
    establish authorized SelfReview or discharge any accepted source obligation.
    """

    policy_id: str
    mode: str
    required_roles: tuple[ReviewRoleRequirement1, ...]
    source_rule_ids: tuple[str, ...]
    unavailability_fact_refs: tuple[str, ...]
    policy_digest: str

    schema_version: ClassVar[str] = REVIEW_POLICY_SCHEMA_VERSION
    object_kind: ClassVar[str] = "review-policy"

    def _body(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Revalidate complete role/source/fact declarations within aggregate limits."""
        limits = checked_policy_budget(budget)
        mode = require_string(self.mode, "review policy mode")
        if mode not in _MODES:
            raise ValueError("unsupported review policy mode")
        if (
            type(self.required_roles) is not tuple
            or len(self.required_roles) > limits.max_references
        ):
            raise ValueError("review roles require a bounded immutable tuple")
        roles: list[dict[str, object]] = []
        identities: list[str] = []
        for role in self.required_roles:
            if type(role) is not ReviewRoleRequirement1:
                raise ValueError("review policy requires actual role requirements")
            roles.append(role.to_dict(budget=limits))
            identities.append(role.role_id)
        if identities != sorted(set(identities)):
            raise ValueError("review role identities must be sorted and unique")
        sources = policy_identifiers(self.source_rule_ids, budget=limits)
        if len(sources) > limits.max_rules:
            raise ValueError("review policy exceeds the source rule budget")
        refs = self.unavailability_fact_refs
        if type(refs) is not tuple or len(refs) > limits.max_references:
            raise ValueError("review availability references require a bounded immutable tuple")
        checked_refs = tuple(require_string(ref, "review availability reference") for ref in refs)
        for ref in checked_refs:
            ConditionExpression.build("exists", reference=ref)
        if checked_refs != tuple(sorted(set(checked_refs))):
            raise ValueError("review availability references must be sorted and unique")
        if len(roles) + len(sources) + len(refs) > limits.max_references:
            raise ValueError("review policy exceeds the aggregate reference budget")
        body: dict[str, object] = {
            "schema_version": REVIEW_POLICY_SCHEMA_VERSION,
            "object_kind": "review-policy",
            "policy_id": require_identifier(self.policy_id, "review policy identity"),
            "mode": mode,
            "required_roles": roles,
            "source_rule_ids": list(sources),
            "unavailability_fact_refs": list(checked_refs),
        }
        policy_wire_size(body, budget=limits)
        return body

    @classmethod
    def build(
        cls,
        *,
        policy_id: str,
        mode: str,
        required_roles: tuple[ReviewRoleRequirement1, ...],
        source_rule_ids: tuple[str, ...],
        unavailability_fact_refs: tuple[str, ...],
        budget: PolicyReadBudget1,
    ) -> ReviewPolicy1:
        """Bind declared requirements without treating unavailable review as permission."""
        candidate = cls(
            policy_id, mode, required_roles, source_rule_ids, unavailability_fact_refs, ""
        )
        body = candidate._body(budget=budget)
        result = cls(
            policy_id,
            mode,
            required_roles,
            source_rule_ids,
            unavailability_fact_refs,
            canonical_digest(body),
        )
        result.to_dict(budget=budget)
        return result

    def to_dict(self, *, budget: PolicyReadBudget1) -> dict[str, object]:
        """Return exact requirements after checking complete nested integrity and bounds."""
        body = self._body(budget=budget)
        digest = require_digest(self.policy_digest, "review policy digest")
        if digest != canonical_digest(body):
            raise ValueError("review policy digest differs")
        result = {**body, "policy_digest": digest}
        policy_wire_size(result, budget=budget)
        return result

    def reference(self, *, budget: PolicyReadBudget1) -> TypedObjectRef1:
        """Return the exact policy identity for an owning evidence contract to resolve."""
        self.to_dict(budget=budget)
        return TypedObjectRef1.build(
            kind="review-policy",
            format_version=REVIEW_POLICY_SCHEMA_VERSION,
            object_id=self.policy_id,
            object_digest=self.policy_digest,
        )

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> ReviewPolicy1:
        """Parse exact arrays and original child references without replacing source requirements."""
        data = policy_record_mapping(
            value,
            fields=_POLICY_FIELDS,
            object_kind="review-policy",
            schema_version=REVIEW_POLICY_SCHEMA_VERSION,
            budget=budget,
        )
        arrays: dict[str, tuple[object, ...]] = {}
        for name in ("required_roles", "source_rule_ids", "unavailability_fact_refs"):
            items = data[name]
            if type(items) is not list or len(items) > budget.max_references:
                raise ValueError("review policy requires bounded arrays")
            arrays[name] = tuple(items)
        result = cls(
            require_identifier(data["policy_id"], "review policy identity"),
            require_string(data["mode"], "review policy mode"),
            tuple(
                ReviewRoleRequirement1.from_dict(item, budget=budget)
                for item in arrays["required_roles"]
            ),
            cast(tuple[str, ...], arrays["source_rule_ids"]),
            cast(tuple[str, ...], arrays["unavailability_fact_refs"]),
            require_digest(data["policy_digest"], "review policy digest"),
        )
        result.to_dict(budget=budget)
        return result
