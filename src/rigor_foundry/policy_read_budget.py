# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — explicit policy parser budgets
"""Bind policy parser allocation ceilings independently of operational authority."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from .audit_primitives import (
    canonical_digest,
    require_exact_fields,
    require_integer,
    require_mapping,
)
from .model_primitives import require_digest

POLICY_READ_BUDGET_SCHEMA_VERSION = "1.0"

_LIMITS = {
    "max_document_bytes": 8 * 1024 * 1024,
    "max_source_bytes": 8 * 1024 * 1024,
    "max_total_source_bytes": 64 * 1024 * 1024,
    "max_sources": 4096,
    "max_rules": 16384,
    "max_references": 65536,
    "max_depth": 32,
}
_FIELDS = frozenset({"schema_version", "object_kind", "budget_digest", *_LIMITS})


@dataclass(frozen=True)
class PolicyReadBudget1:
    """Explicit positive limits for one complete policy input transaction.

    The digest identifies parser limits. It supplies no effect, freshness,
    source-access or policy-admission authority.
    """

    max_document_bytes: int
    max_source_bytes: int
    max_total_source_bytes: int
    max_sources: int
    max_rules: int
    max_references: int
    max_depth: int
    budget_digest: str

    schema_version: ClassVar[str] = POLICY_READ_BUDGET_SCHEMA_VERSION
    object_kind: ClassVar[str] = "policy-read-budget"

    def __post_init__(self) -> None:
        """Reject malformed direct construction as well as forged digests."""
        body = self._body()
        if require_digest(self.budget_digest, "policy budget digest") != canonical_digest(body):
            raise ValueError("policy budget digest differs")

    def _body(self) -> dict[str, object]:
        """Return validated fields before deriving the record digest."""
        body: dict[str, object] = {
            "schema_version": POLICY_READ_BUDGET_SCHEMA_VERSION,
            "object_kind": "policy-read-budget",
        }
        for name, ceiling in _LIMITS.items():
            value = require_integer(getattr(self, name), name, minimum=1)
            if value > ceiling:
                raise ValueError("policy budget exceeds the implementation ceiling")
            body[name] = value
        return body

    @classmethod
    def build(
        cls,
        *,
        max_document_bytes: int,
        max_source_bytes: int,
        max_total_source_bytes: int,
        max_sources: int,
        max_rules: int,
        max_references: int,
        max_depth: int,
    ) -> PolicyReadBudget1:
        """Build a budget with every limit explicitly supplied by its caller."""
        body: dict[str, object] = {
            "schema_version": POLICY_READ_BUDGET_SCHEMA_VERSION,
            "object_kind": "policy-read-budget",
            "max_document_bytes": max_document_bytes,
            "max_source_bytes": max_source_bytes,
            "max_total_source_bytes": max_total_source_bytes,
            "max_sources": max_sources,
            "max_rules": max_rules,
            "max_references": max_references,
            "max_depth": max_depth,
        }
        return cls(
            max_document_bytes,
            max_source_bytes,
            max_total_source_bytes,
            max_sources,
            max_rules,
            max_references,
            max_depth,
            canonical_digest(body),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize the exact closed record after revalidating its values."""
        body = self._body()
        digest = require_digest(self.budget_digest, "policy budget digest")
        if digest != canonical_digest(body):
            raise ValueError("policy budget digest differs")
        return {**body, "budget_digest": digest}

    @classmethod
    def from_dict(cls, value: object) -> PolicyReadBudget1:
        """Parse the closed versioned record without normalization or coercion."""
        data = require_mapping(value, "policy read budget")
        require_exact_fields(data, _FIELDS, "policy read budget")
        if (
            data["schema_version"] != POLICY_READ_BUDGET_SCHEMA_VERSION
            or data["object_kind"] != "policy-read-budget"
        ):
            raise ValueError("unsupported policy read budget")
        limits = {name: require_integer(data[name], name, minimum=1) for name in _LIMITS}
        return cls(
            **limits,
            budget_digest=require_digest(data["budget_digest"], "policy budget digest"),
        )
