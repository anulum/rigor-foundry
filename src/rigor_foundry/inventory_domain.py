# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete configured inventory domain data
"""Describe maintained roots and exact classification rules without enrolling them."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from .audit_primitives import (
    canonical_digest,
    require_exact_fields,
    require_mapping,
    require_string,
)
from .model_primitives import require_digest, require_identifier
from .policy_read_budget import PolicyReadBudget1
from .repository_inventory_rows import require_inventory_path
from .typed_object_reference import TypedObjectRef1

INVENTORY_DOMAIN_SCHEMA_VERSION = "1.0"
_ROLES = frozenset(
    {
        "source",
        "test",
        "tool",
        "fixture",
        "example",
        "benchmark",
        "generator",
        "configuration",
        "documentation",
    }
)
_ROOT_FIELDS = frozenset({"root_id", "canonical_path", "source_kind"})
_RULE_FIELDS = frozenset({"root_id", "field", "selector_kind", "selector", "value"})
_FIELDS = frozenset(
    {"schema_version", "object_kind", "domain_id", "project_id", "roots", "rules", "domain_digest"}
)


@dataclass(frozen=True)
class InventoryDomainRoot:
    """Inline configured root; its path is relative to the host-selected monorepo."""

    root_id: str
    canonical_path: str
    source_kind: str

    def __post_init__(self) -> None:
        """Reject traversal, unknown capture kinds and malformed identities."""
        self.to_dict()

    def to_dict(self) -> dict[str, object]:
        """Revalidate exact data without opening or enrolling its named root."""
        kind = require_string(self.source_kind, "inventory root source kind")
        if kind not in {"git", "ignored", "generated"}:
            raise ValueError("unsupported inventory root source kind")
        return {
            "root_id": require_identifier(self.root_id, "inventory root identity"),
            "canonical_path": require_inventory_path(self.canonical_path),
            "source_kind": kind,
        }

    @classmethod
    def from_dict(cls, value: object) -> InventoryDomainRoot:
        """Parse only the three declared parent-covered inline fields."""
        data = require_mapping(value, "inventory domain root")
        require_exact_fields(data, _ROOT_FIELDS, "inventory domain root")
        return cls(
            require_identifier(data["root_id"], "inventory root identity"),
            require_inventory_path(data["canonical_path"]),
            require_string(data["source_kind"], "inventory root source kind"),
        )


@dataclass(frozen=True)
class InventoryClassificationRule:
    """One explicit path classification; it supplies no execution or source authority."""

    root_id: str
    field: str
    selector_kind: str
    selector: str
    value: str

    def __post_init__(self) -> None:
        """Require a supported field/selector relation and exact non-wildcard selector."""
        self.to_dict()

    def to_dict(self) -> dict[str, object]:
        """Validate declared language tags and the fixed maintained-role vocabulary."""
        field = require_string(self.field, "inventory classification field")
        kind = require_string(self.selector_kind, "inventory selector kind")
        if (field, kind) not in {
            ("language", "exact"),
            ("language", "suffix"),
            ("role", "exact"),
            ("role", "prefix"),
        }:
            raise ValueError("unsupported inventory classification selector")
        selector = require_string(self.selector, "inventory selector")
        if kind == "suffix":
            if (
                not 2 <= len(selector) <= 64
                or not selector.startswith(".")
                or selector in {".", ".."}
                or selector != selector.lower()
                or any(char in "/\\*?[]\0" or char.isspace() for char in selector)
            ):
                raise ValueError("inventory suffix must be exact, lowercase and non-wildcard")
        else:
            require_inventory_path(selector)
        value = require_identifier(self.value, "inventory classification value")
        if field == "role" and value not in _ROLES:
            raise ValueError("unsupported maintained inventory role")
        return {
            "root_id": require_identifier(self.root_id, "inventory rule root"),
            "field": field,
            "selector_kind": kind,
            "selector": selector,
            "value": value,
        }

    @classmethod
    def from_dict(cls, value: object) -> InventoryClassificationRule:
        """Parse a closed inline rule without a callback, regex or loader field."""
        data = require_mapping(value, "inventory classification rule")
        require_exact_fields(data, _RULE_FIELDS, "inventory classification rule")
        return cls(
            require_identifier(data["root_id"], "inventory rule root"),
            require_string(data["field"], "inventory classification field"),
            require_string(data["selector_kind"], "inventory selector kind"),
            require_string(data["selector"], "inventory selector"),
            require_identifier(data["value"], "inventory classification value"),
        )


@dataclass(frozen=True)
class InventoryDomain1:
    """Complete declared root/rule preimage whose digest a retained contract binds.

    Parsing preserves the declaration, including unmatched classifications. It
    does not authenticate its issuer, prove required-root completeness, inspect
    a directory, install a producer or grant source-access permission.
    """

    domain_id: str
    project_id: str
    roots: tuple[InventoryDomainRoot, ...]
    rules: tuple[InventoryClassificationRule, ...]
    domain_digest: str

    schema_version: ClassVar[str] = INVENTORY_DOMAIN_SCHEMA_VERSION
    object_kind: ClassVar[str] = "inventory-domain"

    def __post_init__(self) -> None:
        """Reject malformed direct instances and mismatched complete identities."""
        self.to_dict()

    def _body(self) -> dict[str, object]:
        """Check bounded immutable roots/rules and exact cross-root relationships."""
        if (
            type(self.roots) is not tuple
            or type(self.rules) is not tuple
            or not self.roots
            or len(self.roots) > 4096
            or len(self.rules) > 16384
        ):
            raise ValueError("inventory domain requires bounded immutable roots and rules")
        if any(type(root) is not InventoryDomainRoot for root in self.roots) or any(
            type(rule) is not InventoryClassificationRule for rule in self.rules
        ):
            raise ValueError("inventory domain requires actual inline root and rule records")
        roots = [root.to_dict() for root in self.roots]
        ids = tuple(root.root_id for root in self.roots)
        paths = tuple(root.canonical_path for root in self.roots)
        if ids != tuple(sorted(set(ids))) or len(set(paths)) != len(paths):
            raise ValueError("inventory roots must be sorted, unique and path-distinct")
        rules = [rule.to_dict() for rule in self.rules]
        keys = tuple(
            (rule.root_id, rule.field, rule.selector_kind, rule.selector) for rule in self.rules
        )
        root_ids = frozenset(ids)
        if keys != tuple(sorted(set(keys))) or any(
            rule.root_id not in root_ids for rule in self.rules
        ):
            raise ValueError("inventory rules must be sorted, unique and refer to declared roots")
        return {
            "schema_version": INVENTORY_DOMAIN_SCHEMA_VERSION,
            "object_kind": "inventory-domain",
            "domain_id": require_identifier(self.domain_id, "inventory domain identity"),
            "project_id": require_identifier(self.project_id, "inventory domain project"),
            "roots": roots,
            "rules": rules,
        }

    @classmethod
    def build(
        cls,
        *,
        domain_id: str,
        project_id: str,
        roots: tuple[InventoryDomainRoot, ...],
        rules: tuple[InventoryClassificationRule, ...],
        budget: PolicyReadBudget1,
    ) -> InventoryDomain1:
        """Build explicit configured data through the same closed bounded parser."""
        if type(budget) is not PolicyReadBudget1:
            raise ValueError("policy read budget is required")
        limits = PolicyReadBudget1.from_dict(budget.to_dict())
        if type(roots) is not tuple or type(rules) is not tuple:
            raise ValueError("inventory domain requires immutable root and rule tuples")
        if (
            len(roots) > limits.max_sources
            or len(rules) > limits.max_rules
            or len(roots) + len(rules) > limits.max_references
        ):
            raise ValueError("inventory domain exceeds the input budgets")
        if any(type(root) is not InventoryDomainRoot for root in roots) or any(
            type(rule) is not InventoryClassificationRule for rule in rules
        ):
            raise ValueError("inventory domain requires actual inline root and rule records")
        body: dict[str, object] = {
            "schema_version": INVENTORY_DOMAIN_SCHEMA_VERSION,
            "object_kind": "inventory-domain",
            "domain_id": domain_id,
            "project_id": project_id,
            "roots": [root.to_dict() for root in roots],
            "rules": [rule.to_dict() for rule in rules],
        }
        return cls.from_dict({**body, "domain_digest": canonical_digest(body)}, budget=limits)

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> InventoryDomain1:
        """Bound collections before parsing the exact source declaration."""
        if type(budget) is not PolicyReadBudget1:
            raise ValueError("policy read budget is required")
        limits = PolicyReadBudget1.from_dict(budget.to_dict())
        data = require_mapping(value, "inventory domain")
        require_exact_fields(data, _FIELDS, "inventory domain")
        if (
            data["schema_version"] != INVENTORY_DOMAIN_SCHEMA_VERSION
            or data["object_kind"] != "inventory-domain"
        ):
            raise ValueError("unsupported inventory domain")
        roots, rules = data["roots"], data["rules"]
        if (
            not isinstance(roots, list)
            or not isinstance(rules, list)
            or len(roots) > limits.max_sources
            or len(rules) > limits.max_rules
            or len(roots) + len(rules) > limits.max_references
        ):
            raise ValueError(
                "inventory domain arrays exceed the input budgets or have invalid type"
            )
        return cls(
            require_identifier(data["domain_id"], "inventory domain identity"),
            require_identifier(data["project_id"], "inventory domain project"),
            tuple(InventoryDomainRoot.from_dict(item) for item in roots),
            tuple(InventoryClassificationRule.from_dict(item) for item in rules),
            require_digest(data["domain_digest"], "inventory domain digest"),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize all roots/rules after checking the complete source identity."""
        body = self._body()
        digest = require_digest(self.domain_digest, "inventory domain digest")
        if digest != canonical_digest(body):
            raise ValueError("inventory domain digest differs")
        return {**body, "domain_digest": digest}

    def reference(self) -> dict[str, object]:
        """Return an inert supported source identity without interpreting it as a path."""
        checked = self.to_dict()
        return TypedObjectRef1.build(
            kind="inventory-domain",
            format_version=INVENTORY_DOMAIN_SCHEMA_VERSION,
            object_id=require_identifier(checked["domain_id"], "inventory domain identity"),
            object_digest=require_digest(checked["domain_digest"], "inventory domain digest"),
        ).to_dict()
