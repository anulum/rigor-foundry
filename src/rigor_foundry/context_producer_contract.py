# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — fixed context producer contracts
"""Parse descriptive context-owner constraints without installing their producers."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import ClassVar, Literal, cast

from .audit_primitives import (
    canonical_digest,
    require_exact_fields,
    require_mapping,
    require_string,
)
from .condition_language import ConditionExpression
from .inventory_domain import INVENTORY_DOMAIN_SCHEMA_VERSION
from .model_primitives import require_digest, require_identifier
from .policy_read_budget import PolicyReadBudget1
from .project_registry_models import (
    PROFILED_PROJECT_REGISTRY_SCHEMA_VERSION,
    PROJECT_REGISTRY_SCHEMA_VERSION,
)
from .repository_state import REPOSITORY_STATE_SCHEMA_VERSION
from .task_definition import TASK_DEFINITION_SCHEMA_VERSION, TYPED_OBJECT_REF_SCHEMA_VERSION

CONTEXT_PRODUCER_CONTRACT_SCHEMA_VERSION = "1.0"
ContextOwnerClass = Literal["registry", "task", "inventory", "fact"]
SourceFormat = tuple[str, str]
_REGISTRY_FORMATS = frozenset(
    {
        ("project-registry", PROJECT_REGISTRY_SCHEMA_VERSION),
        ("project-registry", PROFILED_PROJECT_REGISTRY_SCHEMA_VERSION),
    }
)
_TASK_FORMAT = ("task-definition", TASK_DEFINITION_SCHEMA_VERSION)
_INVENTORY_FORMAT = ("repository-state", REPOSITORY_STATE_SCHEMA_VERSION)
_DOMAIN_FORMAT = ("inventory-domain", INVENTORY_DOMAIN_SCHEMA_VERSION)
_TASK_FACTS = frozenset(
    {
        "task.id",
        "task.revision",
        "task.actor",
        "task.project",
        "task.group",
        "task.root",
        "task.lifecycle",
    }
)
_REGISTRY_FACTS = frozenset(
    {
        "project.id",
        "project.group",
        "project.lifecycle",
        "project.target_kind",
        "project.visibility",
        "project.memory_state",
        "registry.generation",
        "registry.digest",
    }
)
_INVENTORY_FACTS = frozenset(
    {
        "inventory.roots",
        "inventory.languages",
        "inventory.roles",
        "inventory.changed_paths",
        "inventory.repository_state",
    }
)
_DOMAINS: dict[str, tuple[str, frozenset[SourceFormat], frozenset[str], frozenset[str]]] = {
    "builtin.task-definition.v1": (
        "task",
        _REGISTRY_FORMATS | {_TASK_FORMAT},
        frozenset({"task-identity"}),
        _TASK_FACTS,
    ),
    "builtin.project-registry.v1": (
        "registry",
        _REGISTRY_FORMATS,
        frozenset({"registry-generation"}),
        _REGISTRY_FACTS,
    ),
    "builtin.maintained-inventory.v1": (
        "inventory",
        _REGISTRY_FORMATS | {_INVENTORY_FORMAT, _DOMAIN_FORMAT},
        frozenset({"repository-state", "baseline-inventory"}),
        _INVENTORY_FACTS,
    ),
    "builtin.context-facts.v1": (
        "fact",
        _REGISTRY_FORMATS | {_TASK_FORMAT, _INVENTORY_FORMAT},
        frozenset({"task-identity", "registry-generation", "repository-state"}),
        _TASK_FACTS | _REGISTRY_FACTS | _INVENTORY_FACTS,
    ),
}
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "contract_id",
        "owner_id",
        "owner_class",
        "implementation_id",
        "implementation_digest",
        "source_formats",
        "subject_kinds",
        "fact_references",
        "root_bindings",
        "contract_digest",
    }
)
_ROOT_FIELDS = frozenset(
    {
        "root_id",
        "project_id",
        "group_id",
        "canonical_path",
        "configured_scope_digest",
    }
)
_MAX_REFERENCES = 65536


def _strings(value: Sequence[object], field: str) -> tuple[str, ...]:
    """Validate ordered identities after the public boundary's count/type check."""
    items = tuple(require_identifier(item, field) for item in value)
    if items != tuple(sorted(set(items))):
        raise ValueError("context contract identities must be sorted and unique")
    return items


def _format(value: object) -> SourceFormat:
    """Parse one closed inline source descriptor without an executable resolver."""
    data = require_mapping(value, "context source format")
    require_exact_fields(data, frozenset({"kind", "format_version"}), "context source format")
    pair = (
        require_identifier(data["kind"], "context source kind"),
        require_string(data["format_version"], "context source version"),
    )
    if pair not in _REGISTRY_FORMATS | {_TASK_FORMAT, _INVENTORY_FORMAT, _DOMAIN_FORMAT}:
        raise ValueError("context source kind or version is unsupported")
    return pair


@dataclass(frozen=True)
class ContextRootBinding:
    """Inline root-domain data; actual registry and completeness checks are separate."""

    root_id: str
    project_id: str
    group_id: str
    canonical_path: str
    configured_scope_digest: str

    def __post_init__(self) -> None:
        """Require portable identities and a normalized relative maintained-root path."""
        require_identifier(self.root_id, "context root identity")
        require_identifier(self.project_id, "context root project")
        require_identifier(self.group_id, "context root group")
        text = require_string(self.canonical_path, "context root path")
        path = PurePosixPath(text)
        if (
            not path.parts
            or path.is_absolute()
            or path.as_posix() != text
            or any(part.casefold() in {".", "..", ".git"} for part in path.parts)
            or "\\" in text
            or "\0" in text
            or ":" in path.parts[0]
        ):
            raise ValueError("context root path must be normalized and relative")
        require_digest(self.configured_scope_digest, "configured scope digest")

    def to_dict(self) -> dict[str, object]:
        """Serialize the inline value after revalidating direct construction."""
        checked = ContextRootBinding(
            self.root_id,
            self.project_id,
            self.group_id,
            self.canonical_path,
            self.configured_scope_digest,
        )
        return {
            "root_id": checked.root_id,
            "project_id": checked.project_id,
            "group_id": checked.group_id,
            "canonical_path": checked.canonical_path,
            "configured_scope_digest": checked.configured_scope_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> ContextRootBinding:
        """Parse only the five declared parent-covered inline fields."""
        data = require_mapping(value, "context root binding")
        require_exact_fields(data, _ROOT_FIELDS, "context root binding")
        return cls(
            require_identifier(data["root_id"], "context root identity"),
            require_identifier(data["project_id"], "context root project"),
            require_identifier(data["group_id"], "context root group"),
            require_string(data["canonical_path"], "context root path"),
            require_digest(data["configured_scope_digest"], "configured scope digest"),
        )


@dataclass(frozen=True)
class ContextProducerContract1:
    """Exact data constraints for one fixed owner, with no installation authority."""

    contract_id: str
    owner_id: str
    owner_class: ContextOwnerClass
    implementation_id: str
    implementation_digest: str
    source_formats: tuple[SourceFormat, ...]
    subject_kinds: tuple[str, ...]
    fact_references: tuple[str, ...]
    root_bindings: tuple[ContextRootBinding, ...]
    contract_digest: str

    schema_version: ClassVar[str] = CONTEXT_PRODUCER_CONTRACT_SCHEMA_VERSION
    object_kind: ClassVar[str] = "context-producer-contract"

    def __post_init__(self) -> None:
        """Check direct records without resolving or enrolling an implementation."""
        body = self._body()
        if require_digest(self.contract_digest, "context contract digest") != canonical_digest(
            body
        ):
            raise ValueError("context contract digest differs")

    def _body(self) -> dict[str, object]:
        """Validate the complete fixed mapping and immutable constrained domains."""
        if any(
            type(items) is not tuple
            for items in (
                self.source_formats,
                self.subject_kinds,
                self.fact_references,
                self.root_bindings,
            )
        ):
            raise ValueError("context contract collections must be immutable tuples")
        count = (
            len(self.source_formats)
            + len(self.subject_kinds)
            + len(self.fact_references)
            + 3 * len(self.root_bindings)
        )
        if count > _MAX_REFERENCES:
            raise ValueError("context contract exceeds the implementation reference ceiling")
        implementation = require_identifier(self.implementation_id, "context implementation")
        domain = _DOMAINS.get(implementation)
        if domain is None or self.owner_class != domain[0]:
            raise ValueError("context implementation or owning class is unsupported")
        formats = tuple(
            _format({"kind": pair[0], "format_version": pair[1]})
            for pair in self.source_formats
            if type(pair) is tuple and len(pair) == 2
        )
        if (
            len(formats) != len(self.source_formats)
            or not formats
            or formats != tuple(sorted(set(formats)))
            or not set(formats) <= domain[1]
        ):
            raise ValueError("context source formats must be supported, sorted and unique")
        if not set(formats) & _REGISTRY_FORMATS:
            raise ValueError("context owner requires a registry source format")
        if self.owner_class in {"task", "fact"} and _TASK_FORMAT not in formats:
            raise ValueError("context owner requires a task definition source format")
        if self.owner_class in {"inventory", "fact"} and _INVENTORY_FORMAT not in formats:
            raise ValueError("context owner requires a repository state source format")
        subjects = _strings(self.subject_kinds, "context subject kind")
        if frozenset(subjects) != domain[2]:
            raise ValueError("context subject kinds differ from the fixed owner")
        facts = _strings(self.fact_references, "context fact reference")
        for reference in facts:
            ConditionExpression.build("exists", reference=reference)
        if not set(facts) <= domain[3] or (self.owner_class == "fact" and not facts):
            raise ValueError("context fact reference is outside the fixed owner domain")
        roots = tuple(
            root.to_dict() for root in self.root_bindings if type(root) is ContextRootBinding
        )
        ids = tuple(
            root.root_id for root in self.root_bindings if type(root) is ContextRootBinding
        )
        paths = tuple(
            root.canonical_path for root in self.root_bindings if type(root) is ContextRootBinding
        )
        if (
            len(roots) != len(self.root_bindings)
            or not roots
            or ids != tuple(sorted(set(ids)))
            or len(set(paths)) != len(paths)
        ):
            raise ValueError("context roots must be nonempty, ordered and unique")
        return {
            "schema_version": CONTEXT_PRODUCER_CONTRACT_SCHEMA_VERSION,
            "object_kind": "context-producer-contract",
            "contract_id": require_identifier(self.contract_id, "context contract identity"),
            "owner_id": require_identifier(self.owner_id, "context owner identity"),
            "owner_class": self.owner_class,
            "implementation_id": implementation,
            "implementation_digest": require_digest(
                self.implementation_digest, "context code digest"
            ),
            "source_formats": [
                {"kind": kind, "format_version": version} for kind, version in formats
            ],
            "subject_kinds": list(subjects),
            "fact_references": list(facts),
            "root_bindings": list(roots),
        }

    @classmethod
    def from_dict(
        cls,
        value: object,
        *,
        budget: PolicyReadBudget1,
    ) -> ContextProducerContract1:
        """Parse exact producer metadata with an explicit relation budget."""
        if type(budget) is not PolicyReadBudget1:
            raise ValueError("policy read budget is required")
        limits = PolicyReadBudget1.from_dict(budget.to_dict())
        data = require_mapping(value, "context producer contract")
        require_exact_fields(data, _FIELDS, "context producer contract")
        if (
            data["schema_version"] != CONTEXT_PRODUCER_CONTRACT_SCHEMA_VERSION
            or data["object_kind"] != "context-producer-contract"
        ):
            raise ValueError("unsupported context producer contract")
        sources = data["source_formats"]
        subjects = data["subject_kinds"]
        facts = data["fact_references"]
        roots = data["root_bindings"]
        if (
            not isinstance(sources, list)
            or not isinstance(subjects, list)
            or not isinstance(facts, list)
            or not isinstance(roots, list)
        ):
            raise ValueError("context contract collections must be arrays")
        if len(sources) + len(subjects) + len(facts) + 3 * len(roots) > limits.max_references:
            raise ValueError("context contract exceeds the reference budget")
        return cls(
            require_identifier(data["contract_id"], "context contract identity"),
            require_identifier(data["owner_id"], "context owner identity"),
            cast(ContextOwnerClass, require_string(data["owner_class"], "context owner class")),
            require_identifier(data["implementation_id"], "context implementation"),
            require_digest(data["implementation_digest"], "context code digest"),
            tuple(_format(item) for item in sources),
            _strings(subjects, "context subject kind"),
            _strings(facts, "context fact reference"),
            tuple(ContextRootBinding.from_dict(item) for item in roots),
            require_digest(data["contract_digest"], "context contract digest"),
        )

    @classmethod
    def build(
        cls,
        *,
        contract_id: str,
        owner_id: str,
        owner_class: ContextOwnerClass,
        implementation_id: str,
        implementation_digest: str,
        source_formats: tuple[SourceFormat, ...],
        subject_kinds: tuple[str, ...],
        fact_references: tuple[str, ...],
        root_bindings: tuple[ContextRootBinding, ...],
        budget: PolicyReadBudget1,
    ) -> ContextProducerContract1:
        """Build explicit constrained metadata without loading its named implementation."""
        if type(budget) is not PolicyReadBudget1:
            raise ValueError("policy read budget is required")
        limits = PolicyReadBudget1.from_dict(budget.to_dict())
        if any(
            type(items) is not tuple
            for items in (
                source_formats,
                subject_kinds,
                fact_references,
                root_bindings,
            )
        ):
            raise ValueError("context contract collections must be immutable tuples")
        count = (
            len(source_formats)
            + len(subject_kinds)
            + len(fact_references)
            + 3 * len(root_bindings)
        )
        if count > limits.max_references:
            raise ValueError("context contract exceeds the reference budget")
        if any(type(root) is not ContextRootBinding for root in root_bindings):
            raise ValueError("context root binding record is required")
        body: dict[str, object] = {
            "schema_version": CONTEXT_PRODUCER_CONTRACT_SCHEMA_VERSION,
            "object_kind": "context-producer-contract",
            "contract_id": contract_id,
            "owner_id": owner_id,
            "owner_class": owner_class,
            "implementation_id": implementation_id,
            "implementation_digest": implementation_digest,
            "source_formats": [
                {"kind": kind, "format_version": version} for kind, version in source_formats
            ],
            "subject_kinds": list(subject_kinds),
            "fact_references": list(fact_references),
            "root_bindings": [root.to_dict() for root in root_bindings],
        }
        return cls.from_dict({**body, "contract_digest": canonical_digest(body)}, budget=limits)

    def to_dict(self) -> dict[str, object]:
        """Serialize and revalidate this descriptive record, without an admission result."""
        body = self._body()
        digest = require_digest(self.contract_digest, "context contract digest")
        if digest != canonical_digest(body):
            raise ValueError("context contract digest differs")
        return {**body, "contract_digest": digest}

    def reference(self) -> dict[str, object]:
        """Return the typed identity of this contract, with no resolver appointment."""
        checked = self.to_dict()
        body: dict[str, object] = {
            "schema_version": TYPED_OBJECT_REF_SCHEMA_VERSION,
            "object_kind": "typed-object-ref",
            "kind": "context-producer-contract",
            "format_version": CONTEXT_PRODUCER_CONTRACT_SCHEMA_VERSION,
            "object_id": checked["contract_id"],
            "object_digest": checked["contract_digest"],
        }
        return {**body, "ref_digest": canonical_digest(body)}
