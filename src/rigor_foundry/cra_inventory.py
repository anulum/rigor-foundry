# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — CRA component-inventory evidence
"""Define strict imported-SBOM inventory and repository-drift records."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, cast

from .audit_primitives import canonical_digest, require_exact_fields
from .cra_protocol import CRA_SCHEMA_VERSION, JsonObject, json_text, require_cra_timestamp
from .git_inventory import GitInventory
from .model_primitives import (
    require_boolean,
    require_digest,
    require_git_object,
    require_identifier,
)
from .models import require_mapping, require_string

SbomFormat = Literal["cyclonedx-1.5", "cyclonedx-1.6", "spdx-2.3"]

_FORMATS = frozenset({"cyclonedx-1.5", "cyclonedx-1.6", "spdx-2.3"})
_SOURCE_TOOL_FIELDS = frozenset({"name", "version", "evidence_ref"})
_COMPONENT_FIELDS = frozenset({"name", "version", "purl"})
_BINDING_FIELDS = frozenset({"head", "tree_oid", "tracked_content_sha256", "object_format"})
_INVENTORY_FIELDS = frozenset(
    {
        "schema_version",
        "product_key",
        "sbom_format",
        "sbom_sha256",
        "source_tool",
        "captured_at",
        "top_level_components",
        "covers_top_level_only",
        "tree_binding",
        "inventory_digest",
    }
)
_DRIFT_FIELDS = frozenset(
    {
        "schema_version",
        "product_key",
        "inventory_digest",
        "observed_at",
        "current_binding",
        "head_changed",
        "tree_changed",
        "tracked_content_changed",
        "drifted",
        "drift_digest",
    }
)


def _format(value: object) -> SbomFormat:
    """Return one explicitly supported imported SBOM format."""
    result = require_string(value, "sbom_format")
    if result not in _FORMATS:
        raise ValueError("sbom_format is unsupported")
    return cast(SbomFormat, result)


@dataclass(frozen=True, order=True)
class InventoryComponent:
    """Identify one imported component without inventing missing version data."""

    name: str
    version: str
    purl: str | None

    @classmethod
    def build(cls, *, name: str, version: str, purl: str | None) -> InventoryComponent:
        """Build one exact component tuple."""
        name = require_string(name, "component.name")
        version = require_string(version, "component.version")
        if purl is not None:
            purl = require_string(purl, "component.purl")
            if not purl.startswith("pkg:"):
                raise ValueError("component.purl must use the package-url scheme")
        return cls(name=name, version=version, purl=purl)

    def to_dict(self) -> JsonObject:
        """Serialise one component identity."""
        return {"name": self.name, "version": self.version, "purl": self.purl}

    @classmethod
    def from_dict(cls, value: object) -> InventoryComponent:
        """Parse one exact component identity."""
        data = require_mapping(value, "component")
        require_exact_fields(data, _COMPONENT_FIELDS, "component")
        raw_purl = data.get("purl")
        return cls.build(
            name=require_string(data.get("name"), "component.name"),
            version=require_string(data.get("version"), "component.version"),
            purl=None if raw_purl is None else require_string(raw_purl, "component.purl"),
        )


@dataclass(frozen=True)
class SourceToolEvidence:
    """Bind an operator-declared SBOM producer and its retained evidence."""

    name: str
    version: str
    evidence_ref: str

    @classmethod
    def build(cls, *, name: str, version: str, evidence_ref: str) -> SourceToolEvidence:
        """Build a complete source-tool declaration."""
        return cls(
            name=require_identifier(name, "source_tool.name"),
            version=require_string(version, "source_tool.version"),
            evidence_ref=require_string(evidence_ref, "source_tool.evidence_ref"),
        )

    def to_dict(self) -> JsonObject:
        """Serialise source-tool evidence."""
        return {
            "name": self.name,
            "version": self.version,
            "evidence_ref": self.evidence_ref,
        }

    @classmethod
    def from_dict(cls, value: object) -> SourceToolEvidence:
        """Parse source-tool evidence."""
        data = require_mapping(value, "source_tool")
        require_exact_fields(data, _SOURCE_TOOL_FIELDS, "source_tool")
        return cls.build(
            name=require_string(data.get("name"), "source_tool.name"),
            version=require_string(data.get("version"), "source_tool.version"),
            evidence_ref=require_string(data.get("evidence_ref"), "source_tool.evidence_ref"),
        )


@dataclass(frozen=True)
class RepositoryBinding:
    """Bind evidence to one exact Git commit, tree, and tracked worktree state."""

    head: str
    tree_oid: str
    tracked_content_sha256: str
    object_format: Literal["sha1", "sha256"]

    @classmethod
    def from_inventory(cls, inventory: GitInventory) -> RepositoryBinding:
        """Capture identities from one already loaded Git inventory."""
        return cls(
            head=inventory.head,
            tree_oid=inventory.head_tree,
            tracked_content_sha256=inventory.tracked_content_digest,
            object_format=cast(Literal["sha1", "sha256"], inventory.object_format),
        )

    def to_dict(self) -> JsonObject:
        """Serialise the exact repository binding."""
        return {
            "head": self.head,
            "tree_oid": self.tree_oid,
            "tracked_content_sha256": self.tracked_content_sha256,
            "object_format": self.object_format,
        }

    @classmethod
    def from_dict(cls, value: object) -> RepositoryBinding:
        """Parse and cross-check one repository binding."""
        data = require_mapping(value, "tree_binding")
        require_exact_fields(data, _BINDING_FIELDS, "tree_binding")
        object_format = require_string(data.get("object_format"), "tree_binding.object_format")
        if object_format not in {"sha1", "sha256"}:
            raise ValueError("tree_binding.object_format is unsupported")
        head = require_git_object(data.get("head"), "tree_binding.head")
        tree_oid = require_git_object(data.get("tree_oid"), "tree_binding.tree_oid")
        expected = 40 if object_format == "sha1" else 64
        if len(head) != expected or len(tree_oid) != expected:
            raise ValueError("tree_binding Git identities contradict object_format")
        return cls(
            head=head,
            tree_oid=tree_oid,
            tracked_content_sha256=require_digest(
                data.get("tracked_content_sha256"), "tree_binding.tracked_content_sha256"
            ),
            object_format=cast(Literal["sha1", "sha256"], object_format),
        )


@dataclass(frozen=True)
class ComponentInventory:
    """Store one deterministic inventory imported from exact SBOM bytes."""

    product_key: str
    sbom_format: SbomFormat
    sbom_sha256: str
    source_tool: SourceToolEvidence
    captured_at: str
    top_level_components: tuple[InventoryComponent, ...]
    covers_top_level_only: bool
    tree_binding: RepositoryBinding
    inventory_digest: str

    @classmethod
    def build(
        cls,
        *,
        product_key: str,
        sbom_format: SbomFormat,
        sbom_sha256: str,
        source_tool: SourceToolEvidence,
        captured_at: str,
        top_level_components: tuple[InventoryComponent, ...],
        covers_top_level_only: bool,
        tree_binding: RepositoryBinding,
    ) -> ComponentInventory:
        """Build a sorted, digest-bound imported inventory."""
        product_key = require_identifier(product_key, "product_key")
        sbom_format = _format(sbom_format)
        sbom_sha256 = require_digest(sbom_sha256, "sbom_sha256")
        source_tool = SourceToolEvidence.from_dict(source_tool.to_dict())
        captured_at = require_cra_timestamp(captured_at, "captured_at")
        if not isinstance(covers_top_level_only, bool):
            raise ValueError("covers_top_level_only must be boolean")
        components = tuple(
            sorted(InventoryComponent.from_dict(item.to_dict()) for item in top_level_components)
        )
        if not components:
            raise ValueError("top_level_components must contain at least one component")
        if len(components) != len(set(components)):
            raise ValueError("top_level_components must be unique")
        tree_binding = RepositoryBinding.from_dict(tree_binding.to_dict())
        body: JsonObject = {
            "schema_version": CRA_SCHEMA_VERSION,
            "product_key": product_key,
            "sbom_format": sbom_format,
            "sbom_sha256": sbom_sha256,
            "source_tool": source_tool.to_dict(),
            "captured_at": captured_at,
            "top_level_components": [item.to_dict() for item in components],
            "covers_top_level_only": covers_top_level_only,
            "tree_binding": tree_binding.to_dict(),
        }
        return cls(
            product_key=product_key,
            sbom_format=sbom_format,
            sbom_sha256=sbom_sha256,
            source_tool=source_tool,
            captured_at=captured_at,
            top_level_components=components,
            covers_top_level_only=covers_top_level_only,
            tree_binding=tree_binding,
            inventory_digest=canonical_digest(body),
        )

    def to_dict(self) -> JsonObject:
        """Serialise the imported inventory."""
        return {
            "schema_version": CRA_SCHEMA_VERSION,
            "product_key": self.product_key,
            "sbom_format": self.sbom_format,
            "sbom_sha256": self.sbom_sha256,
            "source_tool": self.source_tool.to_dict(),
            "captured_at": self.captured_at,
            "top_level_components": [item.to_dict() for item in self.top_level_components],
            "covers_top_level_only": self.covers_top_level_only,
            "tree_binding": self.tree_binding.to_dict(),
            "inventory_digest": self.inventory_digest,
        }

    def to_json(self) -> str:
        """Serialise deterministic human-readable JSON."""
        return json_text(self.to_dict())

    @classmethod
    def from_dict(cls, value: object) -> ComponentInventory:
        """Parse and integrity-check one imported inventory."""
        data = require_mapping(value, "component_inventory")
        require_exact_fields(data, _INVENTORY_FIELDS, "component_inventory")
        if data.get("schema_version") != CRA_SCHEMA_VERSION:
            raise ValueError("component_inventory schema_version is unsupported")
        raw_components = data.get("top_level_components")
        if not isinstance(raw_components, list):
            raise ValueError("top_level_components must be an array")
        components = tuple(InventoryComponent.from_dict(item) for item in raw_components)
        expected = cls.build(
            product_key=require_string(data.get("product_key"), "product_key"),
            sbom_format=_format(data.get("sbom_format")),
            sbom_sha256=require_digest(data.get("sbom_sha256"), "sbom_sha256"),
            source_tool=SourceToolEvidence.from_dict(data.get("source_tool")),
            captured_at=require_string(data.get("captured_at"), "captured_at"),
            top_level_components=components,
            covers_top_level_only=require_boolean(
                data.get("covers_top_level_only"), "covers_top_level_only"
            ),
            tree_binding=RepositoryBinding.from_dict(data.get("tree_binding")),
        )
        if components != expected.top_level_components:
            raise ValueError("top_level_components must use canonical sort order")
        if (
            require_digest(data.get("inventory_digest"), "inventory_digest")
            != expected.inventory_digest
        ):
            raise ValueError("component_inventory digest does not match its content")
        return expected


@dataclass(frozen=True)
class InventoryDriftEvidence:
    """Record exact repository-state drift from one imported inventory."""

    product_key: str
    inventory_digest: str
    observed_at: str
    current_binding: RepositoryBinding
    head_changed: bool
    tree_changed: bool
    tracked_content_changed: bool
    drifted: bool
    drift_digest: str

    @classmethod
    def build(
        cls,
        inventory: ComponentInventory,
        current: RepositoryBinding,
        *,
        observed_at: str,
    ) -> InventoryDriftEvidence:
        """Compare exact Git identities without interpreting product completeness."""
        inventory = ComponentInventory.from_dict(inventory.to_dict())
        current = RepositoryBinding.from_dict(current.to_dict())
        observed_at = require_cra_timestamp(observed_at, "observed_at")
        head_changed = inventory.tree_binding.head != current.head
        tree_changed = inventory.tree_binding.tree_oid != current.tree_oid
        content_changed = (
            inventory.tree_binding.tracked_content_sha256 != current.tracked_content_sha256
        )
        drifted = head_changed or tree_changed or content_changed
        body: JsonObject = {
            "schema_version": CRA_SCHEMA_VERSION,
            "product_key": inventory.product_key,
            "inventory_digest": inventory.inventory_digest,
            "observed_at": observed_at,
            "current_binding": current.to_dict(),
            "head_changed": head_changed,
            "tree_changed": tree_changed,
            "tracked_content_changed": content_changed,
            "drifted": drifted,
        }
        return cls(
            product_key=inventory.product_key,
            inventory_digest=inventory.inventory_digest,
            observed_at=observed_at,
            current_binding=current,
            head_changed=head_changed,
            tree_changed=tree_changed,
            tracked_content_changed=content_changed,
            drifted=drifted,
            drift_digest=canonical_digest(body),
        )

    def to_dict(self) -> JsonObject:
        """Serialise the drift observation."""
        return {
            "schema_version": CRA_SCHEMA_VERSION,
            "product_key": self.product_key,
            "inventory_digest": self.inventory_digest,
            "observed_at": self.observed_at,
            "current_binding": self.current_binding.to_dict(),
            "head_changed": self.head_changed,
            "tree_changed": self.tree_changed,
            "tracked_content_changed": self.tracked_content_changed,
            "drifted": self.drifted,
            "drift_digest": self.drift_digest,
        }

    def to_json(self) -> str:
        """Serialise deterministic human-readable JSON."""
        return json_text(self.to_dict())

    @classmethod
    def from_dict(cls, value: object) -> InventoryDriftEvidence:
        """Parse and integrity-check one drift record."""
        data = require_mapping(value, "inventory_drift")
        require_exact_fields(data, _DRIFT_FIELDS, "inventory_drift")
        if data.get("schema_version") != CRA_SCHEMA_VERSION:
            raise ValueError("inventory_drift schema_version is unsupported")
        binding = RepositoryBinding.from_dict(data.get("current_binding"))
        product_key = require_identifier(data.get("product_key"), "product_key")
        inventory_digest = require_digest(data.get("inventory_digest"), "inventory_digest")
        observed_at = require_cra_timestamp(data.get("observed_at"), "observed_at")
        booleans = {
            field: require_boolean(data.get(field), field)
            for field in (
                "head_changed",
                "tree_changed",
                "tracked_content_changed",
                "drifted",
            )
        }
        if booleans["drifted"] != any(
            booleans[field]
            for field in ("head_changed", "tree_changed", "tracked_content_changed")
        ):
            raise ValueError("inventory_drift drifted flag contradicts change flags")
        body: JsonObject = {
            "schema_version": CRA_SCHEMA_VERSION,
            "product_key": product_key,
            "inventory_digest": inventory_digest,
            "observed_at": observed_at,
            "current_binding": binding.to_dict(),
            **booleans,
        }
        if require_digest(data.get("drift_digest"), "drift_digest") != canonical_digest(body):
            raise ValueError("inventory_drift digest does not match its content")
        return cls(
            product_key=product_key,
            inventory_digest=inventory_digest,
            observed_at=observed_at,
            current_binding=binding,
            head_changed=booleans["head_changed"],
            tree_changed=booleans["tree_changed"],
            tracked_content_changed=booleans["tracked_content_changed"],
            drifted=booleans["drifted"],
            drift_digest=canonical_digest(body),
        )
