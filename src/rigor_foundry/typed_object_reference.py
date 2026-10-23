# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — closed context source references
"""Validate typed source identities without interpreting their IDs as locators."""

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

TYPED_OBJECT_REF_SCHEMA_VERSION = "1.0"
SUPPORTED_CONTEXT_SOURCE_FORMATS = frozenset(
    {
        ("task-definition", "1.0"),
        ("context-producer-contract", "1.0"),
        ("repository-state", "1.0"),
        ("inventory-domain", "1.0"),
        ("project-registry", "gotm-project-registry.v1"),
        ("project-registry", "project-registry.v2"),
    }
)
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "kind",
        "format_version",
        "object_id",
        "object_digest",
        "ref_digest",
    }
)


@dataclass(frozen=True)
class TypedObjectRef1:
    """One closed supported source identity; integrity grants no source authority.

    The supported table is limited to source targets with actual owning parsers.
    Consumers must resolve the target through that parser before trusting its
    identity. This record carries no path, URL, callback or executable loader.
    """

    kind: str
    format_version: str
    object_id: str
    object_digest: str
    ref_digest: str

    schema_version: ClassVar[str] = TYPED_OBJECT_REF_SCHEMA_VERSION
    object_kind: ClassVar[str] = "typed-object-ref"

    def __post_init__(self) -> None:
        """Validate direct construction against the same closed format table."""
        self.to_dict()

    def _body(self) -> dict[str, object]:
        """Validate every identity field before deriving the complete digest."""
        kind = require_identifier(self.kind, "reference kind")
        version = require_string(self.format_version, "reference format version")
        if (kind, version) not in SUPPORTED_CONTEXT_SOURCE_FORMATS:
            raise ValueError("unsupported context source kind or version")
        return {
            "schema_version": TYPED_OBJECT_REF_SCHEMA_VERSION,
            "object_kind": "typed-object-ref",
            "kind": kind,
            "format_version": version,
            "object_id": require_identifier(self.object_id, "reference object identity"),
            "object_digest": require_digest(self.object_digest, "reference object digest"),
        }

    @classmethod
    def build(
        cls, *, kind: str, format_version: str, object_id: str, object_digest: str
    ) -> TypedObjectRef1:
        """Build an exact supported metadata reference without resolving a target."""
        body: dict[str, object] = {
            "schema_version": TYPED_OBJECT_REF_SCHEMA_VERSION,
            "object_kind": "typed-object-ref",
            "kind": kind,
            "format_version": format_version,
            "object_id": object_id,
            "object_digest": object_digest,
        }
        return cls.from_dict({**body, "ref_digest": canonical_digest(body)})

    @classmethod
    def from_dict(cls, value: object) -> TypedObjectRef1:
        """Reject unknown pairs before any owning parser or source lookup."""
        data = require_mapping(value, "typed object reference")
        require_exact_fields(data, _FIELDS, "typed object reference")
        if (
            data["schema_version"] != TYPED_OBJECT_REF_SCHEMA_VERSION
            or data["object_kind"] != "typed-object-ref"
        ):
            raise ValueError("unsupported typed object reference")
        return cls(
            require_identifier(data["kind"], "reference kind"),
            require_string(data["format_version"], "reference format version"),
            require_identifier(data["object_id"], "reference object identity"),
            require_digest(data["object_digest"], "reference object digest"),
            require_digest(data["ref_digest"], "reference digest"),
        )

    def to_dict(self) -> dict[str, object]:
        """Revalidate direct instances before returning their complete identity."""
        body = self._body()
        digest = require_digest(self.ref_digest, "reference digest")
        if digest != canonical_digest(body):
            raise ValueError("typed object reference digest differs")
        return {**body, "ref_digest": digest}
