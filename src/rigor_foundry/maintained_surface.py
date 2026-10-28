# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — maintained file surface identities
"""Retain exact current/before byte identities without authenticating their owner."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from .audit_primitives import canonical_digest, require_exact_fields, require_mapping
from .context_owner_proof import OwnerProof1
from .inventory_domain import InventoryClassificationRule
from .model_primitives import require_digest, require_identifier
from .policy_read_budget import PolicyReadBudget1
from .repository_inventory_rows import require_inventory_path

MAINTAINED_SURFACE_SCHEMA_VERSION = "1.0"
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "surface_id",
        "root_id",
        "relative_path",
        "role",
        "language",
        "content_digest",
        "baseline_content_digest",
        "inventory_proof",
        "surface_digest",
    }
)


@dataclass(frozen=True)
class MaintainedSurface1:
    """One maintained path with an independently defined repository-state subject.

    Parameters
    ----------
    surface_id, root_id : str
        Surface and configured-root identities, never filesystem permissions.
    relative_path, role, language : str
        Exact root-relative path and original declared classifications.
    content_digest : str
        Current raw bytes, or retained before-bytes for a deleted path.
    baseline_content_digest : str or None
        Original before-image, absent only when no earlier file existed.
    inventory_proof : OwnerProof1
        Metadata binding the independent repository state, not this surface.
    surface_digest : str
        Canonical identity of all other closed fields.
    """

    surface_id: str
    root_id: str
    relative_path: str
    role: str
    language: str
    content_digest: str
    baseline_content_digest: str | None
    inventory_proof: OwnerProof1
    surface_digest: str

    schema_version: ClassVar[str] = MAINTAINED_SURFACE_SCHEMA_VERSION
    object_kind: ClassVar[str] = "maintained-surface"

    def __post_init__(self) -> None:
        """Reject malformed direct instances and self-inconsistent byte identities."""
        self.to_dict()

    def _body(self) -> dict[str, object]:
        if type(self.inventory_proof) is not OwnerProof1:
            raise ValueError("maintained surface requires an actual inventory proof")
        proof = self.inventory_proof
        if (
            proof.owner_class != "inventory"
            or proof.source_object.kind != "repository-state"
            or proof.source_object.object_digest != proof.subject_digest
        ):
            raise ValueError("surface proof must bind an independent repository state")
        InventoryClassificationRule(self.root_id, "role", "exact", self.relative_path, self.role)
        return {
            "schema_version": MAINTAINED_SURFACE_SCHEMA_VERSION,
            "object_kind": "maintained-surface",
            "surface_id": require_identifier(self.surface_id, "maintained surface identity"),
            "root_id": require_identifier(self.root_id, "maintained surface root"),
            "relative_path": require_inventory_path(self.relative_path),
            "role": self.role,
            "language": require_identifier(self.language, "maintained surface language"),
            "content_digest": require_digest(self.content_digest, "maintained content digest"),
            "baseline_content_digest": None
            if self.baseline_content_digest is None
            else require_digest(self.baseline_content_digest, "maintained before digest"),
            "inventory_proof": proof.to_dict(),
        }

    @classmethod
    def build(
        cls,
        *,
        surface_id: str,
        root_id: str,
        relative_path: str,
        role: str,
        language: str,
        content_digest: str,
        baseline_content_digest: str | None,
        inventory_proof: OwnerProof1,
        budget: PolicyReadBudget1,
    ) -> MaintainedSurface1:
        """Bind complete explicit surface inputs through the bounded closed parser.

        Parameters
        ----------
        surface_id, root_id, relative_path, role, language, content_digest : str
            Exact original identifiers, classifications and effective byte digest.
        baseline_content_digest : str or None
            Exact earlier byte digest, never inferred from current content.
        inventory_proof : OwnerProof1
            Independently generated repository-state proof metadata.
        budget : PolicyReadBudget1
            Explicit reference-allocation ceiling.

        Returns
        -------
        MaintainedSurface1
            Complete hashed data; an installed owner must still verify it.

        Raises
        ------
        ValueError
            If fields, proof relations or budgets disagree.
        """
        if type(inventory_proof) is not OwnerProof1:
            raise ValueError("maintained surface requires an actual inventory proof")
        body = {
            "schema_version": MAINTAINED_SURFACE_SCHEMA_VERSION,
            "object_kind": "maintained-surface",
            "surface_id": surface_id,
            "root_id": root_id,
            "relative_path": relative_path,
            "role": role,
            "language": language,
            "content_digest": content_digest,
            "baseline_content_digest": baseline_content_digest,
            "inventory_proof": inventory_proof.to_dict(),
        }
        return cls.from_dict({**body, "surface_digest": canonical_digest(body)}, budget=budget)

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> MaintainedSurface1:
        """Parse exact versioned surface data and the independent proof metadata.

        Parameters
        ----------
        value : object
            Complete decoded mapping with no unknown or omitted field.
        budget : PolicyReadBudget1
            Explicit reference-allocation ceiling for the nested proof.

        Returns
        -------
        MaintainedSurface1
            Revalidated inert surface record, without source authentication.

        Raises
        ------
        ValueError
            If the shape, version, path, digest or proof is unsupported.
        """
        data = require_mapping(value, "maintained surface")
        require_exact_fields(data, _FIELDS, "maintained surface")
        if (
            data["schema_version"] != MAINTAINED_SURFACE_SCHEMA_VERSION
            or data["object_kind"] != "maintained-surface"
        ):
            raise ValueError("unsupported maintained surface")
        return cls(
            require_identifier(data["surface_id"], "maintained surface identity"),
            require_identifier(data["root_id"], "maintained surface root"),
            require_inventory_path(data["relative_path"]),
            require_identifier(data["role"], "maintained surface role"),
            require_identifier(data["language"], "maintained surface language"),
            require_digest(data["content_digest"], "maintained content digest"),
            None
            if data["baseline_content_digest"] is None
            else require_digest(data["baseline_content_digest"], "maintained before digest"),
            OwnerProof1.from_dict(data["inventory_proof"], budget=budget),
            require_digest(data["surface_digest"], "maintained surface digest"),
        )

    def to_dict(self) -> dict[str, object]:
        """Revalidate the complete surface and return its closed mapping.

        Returns
        -------
        dict of str to object
            Every original field and the checked canonical surface digest.

        Raises
        ------
        ValueError
            If direct construction or later mutation violates the contract.
        """
        body = self._body()
        digest = require_digest(self.surface_digest, "maintained surface digest")
        if digest != canonical_digest(body):
            raise ValueError("maintained surface digest differs")
        return {**body, "surface_digest": digest}
