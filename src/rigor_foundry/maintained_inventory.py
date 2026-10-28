# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete maintained inventory records
"""Bind every maintained surface to independent repository and baseline subjects."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from .audit_primitives import canonical_digest, require_exact_fields, require_mapping
from .context_owner_proof import OwnerProof1
from .maintained_surface import MaintainedSurface1
from .model_primitives import require_digest, require_identifier
from .policy_read_budget import PolicyReadBudget1

MAINTAINED_INVENTORY_SCHEMA_VERSION = "1.0"
_IDENTITIES = ("project_id", "registry_generation_id")
_DIGESTS = ("registry_sha256", "repository_state_digest", "baseline_inventory_digest")
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        *_IDENTITIES,
        *_DIGESTS,
        "root_ids",
        "surfaces",
        "change_inventory_proof",
        "completeness_proof",
        "inventory_digest",
    }
)


@dataclass(frozen=True)
class MaintainedInventory1:
    """Closed full-root surface data; metadata alone cannot establish completeness.

    Parameters
    ----------
    project_id, registry_generation_id : str
        Original selected project and registry generation.
    registry_sha256, repository_state_digest, baseline_inventory_digest : str
        Independent source identities, preceding both owner proofs.
    root_ids : tuple of str
        Every declared root, including those with no file surface.
    surfaces : tuple of MaintainedSurface1
        Complete sorted root/path union, including deleted before-images.
    change_inventory_proof, completeness_proof : OwnerProof1
        Same actual inventory owner binding current state and retained baseline.
    inventory_digest : str
        Canonical identity of all other fields, not a proof subject.
    """

    project_id: str
    registry_generation_id: str
    registry_sha256: str
    repository_state_digest: str
    baseline_inventory_digest: str
    root_ids: tuple[str, ...]
    surfaces: tuple[MaintainedSurface1, ...]
    change_inventory_proof: OwnerProof1
    completeness_proof: OwnerProof1
    inventory_digest: str

    schema_version: ClassVar[str] = MAINTAINED_INVENTORY_SCHEMA_VERSION
    object_kind: ClassVar[str] = "maintained-inventory"

    def __post_init__(self) -> None:
        """Reject omitted roots, contradictory proof subjects and digest drift."""
        self.to_dict()

    def _body(self) -> dict[str, object]:
        if (
            type(self.root_ids) is not tuple
            or type(self.surfaces) is not tuple
            or not self.root_ids
            or len(self.root_ids) > 4096
            or len(self.root_ids) + 3 * len(self.surfaces) + 4 > 65536
        ):
            raise ValueError(
                "maintained inventory requires bounded complete immutable collections"
            )
        roots = tuple(
            require_identifier(item, "maintained inventory root") for item in self.root_ids
        )
        if roots != tuple(sorted(set(roots))) or any(
            type(item) is not MaintainedSurface1 for item in self.surfaces
        ):
            raise ValueError("inventory requires sorted unique roots and actual surface records")
        keys = tuple((item.root_id, item.relative_path) for item in self.surfaces)
        if keys != tuple(sorted(set(keys))) or any(root not in roots for root, _ in keys):
            raise ValueError("inventory surfaces must be sorted, unique and inside declared roots")
        change, complete = self.change_inventory_proof, self.completeness_proof
        if type(change) is not OwnerProof1 or type(complete) is not OwnerProof1:
            raise ValueError("inventory requires actual change and completeness proof records")
        if (change.owner_class, complete.owner_class) != ("inventory", "inventory") or (
            change.owner_id,
            change.owner_contract,
            change.snapshot_id,
        ) != (complete.owner_id, complete.owner_contract, complete.snapshot_id):
            raise ValueError("inventory proofs differ from one actual selected owner entry")
        if (
            (change.subject_digest, complete.subject_digest)
            != (self.repository_state_digest, self.baseline_inventory_digest)
            or (change.source_object.kind, complete.source_object.kind)
            != ("repository-state", "inventory-baseline")
            or change.source_object.object_digest != change.subject_digest
            or complete.source_object.object_digest != complete.subject_digest
        ):
            raise ValueError("inventory proofs must bind independent state and baseline sources")
        if any(item.inventory_proof != change for item in self.surfaces):
            raise ValueError("maintained surface proof differs from the selected inventory owner")
        return {
            "schema_version": MAINTAINED_INVENTORY_SCHEMA_VERSION,
            "object_kind": "maintained-inventory",
            **{name: require_identifier(getattr(self, name), name) for name in _IDENTITIES},
            **{name: require_digest(getattr(self, name), name) for name in _DIGESTS},
            "root_ids": list(roots),
            "surfaces": [item.to_dict() for item in self.surfaces],
            "change_inventory_proof": change.to_dict(),
            "completeness_proof": complete.to_dict(),
        }

    @classmethod
    def build(
        cls,
        *,
        project_id: str,
        registry_generation_id: str,
        registry_sha256: str,
        repository_state_digest: str,
        baseline_inventory_digest: str,
        root_ids: tuple[str, ...],
        surfaces: tuple[MaintainedSurface1, ...],
        change_inventory_proof: OwnerProof1,
        completeness_proof: OwnerProof1,
        budget: PolicyReadBudget1,
    ) -> MaintainedInventory1:
        """Bind all roots/surfaces through the exact bounded inventory parser.

        Parameters
        ----------
        project_id, registry_generation_id : str
            Original source-selected identities.
        registry_sha256, repository_state_digest, baseline_inventory_digest : str
            Independent source digests, never an enclosing proof/context digest.
        root_ids, surfaces : tuple
            Complete immutable ordered selections.
        change_inventory_proof, completeness_proof : OwnerProof1
            Actual inventory proof metadata for current and before sources.
        budget : PolicyReadBudget1
            Explicit aggregate root/surface/nested-proof reference ceiling.

        Returns
        -------
        MaintainedInventory1
            Closed integrity-checked inventory data, not authenticated admission.

        Raises
        ------
        ValueError
            If collections, fields, proof relations or budgets disagree.
        """
        if (
            type(root_ids) is not tuple
            or type(surfaces) is not tuple
            or any(type(item) is not MaintainedSurface1 for item in surfaces)
            or type(change_inventory_proof) is not OwnerProof1
            or type(completeness_proof) is not OwnerProof1
        ):
            raise ValueError("inventory requires immutable actual surface/proof records")
        if type(budget) is not PolicyReadBudget1:
            raise ValueError("policy read budget is required")
        limits = PolicyReadBudget1.from_dict(budget.to_dict())
        if (
            len(root_ids) > limits.max_sources
            or len(root_ids) + 3 * len(surfaces) + 4 > limits.max_references
        ):
            raise ValueError("maintained inventory exceeds the aggregate reference budget")
        body = {
            "schema_version": MAINTAINED_INVENTORY_SCHEMA_VERSION,
            "object_kind": "maintained-inventory",
            "project_id": project_id,
            "registry_generation_id": registry_generation_id,
            "registry_sha256": registry_sha256,
            "repository_state_digest": repository_state_digest,
            "baseline_inventory_digest": baseline_inventory_digest,
            "root_ids": list(root_ids),
            "surfaces": [item.to_dict() for item in surfaces],
            "change_inventory_proof": change_inventory_proof.to_dict(),
            "completeness_proof": completeness_proof.to_dict(),
        }
        return cls.from_dict({**body, "inventory_digest": canonical_digest(body)}, budget=limits)

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> MaintainedInventory1:
        """Bound the complete collections before parsing nested surface/proof data.

        Parameters
        ----------
        value : object
            Exact complete decoded inventory mapping.
        budget : PolicyReadBudget1
            Explicit aggregate root/surface/nested-proof reference ceiling.

        Returns
        -------
        MaintainedInventory1
            Original checked metadata with all roots and before-images retained.

        Raises
        ------
        ValueError
            If versions, collections, subjects or the complete digest disagree.
        """
        if type(budget) is not PolicyReadBudget1:
            raise ValueError("policy read budget is required")
        limits = PolicyReadBudget1.from_dict(budget.to_dict())
        data = require_mapping(value, "maintained inventory")
        require_exact_fields(data, _FIELDS, "maintained inventory")
        if (
            data["schema_version"] != MAINTAINED_INVENTORY_SCHEMA_VERSION
            or data["object_kind"] != "maintained-inventory"
        ):
            raise ValueError("unsupported maintained inventory")
        roots, surfaces = data["root_ids"], data["surfaces"]
        if (
            not isinstance(roots, list)
            or not isinstance(surfaces, list)
            or len(roots) > limits.max_sources
            or len(roots) + 3 * len(surfaces) + 4 > limits.max_references
        ):
            raise ValueError("maintained inventory exceeds the aggregate reference budget")
        return cls(
            **{name: require_identifier(data[name], name) for name in _IDENTITIES},
            **{name: require_digest(data[name], name) for name in _DIGESTS},
            root_ids=tuple(
                require_identifier(item, "maintained inventory root") for item in roots
            ),
            surfaces=tuple(MaintainedSurface1.from_dict(item, budget=limits) for item in surfaces),
            change_inventory_proof=OwnerProof1.from_dict(
                data["change_inventory_proof"], budget=limits
            ),
            completeness_proof=OwnerProof1.from_dict(data["completeness_proof"], budget=limits),
            inventory_digest=require_digest(
                data["inventory_digest"], "maintained inventory digest"
            ),
        )

    def to_dict(self) -> dict[str, object]:
        """Revalidate every root, surface and independent proof relationship.

        Returns
        -------
        dict of str to object
            Exact complete inventory with its checked canonical identity.

        Raises
        ------
        ValueError
            If direct construction or later field mutation breaks the contract.
        """
        body = self._body()
        digest = require_digest(self.inventory_digest, "maintained inventory digest")
        if digest != canonical_digest(body):
            raise ValueError("maintained inventory digest differs")
        return {**body, "inventory_digest": digest}
