# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete retained inventory baseline preimages
"""Retain explicit Git and directory history without claiming its issuer authority."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise
from pathlib import PurePosixPath
from typing import ClassVar

from .audit_primitives import canonical_digest, require_exact_fields, require_mapping
from .inventory_domain import InventoryDomainRoot
from .model_primitives import require_digest, require_git_object, require_identifier
from .policy_read_budget import PolicyReadBudget1
from .repository_inventory_rows import (
    RepositoryFileRow,
    parse_repository_file_rows,
    require_inventory_path,
)
from .typed_object_reference import TypedObjectRef1

INVENTORY_BASELINE_SCHEMA_VERSION = "1.0"
_ROOT_FIELDS = frozenset({"root", "git_head", "files", "directories"})
_FIELDS = frozenset(
    {
        "schema_version",
        "object_kind",
        "baseline_id",
        "project_id",
        "domain_reference",
        "registry_reference",
        "roots",
        "baseline_digest",
    }
)


@dataclass(frozen=True)
class InventoryBaselineRoot:
    """Complete inline before-state for one explicitly declared root.

    Git rows retain their original blob or gitlink identities. Directory rows
    retain earlier observed bytes and empty-directory topology, without invented
    Git objects or generator provenance. Unknown classifications remain null.

    Attributes
    ----------
    root : InventoryDomainRoot
        Exact root identity, canonical relative path and original capture kind.
    git_head : str or None
        Full original commit for Git roots; absent for directory observations.
    files : tuple of RepositoryFileRow
        Sorted complete before-images, preserving nullable classifications.
    directories : tuple of str
        All sorted directory paths for a directory capture, including empty ones.
    """

    root: InventoryDomainRoot
    git_head: str | None
    files: tuple[RepositoryFileRow, ...]
    directories: tuple[str, ...]

    def __post_init__(self) -> None:
        """Reject contradictory kinds, omitted parents and ambiguous topology."""
        self.to_dict()

    def to_dict(self) -> dict[str, object]:
        """Revalidate every before-image and preserve its original byte identity.

        Returns
        -------
        dict of str to object
            Exact inline root, commit, file rows and directory topology.

        Raises
        ------
        ValueError
            If direct fields contradict their capture kind or topology.
        """
        if (
            type(self.root) is not InventoryDomainRoot
            or type(self.files) is not tuple
            or type(self.directories) is not tuple
            or len(self.files) + len(self.directories) > 65536
            or any(type(row) is not RepositoryFileRow for row in self.files)
        ):
            raise ValueError("baseline root requires bounded actual immutable preimages")
        root = self.root.to_dict()
        files = [row.to_dict() for row in self.files]
        paths = tuple(row.relative_path for row in self.files)
        directories = tuple(require_inventory_path(path) for path in self.directories)
        if paths != tuple(sorted(set(paths))) or directories != tuple(sorted(set(directories))):
            raise ValueError("baseline file and directory paths must be sorted and unique")
        file_set, directory_set = set(paths), set(directories)
        ordered = sorted(file_set | directory_set, key=lambda path: PurePosixPath(path).parts)
        if file_set & directory_set or any(
            before in file_set and after.startswith(before + "/")
            for before, after in pairwise(ordered)
        ):
            raise ValueError("baseline file and directory topology conflicts")
        if self.root.source_kind == "git":
            head = require_git_object(self.git_head, "baseline Git commit")
            if directories or any(
                row.kind not in {"regular", "symlink", "gitlink"}
                or row.object_id is None
                or len(row.object_id) != len(head)
                for row in self.files
            ):
                raise ValueError("Git baseline requires complete original Git file identities")
        else:
            head = None
            if self.git_head is not None or any(
                row.kind not in {"regular", "symlink", "unsupported"}
                or row.object_id is not None
                or (
                    row.kind == "unsupported"
                    and (row.mode is not None or row.byte_digest is not None)
                )
                for row in self.files
            ):
                raise ValueError("directory baseline cannot invent Git or missing-file history")
            if any(
                parent != "." and parent not in directory_set
                for parent in (
                    PurePosixPath(path).parent.as_posix() for path in (*paths, *directories)
                )
            ):
                raise ValueError("directory baseline omits an observed parent directory")
        return {"root": root, "git_head": head, "files": files, "directories": list(directories)}

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> InventoryBaselineRoot:
        """Bound both preimage arrays before parsing their exact closed fields.

        Parameters
        ----------
        value : object
            Decoded mapping containing every and only inline root field.
        budget : PolicyReadBudget1
            Explicit root/file/directory reference allocation ceilings.

        Returns
        -------
        InventoryBaselineRoot
            Revalidated complete before-images without inferred history.

        Raises
        ------
        ValueError
            If fields, collection bounds, object identities or topology disagree.
        """
        if type(budget) is not PolicyReadBudget1:
            raise ValueError("policy read budget is required")
        limits = PolicyReadBudget1.from_dict(budget.to_dict())
        data = require_mapping(value, "inventory baseline root")
        require_exact_fields(data, _ROOT_FIELDS, "inventory baseline root")
        files, directories = data["files"], data["directories"]
        if (
            not isinstance(files, list)
            or not isinstance(directories, list)
            or len(files) + len(directories) > limits.max_references
        ):
            raise ValueError("baseline preimage arrays exceed the reference budget")
        return cls(
            InventoryDomainRoot.from_dict(data["root"]),
            None
            if data["git_head"] is None
            else require_git_object(data["git_head"], "baseline Git commit"),
            parse_repository_file_rows(files, budget=limits),
            tuple(require_inventory_path(path) for path in directories),
        )


@dataclass(frozen=True)
class InventoryBaseline1:
    """Closed complete before-images bound to selected domain and registry sources.

    A valid digest proves data integrity, not source ownership, historical
    authenticity, required-root completeness or generated-source reproducibility.
    Actual consumers must retain and verify the independently selected source.

    Attributes
    ----------
    baseline_id : str
        Explicit identity of this earlier-source record.
    project_id : str
        Declared project, compared with actual registry ownership by consumers.
    domain_reference, registry_reference : TypedObjectRef1
        Exact original source identities, not filesystem locators.
    roots : tuple of InventoryBaselineRoot
        Every declared root and its complete original before-images.
    baseline_digest : str
        Canonical SHA-256 of all other fields, including schema and kind.
    """

    baseline_id: str
    project_id: str
    domain_reference: TypedObjectRef1
    registry_reference: TypedObjectRef1
    roots: tuple[InventoryBaselineRoot, ...]
    baseline_digest: str

    schema_version: ClassVar[str] = INVENTORY_BASELINE_SCHEMA_VERSION
    object_kind: ClassVar[str] = "inventory-baseline"

    def __post_init__(self) -> None:
        """Reject malformed direct records and mismatched complete baseline identities."""
        self.to_dict()

    def _body(self) -> dict[str, object]:
        if (
            type(self.roots) is not tuple
            or not self.roots
            or len(self.roots) > 4096
            or any(type(item) is not InventoryBaselineRoot for item in self.roots)
            or sum(1 + len(item.files) + len(item.directories) for item in self.roots) > 65536
        ):
            raise ValueError("inventory baseline requires bounded complete immutable roots")
        if (
            type(self.domain_reference) is not TypedObjectRef1
            or type(self.registry_reference) is not TypedObjectRef1
            or self.domain_reference.kind != "inventory-domain"
            or self.registry_reference.kind != "project-registry"
        ):
            raise ValueError("baseline requires actual domain and registry references")
        roots = [item.to_dict() for item in self.roots]
        ids = tuple(item.root.root_id for item in self.roots)
        paths = tuple(item.root.canonical_path for item in self.roots)
        if ids != tuple(sorted(set(ids))) or len(set(paths)) != len(paths):
            raise ValueError("baseline roots must be sorted, unique and path-distinct")
        return {
            "schema_version": INVENTORY_BASELINE_SCHEMA_VERSION,
            "object_kind": "inventory-baseline",
            "baseline_id": require_identifier(self.baseline_id, "inventory baseline identity"),
            "project_id": require_identifier(self.project_id, "inventory baseline project"),
            "domain_reference": self.domain_reference.to_dict(),
            "registry_reference": self.registry_reference.to_dict(),
            "roots": roots,
        }

    @classmethod
    def build(
        cls,
        *,
        baseline_id: str,
        project_id: str,
        domain_reference: TypedObjectRef1,
        registry_reference: TypedObjectRef1,
        roots: tuple[InventoryBaselineRoot, ...],
        budget: PolicyReadBudget1,
    ) -> InventoryBaseline1:
        """Bind complete explicit before-images through the same bounded parser.

        Parameters
        ----------
        baseline_id, project_id : str
            Explicit record and project identities.
        domain_reference, registry_reference : TypedObjectRef1
            Independently selected original domain and registry identities.
        roots : tuple of InventoryBaselineRoot
            Complete sorted root set with original Git/directory before-images.
        budget : PolicyReadBudget1
            Explicit source and aggregate preimage-reference ceilings.

        Returns
        -------
        InventoryBaseline1
            Closed data record with its independently derived complete digest.

        Raises
        ------
        ValueError
            If identities, fields, topology or collection limits are invalid.
        """
        if type(budget) is not PolicyReadBudget1:
            raise ValueError("policy read budget is required")
        limits = PolicyReadBudget1.from_dict(budget.to_dict())
        if (
            type(roots) is not tuple
            or len(roots) > limits.max_sources
            or any(type(item) is not InventoryBaselineRoot for item in roots)
            or sum(1 + len(item.files) + len(item.directories) for item in roots)
            > limits.max_references
        ):
            raise ValueError("baseline roots exceed the explicit source/reference budgets")
        if (
            type(domain_reference) is not TypedObjectRef1
            or type(registry_reference) is not TypedObjectRef1
        ):
            raise ValueError("baseline requires actual domain and registry references")
        body: dict[str, object] = {
            "schema_version": INVENTORY_BASELINE_SCHEMA_VERSION,
            "object_kind": "inventory-baseline",
            "baseline_id": baseline_id,
            "project_id": project_id,
            "domain_reference": domain_reference.to_dict(),
            "registry_reference": registry_reference.to_dict(),
            "roots": [item.to_dict() for item in roots],
        }
        return cls.from_dict({**body, "baseline_digest": canonical_digest(body)}, budget=limits)

    @classmethod
    def from_dict(cls, value: object, *, budget: PolicyReadBudget1) -> InventoryBaseline1:
        """Reject unknown fields/versions and aggregate over-budget preimages.

        Parameters
        ----------
        value : object
            Decoded complete versioned baseline mapping.
        budget : PolicyReadBudget1
            Explicit root and combined root/file/directory reference limits.

        Returns
        -------
        InventoryBaseline1
            Original before-images with validated header and canonical identity.

        Raises
        ------
        ValueError
            If structure, version, budgets, references or digest disagree.
        """
        if type(budget) is not PolicyReadBudget1:
            raise ValueError("policy read budget is required")
        limits = PolicyReadBudget1.from_dict(budget.to_dict())
        data = require_mapping(value, "inventory baseline")
        require_exact_fields(data, _FIELDS, "inventory baseline")
        if (
            data["schema_version"] != INVENTORY_BASELINE_SCHEMA_VERSION
            or data["object_kind"] != "inventory-baseline"
        ):
            raise ValueError("unsupported inventory baseline")
        roots = data["roots"]
        if not isinstance(roots, list) or not roots or len(roots) > limits.max_sources:
            raise ValueError("baseline roots exceed the source budget or have invalid type")
        count = len(roots)
        for value in roots:
            row = require_mapping(value, "inventory baseline root")
            for name in ("files", "directories"):
                items = row.get(name)
                if not isinstance(items, list):
                    raise ValueError("baseline preimages must be arrays")
                count += len(items)
                if count > limits.max_references:
                    raise ValueError("baseline preimages exceed the aggregate reference budget")
        return cls(
            require_identifier(data["baseline_id"], "inventory baseline identity"),
            require_identifier(data["project_id"], "inventory baseline project"),
            TypedObjectRef1.from_dict(data["domain_reference"]),
            TypedObjectRef1.from_dict(data["registry_reference"]),
            tuple(InventoryBaselineRoot.from_dict(value, budget=limits) for value in roots),
            require_digest(data["baseline_digest"], "inventory baseline digest"),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialize every baseline preimage after validating its complete digest.

        Returns
        -------
        dict of str to object
            Complete closed mapping without inferred fields or discarded roots.

        Raises
        ------
        ValueError
            If direct construction or a later field mutation breaks the contract.
        """
        body = self._body()
        digest = require_digest(self.baseline_digest, "inventory baseline digest")
        if digest != canonical_digest(body):
            raise ValueError("inventory baseline digest differs")
        return {**body, "baseline_digest": digest}

    def reference(self) -> dict[str, object]:
        """Return the inert supported identity without selecting a historical source.

        Returns
        -------
        dict of str to object
            Typed baseline reference with its independent reference digest.

        Raises
        ------
        ValueError
            If the complete baseline fails revalidation.
        """
        self.to_dict()
        return TypedObjectRef1.build(
            kind="inventory-baseline",
            format_version=INVENTORY_BASELINE_SCHEMA_VERSION,
            object_id=self.baseline_id,
            object_digest=self.baseline_digest,
        ).to_dict()
