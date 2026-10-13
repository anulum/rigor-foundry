# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — registry-derived Tier-0 path scope
"""Derive one path-only scope from exact selected registry generation bytes."""

from __future__ import annotations

import os

from ..models import canonical_digest
from ..project_registry_models import ProjectRegistry
from .path_admission_v2 import PinnedDirectoryV2, PinnedPathScopeV2


def derive_selected_path_scope_v2(
    *,
    registry_bytes: bytes,
    monorepo_root: str,
    selected_project_id: str,
    registry_generation_id: str,
    registry_sha256: str,
) -> PinnedPathScopeV2:
    """Build the exact scope from selected custody, never caller root lists.

    The protected host supplies registry bytes resolved by the selected hash.
    The binder repeats this derivation under the same semantics lease and
    compares the result with the stored scope before invoking any extractor.
    Every project's current canonical root is included, including inactive
    projects; only the selected project must be active. Historical aliases are
    bound by the registry hash but are not current registered roots. A former
    path that is still a repository is checked by the nested-repository rules.

    Parameters
    ----------
    registry_bytes : bytes
        Exact canonical current registry, with or without a deployment profile.
        All path roots come from these bytes; no filesystem lookup occurs.
    monorepo_root : str
        Canonical absolute deployment root other than the filesystem root.
    selected_project_id : str
        Registered active project whose current path becomes the selected root.
    registry_generation_id : str
        Expected selected registry generation.
    registry_sha256 : str
        Expected SHA-256 of the exact selected registry bytes.

    Returns
    -------
    PinnedPathScopeV2
        Lexical roots and canonical scope digest, awaiting descriptor admission
        and protected selection verification by the consumer.

    Raises
    ------
    ValueError
        If registry parsing, deployment-root or project-ID validation fails.
    PermissionError
        If registry bytes are unavailable, selected pins differ, or the
        selected project is absent or inactive.
    """
    if type(registry_bytes) is not bytes:
        raise PermissionError("selected path scope registry body is unavailable")
    registry = ProjectRegistry.from_bytes(registry_bytes)
    if (
        registry.generation_id != registry_generation_id
        or registry.registry_sha256 != registry_sha256
    ):
        raise PermissionError("selected path scope registry generation differs")
    if (
        not isinstance(monorepo_root, str)
        or not monorepo_root.startswith("/")
        or monorepo_root.startswith("//")
        or monorepo_root == "/"
        or os.path.normpath(monorepo_root) != monorepo_root
    ):
        raise ValueError("selected path scope monorepo root is not canonical")
    if not isinstance(selected_project_id, str) or not selected_project_id:
        raise ValueError("selected path scope project id is unavailable")
    selected = [
        item
        for item in registry.projects
        if item.project_id == selected_project_id and item.lifecycle_state == "active"
    ]
    if len(selected) != 1:
        raise PermissionError("selected path scope project is absent or inactive")

    def absolute(relative: str) -> str:
        """Join a registry-validated relative root without filesystem lookup."""
        return f"{monorepo_root}/{relative}"

    groups = [
        {"group_id": item.group_id, "path": absolute(item.root_path)} for item in registry.groups
    ]
    projects = [
        {
            "project_id": item.project_id,
            "group_id": item.owning_group_id,
            "path": absolute(item.canonical_path),
        }
        for item in registry.projects
    ]
    groups.sort(key=lambda item: item["group_id"])
    projects.sort(key=lambda item: item["project_id"])
    selected_path = absolute(selected[0].canonical_path)
    body = {
        "schema": "rigor.selected-path-scope.v2",
        "registry_generation_id": registry_generation_id,
        "registry_sha256": registry_sha256,
        "monorepo_root": monorepo_root,
        "selected_project_id": selected_project_id,
        "selected_root": selected_path,
        "projects": projects,
        "groups": groups,
    }
    return PinnedPathScopeV2(
        monorepo_root=PinnedDirectoryV2(monorepo_root),
        selected_root=PinnedDirectoryV2(selected_path),
        selected_project_root=selected_path,
        registered_projects=tuple(PinnedDirectoryV2(item["path"]) for item in projects),
        registered_groups=tuple(PinnedDirectoryV2(item["path"]) for item in groups),
        registry_generation_id=registry_generation_id,
        registry_sha256=registry_sha256,
        path_scope_digest=canonical_digest(body),
    )
