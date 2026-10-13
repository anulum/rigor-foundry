# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — selected clause-scope registry expansion
"""Resolve v2 scope templates from one pinned current project registry."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from .clause_semantics_scope_v2 import (
    bind_clause_scope_groups_v2,
    validate_clause_scope_v2,
)
from .git_inventory import open_directory_no_follow
from .project_registry_models import ProjectRegistration, ProjectRegistry, ProjectRegistryGroup


@dataclass(frozen=True)
class ExpandedClauseScopeV2:
    """Canonical selectors tied to one verified registry generation.

    Attributes
    ----------
    targets : tuple[str, ...]
        Expanded, deduplicated selectors in UTF-8 byte order.
    exclusions : tuple[str, ...]
        Expanded, deduplicated exclusions in UTF-8 byte order.
    registry_generation_id : str
        Current registry generation from the verified selected body.
    registry_sha256 : str
        Exact digest binding membership and lifecycle states.

    Notes
    -----
    Expansion produces selector data, not an applicable action decision.
    """

    targets: tuple[str, ...]
    exclusions: tuple[str, ...]
    registry_generation_id: str
    registry_sha256: str


def _path(root: Path, relative: str) -> str:
    """Join one registry-validated relative path under a verified root."""
    return f"path:{root / relative}"


def _expand_one(
    selector: str,
    *,
    root: Path,
    project: ProjectRegistration,
    group: ProjectRegistryGroup,
    registry: ProjectRegistry,
) -> tuple[str, ...]:
    """Resolve only the closed v2 template forms; preserve literal selectors."""
    form, separator, value = selector.partition(":")
    if selector == "monorepo-read-root":
        return (f"path:{root}",)
    if not separator or form not in {
        "project-root",
        "project-coordination",
        "group-workspace",
        "group-projects",
        "group-project-records",
        "group-memory",
        "group-exchange-state",
        "group-exchange-inbox",
    }:
        return (selector,)
    if form == "project-root":
        return (_path(root, project.canonical_path),)
    if form == "project-coordination":
        return tuple(
            _path(root, f".coordination/{area}/{project.project_id}")
            for area in ("handovers", "sessions")
        )
    if form == "group-workspace":
        tail = f"/{project.project_id}" if "/" in value else ""
        return (_path(root, f"{group.root_path}/agentic_group_workspace{tail}"),)
    if form in {"group-projects", "group-project-records"}:
        members = tuple(
            item for item in registry.projects if item.owning_group_id == group.group_id
        )
        if form == "group-projects":
            return tuple(_path(root, item.canonical_path) for item in members)
        return tuple(
            _path(root, f".coordination/{area}/{item.project_id}")
            for item in members
            for area in ("handovers", "sessions")
        )
    if form == "group-memory":
        return (_path(root, f"{group.root_path}/agentic_group_memory"),)
    if form == "group-exchange-state":
        return tuple(
            _path(root, f"{group.root_path}/agentic_group_exchange/{area}")
            for area in ("triage", "quarantine", "archive")
        )
    foreign = next(
        item
        for item in registry.groups
        if item.group_id == value and item.lifecycle_state == "active"
    )
    return (_path(root, f"{foreign.root_path}/agentic_group_exchange/inbox"),)


def _wholly_excluded(target: str, exclusion: str) -> bool:
    """Apply single-exclusion containment to one concrete selector."""
    target_form, _, target_value = target.partition(":")
    exclusion_form, _, exclusion_value = exclusion.partition(":")
    if target_form in {"path", "repo"} and exclusion_form in {"path", "repo"}:
        target_parts = PurePosixPath(target_value).parts
        exclusion_parts = PurePosixPath(exclusion_value).parts
        return target_parts[: len(exclusion_parts)] == exclusion_parts
    return (
        target_form in {"remote", "endpoint", "host"}
        and target_form == exclusion_form
        and target_value == exclusion_value
    )


def expand_clause_scope_v2(
    *,
    scope: Mapping[str, object],
    subject: str,
    effect_class: str,
    project_id: str,
    registry: ProjectRegistry,
    expected_registry_sha256: str,
    monorepo_root: Path,
    resolver_version: str,
) -> ExpandedClauseScopeV2:
    """Resolve every selector from the protected current v1 registry.

    This produces canonical selector strings, not a permission decision. A
    protected no-follow canonicaliser and matcher must evaluate them against
    the adapter-extracted action, including exclusions and empty-set rules.

    Parameters
    ----------
    scope : Mapping[str, object]
        Closed v2 target and exclusion selector object.
    subject : str
        Clause subject controlling validation and empty-target refusals.
    effect_class : str
        Effect class controlling allowed selector forms.
    project_id : str
        Active selected project in the pinned registry.
    registry : ProjectRegistry
        Canonical unprofiled registry. Profiled layouts are refused because
        this interim resolver does not implement their parent-layer contract.
    expected_registry_sha256 : str
        Protected precondition for the exact registry bytes.
    monorepo_root : Path
        Canonical absolute root opened without following directory links.
    resolver_version : str
        Must be registry-v1-interim; other resolver identifiers refuse.

    Returns
    -------
    ExpandedClauseScopeV2
        Concrete selectors bound to the selected registry generation.

    Raises
    ------
    ValueError
        If registry or selector validation fails.
    PermissionError
        For an unsupported resolver or profiled layout, mismatched registry,
        inactive project or group, invalid root, forbidden group reference,
        or a veto or constraint target fully removed by exclusions.
    OSError
        If no-follow opening of the actual deployment root fails.
    """
    if resolver_version != "registry-v1-interim":
        raise PermissionError("selected clause scope resolver is unavailable")
    if (
        ProjectRegistry.from_bytes(registry.to_bytes()) != registry
        or registry.registry_sha256 != expected_registry_sha256
    ):
        raise PermissionError("clause scope registry generation differs")
    if registry.profile is not None:
        raise PermissionError("interim clause scope resolver requires an unprofiled registry")
    if not monorepo_root.is_absolute() or ".." in monorepo_root.parts:
        raise PermissionError("clause scope monorepo root is not canonical")
    descriptor = open_directory_no_follow(monorepo_root)
    os.close(descriptor)
    projects = tuple(
        item
        for item in registry.projects
        if item.project_id == project_id and item.lifecycle_state == "active"
    )
    if len(projects) != 1:
        raise PermissionError("clause scope project is not active in selected registry")
    project = projects[0]
    groups = tuple(
        item
        for item in registry.groups
        if item.group_id == project.owning_group_id and item.lifecycle_state == "active"
    )
    if len(groups) != 1:
        raise PermissionError("clause scope owning group is not active")
    group = groups[0]
    validate_clause_scope_v2(
        scope, subject=subject, effect_class=effect_class, project_id=project_id
    )
    bind_clause_scope_groups_v2(
        scope,
        owning_group_id=group.group_id,
        registered_group_ids=frozenset(
            item.group_id for item in registry.groups if item.lifecycle_state == "active"
        ),
    )
    exclusion_values = cast(list[str], scope["exclusions"])
    exclusions = tuple(
        sorted(
            {
                resolved
                for value in exclusion_values
                for resolved in _expand_one(
                    value, root=monorepo_root, project=project, group=group, registry=registry
                )
            },
            key=lambda item: item.encode("utf-8"),
        )
    )
    targets: set[str] = set()
    for value in cast(list[str], scope["targets"]):
        element = _expand_one(
            value, root=monorepo_root, project=project, group=group, registry=registry
        )
        if subject != "admit" and (
            not element
            or all(
                any(_wholly_excluded(target, exclusion) for exclusion in exclusions)
                for target in element
            )
        ):
            raise PermissionError("veto or constraint target element expands to empty")
        targets.update(element)
    return ExpandedClauseScopeV2(
        tuple(sorted(targets, key=lambda item: item.encode("utf-8"))),
        exclusions,
        registry.generation_id,
        registry.registry_sha256,
    )
