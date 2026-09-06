# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — model-bound activation publication preparation
"""Connect validated activation models to exact protected filesystem effects.

No I/O, root enrollment, claim acquisition, signature or activation occurs.
The operator must supply and independently verify root identities, parent modes,
missing directories and the selected lock policy. Lexical mappings cannot prove
physical custody. A Core proposal and successful outcome are separate artifacts.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, replace

from .project_memory_activation_content import (
    PreparedProjectMemoryActivationContent,
    prepare_project_memory_activation_content,
)
from .project_memory_models import ProjectMemoryManifest
from .project_memory_primitives import ProjectMemorySource, require_identifier
from .project_memory_sources import verify_project_memory_sources
from .project_registry_cutover import ProjectRegistryCutoverPlan
from .project_registry_models import ProjectRegistry
from .protected_file_publication import (
    PreparedProtectedFilePublication,
    ProtectedDirectoryCreation,
    ProtectedFileLock,
    ProtectedFilePublication,
    prepare_protected_snapshot_publication,
)


@dataclass(frozen=True)
class ActivationRootBinding:
    """Declared Core root ID and lexical deployment-relative directory.

    Dot denotes the deployment root, never whole-root mutation permission.
    Nested roots are allowed; the longest strict ancestor is selected. A target
    equal to a root must resolve through a separately declared ancestor because
    Core does not allow a dot relative path. Actual descriptors remain required.
    """

    root_id: str
    deployment_path: str


@dataclass(frozen=True)
class ActivationPublicationLayout:
    """Explicit task layout; not an enrollment or self-authenticating policy.

    Transaction storage must be outside project memory and disjoint from every
    business target. ``parent_modes`` must cover exactly the used immediate
    parents. ``new_directories`` declares every intended mkdir in order; an
    omitted directory is assumed existing, never automatically discovered.
    Nonempty ``lock_paths`` fixes acquisition order; ``lock_contents`` is exact
    prior bytes or None for an absent lock. These observations need independent
    freshness/custody checks before Core admission and execution.
    """

    roots: tuple[ActivationRootBinding, ...]
    registry_path: str
    transaction_path: str
    parent_modes: Mapping[str, str]
    new_directories: tuple[str, ...]
    lock_paths: tuple[str, ...]
    lock_contents: Mapping[str, bytes | None]


@dataclass(frozen=True)
class PreparedProjectMemoryActivationPublication:
    """Model-bound content and operations, not a complete signed Core proposal."""

    target_project: str
    content: PreparedProjectMemoryActivationContent
    publication: PreparedProtectedFilePublication
    destinations: tuple[tuple[str, str, str], ...]
    sources: tuple[tuple[ProjectMemorySource, bytes], ...]


def prepare_project_memory_activation_publication(
    previous_registry: bytes,
    previous_outputs: Mapping[str, bytes],
    cutover: ProjectRegistryCutoverPlan,
    memory: ProjectMemoryManifest,
    *,
    bootstrap_manifest: bytes,
    bootstrap_index: bytes,
    record_contents: Mapping[str, bytes],
    source_contents: Mapping[tuple[str, str, str], bytes],
    max_source_bytes: int,
    layout: ActivationPublicationLayout,
    claim_task_id: str,
    content_domain: str,
    max_operations: int,
    max_content_bytes: int,
    schema_version: str = "project-memory-activation-plan-binding.v1",
) -> PreparedProjectMemoryActivationPublication:
    """Derive and prepare exact activation destinations from canonical models.

    Requires every source's exact immutable captured bytes under its own explicit
    ``max_source_bytes`` budget; identity is verified, not authentic capture,
    source freshness, semantic support or sensitivity. Reuses content/plan validation, original-byte snapshots, directory
    creation and file-lock/publication compilation. Transaction snapshots have
    deterministic prior/NNNN-role.raw names; replacement temporaries have exact
    adjacent .activation-<plan-binding>-NNNN.tmp names chosen before admission.
    Every business replacement is preserved before any business write, and the
    registry remains the last business publication. No journal state claiming
    success, receipt, implicit rollback or cleanup is synthesized.

    All supplied paths are deployment-relative. Root IDs are separately enrolled
    Core identifiers. Budgets bound layout entry counts, content and combined
    executable/primary operation counts. Invalid models, layout, unmapped paths,
    parent coverage, aliases or bytes raise ValueError. No live checks are implied.
    """
    if type(max_operations) is not int or not 0 < max_operations <= 2**53 - 1:
        raise ValueError("activation operation budget must be a positive exact integer")
    if type(layout) is not ActivationPublicationLayout:
        raise ValueError("activation requires an exact publication layout")
    for entries in (layout.roots, layout.new_directories, layout.lock_paths):
        if type(entries) is not tuple or len(entries) > max_operations:
            raise ValueError("activation layout tuple exceeds its entry budget")
    if not layout.roots or not layout.lock_paths:
        raise ValueError("activation requires explicit roots and lock policy")
    if len(layout.parent_modes) > max_operations or len(layout.lock_contents) > max_operations:
        raise ValueError("activation layout mapping exceeds its entry budget")
    modes, lock_contents = dict(layout.parent_modes), dict(layout.lock_contents)
    roots = layout.roots
    for root in roots:
        if type(root) is not ActivationRootBinding:
            raise ValueError("activation requires exact root bindings")
        require_identifier(root.root_id, "root_id")
        if root.deployment_path != ".":
            _path(root.deployment_path)
    if len({r.root_id for r in roots}) != len(roots) or len(
        {r.deployment_path for r in roots}
    ) != len(roots):
        raise ValueError("activation root IDs and locations must be unique")
    registry_path, transaction_path = _path(layout.registry_path), _path(layout.transaction_path)
    locks = tuple(_path(path) for path in layout.lock_paths)
    directories = tuple(_path(path) for path in layout.new_directories)
    if len(set(locks)) != len(locks) or set(lock_contents) != set(locks):
        raise ValueError("activation requires exact unique lock observations")

    candidate = ProjectRegistry.from_bytes(cutover.candidate.to_bytes())
    memory = ProjectMemoryManifest.from_bytes(memory.to_bytes())
    sources = verify_project_memory_sources(
        memory, source_contents, max_source_bytes=max_source_bytes
    )
    content = prepare_project_memory_activation_content(
        previous_registry,
        previous_outputs,
        replace(cutover, candidate=candidate),
        memory,
        bootstrap_manifest=bootstrap_manifest,
        bootstrap_index=bootstrap_index,
        record_contents=record_contents,
        max_content_bytes=max_content_bytes,
        schema_version=schema_version,
    )
    selected = next(p for p in candidate.projects if p.project_id == memory.project_id)
    memory_root = selected.canonical_path + "/agentic_project_memory"
    if _overlaps(transaction_path, memory_root):
        raise ValueError("activation transaction storage overlaps project memory")
    consumers = {c.consumer_id: c.path for c in candidate.consumers}
    destinations: list[tuple[str, str, str]] = []
    used_parents: set[str] = set()

    def location(path: str) -> tuple[str, str, str, str, str]:
        """Bind one destination and its explicit immediate-parent observation."""
        _path(path)
        parent = path.rpartition("/")[0]
        if parent not in modes:
            raise ValueError("activation lacks an exact parent mode")
        used_parents.add(parent)
        root_id, relative = _resolve(path, roots)
        parent_root, parent_relative = _resolve(parent, roots)
        return root_id, relative, parent_root, parent_relative, modes[parent]

    files: list[ProtectedFilePublication] = []
    snapshots: dict[tuple[str, str], ProtectedFilePublication] = {}
    for index, item in enumerate(content.objects):
        if item.role == "registry":
            path = registry_path
        elif item.role == "consumer":
            path = consumers[item.identity]
        else:
            path = memory_root + "/" + item.identity
        if _overlaps(path, transaction_path):
            raise ValueError("activation transaction storage overlaps a business target")
        bound = location(path)
        temporary = None
        if item.previous is not None:
            temp_path = (
                path.rpartition("/")[0]
                + f"/.activation-{content.plan_binding_sha256}-{index:04d}.tmp"
            )
            # Same-directory names have the same strict lexical root ancestor.
            _, temporary = _resolve(_path(temp_path), roots)
            snapshot_path = transaction_path + f"/prior/{index:04d}-{item.role}.raw"
            snapshots[(bound[0], bound[1])] = ProtectedFilePublication(
                *location(snapshot_path), None, item.previous
            )
        files.append(ProtectedFilePublication(*bound, item.previous, item.candidate, temporary))
        destinations.append((item.role, item.identity, path))
    planned_locks = tuple(
        ProtectedFileLock(*location(path), lock_contents[path]) for path in locks
    )
    planned_directories = tuple(
        ProtectedDirectoryCreation(*location(path)) for path in directories
    )
    if set(modes) != used_parents:
        raise ValueError("activation parent modes include unrelated paths")
    publication = prepare_protected_snapshot_publication(
        tuple(files),
        snapshots=snapshots,
        claim_task_id=claim_task_id,
        content_domain=content_domain,
        max_operations=max_operations,
        max_content_bytes=max_content_bytes,
        directories=planned_directories,
        locks=planned_locks,
    )
    return PreparedProjectMemoryActivationPublication(
        memory.project_id, content, publication, tuple(destinations), sources
    )


def _path(value: str) -> str:
    """Reject nonportable deployment paths before lexical root resolution."""
    if (
        not isinstance(value, str)
        or len(value) > 4096
        or any(
            part in {"", ".", "..", ".git"} or re.fullmatch(r"[A-Za-z0-9_.-]+", part) is None
            for part in value.split("/")
        )
    ):
        raise ValueError("activation path must be portable and deployment-relative")
    return value


def _resolve(path: str, roots: tuple[ActivationRootBinding, ...]) -> tuple[str, str]:
    """Choose the longest strict declared ancestor without probing the filesystem."""
    candidates = [
        (r.deployment_path, r.root_id)
        for r in roots
        if r.deployment_path == "." or path.startswith(r.deployment_path + "/")
    ]
    if not candidates or not path:
        raise ValueError("activation path lacks an exact enrolled ancestor")
    base, identity = max(candidates, key=lambda pair: 0 if pair[0] == "." else len(pair[0]))
    return identity, path if base == "." else path[len(base) + 1 :]


def _overlaps(left: str, right: str) -> bool:
    """Detect equal or nested lexical paths at directory-component boundaries."""
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")
