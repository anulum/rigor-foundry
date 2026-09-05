# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — group workspace allocation
"""Allocate private scratch/temp for an already-authorised local operator."""

from __future__ import annotations

import os
import re
import stat
from contextlib import ExitStack
from pathlib import Path

from .git_inventory import open_directory_no_follow
from .project_registry_cutover import load_project_registry_state


def allocate_group_workspace(
    monorepo_root: Path,
    registry_path: str,
    *,
    project_id: str,
    session_id: str,
    expected_registry_sha256: str,
) -> Path:
    """Create a new private session allocation without reusing existing content.

    Parameters
    ----------
    monorepo_root:
        Absolute canonical root with no symlink components.
    registry_path:
        Monorepo-relative registry with complete consumer closure.
    project_id:
        Exact active or architecture-only project in an active owning group.
    session_id:
        Single ASCII component of 1–128 letters, digits, hyphens or underscores,
        starting with a letter or digit. Caller records the actual seat binding.
    expected_registry_sha256:
        Exact registry digest pinned by the operator.

    Returns
    -------
    pathlib.Path
        New session directory containing private scratch and tmp directories.

    Raises
    ------
    ValueError, RuntimeError, OSError
        Invalid identity, stale registry, unsafe path or allocation failure.

    Notes
    -----
    Invocation requires separate work authority and coordination recording.
    Membership is not permission. This API neither authenticates Synapse grants
    nor fences same-UID writers. Failure preserves partial allocations for
    inspection; never retry by deleting or reusing them.
    """
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", session_id) is None:
        raise ValueError("invalid workspace session identifier")
    if re.fullmatch(r"[0-9a-f]{64}", expected_registry_sha256) is None:
        raise ValueError("invalid registry digest")
    registry = load_project_registry_state(monorepo_root, registry_path)
    if registry.registry_sha256 != expected_registry_sha256:
        raise ValueError("workspace registry is stale")
    projects = [
        project
        for project in registry.projects
        if project.project_id == project_id
        and project.lifecycle_state in {"active", "architecture-only"}
    ]
    if len(projects) != 1:
        raise ValueError("workspace project is not eligible")
    groups = [
        group
        for group in registry.groups
        if group.group_id == projects[0].owning_group_id and group.lifecycle_state == "active"
    ]
    if len(groups) != 1:
        raise ValueError("workspace owning group is not active")
    container = monorepo_root / groups[0].root_path / "agentic_group_workspace"
    destination = container / project_id / session_id
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as stack:
        container_fd = open_directory_no_follow(container)
        stack.callback(os.close, container_fd)
        descriptors = [container_fd]
        parent_fd = container_fd
        for name, shared in ((project_id, True), (session_id, False)):
            metadata = os.fstat(parent_fd)
            if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
                raise ValueError("workspace parent is not private")
            try:
                os.mkdir(name, mode=0o700, dir_fd=parent_fd)
            except FileExistsError:
                if not shared:
                    raise
            parent_fd = os.open(name, flags, dir_fd=parent_fd)
            stack.callback(os.close, parent_fd)
            descriptors.append(parent_fd)
        for name in ("scratch", "tmp"):
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
            child_fd = os.open(name, flags, dir_fd=parent_fd)
            stack.callback(os.close, child_fd)
            descriptors.append(child_fd)
        current_fd = open_directory_no_follow(destination)
        stack.callback(os.close, current_fd)
        expected = os.fstat(parent_fd)
        observed = os.fstat(current_fd)
        if (expected.st_dev, expected.st_ino) != (observed.st_dev, observed.st_ino):
            raise RuntimeError("workspace path changed during allocation")
        for descriptor in descriptors:
            metadata = os.fstat(descriptor)
            if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
                raise ValueError("workspace allocation is not private")
        if load_project_registry_state(monorepo_root, registry_path) != registry:
            raise RuntimeError("workspace registry changed during allocation")
    return destination
