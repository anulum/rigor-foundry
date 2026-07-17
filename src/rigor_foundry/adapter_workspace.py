# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — tracked-only adapter workspace
"""Materialise exact Git-tracked adapter inputs without ignored or untracked data."""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .audit_primitives import canonical_digest
from .git_inventory import (
    GitInventory,
    TrackedFile,
    load_git_inventory,
    open_directory_no_follow,
    read_stable_regular_file_at,
)
from .git_provenance import GitTrustPolicy

MAX_PROFILE_FILE_BYTES = 32 * 1024 * 1024
MAX_PROFILE_INPUT_BYTES = 256 * 1024 * 1024


def _relative_path(value: str, field: str) -> str:
    """Return one canonical non-empty repository-relative POSIX path."""
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{field} must be repository-relative")
    canonical = path.as_posix()
    if canonical != value or canonical.startswith("./"):
        raise ValueError(f"{field} must use canonical POSIX spelling")
    return canonical


def validate_profile_paths(
    configuration_path: str,
    target_paths: tuple[str, ...],
) -> tuple[str, tuple[str, ...]]:
    """Validate and canonicalise one profile configuration and target set."""
    configuration = _relative_path(configuration_path, "configuration_path")
    if not target_paths:
        raise ValueError("target_paths must not be empty")
    targets = tuple(_relative_path(path, "target_paths") for path in target_paths)
    if len(targets) != len(set(targets)):
        raise ValueError("target_paths must be unique")
    return configuration, tuple(sorted(targets))


def _contains(target: str, path: str) -> bool:
    """Return whether one repository path belongs to a target component tree."""
    if target == ".":
        return True
    target_parts = PurePosixPath(target).parts
    path_parts = PurePosixPath(path).parts
    return path_parts[: len(target_parts)] == target_parts


def _open_parent(root: Path, relative: str) -> tuple[int, str]:
    """Open one file parent through component-wise no-follow descriptors."""
    parts = PurePosixPath(relative).parts
    descriptor = open_directory_no_follow(root)
    try:
        for component in parts[:-1]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY
                | os.O_DIRECTORY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, parts[-1]


def _read_exact(inventory: GitInventory, tracked: TrackedFile) -> bytes:
    """Read one regular tracked file and verify it against inventory identity."""
    if tracked.git_mode not in {"100644", "100755"}:
        raise RuntimeError(f"profile input is not a regular tracked file: {tracked.path}")
    if tracked.byte_size > MAX_PROFILE_FILE_BYTES:
        raise RuntimeError(f"profile input exceeds the per-file bound: {tracked.path}")
    descriptor, name = _open_parent(inventory.root, tracked.path)
    try:
        observed = read_stable_regular_file_at(
            descriptor,
            name,
            tracked.path,
            object_format=inventory.object_format,
            buffer_limit=MAX_PROFILE_FILE_BYTES,
            require_single_link=True,
        )
    finally:
        os.close(descriptor)
    if observed.payload is None:
        raise RuntimeError(f"profile input exceeded its declared buffer: {tracked.path}")
    if (
        observed.byte_size != tracked.byte_size
        or observed.content_digest != tracked.content_digest
        or observed.git_blob_id != tracked.scanned_blob_id
    ):
        raise RuntimeError(f"profile input changed after inventory: {tracked.path}")
    return observed.payload


@dataclass(frozen=True)
class AdapterWorkspace:
    """One disposable, bounded, tracked-only repository snapshot."""

    root: Path
    configuration_path: str
    target_paths: tuple[str, ...]
    configuration_digest: str
    input_digest: str
    input_bytes: int
    input_files: int

    def close(self) -> None:
        """Remove this disposable workspace and all copied tracked bytes."""
        shutil.rmtree(self.root)

    def __enter__(self) -> AdapterWorkspace:
        """Return this live workspace."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object,
    ) -> None:
        """Remove the workspace after every execution outcome."""
        del exc_type, exc_value, traceback
        self.close()


def create_adapter_workspace(
    repository: Path,
    *,
    configuration_path: str,
    target_paths: tuple[str, ...],
    git_trust_policy: GitTrustPolicy | None = None,
    expected_tracked_content_digest: str | None = None,
) -> AdapterWorkspace:
    """Create a stable tracked-only snapshot for one built-in adapter.

    The source worktree must be clean. Every copied file is reopened through a
    no-follow parent descriptor, requires a single link, and must reproduce the
    inventory SHA-256 and Git blob identity. Ignored and untracked paths cannot
    enter the snapshot because selection starts from the Git index inventory.
    """
    configuration, targets = validate_profile_paths(configuration_path, target_paths)
    inventory = load_git_inventory(repository, git_trust_policy=git_trust_policy)
    if inventory.dirty_paths:
        raise RuntimeError("built-in adapter profiles require a clean tracked worktree")
    if (
        expected_tracked_content_digest is not None
        and inventory.tracked_content_digest != expected_tracked_content_digest
    ):
        raise RuntimeError("profile inventory does not match the audited tracked input")
    selected = tuple(
        item
        for item in inventory.files
        if item.path == configuration or any(_contains(target, item.path) for target in targets)
    )
    by_path = {item.path: item for item in selected}
    if configuration not in by_path:
        raise RuntimeError("profile configuration must be a tracked regular file")
    for target in targets:
        if not any(_contains(target, item.path) for item in selected):
            raise RuntimeError(f"profile target contains no tracked files: {target}")
    total_bytes = sum(item.byte_size for item in selected)
    if total_bytes > MAX_PROFILE_INPUT_BYTES:
        raise RuntimeError("profile input exceeds the aggregate byte bound")
    temporary = Path(tempfile.mkdtemp(prefix=".rigor-profile-", dir=inventory.root.parent))
    # The sandbox UID must traverse the read-only bind source; no write bit is shared.
    os.chmod(temporary, 0o755)  # nosec B103
    records: list[dict[str, object]] = []
    try:
        for item in selected:
            payload = _read_exact(inventory, item)
            destination = temporary.joinpath(*PurePosixPath(item.path).parts)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            destination.write_bytes(payload)
            destination.chmod(0o555 if item.git_mode == "100755" else 0o444)
            records.append(
                {
                    "path": item.path,
                    "git_mode": item.git_mode,
                    "byte_size": item.byte_size,
                    "content_digest": item.content_digest,
                    "git_blob_id": item.scanned_blob_id,
                }
            )
        input_body = {
            "version": "tracked-adapter-workspace-v1",
            "head": inventory.head,
            "head_tree": inventory.head_tree,
            "object_format": inventory.object_format,
            "tracked_content_digest": inventory.tracked_content_digest,
            "configuration_path": configuration,
            "target_paths": list(targets),
            "files": records,
        }
        return AdapterWorkspace(
            root=temporary,
            configuration_path=configuration,
            target_paths=targets,
            configuration_digest=by_path[configuration].content_digest,
            input_digest=canonical_digest(input_body),
            input_bytes=total_bytes,
            input_files=len(selected),
        )
    except Exception:
        shutil.rmtree(temporary)
        raise
