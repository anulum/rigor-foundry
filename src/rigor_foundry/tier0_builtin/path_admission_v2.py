# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — descriptor-bound path admission
"""Check one selected file target against pinned roots without following links."""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass

from ..effect_journal_records_v2 import parse_effect_target_ref_v2
from .linux_openat2_v2 import open_child_directory_nofollow_v2, open_child_file_nofollow_v2

_ROOT_RESOLUTION_ERRNOS = frozenset({errno.ENOTDIR, errno.ELOOP, errno.EACCES})


@dataclass(frozen=True)
class PinnedDirectoryV2:
    """One canonical directory path from the selected registry generation.

    Attributes
    ----------
    path : str
        Lexical path awaiting validation and no-follow filesystem opening.
        Constructing this record does not open or protect the directory.
    """

    path: str


@dataclass(frozen=True)
class PinnedPathScopeV2:
    """Selected canonical paths and their registry-generation digest binding.

    Attributes
    ----------
    monorepo_root : PinnedDirectoryV2
        Absolute deployment root containing the selected path.
    selected_root : PinnedDirectoryV2
        Root beneath which target descent is permitted by this scope.
    selected_project_root : str or None
        Registered selected project identity used in repository checks.
    registered_projects : tuple[PinnedDirectoryV2, ...]
        Current canonical project roots, including inactive registrations.
    registered_groups : tuple[PinnedDirectoryV2, ...]
        Current portfolio roots considered during ancestor checks.
    registry_generation_id : str
        Selected registry generation, empty for unbound path-only fixtures.
    registry_sha256 : str
        Exact registry digest, empty for unbound path-only fixtures.
    path_scope_digest : str
        Derived scope digest, empty for unbound path-only fixtures.

    Notes
    -----
    This record carries lexical data. Protected consumers must derive it
    from selected registry bytes and compare it under their own lease.
    """

    monorepo_root: PinnedDirectoryV2
    selected_root: PinnedDirectoryV2
    selected_project_root: str | None
    registered_projects: tuple[PinnedDirectoryV2, ...]
    registered_groups: tuple[PinnedDirectoryV2, ...]
    registry_generation_id: str = ""
    registry_sha256: str = ""
    path_scope_digest: str = ""


@dataclass(frozen=True)
class AdmittedParentV2:
    """Checked root and parent descriptors, valid only inside their context.

    Attributes
    ----------
    root_fd : int
        Held selected-root descriptor owned by the surrounding context.
    parent_fd : int
        Held target-parent descriptor owned by the surrounding context.
    target_name : str
        Final single filename to use relative to the held parent.
    target_path : str
        Original validated absolute target path.
    target_exists : bool
        Whether a regular final leaf existed during admission.

    Notes
    -----
    Observations can become stale. An effect handler must revalidate them;
    callers must not close these descriptors or use them after context exit.
    """

    root_fd: int
    parent_fd: int
    target_name: str
    target_path: str
    target_exists: bool


class RegisteredRootUnavailableV2(PermissionError):
    """Refuse admission and retain the failing root for protected operator status.

    Parameters
    ----------
    root_path : str
        Root that could not be resolved during current registered-root checks.

    Attributes
    ----------
    root_path : str
        Private diagnostic path excluded from the public exception message.
    """

    def __init__(self, root_path: str) -> None:
        """Keep the private root path out of the public exception message."""
        super().__init__("Tier-0 registered project root cannot be resolved")
        self.root_path = root_path


def _components(path: str) -> tuple[str, ...]:
    """Reject non-canonical or repository-internal path components."""
    parse_effect_target_ref_v2({"form": "path", "value": path})
    parts = tuple(part for part in path.split("/") if part)
    if ".git" in parts:
        raise PermissionError("Tier-0 .git path segment is forbidden")
    return parts


def _within(path: str, root: str) -> bool:
    """Compare canonical absolute paths on component boundaries."""
    return root == "/" or path == root or path.startswith(root + "/")


def _entry_mode(dir_fd: int, name: str) -> int | None:
    """Use fstatat without following an entry; absence is the only empty case."""
    try:
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode
    except FileNotFoundError:
        return None


def _has_git_entry(dir_fd: int) -> bool:
    """Recognize a .git entry of any type."""
    return _entry_mode(dir_fd, ".git") is not None


def is_bare_repository_layout(dir_fd: int) -> bool:
    """Recognize HEAD regular, objects directory and refs directory.

    Parameters
    ----------
    dir_fd : int
        Held directory descriptor to inspect without following child links.

    Returns
    -------
    bool
        Whether all three entries have the expected no-follow types.
        This conservative layout check is not Git object validation.

    Raises
    ------
    OSError
        If metadata inspection fails for reasons other than absent entries.
    """
    head = _entry_mode(dir_fd, "HEAD")
    objects = _entry_mode(dir_fd, "objects")
    refs = _entry_mode(dir_fd, "refs")
    return (
        head is not None
        and stat.S_ISREG(head)
        and objects is not None
        and stat.S_ISDIR(objects)
        and refs is not None
        and stat.S_ISDIR(refs)
    )


def _identity(dir_fd: int) -> tuple[int, int]:
    """Read stable directory identity through its held descriptor."""
    info = os.fstat(dir_fd)
    return info.st_dev, info.st_ino


def _current_root_identity(path: str) -> tuple[int, int] | None:
    """Resolve one registry path no-follow in this admission, if it exists."""
    current_fd = os.open("/", os.O_PATH | os.O_DIRECTORY)
    try:
        for part in _components(path):
            next_fd = open_child_directory_nofollow_v2(current_fd, part)
            os.close(current_fd)
            current_fd = next_fd
        return _identity(current_fd)
    except FileNotFoundError:
        return None
    finally:
        os.close(current_fd)


def _registered_project_at(path: str, dir_fd: int, scope: PinnedPathScopeV2) -> str | None:
    """Match registered projects against current no-follow root identities."""
    actual = _identity(dir_fd)
    for root in scope.registered_projects:
        root_unavailable = False
        try:
            current = _current_root_identity(root.path)
        except OSError as exc:
            if exc.errno not in _ROOT_RESOLUTION_ERRNOS:
                raise
            root_unavailable = True
        if root_unavailable:
            raise RegisteredRootUnavailableV2(root.path)
        if root.path == path and current != actual:
            raise PermissionError("root-moved")
        if current is not None and (root.path == path or actual == current):
            return root.path
    return None


def _validate_scope(scope: PinnedPathScopeV2, target_path: str) -> tuple[str, ...]:
    """Validate selected-root and registry relations before filesystem descent."""
    target_parts = _components(target_path)
    mono = scope.monorepo_root.path
    root = scope.selected_root.path
    _components(mono)
    _components(root)
    if mono == "/" or root == "/":
        raise PermissionError("Tier-0 selected and monorepo roots must be below /.")
    if not _within(root, mono) or not _within(target_path, root) or target_path == root:
        raise PermissionError("Tier-0 target is outside the selected root")
    all_roots = (*scope.registered_projects, *scope.registered_groups)
    if len({item.path for item in all_roots}) != len(all_roots):
        raise ValueError("Tier-0 registry contains duplicate roots")
    for item in all_roots:
        _components(item.path)
        if not _within(item.path, mono):
            raise ValueError("Tier-0 registered root lies outside monorepo")
    if scope.selected_project_root is None:
        if root not in {item.path for item in scope.registered_groups}:
            raise PermissionError("Tier-0 group selector root is not registered")
    else:
        _components(scope.selected_project_root)
        projects_at_root = [
            item.path for item in scope.registered_projects if _within(root, item.path)
        ]
        if not projects_at_root or max(projects_at_root, key=len) != scope.selected_project_root:
            raise PermissionError("Tier-0 nearest registered project differs")
    return target_parts


@contextmanager
def open_admitted_parent_v2(
    target_path: str, scope: PinnedPathScopeV2
) -> Iterator[AdmittedParentV2]:
    """Re-resolve selected root and target parent with all repository checks.

    The caller must keep this context open while using either returned fd.
    ``scope`` must come from the protected selected registry and must not be
    supplied by the invoking caller.

    Parameters
    ----------
    target_path : str
        Canonical absolute file target beneath the selected root.
    scope : PinnedPathScopeV2
        Host-selected roots for registered and nested-repository checks.

    Yields
    ------
    AdmittedParentV2
        Held root and parent descriptors plus the checked final leaf.
        All opened descriptors close on exit, including exception paths.

    Raises
    ------
    ValueError
        If target or scope paths are malformed.
    PermissionError
        For forbidden roots, repository internals, nested or bare repositories,
        registered-project mismatches, or a nonregular final target.
    RegisteredRootUnavailableV2
        If a registered root cannot be resolved for the identity comparison.
    OSError
        Propagated from real no-follow opening or metadata inspection.
    """
    target_parts = _validate_scope(scope, target_path)
    root_parts = _components(scope.selected_root.path)
    mono = scope.monorepo_root.path
    root = scope.selected_root.path
    registered = {item.path for item in (*scope.registered_projects, *scope.registered_groups)}
    with ExitStack() as stack:
        current_fd = os.open("/", os.O_PATH | os.O_DIRECTORY)
        stack.callback(os.close, current_fd)
        current_path = "/"
        for part in root_parts:
            current_fd = open_child_directory_nofollow_v2(current_fd, part)
            stack.callback(os.close, current_fd)
            current_path = current_path.rstrip("/") + "/" + part
            if is_bare_repository_layout(current_fd):
                raise PermissionError("Tier-0 bare repository on root descent")
            if (
                _within(current_path, mono)
                and current_path not in (mono, root)
                and current_path not in registered
                and _has_git_entry(current_fd)
            ):
                raise PermissionError("unregistered-ancestor-repository")
        root_fd = current_fd
        git_mode = _entry_mode(root_fd, ".git")
        if git_mode is not None and (
            root != scope.selected_project_root or not stat.S_ISDIR(git_mode)
        ):
            raise PermissionError("Tier-0 nested repository at selected root")
        if _registered_project_at(root, root_fd, scope) != scope.selected_project_root:
            raise PermissionError("Tier-0 selected root differs from registered project")
        parent_fd = root_fd
        parent_parts = target_parts[len(root_parts) : -1]
        for part in parent_parts:
            parent_fd = open_child_directory_nofollow_v2(parent_fd, part, no_xdev=True)
            stack.callback(os.close, parent_fd)
            current_path = current_path.rstrip("/") + "/" + part
            if _has_git_entry(parent_fd) or is_bare_repository_layout(parent_fd):
                raise PermissionError("Tier-0 nested repository on target descent")
            if _registered_project_at(current_path, parent_fd, scope) is not None:
                raise PermissionError("Tier-0 nested registered project on target descent")
        target_name = target_parts[-1]
        mode = _entry_mode(parent_fd, target_name)
        if mode is not None and not stat.S_ISREG(mode):
            raise PermissionError("Tier-0 target is not a regular file")
        if mode is not None:
            checked_fd = open_child_file_nofollow_v2(parent_fd, target_name, no_xdev=True)
            os.close(checked_fd)
        yield AdmittedParentV2(root_fd, parent_fd, target_name, target_path, mode is not None)


def canonicalize_atomic_path_v2(path: str, scope: PinnedPathScopeV2) -> dict[str, str]:
    """Return a checked path reference from protected selected registry data.

    Parameters
    ----------
    path : str
        Canonical absolute target beneath the selected root.
    scope : PinnedPathScopeV2
        Scope supplied by the protected selected-registry consumer.

    Returns
    -------
    dict[str, str]
        Exact path reference after descriptor-backed observation. Descriptors
        close before return; this reference is neither a lease nor a permit.

    Raises
    ------
    ValueError
        If path or scope validation fails.
    PermissionError
        If repository or target admission checks refuse.
    OSError
        If real filesystem resolution or inspection fails.
    """
    with open_admitted_parent_v2(path, scope):
        return {"form": "path", "value": path}
