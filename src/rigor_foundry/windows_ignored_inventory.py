# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native Windows declared ignored inventory
"""Observe declared ignored paths through retained, no-reparse NTFS handles."""

from __future__ import annotations

import os
import stat
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from .audit_primitives import canonical_digest
from .git_inventory import GitInventory, StableReadError, is_git_ignored
from .git_provenance import GitRunner
from .ignored_inventory import (
    _DIRECTORY_MANIFEST_SCHEMA_VERSION,
    _DIRECTORY_MAX_BYTES,
    _DIRECTORY_MAX_DEPTH,
    _DIRECTORY_MAX_ENTRIES,
    IgnoredInventoryDeclaration,
    IgnoredInventoryEvidence,
    IgnoredReason,
    _DirectoryReadError,
    _unavailable,
)
from .windows_directory_inventory import WindowsDirectoryEntry
from .windows_file_io import read_regular_file
from .windows_handles import WindowsChildSnapshot, WindowsDirectory, WindowsFileIdentity

_UNSAFE_ATTRIBUTES = stat.FILE_ATTRIBUTE_REPARSE_POINT
_DIRECTORY_ATTRIBUTE = stat.FILE_ATTRIBUTE_DIRECTORY
_DirectoryFingerprint = tuple[tuple[int, int], tuple[int, int, int, int]]


@dataclass(frozen=True)
class _BoundDirectory:
    """Retained directory and its observed native stability token."""

    directory: WindowsDirectory
    fingerprint: _DirectoryFingerprint


@dataclass(frozen=True)
class _ParentApproval:
    """The parent state seen while validating Git ignore ownership."""

    fingerprints: tuple[_DirectoryFingerprint, ...]
    failure: IgnoredReason | None


@dataclass(frozen=True)
class _ObservedEntry:
    """An enumerated entry, its handle metadata and any descendants read."""

    listing: WindowsDirectoryEntry
    snapshot: WindowsChildSnapshot
    descendants: _ObservedDirectory | None


@dataclass(frozen=True)
class _ObservedDirectory:
    """The membership and change metadata retained for final tree validation."""

    change_token: tuple[int, int, int, int]
    entries: tuple[_ObservedEntry, ...]


class _ParentReadError(Exception):
    """A parent path that cannot be traversed, with its last safe Git query."""

    def __init__(self, reason: IgnoredReason, check_path: PurePosixPath) -> None:
        super().__init__(reason)
        self.reason = reason
        self.check_path = check_path


def _missing(
    declaration: IgnoredInventoryDeclaration, reason: IgnoredReason
) -> IgnoredInventoryEvidence:
    """Report absence without storing native metadata."""
    return IgnoredInventoryEvidence(
        declaration.evidence_id,
        declaration.path,
        declaration.capture,
        "missing",
        None,
        None,
        None,
        reason,
    )


def _open_bound_directory(
    parent: WindowsDirectory, name: str, identity: WindowsFileIdentity, stack: ExitStack
) -> WindowsDirectory:
    """Require the opened directory to match the exact previously inspected entry."""
    child = stack.enter_context(parent.open_directory(Path(name)))
    if child.identity != (identity.volume, identity.file_id):
        raise _DirectoryReadError("changed-while-read")
    return child


def _open_parent(
    root: WindowsDirectory, relative: PurePosixPath, stack: ExitStack
) -> tuple[WindowsDirectory, tuple[_BoundDirectory, ...]]:
    """Retain every directory component, stopping at the first unsafe entry."""
    parent = root
    bound: list[_BoundDirectory] = []
    for index, component in enumerate(relative.parts[:-1], start=1):
        prefix = PurePosixPath(*relative.parts[:index])
        try:
            identity = parent.inspect_child(component).identity
        except FileNotFoundError as exc:
            raise _ParentReadError("missing-parent", relative) from exc
        except ValueError as exc:
            raise _ParentReadError("unsafe-parent", prefix) from exc
        except OSError as exc:
            raise _ParentReadError("inaccessible-parent", prefix) from exc
        if (
            identity.attributes & _UNSAFE_ATTRIBUTES
            or not identity.attributes & _DIRECTORY_ATTRIBUTE
        ):
            raise _ParentReadError("unsafe-parent", prefix)
        try:
            child = _open_bound_directory(parent, component, identity, stack)
            bound.append(_BoundDirectory(child, (child.identity, child.change_token())))
        except PermissionError as exc:
            raise _ParentReadError("inaccessible-parent", prefix) from exc
        except (OSError, ValueError, _DirectoryReadError) as exc:
            raise _ParentReadError("changed-while-read", prefix) from exc
        parent = child
    return parent, tuple(bound)


def _sorted_entries(
    directory: WindowsDirectory, maximum_entries: int
) -> tuple[WindowsDirectoryEntry, ...]:
    """Use the same bytewise traversal order as the POSIX manifest."""
    return tuple(
        sorted(
            directory.list_entries(maximum_entries=maximum_entries),
            key=lambda item: os.fsencode(item.name),
        )
    )


def _capture_tree(
    directory: WindowsDirectory, *, prefix: bytes, depth: int, counters: list[int]
) -> tuple[list[dict[str, object]], _ObservedDirectory]:
    """Hash a bounded native directory and retain its observations for the final pass."""
    if depth > _DIRECTORY_MAX_DEPTH:
        raise _DirectoryReadError("limit-exceeded")
    before = directory.change_token()
    try:
        batch = _sorted_entries(directory, _DIRECTORY_MAX_ENTRIES - counters[0])
    except OverflowError as exc:
        raise _DirectoryReadError("limit-exceeded") from exc
    counters[0] += len(batch)
    manifest: list[dict[str, object]] = []
    entries: list[_ObservedEntry] = []
    for entry in batch:
        name = os.fsencode(entry.name)
        relative = prefix + b"/" + name if prefix else name
        snapshot = directory.inspect_child(entry.name)
        identity = snapshot.identity
        if identity.file_id != entry.file_id:
            raise _DirectoryReadError("changed-while-read")
        if identity.attributes & _UNSAFE_ATTRIBUTES:
            raise _DirectoryReadError("symlink")
        descendants = None
        if identity.attributes & _DIRECTORY_ATTRIBUTE:
            with ExitStack() as child_handles:
                child = _open_bound_directory(directory, entry.name, identity, child_handles)
                manifest.append({"path_bytes_hex": relative.hex(), "kind": "directory"})
                child_manifest, descendants = _capture_tree(
                    child, prefix=relative, depth=depth + 1, counters=counters
                )
                manifest.extend(child_manifest)
        else:
            result = read_regular_file(
                directory.path / entry.name,
                retained_parent=directory,
                expected_identity=identity,
                buffer_limit=0,
                maximum_bytes=_DIRECTORY_MAX_BYTES - counters[1],
            )
            counters[1] += result.byte_size
            manifest.append(
                {
                    "path_bytes_hex": relative.hex(),
                    "kind": "regular-file",
                    "byte_size": result.byte_size,
                    "content_sha256": result.content_digest,
                }
            )
        entries.append(_ObservedEntry(entry, snapshot, descendants))
    return manifest, _ObservedDirectory(before, tuple(entries))


def _validate_tree(directory: WindowsDirectory, observed: _ObservedDirectory) -> None:
    """Revisit every captured entry after all directory contents have been read."""
    try:
        listing = _sorted_entries(directory, len(observed.entries))
        if listing != tuple(entry.listing for entry in observed.entries):
            raise _DirectoryReadError("changed-while-read")
        for entry in observed.entries:
            name = entry.listing.name
            # Directory listings can carry stale replicated metadata on NTFS.
            if directory.inspect_child(name) != entry.snapshot:
                raise _DirectoryReadError("changed-while-read")
            if entry.descendants is not None:
                with ExitStack() as child_handles:
                    child = _open_bound_directory(
                        directory, name, entry.snapshot.identity, child_handles
                    )
                    _validate_tree(child, entry.descendants)
        if directory.change_token() != observed.change_token:
            raise _DirectoryReadError("changed-while-read")
    except (OSError, ValueError, OverflowError) as exc:
        raise _DirectoryReadError("changed-while-read") from exc


def _observe_leaf(
    parent: WindowsDirectory,
    name: str,
    declaration: IgnoredInventoryDeclaration,
) -> IgnoredInventoryEvidence:
    """Observe a leaf through the bound parent and retain only permitted evidence."""
    try:
        identity = parent.inspect_child(name).identity
    except FileNotFoundError:
        return _missing(declaration, "missing")
    except (OSError, ValueError):
        return _unavailable(declaration, "inaccessible")
    if identity.attributes & _UNSAFE_ATTRIBUTES:
        return _unavailable(declaration, "symlink")
    if identity.attributes & _DIRECTORY_ATTRIBUTE:
        if declaration.capture == "file-sha256":
            return _unavailable(declaration, "not-regular-file")
        with ExitStack() as child_handles:
            child = _open_bound_directory(parent, name, identity, child_handles)
            if declaration.capture == "presence":
                return IgnoredInventoryEvidence(
                    declaration.evidence_id,
                    declaration.path,
                    declaration.capture,
                    "observed",
                    "directory",
                    None,
                    None,
                    "observed",
                )
            counters = [0, 0]
            manifest, observed = _capture_tree(child, prefix=b"", depth=0, counters=counters)
            _validate_tree(child, observed)
        return IgnoredInventoryEvidence(
            declaration.evidence_id,
            declaration.path,
            declaration.capture,
            "observed",
            "directory",
            counters[1],
            canonical_digest(
                {"schema_version": _DIRECTORY_MANIFEST_SCHEMA_VERSION, "entries": manifest}
            ),
            "observed",
        )
    if declaration.capture == "directory-sha256":
        return _unavailable(declaration, "not-regular-file")
    result = read_regular_file(
        parent.path / name, retained_parent=parent, expected_identity=identity, buffer_limit=0
    )
    return IgnoredInventoryEvidence(
        declaration.evidence_id,
        declaration.path,
        declaration.capture,
        "observed",
        "regular-file",
        result.byte_size,
        result.content_digest if declaration.capture == "file-sha256" else None,
        "observed",
    )


def _observe(
    root: WindowsDirectory, declaration: IgnoredInventoryDeclaration, approval: _ParentApproval
) -> IgnoredInventoryEvidence:
    """Collect a declaration and reject changes to the held parent chain."""
    relative = PurePosixPath(declaration.path)
    with ExitStack() as stack:
        try:
            parent, bindings = _open_parent(root, relative, stack)
        except _ParentReadError as exc:
            if approval.failure != exc.reason:
                return _unavailable(declaration, "changed-while-read")
            if exc.reason == "missing-parent":
                return _missing(declaration, exc.reason)
            return _unavailable(declaration, exc.reason)
        if approval.failure is not None or (
            tuple(binding.fingerprint for binding in bindings) != approval.fingerprints
        ):
            return _unavailable(declaration, "changed-while-read")
        try:
            evidence = _observe_leaf(parent, relative.name, declaration)
        except _DirectoryReadError as exc:
            evidence = _unavailable(declaration, exc.reason)
        except StableReadError as exc:
            reason = cast(IgnoredReason, exc.reason)
            if reason == "not-regular-file" and declaration.capture == "presence":
                reason = "changed-while-read"
            evidence = _unavailable(declaration, reason)
        except (OSError, ValueError):
            evidence = _unavailable(declaration, "inaccessible")
        try:
            if any(
                binding.directory.change_token() != binding.fingerprint[1] for binding in bindings
            ):
                return _unavailable(declaration, "changed-while-read")
        except (OSError, ValueError):
            return _unavailable(declaration, "changed-while-read")
        return evidence


def collect_windows_ignored_inventory(
    inventory: GitInventory,
    declarations: tuple[IgnoredInventoryDeclaration, ...],
    *,
    git_runner: GitRunner,
) -> tuple[IgnoredInventoryEvidence, ...]:
    """Validate declared Git ignore ownership, then observe through fixed local NTFS handles.

    Parameters
    ----------
    inventory : GitInventory
        Current tracked inventory and Git executable provenance.
    declarations : tuple[IgnoredInventoryDeclaration, ...]
        Exact portable ignored paths to observe.
    git_runner : GitRunner
        The same bound executable used for tracked inventory.

    Returns
    -------
    tuple[IgnoredInventoryEvidence, ...]
        One content-free observation in declaration order.
    """
    with WindowsDirectory(inventory.root) as root:
        before = root.identity, root.change_token()
        tracked = {file.path for file in inventory.files}
        approvals: list[_ParentApproval] = []
        for declaration in declarations:
            if declaration.path in tracked:
                raise ValueError(f"ignored inventory path is tracked: {declaration.path}")
            relative = PurePosixPath(declaration.path)
            check_path = relative
            with ExitStack() as stack:
                try:
                    _, bindings = _open_parent(root, relative, stack)
                except _ParentReadError as exc:
                    check_path = exc.check_path
                    approval = _ParentApproval((), exc.reason)
                else:
                    approval = _ParentApproval(
                        tuple(binding.fingerprint for binding in bindings), None
                    )
            git_path = Path(check_path.as_posix())
            if git_path.drive or git_path.as_posix() != check_path.as_posix():
                raise ValueError(
                    f"ignored inventory path is not a native relative path: {declaration.path}"
                )
            if not is_git_ignored(
                inventory.root,
                git_path,
                git_runner=git_runner,
                expected_git_provenance=inventory.git_provenance,
            ):
                raise ValueError(f"ignored inventory path is not ignored: {declaration.path}")
            approvals.append(approval)
        evidence = tuple(
            _observe(root, declaration, approval)
            for declaration, approval in zip(declarations, approvals, strict=True)
        )
        try:
            with WindowsDirectory(inventory.root) as current:
                after = current.identity, current.change_token()
        except (OSError, ValueError) as exc:
            raise RuntimeError(
                "repository root changed during ignored inventory collection"
            ) from exc
        if after != before:
            raise RuntimeError("repository root changed during ignored inventory collection")
        return evidence
