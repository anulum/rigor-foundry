# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete bounded directory file observations
"""Observe a selected directory without inventing Git or historical identities."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .audit_primitives import require_integer
from .git_inventory import open_directory_no_follow, read_stable_regular_file_at
from .policy_read_budget import PolicyReadBudget1
from .repository_inventory_rows import RepositoryFileRow, require_inventory_path


@dataclass(frozen=True)
class DirectoryFileInputs:
    """Complete current directory observations, including empty subdirectories.

    Unsupported leaves remain explicit; symlinks retain only link bytes.
    This does not establish a baseline, ignored/generated provenance, complete
    configured roots, source permission or an atomic/authenticated snapshot.
    """

    root: Path
    root_device: int
    root_inode: int
    files: tuple[RepositoryFileRow, ...]
    directories: tuple[str, ...]
    source_bytes_read: int


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Keep pathname/descriptor identity without read-induced access times."""
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


@dataclass
class _DirectoryCapture:
    """Share explicit byte and entry ceilings across both complete traversals."""

    limits: PolicyReadBudget1
    remaining: int
    maximum_entries: int
    entries: int = 0

    def charge(self, size: int) -> None:
        """Charge actual file/link bytes and encoded names under the total limit."""
        if size > self.remaining:
            raise ValueError("directory input transaction exceeds the total byte budget")
        self.remaining -= size

    def names(self, descriptor: int, maximum: int) -> tuple[str, ...]:
        """Bound iterator allocation before retaining an entire directory listing."""
        names: list[str] = []
        size = 0
        with os.scandir(descriptor) as iterator:
            for entry in iterator:
                if len(names) >= maximum:
                    raise ValueError("directory inputs exceed the entry budget")
                try:
                    encoded = entry.name.encode("utf-8")
                except UnicodeEncodeError as exc:
                    raise ValueError("directory input path is not UTF-8") from exc
                size += len(encoded)
                if size > self.limits.max_document_bytes:
                    raise ValueError("directory listing exceeds the document byte budget")
                self.charge(len(encoded))
                names.append(entry.name)
        return tuple(sorted(names))

    def walk(
        self, descriptor: int, prefix: str, depth: int
    ) -> tuple[list[RepositoryFileRow], list[str], list[tuple[str, tuple[int, ...]]]]:
        """Read every entry through retained no-follow directory descriptors."""
        before = _identity(os.fstat(descriptor))
        maximum = self.maximum_entries - self.entries
        names = self.names(descriptor, maximum)
        self.entries += len(names)
        files: list[RepositoryFileRow] = []
        directories: list[str] = []
        identities = [(prefix, before)]
        for name in names:
            relative = require_inventory_path(f"{prefix}/{name}" if prefix else name)
            if depth + 1 > self.limits.max_depth:
                raise ValueError("directory inputs exceed the path depth budget")
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            expected = _identity(metadata)
            if stat.S_ISDIR(metadata.st_mode):
                child = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                    dir_fd=descriptor,
                )
                try:
                    if _identity(os.fstat(child)) != expected:
                        raise ValueError("directory child object changed before traversal")
                    child_files, child_directories, child_identities = self.walk(
                        child, relative, depth + 1
                    )
                finally:
                    os.close(child)
                directories.extend((relative, *child_directories))
                files.extend(child_files)
                identities.extend(child_identities)
            elif stat.S_ISREG(metadata.st_mode):
                observed = read_stable_regular_file_at(
                    descriptor,
                    name,
                    relative,
                    buffer_limit=0,
                    maximum_bytes=min(self.limits.max_source_bytes, self.remaining),
                )
                self.charge(observed.byte_size)
                files.append(
                    RepositoryFileRow(
                        relative,
                        "regular",
                        "100755" if metadata.st_mode & stat.S_IXUSR else "100644",
                        None,
                        observed.content_digest,
                        observed.byte_size,
                        None,
                        None,
                    )
                )
            elif stat.S_ISLNK(metadata.st_mode):
                payload = os.fsencode(os.readlink(name, dir_fd=descriptor))
                if len(payload) > self.limits.max_source_bytes:
                    raise ValueError("directory link bytes exceed the source byte budget")
                self.charge(len(payload))
                files.append(
                    RepositoryFileRow(
                        relative,
                        "symlink",
                        "120000",
                        None,
                        hashlib.sha256(payload).hexdigest(),
                        len(payload),
                        None,
                        None,
                    )
                )
            else:
                files.append(
                    RepositoryFileRow(relative, "unsupported", None, None, None, None, None, None)
                )
            if _identity(os.stat(name, dir_fd=descriptor, follow_symlinks=False)) != expected:
                raise ValueError("directory entry changed during observation")
            if not stat.S_ISDIR(metadata.st_mode):
                identities.append((relative, expected))
        if (
            self.names(descriptor, len(names)) != names
            or _identity(os.fstat(descriptor)) != before
        ):
            raise ValueError("directory listing or object changed during observation")
        return files, directories, identities


def observe_directory_file_inputs(
    root: Path,
    *,
    budget: PolicyReadBudget1,
    maximum_total_bytes: int | None = None,
    maximum_entries: int | None = None,
) -> DirectoryFileInputs:
    """Observe every current leaf and directory under one already-authorised root.

    Parameters
    ----------
    root:
        Exact absolute physical directory selected by the enclosing source owner.
        Missing roots and unsafe parents refuse; they never become empty results.
    budget:
        Explicit entry/depth, per-file/link, per-listing and transaction ceilings.
        Transaction bytes count both complete file/link passes and every UTF-8
        name returned by their opening and closing directory enumerations.

    maximum_total_bytes:
        Optional nonnegative remaining enclosing transaction allowance. It can
        only tighten the original budget; zero still permits a truly empty root.
    maximum_entries:
        Optional nonnegative remaining enclosing entry allowance. It only
        tightens the original source/reference ceilings and counts directories.

    Returns
    -------
    DirectoryFileInputs
        Two agreeing complete traversals and unchanged root pathname identity.
        No Git object, history, classification or ignored/generated origin is
        invented. Unsupported leaves remain visible and cannot prove admission.

    Raises
    ------
    ValueError
        If inputs, budgets, names, repeated observations or identities differ.
        Git administration paths refuse instead of being silently omitted.
    OSError
        If the root or any entry cannot be inspected without following links.
    RuntimeError
        If the host lacks the required descriptor-relative filesystem support.
    """
    if type(budget) is not PolicyReadBudget1:
        raise ValueError("policy read budget is required")
    limits = PolicyReadBudget1.from_dict(budget.to_dict())
    maximum = (
        limits.max_total_source_bytes
        if maximum_total_bytes is None
        else (require_integer(maximum_total_bytes, "remaining directory source bytes", minimum=0))
    )
    if maximum > limits.max_total_source_bytes:
        raise ValueError("remaining directory source bytes exceed the original budget")
    entry_ceiling = min(limits.max_sources, limits.max_references)
    entries = (
        entry_ceiling
        if maximum_entries is None
        else require_integer(maximum_entries, "remaining directory entries", minimum=0)
    )
    if entries > entry_ceiling:
        raise ValueError("remaining directory entries exceed the original budget")
    descriptor = open_directory_no_follow(root)
    try:
        original = _identity(os.fstat(descriptor))
        capture = _DirectoryCapture(limits, maximum, entries)
        first = capture.walk(descriptor, "", 0)
        capture.entries = 0
        second = capture.walk(descriptor, "", 0)
        closing_descriptor = open_directory_no_follow(root)
        try:
            closing = _identity(os.fstat(closing_descriptor))
        finally:
            os.close(closing_descriptor)
        if original != closing:
            raise ValueError("selected directory root object changed")
        if first != second:
            raise ValueError("directory input observations changed during capture")
        return DirectoryFileInputs(
            root,
            original[0],
            original[1],
            tuple(sorted(first[0], key=lambda row: row.relative_path)),
            tuple(sorted(first[1])),
            maximum - capture.remaining,
        )
    finally:
        os.close(descriptor)
