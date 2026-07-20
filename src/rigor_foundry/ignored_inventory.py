# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — bounded ignored-path evidence inventory
"""Collect explicit ignored-path evidence without retaining repository content."""

from __future__ import annotations

import errno
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal, cast

from .audit_primitives import canonical_digest, require_mapping, require_string
from .git_inventory import (
    GitInventory,
    StableReadError,
    is_git_ignored,
    open_directory_no_follow,
    read_stable_regular_file_at,
)
from .git_provenance import GitRunner

IGNORED_INVENTORY_SCHEMA_VERSION = "1.0"
IgnoredCapture = Literal["presence", "file-sha256", "directory-sha256"]
IgnoredStatus = Literal["observed", "missing", "unavailable"]
IgnoredKind = Literal["regular-file", "directory", "other"]
IgnoredReason = Literal[
    "changed-while-read",
    "inaccessible",
    "inaccessible-parent",
    "missing",
    "missing-parent",
    "multiple-links",
    "not-regular-file",
    "limit-exceeded",
    "observed",
    "platform-unavailable",
    "symlink",
    "unsafe-parent",
]
_MISSING_REASONS = frozenset({"missing", "missing-parent"})
_UNAVAILABLE_REASONS = frozenset(
    {
        "changed-while-read",
        "inaccessible",
        "inaccessible-parent",
        "multiple-links",
        "not-regular-file",
        "limit-exceeded",
        "platform-unavailable",
        "symlink",
        "unsafe-parent",
    }
)
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_GLOB_CHARACTERS = frozenset("*?[]{}\\")


def _exact_relative_path(value: object, field: str) -> str:
    """Return one exact normalised repository-relative POSIX path."""
    result = require_string(value, field)
    if any(ord(character) < 32 or ord(character) == 127 for character in result):
        raise ValueError(f"{field} must not contain control characters")
    if any(character in result for character in _GLOB_CHARACTERS):
        raise ValueError(f"{field} must not contain glob or escape syntax")
    path = PurePosixPath(result)
    if path.is_absolute() or "." in path.parts or ".." in path.parts:
        raise ValueError(f"{field} must be an exact repository-relative path")
    normalised = path.as_posix()
    if normalised != result or normalised in {"", "."} or "//" in result:
        raise ValueError(f"{field} must be a normalised repository-relative path")
    return normalised


@dataclass(frozen=True)
class IgnoredInventoryDeclaration:
    """One policy-declared ignored path and bounded capture mode."""

    evidence_id: str
    path: str
    capture: IgnoredCapture

    def __post_init__(self) -> None:
        """Validate direct construction as strictly as parsed construction."""
        if (
            not isinstance(self.evidence_id, str)
            or _IDENTIFIER.fullmatch(self.evidence_id) is None
        ):
            raise ValueError("ignored inventory evidence_id must be a portable identifier")
        _exact_relative_path(self.path, "ignored inventory path")
        if not isinstance(self.capture, str) or self.capture not in {
            "presence",
            "file-sha256",
            "directory-sha256",
        }:
            raise ValueError("ignored inventory capture is unsupported")

    def to_dict(self) -> dict[str, str]:
        """Serialise one declaration."""
        return {
            "evidence_id": self.evidence_id,
            "path": self.path,
            "capture": self.capture,
        }

    @classmethod
    def from_dict(cls, value: object, index: int) -> IgnoredInventoryDeclaration:
        """Parse one strict ignored-path declaration."""
        data = require_mapping(value, f"ignored_inventory[{index}]")
        if frozenset(data) != {"evidence_id", "path", "capture"}:
            raise ValueError(f"ignored_inventory[{index}] fields do not match schema")
        evidence_id = require_string(
            data.get("evidence_id"),
            f"ignored_inventory[{index}].evidence_id",
        )
        capture = require_string(data.get("capture"), f"ignored_inventory[{index}].capture")
        return cls(
            evidence_id=evidence_id,
            path=_exact_relative_path(data.get("path"), f"ignored_inventory[{index}].path"),
            capture=cast(IgnoredCapture, capture),
        )


def parse_ignored_inventory(value: object) -> tuple[IgnoredInventoryDeclaration, ...]:
    """Parse a sorted, unique ignored-inventory declaration array."""
    if not isinstance(value, list):
        raise ValueError("ignored_inventory must be an array")
    declarations = tuple(
        IgnoredInventoryDeclaration.from_dict(item, index) for index, item in enumerate(value)
    )
    keys = tuple((item.evidence_id, item.path, item.capture) for item in declarations)
    if keys != tuple(sorted(keys)):
        raise ValueError("ignored_inventory must be sorted by evidence_id, path, and capture")
    if len({item.evidence_id for item in declarations}) != len(declarations):
        raise ValueError("ignored_inventory evidence_id values must be unique")
    if len({item.path for item in declarations}) != len(declarations):
        raise ValueError("ignored_inventory paths must be unique")
    return declarations


@dataclass(frozen=True)
class IgnoredInventoryEvidence:
    """One bounded observation of a declared ignored repository path."""

    evidence_id: str
    path: str
    capture: IgnoredCapture
    status: IgnoredStatus
    observed_kind: IgnoredKind | None
    byte_size: int | None
    content_sha256: str | None
    reason: IgnoredReason

    def __post_init__(self) -> None:
        """Validate direct construction and every exact field relation."""
        IgnoredInventoryDeclaration(self.evidence_id, self.path, self.capture)
        if not isinstance(self.status, str) or self.status not in {
            "observed",
            "missing",
            "unavailable",
        }:
            raise ValueError("ignored inventory evidence status is unsupported")
        if self.observed_kind is not None and (
            not isinstance(self.observed_kind, str)
            or self.observed_kind not in {"regular-file", "directory", "other"}
        ):
            raise ValueError("ignored inventory observed kind is unsupported")
        if self.byte_size is not None and (
            isinstance(self.byte_size, bool)
            or not isinstance(self.byte_size, int)
            or self.byte_size < 0
        ):
            raise ValueError("ignored inventory byte_size is invalid")
        if self.content_sha256 is not None and (
            not isinstance(self.content_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.content_sha256) is None
        ):
            raise ValueError("ignored inventory content_sha256 is invalid")
        if not isinstance(self.reason, str) or self.reason not in (
            _MISSING_REASONS | _UNAVAILABLE_REASONS | {"observed"}
        ):
            raise ValueError("ignored inventory evidence reason is unsupported")
        self._validate_relation()

    def to_dict(self) -> dict[str, object]:
        """Serialise bounded evidence without raw content or link targets."""
        return {
            "schema_version": IGNORED_INVENTORY_SCHEMA_VERSION,
            "evidence_id": self.evidence_id,
            "path": self.path,
            "capture": self.capture,
            "status": self.status,
            "observed_kind": self.observed_kind,
            "byte_size": self.byte_size,
            "content_sha256": self.content_sha256,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, value: object, index: int) -> IgnoredInventoryEvidence:
        """Parse one bounded ignored-path evidence record."""
        data = require_mapping(value, f"ignored_inventory_evidence[{index}]")
        expected = {
            "schema_version",
            "evidence_id",
            "path",
            "capture",
            "status",
            "observed_kind",
            "byte_size",
            "content_sha256",
            "reason",
        }
        if frozenset(data) != expected:
            raise ValueError(f"ignored_inventory_evidence[{index}] fields do not match schema")
        if data.get("schema_version") != IGNORED_INVENTORY_SCHEMA_VERSION:
            raise ValueError("unsupported ignored-inventory evidence schema version")
        declaration = IgnoredInventoryDeclaration.from_dict(
            {
                "evidence_id": data.get("evidence_id"),
                "path": data.get("path"),
                "capture": data.get("capture"),
            },
            index,
        )
        status = require_string(data.get("status"), f"ignored_inventory_evidence[{index}].status")
        raw_kind = data.get("observed_kind")
        raw_size = data.get("byte_size")
        raw_digest = data.get("content_sha256")
        reason = require_string(data.get("reason"), f"ignored_inventory_evidence[{index}].reason")
        return cls(
            evidence_id=declaration.evidence_id,
            path=declaration.path,
            capture=declaration.capture,
            status=cast(IgnoredStatus, status),
            observed_kind=cast(IgnoredKind | None, raw_kind),
            byte_size=cast(int | None, raw_size),
            content_sha256=cast(str | None, raw_digest),
            reason=cast(IgnoredReason, reason),
        )

    def _validate_relation(self) -> None:
        """Reject contradictory evidence fields."""
        if self.status == "missing":
            if self.reason not in _MISSING_REASONS or any(
                value is not None
                for value in (self.observed_kind, self.byte_size, self.content_sha256)
            ):
                raise ValueError("missing ignored evidence fields contradict status")
            return
        if self.status == "unavailable":
            if self.reason not in _UNAVAILABLE_REASONS or any(
                value is not None
                for value in (self.observed_kind, self.byte_size, self.content_sha256)
            ):
                raise ValueError("unavailable ignored evidence fields contradict status")
            if self.reason == "not-regular-file" and self.capture == "presence":
                raise ValueError("not-regular-file requires digest capture")
            return
        if self.reason != "observed" or self.observed_kind is None:
            raise ValueError("observed ignored evidence requires observed kind and reason")
        if self.observed_kind == "regular-file":
            if self.byte_size is None:
                raise ValueError("regular-file ignored evidence requires byte_size")
            if self.capture == "directory-sha256":
                raise ValueError("directory-sha256 evidence requires a directory")
            if self.capture == "file-sha256" and self.content_sha256 is None:
                raise ValueError("file-sha256 evidence requires content_sha256")
            if self.capture == "presence" and self.content_sha256 is not None:
                raise ValueError("presence evidence must not carry content_sha256")
            return
        if self.observed_kind == "directory" and self.capture == "directory-sha256":
            if self.byte_size is None or self.content_sha256 is None:
                raise ValueError("directory-sha256 evidence requires size and content digest")
            return
        if self.capture != "presence" or any(
            value is not None for value in (self.byte_size, self.content_sha256)
        ):
            raise ValueError("non-file observed evidence requires presence-only empty metadata")


def _validate_evidence_sequence(
    evidence: tuple[IgnoredInventoryEvidence, ...],
) -> None:
    """Require one canonical evidence record per unique declaration identity."""
    keys = tuple((item.evidence_id, item.path, item.capture) for item in evidence)
    if keys != tuple(sorted(keys)):
        raise ValueError(
            "ignored_inventory_evidence must be sorted by evidence_id, path, and capture"
        )
    if len({item.evidence_id for item in evidence}) != len(evidence):
        raise ValueError("ignored_inventory_evidence evidence_id values must be unique")
    if len({item.path for item in evidence}) != len(evidence):
        raise ValueError("ignored_inventory_evidence paths must be unique")


def ignored_inventory_digest(evidence: tuple[IgnoredInventoryEvidence, ...]) -> str:
    """Return the canonical identity of one ordered ignored evidence tuple."""
    _validate_evidence_sequence(evidence)
    return canonical_digest([item.to_dict() for item in evidence])


def parse_ignored_evidence_array(value: object) -> tuple[IgnoredInventoryEvidence, ...]:
    """Parse an ignored evidence array into immutable typed records."""
    if not isinstance(value, list):
        raise ValueError("ignored_inventory_evidence must be an array")
    evidence = tuple(
        IgnoredInventoryEvidence.from_dict(item, index) for index, item in enumerate(value)
    )
    _validate_evidence_sequence(evidence)
    return evidence


def _unavailable(
    declaration: IgnoredInventoryDeclaration,
    reason: IgnoredReason,
) -> IgnoredInventoryEvidence:
    """Return one content-free unavailable observation."""
    return IgnoredInventoryEvidence(
        declaration.evidence_id,
        declaration.path,
        declaration.capture,
        "unavailable",
        None,
        None,
        None,
        reason,
    )


def _snapshot(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    """Return the complete identity fields used for stable presence evidence."""
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _observe_present(
    parent: int,
    name: str,
    declaration: IgnoredInventoryDeclaration,
    expected: tuple[int, int, int, int, int, int, int],
) -> IgnoredInventoryEvidence:
    """Bind a present non-regular entry without blocking FIFOs or devices."""
    if (
        not hasattr(os, "O_PATH")
        or not hasattr(os, "O_NOFOLLOW")
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        return _unavailable(declaration, "platform-unavailable")
    descriptor: int | None = None
    flags = os.O_PATH | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
        before = os.fstat(descriptor)
        path_before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        after = os.fstat(descriptor)
        path_after = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError:
        return _unavailable(declaration, "inaccessible")
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if stat.S_ISREG(before.st_mode) and before.st_nlink != 1:
        return _unavailable(declaration, "multiple-links")
    if (
        _snapshot(before) != expected
        or _snapshot(before) != _snapshot(after)
        or _snapshot(path_before) != _snapshot(before)
        or _snapshot(path_after) != _snapshot(before)
    ):
        return _unavailable(declaration, "changed-while-read")
    if stat.S_ISLNK(before.st_mode):
        return _unavailable(declaration, "symlink")
    if stat.S_ISDIR(before.st_mode):
        kind: IgnoredKind = "directory"
    else:
        kind = "other"
    if declaration.capture != "presence":
        return _unavailable(declaration, "not-regular-file")
    return IgnoredInventoryEvidence(
        declaration.evidence_id,
        declaration.path,
        declaration.capture,
        "observed",
        kind,
        None,
        None,
        "observed",
    )


_DIRECTORY_MAX_DEPTH = 64
_DIRECTORY_MAX_ENTRIES = 10_000
_DIRECTORY_MAX_BYTES = 128 * 1024 * 1024
_DIRECTORY_MANIFEST_SCHEMA_VERSION = "1.0"


class _DirectoryReadError(Exception):
    """Carry one bounded ignored-evidence failure reason."""

    def __init__(self, reason: IgnoredReason) -> None:
        super().__init__(reason)
        self.reason = reason


def _directory_entries(
    descriptor: int,
    *,
    prefix: bytes,
    depth: int,
    counters: list[int],
) -> list[dict[str, object]]:
    """Hash one no-follow directory tree through descriptor-relative reads."""
    if depth > _DIRECTORY_MAX_DEPTH:
        raise _DirectoryReadError("limit-exceeded")
    before = _snapshot(os.fstat(descriptor))
    try:
        names = sorted(os.listdir(descriptor), key=os.fsencode)
    except OSError as exc:
        raise _DirectoryReadError("inaccessible") from exc
    entries: list[dict[str, object]] = []
    directory_flags = (
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    for name in names:
        counters[0] += 1
        if counters[0] > _DIRECTORY_MAX_ENTRIES:
            raise _DirectoryReadError("limit-exceeded")
        name_bytes = os.fsencode(name)
        relative = prefix + b"/" + name_bytes if prefix else name_bytes
        try:
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError as exc:
            raise _DirectoryReadError("changed-while-read") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise _DirectoryReadError("symlink")
        if stat.S_ISDIR(metadata.st_mode):
            child: int | None = None
            try:
                child = os.open(name, directory_flags, dir_fd=descriptor)
                child_before = _snapshot(os.fstat(child))
                entries.append({"path_bytes_hex": relative.hex(), "kind": "directory"})
                entries.extend(
                    _directory_entries(
                        child,
                        prefix=relative,
                        depth=depth + 1,
                        counters=counters,
                    )
                )
                path_after = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if _snapshot(path_after) != child_before:
                    raise _DirectoryReadError("changed-while-read")
            except _DirectoryReadError:
                raise
            except OSError as exc:
                raise _DirectoryReadError("inaccessible") from exc
            finally:
                if child is not None:
                    os.close(child)
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise _DirectoryReadError("not-regular-file")
        if metadata.st_nlink != 1:
            raise _DirectoryReadError("multiple-links")
        remaining = _DIRECTORY_MAX_BYTES - counters[1]
        if metadata.st_size > remaining:
            raise _DirectoryReadError("limit-exceeded")
        try:
            result = read_stable_regular_file_at(
                descriptor,
                name,
                relative.hex(),
                buffer_limit=remaining,
                maximum_bytes=remaining,
                require_single_link=True,
            )
        except StableReadError as exc:
            raise _DirectoryReadError(cast(IgnoredReason, exc.reason)) from exc
        counters[1] += result.byte_size
        entries.append(
            {
                "path_bytes_hex": relative.hex(),
                "kind": "regular-file",
                "byte_size": result.byte_size,
                "content_sha256": result.content_digest,
            }
        )
    try:
        after_names = sorted(os.listdir(descriptor), key=os.fsencode)
        after = _snapshot(os.fstat(descriptor))
    except OSError as exc:
        raise _DirectoryReadError("changed-while-read") from exc
    if names != after_names or before != after:
        raise _DirectoryReadError("changed-while-read")
    return entries


def _observe_directory_hash(
    parent: int,
    name: str,
    declaration: IgnoredInventoryDeclaration,
    expected: tuple[int, int, int, int, int, int, int],
) -> IgnoredInventoryEvidence:
    """Return a bounded canonical digest for one stable ignored directory tree."""
    descriptor: int | None = None
    flags = (
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
        if _snapshot(os.fstat(descriptor)) != expected:
            return _unavailable(declaration, "changed-while-read")
        counters = [0, 0]
        entries = _directory_entries(descriptor, prefix=b"", depth=0, counters=counters)
        path_after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if _snapshot(path_after) != expected:
            return _unavailable(declaration, "changed-while-read")
        return IgnoredInventoryEvidence(
            declaration.evidence_id,
            declaration.path,
            declaration.capture,
            "observed",
            "directory",
            counters[1],
            canonical_digest(
                {
                    "schema_version": _DIRECTORY_MANIFEST_SCHEMA_VERSION,
                    "entries": entries,
                }
            ),
            "observed",
        )
    except _DirectoryReadError as exc:
        return _unavailable(declaration, exc.reason)
    except OSError:
        return _unavailable(declaration, "inaccessible")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _collect_one(
    root_descriptor: int,
    declaration: IgnoredInventoryDeclaration,
) -> IgnoredInventoryEvidence:
    """Collect one declaration through descriptor-relative no-follow traversal."""
    descriptors: list[int] = []
    parent_bindings: list[tuple[int, str, int, tuple[int, ...]]] = []
    parent = root_descriptor
    directory_flags = (
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    parts = PurePosixPath(declaration.path).parts

    def finish(evidence: IgnoredInventoryEvidence) -> IgnoredInventoryEvidence:
        """Reject evidence if any opened parent pathname changed identity."""
        try:
            for parent_fd, component, child_fd, before in parent_bindings:
                child_after = os.fstat(child_fd)
                path_after = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
                if _snapshot(child_after) != before or _snapshot(path_after) != before:
                    return _unavailable(declaration, "changed-while-read")
        except OSError:
            return _unavailable(declaration, "changed-while-read")
        return evidence

    try:
        for component in parts[:-1]:
            try:
                descriptor = os.open(component, directory_flags, dir_fd=parent)
            except FileNotFoundError:
                return finish(
                    IgnoredInventoryEvidence(
                        declaration.evidence_id,
                        declaration.path,
                        declaration.capture,
                        "missing",
                        None,
                        None,
                        None,
                        "missing-parent",
                    )
                )
            except OSError as exc:
                reason: IgnoredReason = (
                    "unsafe-parent"
                    if exc.errno in {errno.ELOOP, errno.ENOTDIR}
                    else "inaccessible-parent"
                )
                return finish(_unavailable(declaration, reason))
            parent_bindings.append(
                (parent, component, descriptor, _snapshot(os.fstat(descriptor)))
            )
            descriptors.append(descriptor)
            parent = descriptor
        name = parts[-1]
        try:
            metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return finish(
                IgnoredInventoryEvidence(
                    declaration.evidence_id,
                    declaration.path,
                    declaration.capture,
                    "missing",
                    None,
                    None,
                    None,
                    "missing",
                )
            )
        except OSError:
            return finish(_unavailable(declaration, "inaccessible"))
        if stat.S_ISDIR(metadata.st_mode) and declaration.capture == "directory-sha256":
            return finish(_observe_directory_hash(parent, name, declaration, _snapshot(metadata)))
        if not stat.S_ISREG(metadata.st_mode):
            return finish(_observe_present(parent, name, declaration, _snapshot(metadata)))
        if declaration.capture == "directory-sha256":
            return finish(_unavailable(declaration, "not-regular-file"))
        try:
            result = read_stable_regular_file_at(
                parent,
                name,
                declaration.path,
                buffer_limit=0,
                require_single_link=True,
            )
        except StableReadError as exc:
            stable_reason: IgnoredReason = cast(IgnoredReason, exc.reason)
            if stable_reason == "not-regular-file" and declaration.capture == "presence":
                stable_reason = "changed-while-read"
            return finish(_unavailable(declaration, stable_reason))
        return finish(
            IgnoredInventoryEvidence(
                declaration.evidence_id,
                declaration.path,
                declaration.capture,
                "observed",
                "regular-file",
                result.byte_size,
                result.content_digest if declaration.capture == "file-sha256" else None,
                "observed",
            )
        )
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _first_unsafe_prefix(root_descriptor: int, path: str) -> Path | None:
    """Return only the first symlink or non-directory lexical parent prefix."""
    descriptor = os.dup(root_descriptor)
    prefix: list[str] = []
    flags = (
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        for component in PurePosixPath(path).parts[:-1]:
            prefix.append(component)
            try:
                metadata = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                return None
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                return Path(*prefix)
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return None
    finally:
        os.close(descriptor)


def collect_ignored_inventory(
    inventory: GitInventory,
    declarations: tuple[IgnoredInventoryDeclaration, ...],
    *,
    git_runner: GitRunner,
) -> tuple[IgnoredInventoryEvidence, ...]:
    """Validate and collect all declared ignored paths under one Git identity."""
    if not declarations:
        return ()
    try:
        root_descriptor = open_directory_no_follow(inventory.root)
    except OSError as exc:
        raise RuntimeError("cannot open repository root for ignored inventory") from exc
    try:
        root_before = _snapshot(os.fstat(root_descriptor))
        tracked = {item.path for item in inventory.files}
        for declaration in declarations:
            if declaration.path in tracked:
                raise ValueError(f"ignored inventory path is tracked: {declaration.path}")
            unsafe_prefix = _first_unsafe_prefix(root_descriptor, declaration.path)
            check_path = unsafe_prefix or Path(declaration.path)
            if not is_git_ignored(
                inventory.root,
                check_path,
                git_runner=git_runner,
                expected_git_provenance=inventory.git_provenance,
            ):
                raise ValueError(f"ignored inventory path is not ignored: {declaration.path}")
        evidence = tuple(
            _collect_one(root_descriptor, declaration) for declaration in declarations
        )
        try:
            post_root_descriptor = open_directory_no_follow(inventory.root)
        except (OSError, RuntimeError) as exc:
            raise RuntimeError(
                "repository root changed during ignored inventory collection"
            ) from exc
        try:
            root_after = _snapshot(os.fstat(post_root_descriptor))
        finally:
            os.close(post_root_descriptor)
        if root_after != root_before:
            raise RuntimeError("repository root changed during ignored inventory collection")
        return evidence
    finally:
        os.close(root_descriptor)
