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
from .git_inventory import GitInventory, is_git_ignored, read_stable_regular_file_at
from .git_provenance import GitRunner

IGNORED_INVENTORY_SCHEMA_VERSION = "1.0"
IgnoredCapture = Literal["presence", "file-sha256"]
IgnoredStatus = Literal["observed", "missing", "unavailable"]
IgnoredKind = Literal["regular-file", "directory", "other"]
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_GLOB_CHARACTERS = frozenset("*?[]{}\\")


def _exact_relative_path(value: object, field: str) -> str:
    """Return one exact normalised repository-relative POSIX path."""
    result = require_string(value, field)
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
        if _IDENTIFIER.fullmatch(evidence_id) is None:
            raise ValueError(
                f"ignored_inventory[{index}].evidence_id must be a portable identifier"
            )
        capture = require_string(data.get("capture"), f"ignored_inventory[{index}].capture")
        if capture not in {"presence", "file-sha256"}:
            raise ValueError(f"ignored_inventory[{index}].capture is unsupported")
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
    reason: str

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
        if status not in {"observed", "missing", "unavailable"}:
            raise ValueError(f"ignored_inventory_evidence[{index}].status is unsupported")
        raw_kind = data.get("observed_kind")
        if raw_kind is not None and raw_kind not in {"regular-file", "directory", "other"}:
            raise ValueError(f"ignored_inventory_evidence[{index}].observed_kind is unsupported")
        raw_size = data.get("byte_size")
        if raw_size is not None and (
            isinstance(raw_size, bool) or not isinstance(raw_size, int) or raw_size < 0
        ):
            raise ValueError(f"ignored_inventory_evidence[{index}].byte_size is invalid")
        raw_digest = data.get("content_sha256")
        if raw_digest is not None and (
            not isinstance(raw_digest, str) or re.fullmatch(r"[0-9a-f]{64}", raw_digest) is None
        ):
            raise ValueError(f"ignored_inventory_evidence[{index}].content_sha256 is invalid")
        evidence = cls(
            evidence_id=declaration.evidence_id,
            path=declaration.path,
            capture=declaration.capture,
            status=cast(IgnoredStatus, status),
            observed_kind=raw_kind,
            byte_size=raw_size,
            content_sha256=raw_digest,
            reason=require_string(
                data.get("reason"), f"ignored_inventory_evidence[{index}].reason"
            ),
        )
        evidence._validate_relation()
        return evidence

    def _validate_relation(self) -> None:
        """Reject contradictory evidence fields."""
        if self.status != "observed" and any(
            value is not None
            for value in (self.observed_kind, self.byte_size, self.content_sha256)
        ):
            raise ValueError("non-observed ignored evidence must not carry observations")
        if self.status == "observed" and self.observed_kind is None:
            raise ValueError("observed ignored evidence requires observed_kind")
        if self.observed_kind == "regular-file" and self.byte_size is None:
            raise ValueError("regular-file ignored evidence requires byte_size")
        if self.capture == "file-sha256" and self.status == "observed":
            if self.observed_kind != "regular-file" or self.content_sha256 is None:
                raise ValueError("file-sha256 evidence requires an observed regular file")
        elif self.content_sha256 is not None:
            raise ValueError("content_sha256 is only permitted for file-sha256 evidence")


def ignored_inventory_digest(evidence: tuple[IgnoredInventoryEvidence, ...]) -> str:
    """Return the canonical identity of one ordered ignored evidence tuple."""
    return canonical_digest([item.to_dict() for item in evidence])


def _unavailable(
    declaration: IgnoredInventoryDeclaration,
    reason: str,
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


def _collect_one(
    root_descriptor: int,
    declaration: IgnoredInventoryDeclaration,
) -> IgnoredInventoryEvidence:
    """Collect one declaration through descriptor-relative no-follow traversal."""
    descriptors: list[int] = []
    parent = root_descriptor
    directory_flags = (
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    parts = PurePosixPath(declaration.path).parts
    try:
        for component in parts[:-1]:
            try:
                descriptor = os.open(component, directory_flags, dir_fd=parent)
            except FileNotFoundError:
                return IgnoredInventoryEvidence(
                    declaration.evidence_id,
                    declaration.path,
                    declaration.capture,
                    "missing",
                    None,
                    None,
                    None,
                    "missing-parent",
                )
            except OSError as exc:
                reason = (
                    "unsafe-parent"
                    if exc.errno in {errno.ELOOP, errno.ENOTDIR}
                    else "inaccessible-parent"
                )
                return _unavailable(declaration, reason)
            descriptors.append(descriptor)
            parent = descriptor
        name = parts[-1]
        try:
            metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return IgnoredInventoryEvidence(
                declaration.evidence_id,
                declaration.path,
                declaration.capture,
                "missing",
                None,
                None,
                None,
                "missing",
            )
        except OSError:
            return _unavailable(declaration, "inaccessible")
        if stat.S_ISLNK(metadata.st_mode):
            return _unavailable(declaration, "symlink")
        if stat.S_ISDIR(metadata.st_mode):
            if declaration.capture == "file-sha256":
                return _unavailable(declaration, "not-regular-file")
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
        if not stat.S_ISREG(metadata.st_mode):
            if declaration.capture == "file-sha256":
                return _unavailable(declaration, "not-regular-file")
            return IgnoredInventoryEvidence(
                declaration.evidence_id,
                declaration.path,
                declaration.capture,
                "observed",
                "other",
                None,
                None,
                "observed",
            )
        try:
            result = read_stable_regular_file_at(
                parent,
                name,
                declaration.path,
                buffer_limit=0,
            )
        except RuntimeError:
            return _unavailable(declaration, "changed-or-inaccessible")
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
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def collect_ignored_inventory(
    inventory: GitInventory,
    declarations: tuple[IgnoredInventoryDeclaration, ...],
    *,
    git_runner: GitRunner,
) -> tuple[IgnoredInventoryEvidence, ...]:
    """Validate and collect all declared ignored paths under one Git identity."""
    tracked = {item.path for item in inventory.files}
    for declaration in declarations:
        if declaration.path in tracked:
            raise ValueError(f"ignored inventory path is tracked: {declaration.path}")
        candidate = Path(declaration.path)
        try:
            ignored = is_git_ignored(
                inventory.root,
                candidate,
                git_runner=git_runner,
                expected_git_provenance=inventory.git_provenance,
            )
        except RuntimeError:
            ignored = any(
                is_git_ignored(
                    inventory.root,
                    parent,
                    git_runner=git_runner,
                    expected_git_provenance=inventory.git_provenance,
                )
                for parent in reversed(candidate.parents)
                if parent != Path(".")
            )
        if not ignored:
            raise ValueError(f"ignored inventory path is not ignored: {declaration.path}")
    root_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
    try:
        root_descriptor = os.open(inventory.root, root_flags)
    except OSError as exc:
        raise RuntimeError("cannot open repository root for ignored inventory") from exc
    try:
        return tuple(_collect_one(root_descriptor, declaration) for declaration in declarations)
    finally:
        os.close(root_descriptor)
