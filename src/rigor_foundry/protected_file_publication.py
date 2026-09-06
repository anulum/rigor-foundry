# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — exact protected file publication planning
"""Compile linear file publication effects in the Core v1 operation vocabulary.

No I/O, permission, enrollment, observation or execution is performed. Parents
must exist or be explicitly created by the snapshot-publication API, which also
composes exact file locks. Receipts remain separate. Core is responsible for physical aliases, exact
claim/opcode permissions, content-domain trust and actual durability evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast


@dataclass(frozen=True)
class ProtectedFilePublication:
    """An exact private-file destination and its explicitly named parent.

    Files use mode0600. ``previous=None`` means intended exclusive creation,
    not observed absence; otherwise an exact same-directory temporary path is
    mandatory. Cross-root parent references are allowed for enrolled root-level
    files, but only the trusted physical verifier can establish that relationship.
    Parent mode must match the independently observed existing directory or an
    explicitly planned directory creation.
    """

    root_id: str
    relative_path: str
    parent_root_id: str
    parent_relative_path: str
    parent_mode: str
    previous: bytes | None
    candidate: bytes
    temporary_path: str | None = None


@dataclass(frozen=True)
class PreparedProtectedFilePublication:
    """Canonical operation arrays and raw-SHA-addressed immutable payloads.

    ``operation_fields`` contains exactly operations and auxiliary_operations;
    it is not a complete proposal, signature, grant or activation receipt.
    ``contents`` pairs raw SHA-256 handles with their complete bytes. The caller
    must enroll the explicit raw-byte content domain independently in Core.
    """

    operation_fields: bytes
    contents: tuple[tuple[str, bytes], ...]


@dataclass(frozen=True)
class ProtectedDirectoryCreation:
    """An explicitly absent mode0700 directory and its immediate parent.

    A declaration is not permission, an absence observation or mkdir(parents=True).
    Newly created parents must precede children in the declared tuple. Existing
    parents retain their exact declared modes; no chmod or cleanup is generated.
    """

    root_id: str
    relative_path: str
    parent_root_id: str
    parent_relative_path: str
    parent_mode: str


@dataclass(frozen=True)
class ProtectedFileLock:
    """An exact mode0600 lock inode, retained after release.

    ``previous=None`` declares absent and requires exclusive empty creation and
    durability before acquisition. Bytes declare exact existing content, which
    is never rewritten. Tuple order is the externally agreed acquisition order,
    not discovered sorting or permission to use a caller-selected lock authority.
    Physical custody and nonblocking runtime acquisition remain Core obligations.
    """

    root_id: str
    relative_path: str
    parent_root_id: str
    parent_relative_path: str
    parent_mode: str
    previous: bytes | None


def prepare_protected_snapshot_publication(
    files: tuple[ProtectedFilePublication, ...],
    *,
    snapshots: Mapping[tuple[str, str], ProtectedFilePublication],
    claim_task_id: str,
    content_domain: str,
    max_operations: int,
    max_content_bytes: int,
    directories: tuple[ProtectedDirectoryCreation, ...] = (),
    locks: tuple[ProtectedFileLock, ...] = (),
) -> PreparedProtectedFilePublication:
    """Require durable original-byte snapshots before any business publication.

    ``snapshots`` keys are exact (root_id, relative_path) replacement targets;
    values declare exclusive-create snapshot destinations with the exact prior
    bytes. Every replacement requires one snapshot, including an empty prior
    file. Creates require none. Extra/missing/overwriting/nonidentical snapshots
    are refused, and all snapshot destinations share collision and budget checks
    with business files. Snapshot order follows the original target order,
    independently of input mapping iteration order.

    This is no-I/O preparation, not evidence that snapshots already exist or
    that their namespace is protected. Independently enrolled exact roots and
    parent directories remain prerequisites unless explicitly listed in
    ``directories``. New directories must be needed by this publication and are
    created in the given parent-before-child order, each followed by parent fsync.
    Directory effects count against the same operation budget. On execution failure the
    writer must retain partial files and stop; it may not perform a later target
    write unless every preceding snapshot create/file-fsync/parent-fsync completed.
    No successful activation receipt is synthesized from these intended effects.
    Explicit ``locks`` are acquired in tuple order before snapshots and released
    in reverse order after publication. Missing lock files are created/fsynced
    before acquisition, under independent Core custody; existing ones are never
    replaced. All directories are created before this lock setup. Empty locks
    are supported for composition, not evidence that an activation lock policy
    has been satisfied. Runtime failure stops; this success plan has no cleanup.
    """
    # Reuse the complete public boundary before deriving preservation obligations.
    prepare_protected_file_publication(
        files,
        claim_task_id=claim_task_id,
        content_domain=content_domain,
        max_operations=max_operations,
        max_content_bytes=max_content_bytes,
    )
    expected = {(file.root_id, file.relative_path) for file in files if file.previous is not None}
    if len(snapshots) != len(expected):
        raise ValueError("preservation requires exactly every replacement snapshot")
    supplied = dict(snapshots)
    if set(supplied) != expected:
        raise ValueError("snapshot keys differ from exact replacement targets")
    ordered: list[ProtectedFilePublication] = []
    for file in files:
        if file.previous is None:
            continue
        snapshot = supplied[(file.root_id, file.relative_path)]
        if (
            type(snapshot) is not ProtectedFilePublication
            or snapshot.previous is not None
            or snapshot.temporary_path is not None
            or type(snapshot.candidate) is not bytes
            or snapshot.candidate != file.previous
        ):
            raise ValueError("snapshot must exclusively create exact original bytes")
        ordered.append(snapshot)
    publication = prepare_protected_file_publication(
        (*ordered, *files),
        claim_task_id=claim_task_id,
        content_domain=content_domain,
        max_operations=max_operations,
        max_content_bytes=max_content_bytes,
    )
    publication, context_files = _wrap_locks(
        publication,
        locks,
        (*ordered, *files),
        claim_task_id,
        content_domain,
        max_operations,
        max_content_bytes,
    )
    return _prepend_directories(publication, directories, context_files, max_operations)


def _wrap_locks(
    publication: PreparedProtectedFilePublication,
    locks: tuple[ProtectedFileLock, ...],
    files: tuple[ProtectedFilePublication, ...],
    claim: str,
    domain: str,
    max_operations: int,
    max_content_bytes: int,
) -> tuple[PreparedProtectedFilePublication, tuple[ProtectedFilePublication, ...]]:
    """Compile exact lock setup/acquisition/release around preservation and publication."""
    if type(locks) is not tuple or any(type(lock) is not ProtectedFileLock for lock in locks):
        raise ValueError("lock declarations must be an immutable exact tuple")
    if len(locks) > max_operations // 2:
        raise ValueError("lock count exceeds the operation budget")
    if not locks:
        return publication, files
    declared = tuple(
        ProtectedFilePublication(
            lock.root_id,
            lock.relative_path,
            lock.parent_root_id,
            lock.parent_relative_path,
            lock.parent_mode,
            None,
            b"" if lock.previous is None else lock.previous,
        )
        for lock in locks
    )
    # Validate all cross-phase paths and bytes, not fictitious existing-lock writes.
    # Actual execution operation count is checked below and again with directories.
    body = cast(dict[str, list[dict[str, object]]], json.loads(publication.operation_fields))
    representation_count = (
        len(body["operations"]) + len(body["auxiliary_operations"]) + 4 * len(declared)
    )
    prepare_protected_file_publication(
        (*files, *declared),
        claim_task_id=claim,
        content_domain=domain,
        max_operations=representation_count,
        max_content_bytes=max_content_bytes,
    )
    new_files = tuple(
        file for lock, file in zip(locks, declared, strict=True) if lock.previous is None
    )
    primary: list[dict[str, object]] = []
    setup: list[dict[str, object]] = []
    contents = dict(publication.contents)
    if new_files:
        created = prepare_protected_file_publication(
            new_files,
            claim_task_id=claim,
            content_domain=domain,
            max_operations=max_operations,
            max_content_bytes=max_content_bytes,
        )
        creation = cast(dict[str, list[dict[str, object]]], json.loads(created.operation_fields))
        primary, setup = creation["operations"], creation["auxiliary_operations"]
        for operation in primary + setup:
            operation["operation_id"] = "lock-setup-" + str(operation["operation_id"])
        contents.update(created.contents)
    acquire: list[dict[str, object]] = []
    release: list[dict[str, object]] = []
    for index, lock in enumerate(locks):
        state = _file_state(b"" if lock.previous is None else lock.previous)
        path = _transition(lock.root_id, lock.relative_path, state, state)
        acquire.append(_operation(f"lock-{index:06d}-acquire", "lock", [path]))
        release.append(_operation(f"lock-{index:06d}-release", "unlock", [path]))
    body["operations"] = primary + body["operations"]
    body["auxiliary_operations"] = (
        setup + acquire + body["auxiliary_operations"] + list(reversed(release))
    )
    if len(body["operations"]) + len(body["auxiliary_operations"]) > max_operations:
        raise ValueError("lock effects exceed the combined operation budget")
    context = tuple(
        ProtectedFilePublication(
            file.root_id,
            file.relative_path,
            file.parent_root_id,
            file.parent_relative_path,
            file.parent_mode,
            lock.previous,
            file.candidate,
        )
        for lock, file in zip(locks, declared, strict=True)
    )
    return PreparedProtectedFilePublication(
        json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode(),
        tuple(sorted(contents.items())),
    ), (*files, *context)


def _prepend_directories(
    publication: PreparedProtectedFilePublication,
    directories: tuple[ProtectedDirectoryCreation, ...],
    files: tuple[ProtectedFilePublication, ...],
    max_operations: int,
) -> PreparedProtectedFilePublication:
    """Prepend validated parent-first mkdir/fsync effects without implicit discovery."""
    if type(directories) is not tuple or any(
        type(d) is not ProtectedDirectoryCreation for d in directories
    ):
        raise ValueError("directory declarations must be an immutable exact tuple")
    body = cast(dict[str, list[dict[str, object]]], json.loads(publication.operation_fields))
    if (
        len(body["operations"]) + len(body["auxiliary_operations"]) + 2 * len(directories)
        > max_operations
    ):
        raise ValueError("directory effects exceed the combined operation budget")
    parent_modes = {(f.parent_root_id, f.parent_relative_path): f.parent_mode for f in files}
    for directory in directories:
        _identifier(directory.root_id)
        _identifier(directory.parent_root_id)
        _path(directory.relative_path)
        _path(directory.parent_relative_path)
        _parent_mode(directory.parent_mode)
        parent = directory.parent_root_id, directory.parent_relative_path
        if parent in parent_modes and parent_modes[parent] != directory.parent_mode:
            raise ValueError("directory parent modes contradict another declared parent")
        parent_modes[parent] = directory.parent_mode
    created = {(d.root_id, d.relative_path) for d in directories}
    if len(created) != len(directories):
        raise ValueError("duplicate directory creation")
    occupied = {
        (f.root_id, name)
        for f in files
        for name in (f.relative_path, f.temporary_path)
        if name is not None
    }
    needed = {(f.parent_root_id, f.parent_relative_path) for f in files}
    needed.update((d.parent_root_id, d.parent_relative_path) for d in directories)
    if created & occupied or not created <= needed:
        raise ValueError("directory aliases a file or is unrelated to publication")
    for file in files:
        if (file.parent_root_id, file.parent_relative_path) in created and (
            file.parent_mode != "0700" or file.previous is not None
        ):
            raise ValueError("file precondition contradicts newly created parent")
    seen: set[tuple[str, str]] = set()
    prefix: list[dict[str, object]] = []
    after: dict[str, object] = {"kind": "directory", "mode": "0700"}
    for index, directory in enumerate(directories):
        key = directory.root_id, directory.relative_path
        parent = directory.parent_root_id, directory.parent_relative_path
        if (
            directory.root_id == directory.parent_root_id
            and directory.relative_path.rpartition("/")[0] != directory.parent_relative_path
        ):
            raise ValueError("directory parent is not immediate")
        if parent in created and (parent not in seen or directory.parent_mode != "0700"):
            raise ValueError("new directory parents must precede children with exact mode")
        parent_state: dict[str, object] = {"kind": "directory", "mode": directory.parent_mode}
        identity = f"directory-{index:06d}"
        prefix.append(
            _operation(
                identity + "-create",
                "mkdir",
                [
                    _transition(
                        directory.root_id, directory.relative_path, {"kind": "absent"}, after
                    ),
                ],
            )
        )
        prefix.append(
            _operation(
                identity + "-parent-sync",
                "fsync",
                [
                    _transition(
                        directory.parent_root_id,
                        directory.parent_relative_path,
                        parent_state,
                        parent_state,
                    ),
                ],
            )
        )
        seen.add(key)
    body["auxiliary_operations"] = prefix + body["auxiliary_operations"]
    return PreparedProtectedFilePublication(
        json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode(),
        publication.contents,
    )


def prepare_protected_file_publication(
    files: tuple[ProtectedFilePublication, ...],
    *,
    claim_task_id: str,
    content_domain: str,
    max_operations: int,
    max_content_bytes: int,
) -> PreparedProtectedFilePublication:
    """Expand exact private-file creates/replacements without hidden cleanup.

    Each create is followed by file and parent fsync. Each replacement creates
    its predeclared absent temporary, fsyncs it, renames it over the exact prior
    target and fsyncs the parent. First failure must stop execution and retain
    partial files for separately admitted recovery; this plan has no rollback.
    Input order is preserved, so the consumer can put registry publication last.

    Budgets are positive exact integers. Operation count includes primary and
    auxiliary effects; byte count includes every prior and candidate occurrence,
    even when equal content is stored only once. Invalid paths, declared aliases,
    mutable bytes, excess budgets or inconsistent parent modes raise ValueError.
    This compiler does not resolve symlinks or establish filesystem preconditions.
    """
    for budget in (max_operations, max_content_bytes):
        if type(budget) is not int or not 0 < budget <= 2**53 - 1:
            raise ValueError("publication budgets must be positive exact integers")
    _identifier(claim_task_id)
    _identifier(content_domain)
    if type(files) is not tuple or any(
        type(file) is not ProtectedFilePublication for file in files
    ):
        raise ValueError("publication requires an immutable tuple of exact file declarations")
    if not files or len(files) > max_operations // 4:
        raise ValueError("publication file count exceeds its operation budget")
    paths: set[tuple[str, str]] = set()
    parents: dict[tuple[str, str], str] = {}
    total = 0
    operation_count = 0
    for file in files:
        _identifier(file.root_id)
        _identifier(file.parent_root_id)
        _path(file.relative_path)
        _path(file.parent_relative_path)
        _parent_mode(file.parent_mode)
        parent = file.parent_root_id, file.parent_relative_path
        if parent in parents and parents[parent] != file.parent_mode:
            raise ValueError("publication parent has contradictory modes")
        parents[parent] = file.parent_mode
        if (
            file.root_id == file.parent_root_id
            and file.relative_path.rpartition("/")[0] != file.parent_relative_path
        ):
            raise ValueError("publication parent is not the immediate textual parent")
        if type(file.candidate) is not bytes or (
            file.previous is not None and type(file.previous) is not bytes
        ):
            raise ValueError("publication requires immutable file bytes")
        names = [file.relative_path]
        if file.previous is None:
            if file.temporary_path is not None:
                raise ValueError("exclusive creation cannot declare a replacement temporary")
            operation_count += 4
        else:
            temporary = _path(file.temporary_path)
            if temporary.rpartition("/")[0] != file.relative_path.rpartition("/")[0]:
                raise ValueError("replacement temporary must share the target directory")
            names.append(temporary)
            operation_count += 5
        for name in names:
            key = file.root_id, name
            if key in paths:
                raise ValueError("publication target or temporary collision")
            paths.add(key)
        total += len(file.candidate) + len(file.previous or b"")
    if paths.intersection(parents):
        raise ValueError("publication file aliases a declared parent directory")
    if operation_count > max_operations or total > max_content_bytes:
        raise ValueError("expanded publication exceeds its operation or byte budget")

    primary: list[dict[str, object]] = []
    auxiliary: list[dict[str, object]] = []
    contents: dict[str, bytes] = {}
    absent: dict[str, object] = {"kind": "absent"}
    for index, file in enumerate(files):
        prefix = f"file-{index:06d}"
        after = _file_state(file.candidate)
        before = absent if file.previous is None else _file_state(file.previous)
        digest = hashlib.sha256(file.candidate).hexdigest()
        contents[digest] = file.candidate
        primary.append(
            {
                "operation_id": prefix + "-effect",
                "root_id": file.root_id,
                "relative_path": file.relative_path,
                "claim_task_id": claim_task_id,
                "action": "create" if file.previous is None else "replace",
                "before": before,
                "after_sha256": digest,
                "after_size_bytes": len(file.candidate),
                "mode": "0600",
            }
        )
        write_path = file.temporary_path or file.relative_path
        created = _transition(file.root_id, write_path, absent, after)
        auxiliary.append(
            {
                "operation_id": prefix + "-create",
                "opcode": "create",
                "paths": [created],
                "content_reference": {
                    "domain": content_domain,
                    "handle": digest,
                    "sha256": digest,
                    "size_bytes": len(file.candidate),
                },
            }
        )
        auxiliary.append(
            _operation(
                prefix + "-file-sync",
                "fsync",
                [_transition(file.root_id, write_path, after, after)],
            )
        )
        if file.previous is not None:
            auxiliary.append(
                _operation(
                    prefix + "-publish",
                    "rename",
                    [
                        _transition(file.root_id, write_path, after, absent),
                        _transition(file.root_id, file.relative_path, before, after),
                    ],
                )
            )
        directory: dict[str, object] = {"kind": "directory", "mode": file.parent_mode}
        auxiliary.append(
            _operation(
                prefix + "-parent-sync",
                "fsync",
                [
                    _transition(
                        file.parent_root_id, file.parent_relative_path, directory, directory
                    ),
                ],
            )
        )
    body = {"operations": primary, "auxiliary_operations": auxiliary}
    return PreparedProtectedFilePublication(
        json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("utf-8"),
        tuple(sorted(contents.items())),
    )


def _identifier(value: str) -> None:
    """Require a bounded operation-domain or root identifier."""
    if (
        not isinstance(value, str)
        or len(value) > 256
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]*", value) is None
    ):
        raise ValueError("publication identifier is invalid")


def _parent_mode(value: str) -> None:
    """Require owner directory access while prohibiting group or other writes."""
    if (
        not isinstance(value, str)
        or re.fullmatch(r"0[0-7]{3}", value) is None
        or int(value, 8) & 0o722 != 0o700
    ):
        raise ValueError("publication parent requires owner rwx and no shared write")


def _path(value: str | None) -> str:
    """Require an exact bounded relative path without traversal or wildcard syntax."""
    if (
        not isinstance(value, str)
        or len(value) > 4096
        or any(part in ("", ".", "..") for part in value.split("/"))
        or any(
            ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF or c in "\\*?[]"
            for c in value
        )
    ):
        raise ValueError("publication path must be exact and relative")
    return value


def _file_state(content: bytes) -> dict[str, object]:
    """Describe mode and exact bytes for a private-file transition."""
    return {
        "kind": "file",
        "mode": "0600",
        "sha256": hashlib.sha256(content).hexdigest(),
        "size_bytes": len(content),
    }


def _transition(
    root: str, path: str, before: dict[str, object], after: dict[str, object]
) -> dict[str, object]:
    """Bind before/after metadata to one explicitly named root-relative path."""
    return {"root_id": root, "relative_path": path, "before": before, "after": after}


def _operation(identity: str, opcode: str, paths: list[dict[str, object]]) -> dict[str, object]:
    """Represent a non-content auxiliary effect with its declared transitions."""
    return {"operation_id": identity, "opcode": opcode, "paths": paths, "content_reference": None}
