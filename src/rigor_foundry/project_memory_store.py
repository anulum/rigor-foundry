# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — private project-memory generation store
"""Commit immutable records and digest-chained project-memory generations."""

from __future__ import annotations

import hashlib
import os
import stat
from contextlib import suppress
from pathlib import Path

from .internal_storage import (
    atomic_replace_text,
    exclusive_lock,
    resolve_ignored_path,
    write_new_text,
)
from .project_memory_models import ProjectMemoryManifest, ProjectMemoryRecord
from .project_memory_primitives import (
    PROJECT_MEMORY_MAX_CONTENT_BYTES,
    PROJECT_MEMORY_MAX_INDEX_BYTES,
    PROJECT_MEMORY_MAX_MANIFEST_BYTES,
    ProjectMemoryInvalid,
)

PROJECT_MEMORY_ROOT = Path("agentic_project_memory")
PROJECT_MEMORY_MANIFEST = Path("memory_manifest.json")
PROJECT_MEMORY_INDEX = Path("memory_index.md")
PROJECT_MEMORY_HISTORY = Path("history/manifests")
PROJECT_MEMORY_LOCK = Path(".generation.lock")
PROJECT_MEMORY_MAX_HISTORY_ENTRIES = 10_000


class ProjectMemoryStoreInvalid(ValueError):
    """The private store cannot safely accept or expose a generation."""


def _validate_directory(path: Path, label: str) -> None:
    """Require one owner-only, real directory."""
    try:
        metadata = path.stat(follow_symlinks=False)
    except FileNotFoundError as exc:
        raise ProjectMemoryStoreInvalid(f"{label} is missing") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ProjectMemoryStoreInvalid(f"{label} must be an owner-only real directory")


def _ensure_directory(path: Path, label: str) -> None:
    """Create one owner-only directory or verify the existing object."""
    with suppress(FileExistsError):
        path.mkdir(mode=0o700)
    _validate_directory(path, label)


def _read_private_file(path: Path, *, label: str, maximum: int) -> bytes:
    """Read one stable owner-only regular file without following a link."""
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise ProjectMemoryStoreInvalid(f"{label} is unavailable") from exc
        before = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size > maximum
        ):
            raise ProjectMemoryStoreInvalid(f"{label} is not a bounded owner-only regular file")
        payload = bytearray()
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > maximum:
                raise ProjectMemoryStoreInvalid(f"{label} exceeds its byte bound")
        after = os.fstat(descriptor)
        try:
            path_metadata = path.stat(follow_symlinks=False)
        except FileNotFoundError as exc:
            raise ProjectMemoryStoreInvalid(f"{label} changed while being read") from exc
        if (
            (after.st_dev, after.st_ino) != identity
            or (path_metadata.st_dev, path_metadata.st_ino) != identity
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
        ):
            raise ProjectMemoryStoreInvalid(f"{label} changed while being read")
        return bytes(payload)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _private_root(repository_root: Path) -> Path:
    """Resolve and validate the repository's ignored private memory root."""
    try:
        root = resolve_ignored_path(
            repository_root,
            PROJECT_MEMORY_ROOT,
            label="project-memory root",
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise ProjectMemoryStoreInvalid("project-memory root is not safely Git-ignored") from exc
    _validate_directory(root, "project-memory root")
    return root


def _validate_content(record: ProjectMemoryRecord, payload: bytes) -> None:
    """Bind one admissible immutable Markdown payload to its record metadata."""
    if not payload or len(payload) > PROJECT_MEMORY_MAX_CONTENT_BYTES:
        raise ProjectMemoryStoreInvalid("project-memory content byte count is out of bounds")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProjectMemoryStoreInvalid("project-memory content must be UTF-8") from exc
    if text.startswith("\ufeff") or "\x00" in text or not text.endswith("\n"):
        raise ProjectMemoryStoreInvalid(
            "project-memory content must be BOM-free, NUL-free Markdown ending in a newline"
        )
    if len(payload) != record.content_bytes:
        raise ProjectMemoryStoreInvalid(
            "project-memory content byte count does not match metadata"
        )
    if hashlib.sha256(payload).hexdigest() != record.content_sha256:
        raise ProjectMemoryStoreInvalid("project-memory content digest does not match metadata")


def write_project_memory_record(
    repository_root: Path,
    record: ProjectMemoryRecord,
    content: bytes,
) -> Path:
    """Create one immutable private Markdown record.

    Parameters
    ----------
    repository_root:
        Exact Git worktree root containing the ignored private store.
    record:
        Validated metadata whose path, length and digest bind ``content``.
    content:
        Already-admitted UTF-8 Markdown bytes. This function does not classify
        secrets or establish factual truth.

    Returns
    -------
    pathlib.Path
        The newly created immutable content path.

    Raises
    ------
    ProjectMemoryStoreInvalid
        If the private boundary, metadata, content or immutable-create contract
        fails.
    """
    try:
        record = ProjectMemoryRecord.from_dict(record.to_dict(), "record")
    except ProjectMemoryInvalid as exc:
        raise ProjectMemoryStoreInvalid("project-memory record metadata is invalid") from exc
    _validate_content(record, content)
    root = _private_root(repository_root)
    records = root / "records"
    category = records / record.category
    _ensure_directory(records, "project-memory records directory")
    _ensure_directory(category, "project-memory category directory")
    destination = root / record.content_path
    try:
        resolved = resolve_ignored_path(
            repository_root,
            PROJECT_MEMORY_ROOT / Path(record.content_path),
            label="project-memory content",
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise ProjectMemoryStoreInvalid("project-memory content path is unsafe") from exc
    if resolved != destination:
        raise ProjectMemoryStoreInvalid("project-memory content path changed during resolution")
    try:
        write_new_text(destination, content.decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ProjectMemoryStoreInvalid("project-memory immutable content create failed") from exc
    observed = _read_private_file(
        destination,
        label="project-memory content",
        maximum=PROJECT_MEMORY_MAX_CONTENT_BYTES,
    )
    _validate_content(record, observed)
    return destination


def _history_path(root: Path, manifest: ProjectMemoryManifest) -> Path:
    """Return the immutable content-addressed generation path."""
    return (
        root / PROJECT_MEMORY_HISTORY / f"{manifest.generation_id}_{manifest.manifest_sha256}.json"
    )


def _load_manifest(path: Path, label: str) -> ProjectMemoryManifest:
    """Read and validate one private canonical manifest."""
    payload = _read_private_file(path, label=label, maximum=PROJECT_MEMORY_MAX_MANIFEST_BYTES)
    try:
        return ProjectMemoryManifest.from_bytes(payload)
    except ProjectMemoryInvalid as exc:
        raise ProjectMemoryStoreInvalid(f"{label} is invalid") from exc


def _verify_manifest_content(root: Path, manifest: ProjectMemoryManifest) -> None:
    """Verify every current record against its immutable content file."""
    for record in manifest.records:
        path = root / record.content_path
        payload = _read_private_file(
            path,
            label=f"project-memory content {record.record_id}",
            maximum=PROJECT_MEMORY_MAX_CONTENT_BYTES,
        )
        _validate_content(record, payload)


def _validate_transition(
    previous: ProjectMemoryManifest | None,
    candidate: ProjectMemoryManifest,
) -> None:
    """Require an append/supersede/expiry-only current-view transition."""
    if previous is None:
        if candidate.previous_manifest_sha256 is not None:
            raise ProjectMemoryStoreInvalid("initial generation cannot name a predecessor")
        if any(record.supersedes for record in candidate.records):
            raise ProjectMemoryStoreInvalid("initial generation cannot claim unseen supersession")
        return
    if candidate.project_id != previous.project_id:
        raise ProjectMemoryStoreInvalid("project identity cannot change between generations")
    if candidate.previous_manifest_sha256 != previous.manifest_sha256:
        raise ProjectMemoryStoreInvalid("candidate does not name the exact current predecessor")
    if candidate.generated_at <= previous.generated_at:
        raise ProjectMemoryStoreInvalid("generation time must increase monotonically")
    previous_by_id = {record.record_id: record for record in previous.records}
    candidate_by_id = {record.record_id: record for record in candidate.records}
    retained = previous_by_id.keys() & candidate_by_id.keys()
    if any(previous_by_id[record_id] != candidate_by_id[record_id] for record_id in retained):
        raise ProjectMemoryStoreInvalid("an existing record's metadata cannot change")
    introduced = candidate_by_id.keys() - previous_by_id.keys()
    superseded: set[str] = set()
    for record_id in introduced:
        references = set(candidate_by_id[record_id].supersedes)
        if not references <= previous_by_id.keys():
            raise ProjectMemoryStoreInvalid("a new record supersedes an unknown current record")
        if references & candidate_by_id.keys():
            raise ProjectMemoryStoreInvalid("a superseded record cannot remain current")
        if references & superseded:
            raise ProjectMemoryStoreInvalid(
                "one prior record cannot have multiple direct successors"
            )
        superseded.update(references)
    omitted = previous_by_id.keys() - candidate_by_id.keys()
    for record_id in omitted:
        expired = not previous_by_id[record_id].is_current_at(candidate.generated_at)
        if not expired and record_id not in superseded:
            raise ProjectMemoryStoreInvalid(
                "an unexpired current record cannot disappear without supersession"
            )


def _retain_history_manifest(path: Path, payload: bytes) -> None:
    """Create one immutable history object or accept only byte-identical retry."""
    if path.exists() or path.is_symlink():
        observed = _read_private_file(
            path,
            label="project-memory history manifest",
            maximum=PROJECT_MEMORY_MAX_MANIFEST_BYTES,
        )
        if observed != payload:
            raise ProjectMemoryStoreInvalid("history manifest identity collides with other bytes")
        return
    try:
        write_new_text(path, payload.decode("ascii"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ProjectMemoryStoreInvalid("cannot retain immutable history manifest") from exc


def commit_project_memory_generation(
    repository_root: Path,
    manifest: ProjectMemoryManifest,
) -> Path:
    """Commit one validated current view with permanent history.

    The current manifest replacement is the logical commit point. The index is
    written first and accepted only when its digest matches that manifest. An
    interrupted operation therefore fails closed and can retry the same exact
    history object without overwriting it.

    Parameters
    ----------
    repository_root:
        Exact Git worktree root containing the ignored private store.
    manifest:
        Candidate generation built by :class:`ProjectMemoryManifest`.

    Returns
    -------
    pathlib.Path
        Immutable history path for the committed generation.

    Raises
    ------
    ProjectMemoryStoreInvalid
        If content, predecessor, filesystem or generation closure fails.
    """
    try:
        manifest = ProjectMemoryManifest.from_bytes(manifest.to_bytes())
    except ProjectMemoryInvalid as exc:
        raise ProjectMemoryStoreInvalid("candidate project-memory manifest is invalid") from exc
    root = _private_root(repository_root)
    history = root / "history"
    manifests = root / PROJECT_MEMORY_HISTORY
    _ensure_directory(history, "project-memory history directory")
    _ensure_directory(manifests, "project-memory manifest-history directory")
    with exclusive_lock(root / PROJECT_MEMORY_LOCK):
        current_path = root / PROJECT_MEMORY_MANIFEST
        if current_path.exists() or current_path.is_symlink():
            previous = _load_manifest(current_path, "current project-memory manifest")
            previous_history = _history_path(root, previous)
            if (
                _read_private_file(
                    previous_history,
                    label="current project-memory history manifest",
                    maximum=PROJECT_MEMORY_MAX_MANIFEST_BYTES,
                )
                != previous.to_bytes()
            ):
                raise ProjectMemoryStoreInvalid("current predecessor is absent from exact history")
        else:
            previous = None
        _validate_transition(previous, manifest)
        _verify_manifest_content(root, manifest)
        payload = manifest.to_bytes()
        history_path = _history_path(root, manifest)
        _retain_history_manifest(history_path, payload)
        try:
            atomic_replace_text(root / PROJECT_MEMORY_INDEX, manifest.index_text())
            atomic_replace_text(current_path, payload.decode("ascii"))
        except (OSError, UnicodeError, ValueError) as exc:
            raise ProjectMemoryStoreInvalid(
                "cannot replace the derived current generation"
            ) from exc
        loaded = load_project_memory_generation(repository_root)
        if loaded != manifest:
            raise ProjectMemoryStoreInvalid("committed generation did not round-trip exactly")
        return history_path


def load_project_memory_generation(repository_root: Path) -> ProjectMemoryManifest:
    """Load a current generation only when manifest, index, content and history close.

    Parameters
    ----------
    repository_root:
        Exact Git worktree root containing the ignored private store.

    Returns
    -------
    ProjectMemoryManifest
        The verified current active view.

    Raises
    ------
    ProjectMemoryStoreInvalid
        If any current or immutable closure check fails.
    """
    root = _private_root(repository_root)
    manifest = _load_manifest(root / PROJECT_MEMORY_MANIFEST, "current project-memory manifest")
    index = _read_private_file(
        root / PROJECT_MEMORY_INDEX,
        label="current project-memory index",
        maximum=PROJECT_MEMORY_MAX_INDEX_BYTES,
    )
    expected_index = manifest.index_text().encode("utf-8")
    if index != expected_index or hashlib.sha256(index).hexdigest() != manifest.index_sha256:
        raise ProjectMemoryStoreInvalid("current project-memory index does not match its manifest")
    _verify_manifest_content(root, manifest)
    history = _read_private_file(
        _history_path(root, manifest),
        label="current project-memory history manifest",
        maximum=PROJECT_MEMORY_MAX_MANIFEST_BYTES,
    )
    if history != manifest.to_bytes():
        raise ProjectMemoryStoreInvalid("current project-memory manifest is absent from history")
    return manifest


def verify_project_memory_history(repository_root: Path) -> tuple[str, ...]:
    """Verify the complete predecessor chain without making it boot context.

    Parameters
    ----------
    repository_root:
        Exact Git worktree root containing the ignored private store.

    Returns
    -------
    tuple[str, ...]
        Manifest digests from the current generation to the initial one.

    Raises
    ------
    ProjectMemoryStoreInvalid
        If history is ambiguous, missing, cyclic, oversized or inconsistent.
    """
    root = _private_root(repository_root)
    current = load_project_memory_generation(repository_root)
    history_root = root / PROJECT_MEMORY_HISTORY
    _validate_directory(history_root, "project-memory manifest-history directory")
    candidates: dict[str, ProjectMemoryManifest] = {}
    observed_entries = 0
    try:
        entries = os.scandir(history_root)
    except OSError as exc:
        raise ProjectMemoryStoreInvalid("project-memory history cannot be enumerated") from exc
    with entries:
        for entry in entries:
            observed_entries += 1
            if observed_entries > PROJECT_MEMORY_MAX_HISTORY_ENTRIES:
                raise ProjectMemoryStoreInvalid(
                    "project-memory history entry count is out of bounds"
                )
            if not entry.is_file(follow_symlinks=False):
                raise ProjectMemoryStoreInvalid(
                    "project-memory history contains a non-regular entry"
                )
            name = entry.name
            stem, separator, suffix = name.partition("_")
            if (
                not separator
                or len(stem) != 22
                or len(suffix) != 69
                or not suffix.endswith(".json")
            ):
                raise ProjectMemoryStoreInvalid("project-memory history filename is invalid")
            digest = suffix[:-5]
            if digest in candidates:
                raise ProjectMemoryStoreInvalid("project-memory history digest is ambiguous")
            historical = _load_manifest(Path(entry.path), "project-memory history manifest")
            if historical.generation_id != stem or historical.manifest_sha256 != digest:
                raise ProjectMemoryStoreInvalid(
                    "project-memory history filename does not match its manifest"
                )
            _verify_manifest_content(root, historical)
            candidates[digest] = historical
    chain: list[str] = []
    cursor = current
    while True:
        if cursor.manifest_sha256 in chain:
            raise ProjectMemoryStoreInvalid("project-memory history contains a digest cycle")
        chain.append(cursor.manifest_sha256)
        historical_cursor = candidates.get(cursor.manifest_sha256)
        if historical_cursor is None:
            raise ProjectMemoryStoreInvalid("project-memory predecessor is missing from history")
        if historical_cursor != cursor:
            raise ProjectMemoryStoreInvalid(
                "project-memory history digest resolves to other metadata"
            )
        previous_digest = historical_cursor.previous_manifest_sha256
        if previous_digest is None:
            break
        previous = candidates.get(previous_digest)
        if previous is None:
            raise ProjectMemoryStoreInvalid("project-memory predecessor is missing from history")
        if (
            previous.project_id != current.project_id
            or previous.generated_at >= historical_cursor.generated_at
        ):
            raise ProjectMemoryStoreInvalid(
                "project-memory predecessor order or identity is invalid"
            )
        cursor = previous
    return tuple(chain)
