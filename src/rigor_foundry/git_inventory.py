# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Git-tracked repository inventory
"""Load a fail-closed, read-only inventory from one Git repository."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .git_provenance import GitExecutableProvenance, GitRunner, GitTrustPolicy

ContentKind = Literal["text", "binary", "non-utf8", "symlink", "missing", "gitlink", "oversize"]
MAX_TEXT_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class TrackedFile:
    """One Git-tracked repository file.

    Parameters
    ----------
    path:
        POSIX repository-relative path.
    absolute_path:
        Resolved filesystem path below the repository root.
    text:
        UTF-8 text, or ``None`` for binary/non-UTF-8 content.
    content_kind:
        Why content is text or was deliberately not parsed.
    byte_size:
        Stored worktree byte count when available.
    content_digest:
        SHA-256 of the exact worktree bytes or symlink target bytes.

    """

    path: str
    absolute_path: Path
    text: str | None
    content_kind: ContentKind
    byte_size: int
    content_digest: str
    git_mode: str
    object_id: str
    scanned_blob_id: str | None


@dataclass(frozen=True)
class TrackedIndexEntry:
    """One stage-zero Git index entry with its exact mode and object id."""

    path: str
    git_mode: str
    object_id: str


@dataclass(frozen=True)
class GitInventory:
    """Exact Git state and tracked file content for one scan."""

    root: Path
    head: str
    head_tree: str
    object_format: str
    branch: str
    tracked_content_digest: str
    dirty_paths: tuple[str, ...]
    files: tuple[TrackedFile, ...]
    git_provenance: GitExecutableProvenance

    def text_files(self) -> tuple[TrackedFile, ...]:
        """Return tracked UTF-8 text files in repository order."""
        return tuple(item for item in self.files if item.text is not None)


def _run_git(
    runner: GitRunner,
    root: Path,
    *args: str,
    safe_directory: str | None = None,
) -> bytes:
    """Run one fixed-argument Git command and return raw standard output.

    ``safe.directory`` is process-local and restricted to the resolved audit
    root after discovery. Root discovery alone uses Git's wildcard because the
    enclosing worktree is not yet known; no persistent configuration changes.
    """
    safe_value = str(root.resolve()) if safe_directory is None else safe_directory
    try:
        completed = runner.run(
            root,
            "-c",
            f"safe.directory={safe_value}",
            *args,
        )
    except (OSError, RuntimeError) as exc:
        raise RuntimeError(f"git {' '.join(args)} failed for {root}") from exc
    return completed.stdout


def _decode_git_field(value: bytes, field: str) -> str:
    """Decode one Git-controlled UTF-8 field."""
    try:
        decoded = value.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"git returned non-UTF-8 {field}") from exc
    if not decoded:
        raise RuntimeError(f"git returned empty {field}")
    return decoded


def _repository_root(path: Path, runner: GitRunner) -> Path:
    """Resolve the containing Git worktree root."""
    candidate = path.resolve()
    working = candidate if candidate.is_dir() else candidate.parent
    root_text = _decode_git_field(
        _run_git(runner, working, "rev-parse", "--show-toplevel", safe_directory="*"),
        "repository root",
    )
    root = Path(root_text).resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError("Git repository root is not a directory")
    return root


def _tracked_entries(root: Path, runner: GitRunner) -> tuple[TrackedIndexEntry, ...]:
    """Return stage-zero index entries without discarding modes or object ids."""
    raw = _run_git(runner, root, "ls-files", "--stage", "-z")
    entries: list[TrackedIndexEntry] = []
    for record in (part for part in raw.split(b"\0") if part):
        metadata, separator, path_bytes = record.partition(b"\t")
        fields = metadata.split(b" ")
        if not separator or len(fields) != 3:
            raise RuntimeError("Git index returned a malformed staged entry")
        try:
            mode, object_id, stage = (field.decode("ascii") for field in fields)
            path = path_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RuntimeError("Git index contains a non-UTF-8 field") from exc
        if stage != "0":
            raise RuntimeError(f"Git index contains an unresolved stage for {path}")
        if mode not in {"100644", "100755", "120000", "160000"}:
            raise RuntimeError(f"Git index contains unsupported mode {mode} for {path}")
        if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", object_id) is None:
            raise RuntimeError(f"Git index contains an invalid object id for {path}")
        entries.append(TrackedIndexEntry(path=path, git_mode=mode, object_id=object_id))
    paths = tuple(item.path for item in entries)
    if len(paths) != len(set(paths)):
        raise RuntimeError("Git index returned duplicate tracked paths")
    return tuple(sorted(entries, key=lambda item: item.path))


def _dirty_paths(root: Path, runner: GitRunner) -> tuple[str, ...]:
    """Return tracked paths changed in the index or worktree."""
    raw = _run_git(runner, root, "status", "--porcelain=v1", "-z", "--untracked-files=no")
    fields = [field for field in raw.split(b"\0") if field]
    paths: set[str] = set()
    index = 0
    while index < len(fields):
        field = fields[index]
        if len(field) < 4:
            raise RuntimeError("Git status returned a malformed record")
        try:
            path = field[3:].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RuntimeError("Git status contains a non-UTF-8 path") from exc
        paths.add(path)
        if field[:1] in {b"R", b"C"} or field[1:2] in {b"R", b"C"}:
            index += 1
            if index >= len(fields):
                raise RuntimeError("Git status rename record is incomplete")
            try:
                paths.add(fields[index].decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise RuntimeError("Git status contains a non-UTF-8 rename path") from exc
        index += 1
    return tuple(sorted(paths))


def _blob_id(payload: bytes, object_format: str) -> str:
    """Return the Git blob identity for exact bytes without writing an object."""
    digest = hashlib.new(object_format)
    digest.update(f"blob {len(payload)}\0".encode())
    digest.update(payload)
    return digest.hexdigest()


def _file_snapshot(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    """Return descriptor fields that must remain stable during one read."""
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_regular_bytes(
    path: Path,
    relative: str,
    object_format: str,
) -> tuple[int, bytes | None, str, str]:
    """Read one regular file once and derive both content identities.

    Returns
    -------
    tuple[int, bytes | None, str, str]
        Exact byte count, buffered payload for bounded files, SHA-256, and Git
        blob object identifier.

    Raises
    ------
    RuntimeError
        If the path is not one stable regular file for the complete read.
    """
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"cannot open tracked path: {relative}") from exc
    try:
        before = os.fstat(descriptor)
        path_before = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or _file_snapshot(path_before)[:2] != (
            before.st_dev,
            before.st_ino,
        ):
            raise RuntimeError(f"tracked path is not one regular file: {relative}")
        content_digest = hashlib.sha256()
        blob_digest = hashlib.new(object_format)
        blob_digest.update(f"blob {before.st_size}\0".encode())
        buffered = bytearray() if before.st_size <= MAX_TEXT_BYTES else None
        byte_count = 0
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            while chunk := handle.read(1024 * 1024):
                byte_count += len(chunk)
                content_digest.update(chunk)
                blob_digest.update(chunk)
                if buffered is not None:
                    buffered.extend(chunk)
        after = os.fstat(descriptor)
        path_after = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise RuntimeError(f"cannot read tracked path: {relative}") from exc
    finally:
        os.close(descriptor)
    if (
        byte_count != before.st_size
        or _file_snapshot(after) != _file_snapshot(before)
        or _file_snapshot(path_after)[:2] != (before.st_dev, before.st_ino)
    ):
        raise RuntimeError(f"tracked path changed while being read: {relative}")
    payload = None if buffered is None else bytes(buffered)
    return byte_count, payload, content_digest.hexdigest(), blob_digest.hexdigest()


def _read_tracked_file(
    root: Path,
    entry: TrackedIndexEntry,
    object_format: str,
) -> TrackedFile:
    """Read one tracked path without following it outside the worktree."""
    relative = entry.path
    relative_path = Path(relative)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise RuntimeError(f"tracked path escapes repository root: {relative}")
    absolute = root / relative_path
    if entry.git_mode == "160000":
        object_bytes = entry.object_id.encode("ascii")
        return TrackedFile(
            path=relative,
            absolute_path=absolute,
            text=None,
            content_kind="gitlink",
            byte_size=0,
            content_digest=hashlib.sha256(object_bytes).hexdigest(),
            git_mode=entry.git_mode,
            object_id=entry.object_id,
            scanned_blob_id=None,
        )
    if entry.git_mode == "120000":
        if not absolute.is_symlink():
            raise RuntimeError(f"tracked symlink is unavailable: {relative}")
        try:
            target = os.readlink(absolute)
        except OSError as exc:
            raise RuntimeError(f"cannot read tracked symlink: {relative}") from exc
        target_bytes = os.fsencode(target)
        return TrackedFile(
            path=relative,
            absolute_path=absolute,
            text=None,
            content_kind="symlink",
            byte_size=len(target_bytes),
            content_digest=hashlib.sha256(target_bytes).hexdigest(),
            git_mode=entry.git_mode,
            object_id=entry.object_id,
            scanned_blob_id=_blob_id(target_bytes, object_format),
        )
    if absolute.is_symlink():
        raise RuntimeError(f"tracked regular file is a symlink: {relative}")
    if not absolute.exists():
        return TrackedFile(
            path=relative,
            absolute_path=absolute,
            text=None,
            content_kind="missing",
            byte_size=0,
            content_digest=hashlib.sha256(b"").hexdigest(),
            git_mode=entry.git_mode,
            object_id=entry.object_id,
            scanned_blob_id=None,
        )
    if not absolute.is_file():
        return TrackedFile(
            path=relative,
            absolute_path=absolute,
            text=None,
            content_kind="missing",
            byte_size=0,
            content_digest=hashlib.sha256(b"").hexdigest(),
            git_mode=entry.git_mode,
            object_id=entry.object_id,
            scanned_blob_id=None,
        )
    byte_size, payload, content_digest, scanned_blob_id = _read_regular_bytes(
        absolute,
        relative,
        object_format,
    )
    if payload is None:
        return TrackedFile(
            path=relative,
            absolute_path=absolute,
            text=None,
            content_kind="oversize",
            byte_size=byte_size,
            content_digest=content_digest,
            git_mode=entry.git_mode,
            object_id=entry.object_id,
            scanned_blob_id=scanned_blob_id,
        )
    if b"\0" in payload:
        text = None
        content_kind: ContentKind = "binary"
    else:
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            text = None
            content_kind = "non-utf8"
        else:
            content_kind = "text"
    return TrackedFile(
        path=relative,
        absolute_path=absolute,
        text=text,
        content_kind=content_kind,
        byte_size=byte_size,
        content_digest=content_digest,
        git_mode=entry.git_mode,
        object_id=entry.object_id,
        scanned_blob_id=scanned_blob_id,
    )


def _tracked_content_digest(files: tuple[TrackedFile, ...]) -> str:
    """Return an exact deterministic identity for tracked worktree content."""
    payload = [
        {
            "path": item.path,
            "kind": item.content_kind,
            "byte_size": item.byte_size,
            "content_digest": item.content_digest,
            "git_mode": item.git_mode,
            "object_id": item.object_id,
            "scanned_blob_id": item.scanned_blob_id,
        }
        for item in files
    ]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def is_git_ignored(
    root: Path,
    path: Path,
    *,
    git_trust_policy: GitTrustPolicy | None = None,
    git_runner: GitRunner | None = None,
    expected_git_provenance: GitExecutableProvenance | None = None,
) -> bool:
    """Return whether one repository-relative path is covered by Git ignore rules.

    A caller may supply either a trust policy or an already initialised runner
    so tracked-path and ignore checks share one executable identity.
    """
    if git_trust_policy is not None and git_runner is not None:
        raise ValueError("supply either a Git trust policy or an existing runner, not both")
    runner = git_runner or GitRunner(git_trust_policy)
    if (
        expected_git_provenance is not None
        and runner.provenance.identity_digest != expected_git_provenance.identity_digest
    ):
        raise RuntimeError("Git executable provenance does not match expected identity")
    repository = _repository_root(root, runner)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("ignore-check path must be repository-relative")
    try:
        completed = runner.run(
            repository,
            "-c",
            f"safe.directory={repository}",
            "check-ignore",
            "--quiet",
            "--no-index",
            "--",
            path.as_posix(),
            check=False,
        )
    except (OSError, RuntimeError) as exc:
        raise RuntimeError(f"git check-ignore failed for {path}") from exc
    if completed.returncode == 0:
        return True
    if completed.returncode == 1:
        return False
    raise RuntimeError(f"git check-ignore returned {completed.returncode} for {path}")


def load_git_inventory(
    path: Path,
    *,
    git_trust_policy: GitTrustPolicy | None = None,
    git_runner: GitRunner | None = None,
) -> GitInventory:
    """Load one exact read-only repository inventory.

    Parameters
    ----------
    path:
        Repository root or any path inside its Git worktree.
    git_trust_policy:
        Optional operator trust contract used to create one runner.
    git_runner:
        Optional existing runner. Supplying both runner and policy is invalid.

    Returns
    -------
    GitInventory
        Exact HEAD, dirty tracked paths, and tracked file content.

    Raises
    ------
    RuntimeError
        If Git state or tracked paths cannot be read safely.
    ValueError
        If both trust inputs are supplied.

    """
    if git_trust_policy is not None and git_runner is not None:
        raise ValueError("supply either a Git trust policy or an existing runner, not both")
    runner = git_runner or GitRunner(git_trust_policy)
    root = _repository_root(path, runner)
    head = _decode_git_field(_run_git(runner, root, "rev-parse", "HEAD"), "HEAD")
    head_tree = _decode_git_field(
        _run_git(runner, root, "rev-parse", "HEAD^{tree}"),
        "HEAD tree",
    )
    object_format = _decode_git_field(
        _run_git(runner, root, "rev-parse", "--show-object-format"),
        "object format",
    )
    if object_format not in {"sha1", "sha256"}:
        raise RuntimeError(f"Git repository uses unsupported object format: {object_format}")
    branch = _decode_git_field(
        _run_git(runner, root, "rev-parse", "--abbrev-ref", "HEAD"),
        "branch",
    )
    entries = _tracked_entries(root, runner)
    files = tuple(_read_tracked_file(root, entry, object_format) for entry in entries)
    return GitInventory(
        root=root,
        head=head,
        head_tree=head_tree,
        object_format=object_format,
        branch=branch,
        tracked_content_digest=_tracked_content_digest(files),
        dirty_paths=_dirty_paths(root, runner),
        files=files,
        git_provenance=runner.provenance,
    )
