# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
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
import shutil
import subprocess  # nosec B404
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

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


@dataclass(frozen=True)
class GitInventory:
    """Exact Git state and tracked file content for one scan."""

    root: Path
    head: str
    head_tree: str
    branch: str
    tracked_content_digest: str
    dirty_paths: tuple[str, ...]
    files: tuple[TrackedFile, ...]

    def text_files(self) -> tuple[TrackedFile, ...]:
        """Return tracked UTF-8 text files in repository order."""
        return tuple(item for item in self.files if item.text is not None)


def _git_executable() -> str:
    """Return a verified absolute Git executable path."""
    located = shutil.which("git")
    if located is None:
        raise RuntimeError("git executable is unavailable")
    try:
        resolved = Path(located).resolve(strict=True)
    except (OSError, ValueError) as exc:
        raise RuntimeError("git executable cannot be resolved") from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise RuntimeError("resolved git path is not executable")
    return str(resolved)


def _run_git(root: Path, *args: str, safe_directory: str | None = None) -> bytes:
    """Run one fixed-argument Git command and return raw standard output.

    ``safe.directory`` is process-local and restricted to the resolved audit
    root after discovery. Root discovery alone uses Git's wildcard because the
    enclosing worktree is not yet known; no persistent configuration changes.
    """
    executable = _git_executable()
    safe_value = str(root.resolve()) if safe_directory is None else safe_directory
    try:
        completed = subprocess.run(  # nosec B603
            [executable, "-c", f"safe.directory={safe_value}", *args],
            cwd=root,
            check=True,
            capture_output=True,
            shell=False,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
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


def _repository_root(path: Path) -> Path:
    """Resolve the containing Git worktree root."""
    candidate = path.resolve()
    working = candidate if candidate.is_dir() else candidate.parent
    root_text = _decode_git_field(
        _run_git(working, "rev-parse", "--show-toplevel", safe_directory="*"),
        "repository root",
    )
    root = Path(root_text).resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError("Git repository root is not a directory")
    return root


def _tracked_paths(root: Path) -> tuple[str, ...]:
    """Return all tracked paths without interpreting shell characters."""
    raw = _run_git(root, "ls-files", "-z")
    try:
        paths = tuple(part.decode("utf-8") for part in raw.split(b"\0") if part)
    except UnicodeDecodeError as exc:
        raise RuntimeError("Git index contains a non-UTF-8 path") from exc
    if len(paths) != len(set(paths)):
        raise RuntimeError("Git index returned duplicate tracked paths")
    return tuple(sorted(paths))


def _dirty_paths(root: Path) -> tuple[str, ...]:
    """Return tracked paths changed in the index or worktree."""
    raw = _run_git(root, "status", "--porcelain=v1", "-z", "--untracked-files=no")
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


def _read_tracked_file(root: Path, relative: str) -> TrackedFile:
    """Read one tracked path without following it outside the worktree."""
    relative_path = Path(relative)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise RuntimeError(f"tracked path escapes repository root: {relative}")
    absolute = root / relative_path
    if absolute.is_symlink():
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
        )
    if not absolute.exists():
        return TrackedFile(
            path=relative,
            absolute_path=absolute,
            text=None,
            content_kind="missing",
            byte_size=0,
            content_digest=hashlib.sha256(b"").hexdigest(),
        )
    if absolute.is_dir():
        return TrackedFile(
            path=relative,
            absolute_path=absolute,
            text=None,
            content_kind="gitlink",
            byte_size=0,
            content_digest=hashlib.sha256(b"").hexdigest(),
        )
    if not absolute.is_file():
        return TrackedFile(
            path=relative,
            absolute_path=absolute,
            text=None,
            content_kind="missing",
            byte_size=0,
            content_digest=hashlib.sha256(b"").hexdigest(),
        )
    try:
        byte_size = absolute.stat().st_size
        if byte_size > MAX_TEXT_BYTES:
            return TrackedFile(
                path=relative,
                absolute_path=absolute,
                text=None,
                content_kind="oversize",
                byte_size=byte_size,
                content_digest=_stream_digest(absolute),
            )
        payload = absolute.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"cannot read tracked path: {relative}") from exc
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
        byte_size=len(payload),
        content_digest=hashlib.sha256(payload).hexdigest(),
    )


def _stream_digest(path: Path) -> str:
    """Return SHA-256 for a large tracked file without loading it into memory."""
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as exc:
        raise RuntimeError(f"cannot hash tracked path: {path}") from exc
    return digest.hexdigest()


def _tracked_content_digest(files: tuple[TrackedFile, ...]) -> str:
    """Return an exact deterministic identity for tracked worktree content."""
    payload = [
        {
            "path": item.path,
            "kind": item.content_kind,
            "byte_size": item.byte_size,
            "content_digest": item.content_digest,
        }
        for item in files
    ]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def is_git_ignored(root: Path, path: Path) -> bool:
    """Return whether one repository-relative path is covered by Git ignore rules."""
    repository = _repository_root(root)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("ignore-check path must be repository-relative")
    executable = _git_executable()
    try:
        completed = subprocess.run(  # nosec B603
            [
                executable,
                "-c",
                f"safe.directory={repository}",
                "check-ignore",
                "--quiet",
                "--no-index",
                "--",
                path.as_posix(),
            ],
            cwd=repository,
            check=False,
            capture_output=True,
            shell=False,
        )
    except OSError as exc:
        raise RuntimeError(f"git check-ignore failed for {path}") from exc
    if completed.returncode == 0:
        return True
    if completed.returncode == 1:
        return False
    raise RuntimeError(f"git check-ignore returned {completed.returncode} for {path}")


def load_git_inventory(path: Path) -> GitInventory:
    """Load one exact read-only repository inventory.

    Parameters
    ----------
    path:
        Repository root or any path inside its Git worktree.

    Returns
    -------
    GitInventory
        Exact HEAD, dirty tracked paths, and tracked file content.

    Raises
    ------
    RuntimeError
        If Git state or tracked paths cannot be read safely.

    """
    root = _repository_root(path)
    head = _decode_git_field(_run_git(root, "rev-parse", "HEAD"), "HEAD")
    head_tree = _decode_git_field(
        _run_git(root, "rev-parse", "HEAD^{tree}"),
        "HEAD tree",
    )
    branch = _decode_git_field(
        _run_git(root, "rev-parse", "--abbrev-ref", "HEAD"),
        "branch",
    )
    paths = _tracked_paths(root)
    files = tuple(_read_tracked_file(root, relative) for relative in paths)
    return GitInventory(
        root=root,
        head=head,
        head_tree=head_tree,
        branch=branch,
        tracked_content_digest=_tracked_content_digest(files),
        dirty_paths=_dirty_paths(root),
        files=files,
    )
