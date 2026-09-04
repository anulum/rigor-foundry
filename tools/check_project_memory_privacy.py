# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — fail-closed project-memory privacy guard
"""Keep repo-local project memory private across Git and publication surfaces."""

from __future__ import annotations

import argparse
import os
import stat
import subprocess
from collections.abc import Callable, Collection
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

PRIVATE_ROOT = "agentic_project_memory"
PORTABLE_IGNORE_RULE = f"/{PRIVATE_ROOT}/"
_GIT = "/usr/bin/git"
_MAX_ENTRIES = 10_000
_MAX_INVENTORY_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class PublicationInventory:
    """One named, NUL-delimited repository-relative publication inventory."""

    surface: str
    path: Path


def _redacted_exit_code(
    validator: Callable[[], Collection[object]],
) -> int:
    """Render a fixed result while retaining findings only in process memory."""
    try:
        failed = bool(validator())
    except Exception:
        failed = True
    if failed:
        print("Project-memory privacy guard failed; finding details are redacted.")
        return 1
    print("Project-memory privacy guard passed")
    return 0


def _git(
    root: Path,
    *arguments: str,
    input_data: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run one bounded Git query without a shell or locale-dependent decoding."""
    return subprocess.run(  # nosec B603
        [_GIT, "-C", os.fspath(root), *arguments],
        check=False,
        capture_output=True,
        input=input_data,
        shell=False,
        timeout=10,
    )


def _repository_errors(repository_root: Path) -> tuple[Path | None, list[str]]:
    """Resolve an exact non-symlink Git worktree root."""
    errors: list[str] = []
    try:
        root_status = repository_root.lstat()
        root = repository_root.resolve(strict=True)
    except OSError:
        return None, ["repository-root-unavailable"]
    if stat.S_ISLNK(root_status.st_mode) or not stat.S_ISDIR(root_status.st_mode):
        return None, ["repository-root-not-real-directory"]
    top_level = _git(root, "rev-parse", "--show-toplevel")
    if top_level.returncode != 0:
        return None, ["repository-root-not-git-worktree"]
    try:
        discovered = Path(os.fsdecode(top_level.stdout.rstrip(b"\n"))).resolve(strict=True)
    except (OSError, UnicodeDecodeError):
        return None, ["git-worktree-root-unavailable"]
    if discovered != root:
        errors.append("repository-root-not-worktree-root")
    return root, errors


def _portable_ignore_errors(root: Path) -> list[str]:
    """Require a tracked root-anchored rule whose effective source is ``.gitignore``."""
    ignore_path = root / ".gitignore"
    try:
        ignore_status = ignore_path.lstat()
    except OSError:
        return ["portable-ignore-file-unavailable"]
    if stat.S_ISLNK(ignore_status.st_mode) or not stat.S_ISREG(ignore_status.st_mode):
        return ["portable-ignore-file-not-regular"]

    tracked = _git(root, "ls-files", "--error-unmatch", "--", ".gitignore")
    if tracked.returncode != 0:
        return ["portable-ignore-file-not-cached"]
    try:
        ignore_bytes = ignore_path.read_bytes()
        lines = ignore_bytes.decode("utf-8").splitlines()
    except (OSError, UnicodeError):
        return ["portable-ignore-file-unreadable"]
    cached_content = _git(root, "show", ":0:.gitignore")
    if cached_content.returncode != 0:
        return ["portable-ignore-cache-read-failed"]
    if cached_content.stdout != ignore_bytes:
        return ["portable-ignore-file-index-mismatch"]
    if PORTABLE_IGNORE_RULE not in lines:
        return ["portable-ignore-rule-missing"]

    canary = f"{PRIVATE_ROOT}/.rigor-memory-leak-canary"
    effective = _git(
        root,
        "check-ignore",
        "--no-index",
        "--verbose",
        "-z",
        "--stdin",
        input_data=canary.encode("utf-8") + b"\0",
    )
    if effective.returncode != 0:
        return ["portable-ignore-rule-ineffective"]
    fields = effective.stdout.split(b"\0")
    if len(fields) < 5 or fields[0] != b".gitignore":
        return ["portable-ignore-source-invalid"]
    if fields[2] != b"/agentic_project_memory/":
        return ["portable-ignore-rule-overridden"]
    return []


def _cached_content_errors(root: Path) -> list[str]:
    """Reject tracked, intent-to-add, or force-added private-root entries."""
    cached = _git(root, "ls-files", "--cached", "-z", "--", PRIVATE_ROOT)
    if cached.returncode != 0:
        return ["private-root-cache-query-failed"]
    if cached.stdout:
        return ["private-root-content-cached"]
    return []


def _private_tree_errors(root: Path) -> list[str]:
    """Reject aliases and permissions that expose the private local tree."""
    private_root = root / PRIVATE_ROOT
    try:
        root_status = private_root.lstat()
    except OSError:
        return ["private-root-unavailable"]
    if stat.S_ISLNK(root_status.st_mode) or not stat.S_ISDIR(root_status.st_mode):
        return ["private-root-not-real-directory"]
    errors: list[str] = []
    if stat.S_IMODE(root_status.st_mode) != 0o700:
        errors.append("private-root-mode-invalid")
    if root_status.st_uid != os.getuid():
        errors.append("private-root-owner-invalid")

    pending = [private_root]
    observed = 0
    while pending:
        directory = pending.pop()
        try:
            entries = tuple(os.scandir(directory))
        except OSError:
            errors.append("private-tree-unreadable")
            continue
        observed += len(entries)
        if observed > _MAX_ENTRIES:
            errors.append("private-tree-entry-limit-exceeded")
            break
        for entry in entries:
            try:
                entry_status = entry.stat(follow_symlinks=False)
            except OSError:
                errors.append("private-tree-entry-unavailable")
                continue
            mode = entry_status.st_mode
            if stat.S_ISLNK(mode):
                errors.append("private-tree-symlink")
            elif stat.S_ISDIR(mode):
                if stat.S_IMODE(mode) != 0o700 or entry_status.st_uid != os.getuid():
                    errors.append("private-directory-access-invalid")
                else:
                    pending.append(Path(entry.path))
            elif stat.S_ISREG(mode):
                if (
                    stat.S_IMODE(mode) != 0o600
                    or entry_status.st_uid != os.getuid()
                    or entry_status.st_nlink != 1
                ):
                    errors.append("private-file-access-invalid")
            else:
                errors.append("private-tree-special-file")
    return errors


def _normal_inventory_path(raw: bytes) -> str | None:
    """Decode one exact normalised repository-relative inventory entry."""
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if (
        not value
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or "." in path.parts or ".." in path.parts:
        return None
    if path.as_posix() != value or "//" in value:
        return None
    return value


def _inventory_errors(inventory: PublicationInventory) -> list[str]:
    """Reject malformed inventories and any publication of the private root."""
    if not inventory.surface or any(ord(character) < 33 for character in inventory.surface):
        return ["publication-surface-invalid"]
    try:
        status = inventory.path.lstat()
    except OSError:
        return [f"publication-inventory-unavailable:{inventory.surface}"]
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        return [f"publication-inventory-not-regular:{inventory.surface}"]
    if status.st_size > _MAX_INVENTORY_BYTES:
        return [f"publication-inventory-too-large:{inventory.surface}"]
    try:
        content = inventory.path.read_bytes()
    except OSError:
        return [f"publication-inventory-unreadable:{inventory.surface}"]
    if content and not content.endswith(b"\0"):
        return [f"publication-inventory-not-nul-terminated:{inventory.surface}"]
    errors: list[str] = []
    observed: set[str] = set()
    for raw in content.split(b"\0")[:-1]:
        value = _normal_inventory_path(raw)
        if value is None:
            errors.append(f"publication-inventory-entry-invalid:{inventory.surface}")
        elif value in observed:
            errors.append(f"publication-inventory-entry-duplicate:{inventory.surface}")
        elif value == PRIVATE_ROOT or value.startswith(f"{PRIVATE_ROOT}/"):
            errors.append(f"publication-includes-private-root:{inventory.surface}")
        if value is not None:
            observed.add(value)
    return errors


def project_memory_privacy_errors(
    repository_root: Path,
    inventories: tuple[PublicationInventory, ...] = (),
    required_surfaces: frozenset[str] = frozenset(),
) -> list[str]:
    """Return project-memory privacy violations without reading private content."""
    root, errors = _repository_errors(repository_root)
    if root is None:
        return errors
    surfaces = tuple(inventory.surface for inventory in inventories)
    if len(set(surfaces)) != len(surfaces):
        errors.append("publication-surface-duplicate")
    supplied = frozenset(surfaces)
    if supplied != required_surfaces:
        errors.append("publication-surface-set-mismatch")
    errors.extend(_portable_ignore_errors(root))
    errors.extend(_cached_content_errors(root))
    errors.extend(_private_tree_errors(root))
    for inventory in inventories:
        errors.extend(_inventory_errors(inventory))
    return sorted(set(errors))


def _inventory_argument(value: str) -> PublicationInventory:
    """Parse ``SURFACE=PATH`` without accepting an empty component."""
    surface, separator, path = value.partition("=")
    if not separator or not surface or not path:
        raise argparse.ArgumentTypeError("inventory must use SURFACE=PATH")
    return PublicationInventory(surface=surface, path=Path(path))


def main(argv: list[str] | None = None) -> int:
    """Run the project-memory privacy guard with redacted process output."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--publication-inventory",
        action="append",
        default=[],
        type=_inventory_argument,
        metavar="SURFACE=PATH",
    )
    parser.add_argument(
        "--required-publication-surface",
        action="append",
        default=[],
        metavar="SURFACE",
    )
    arguments = parser.parse_args(argv)
    inventories = tuple(arguments.publication_inventory)
    required = frozenset(arguments.required_publication_surface)
    return _redacted_exit_code(
        lambda: project_memory_privacy_errors(
            arguments.repository_root,
            inventories,
            required,
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
