# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — explicit fail-closed adopter bootstrap
"""Create a new policy and canonical ignored TODO without guessing paths."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .git_inventory import is_git_ignored
from .git_provenance import GitRunner, GitTrustPolicy
from .models import AUDIT_DOMAINS, AuditDomainSpec, AuditPolicy

_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
_DIRECTORY_FLAGS |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_CREATE_FLAGS = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
_CREATE_FLAGS |= getattr(os, "O_NOFOLLOW", 0)

_TODO_TEMPLATE = """# RigorFoundry TODO

> This is the adopter-owned canonical work ledger. Audit output contains
> candidates, not verdicts. Verify production impact and evidence before
> promoting any candidate into an actionable task.
"""


@dataclass(frozen=True)
class BootstrapResult:
    """Paths and policy identity created by one successful bootstrap."""

    policy_path: Path
    todo_path: Path
    policy_digest: str


def _relative_path(value: Path, label: str) -> Path:
    """Return one non-empty normalized repository-relative path."""
    if value.is_absolute() or not value.parts or value == Path(".") or ".." in value.parts:
        raise ValueError(f"{label} must be a normalized repository-relative path")
    return value


def _directory_identity(descriptor: int) -> tuple[int, int]:
    """Return one retained directory descriptor identity."""
    metadata = os.fstat(descriptor)
    return metadata.st_dev, metadata.st_ino


def _open_directory(root_descriptor: int, relative: Path, label: str) -> int:
    """Open an existing relative directory without following components."""
    descriptor = os.dup(root_descriptor)
    try:
        for component in relative.parts:
            next_descriptor = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            _directory_identity(descriptor)
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise ValueError(f"{label} parent must be an existing symlink-free directory") from exc


def _open_parent(root_descriptor: int, relative: Path, label: str) -> tuple[int, str]:
    """Open and retain the exact parent of one new repository path."""
    parent = relative.parent
    descriptor = (
        os.dup(root_descriptor)
        if parent == Path(".")
        else _open_directory(root_descriptor, parent, label)
    )
    return descriptor, relative.name


def _git_tracked(repository: Path, relative: Path, runner: GitRunner) -> bool:
    """Return whether Git already owns one exact repository-relative path."""
    completed = runner.run(
        repository,
        "-c",
        f"safe.directory={repository}",
        "ls-files",
        "--error-unmatch",
        "--",
        relative.as_posix(),
        check=False,
    )
    if completed.returncode == 0:
        return True
    if completed.returncode == 1:
        return False
    raise RuntimeError(f"Git tracked-path check failed for {relative}")


def _reject_existing_symlinks(repository: Path, relative: Path, label: str) -> None:
    """Reject a current symlink component before invoking path-sensitive Git plumbing."""
    cursor = repository
    for component in relative.parts:
        cursor /= component
        if cursor.is_symlink():
            raise ValueError(f"{label} must have symlink-free path components")


def _create_text(
    parent_descriptor: int,
    name: str,
    text: str,
    *,
    mode: int,
    label: str,
) -> tuple[int, int]:
    """Create and synchronize one descriptor-bound regular file exactly once."""
    descriptor: int | None = None
    try:
        descriptor = os.open(name, _CREATE_FLAGS, mode, dir_fd=parent_descriptor)
        os.fchmod(descriptor, mode)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"{label} was not created as a regular file")
        identity = metadata.st_dev, metadata.st_ino
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            descriptor = None
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.fsync(parent_descriptor)
        return identity
    except FileExistsError as exc:
        raise ValueError(f"{label} already exists; bootstrap never overwrites") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _path_identity(parent_descriptor: int, name: str) -> tuple[int, int]:
    """Return one no-follow path identity below a retained parent."""
    metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise RuntimeError("created bootstrap path is no longer a single-link regular file")
    return metadata.st_dev, metadata.st_ino


def _require_absent(parent_descriptor: int, name: str, label: str) -> None:
    """Require one exact no-follow path to remain absent."""
    try:
        os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise ValueError(f"bootstrap never overwrites or adopts an existing {label}")


def _validate_roots(
    repository_descriptor: int,
    values: tuple[Path, ...],
    label: str,
) -> tuple[str, ...]:
    """Validate unique existing source or test roots through retained descriptors."""
    if not values:
        raise ValueError(f"at least one {label} is required")
    validated = tuple(_relative_path(value, label) for value in values)
    serialized = tuple(value.as_posix() for value in validated)
    if len(serialized) != len(set(serialized)):
        raise ValueError(f"{label} values must be unique")
    for relative in validated:
        descriptor = _open_directory(repository_descriptor, relative, label)
        os.close(descriptor)
    return serialized


def _bootstrap_policy(
    *,
    todo_path: Path,
    review_ledger_path: Path,
    source_roots: tuple[str, ...],
    test_roots: tuple[str, ...],
    source_line_threshold: int,
    test_line_threshold: int,
) -> AuditPolicy:
    """Build a round-trip-validated policy whose domains fail closed by default."""
    rationale = "bootstrap default requires adopter evidence before applicability changes"
    policy = AuditPolicy(
        source_line_threshold=source_line_threshold,
        test_line_threshold=test_line_threshold,
        source_roots=source_roots,
        test_roots=test_roots,
        canonical_todo=todo_path.as_posix(),
        review_ledger=review_ledger_path.as_posix(),
        enforcement_mode="observe",
        audit_domains=tuple(
            AuditDomainSpec(name=domain, applicability="required", rationale=rationale)
            for domain in AUDIT_DOMAINS
        ),
    )
    return AuditPolicy.from_dict(policy.to_dict())


def bootstrap_repository(
    repository_root: Path,
    *,
    policy_path: Path,
    todo_path: Path,
    review_ledger_path: Path,
    source_roots: tuple[Path, ...],
    test_roots: tuple[Path, ...],
    source_line_threshold: int = 700,
    test_line_threshold: int = 1000,
    git_trust_policy: GitTrustPolicy | None = None,
) -> BootstrapResult:
    """Create one explicit policy and ignored TODO without guessing or overwrite.

    All three adopter-owned paths and both code-root classes are required. The
    policy path must be trackable, while TODO and review-ledger paths must
    already be covered by Git ignore rules. Existing targets, symlinked path
    components, a non-root worktree path, or a concurrent replacement aborts
    before a successful result is returned.
    """
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise RuntimeError("platform lacks descriptor-bound bootstrap support")
    lexical_root = repository_root.absolute()
    repository = repository_root.resolve(strict=True)
    if lexical_root != repository or not repository.is_dir():
        raise ValueError("repository root must be a real directory without symlink components")
    policy_relative = _relative_path(policy_path, "policy path")
    todo_relative = _relative_path(todo_path, "TODO path")
    ledger_relative = _relative_path(review_ledger_path, "review-ledger path")
    if len({policy_relative, todo_relative, ledger_relative}) != 3:
        raise ValueError("policy, TODO, and review-ledger paths must be distinct")
    for label, relative in (
        ("policy path", policy_relative),
        ("TODO path", todo_relative),
        ("review-ledger path", ledger_relative),
    ):
        _reject_existing_symlinks(repository, relative, label)

    repository_descriptor = os.open(repository, _DIRECTORY_FLAGS)
    policy_parent: int | None = None
    todo_parent: int | None = None
    ledger_parent: int | None = None
    try:
        root_identity = _directory_identity(repository_descriptor)
        runner = GitRunner(git_trust_policy)
        top_level = os.fsdecode(
            runner.run(
                repository,
                "-c",
                f"safe.directory={repository}",
                "rev-parse",
                "--show-toplevel",
            ).stdout.strip()
        )
        if Path(top_level).resolve(strict=True) != repository:
            raise ValueError("repository root must be the exact Git worktree root")
        if _git_tracked(repository, policy_relative, runner):
            raise ValueError("policy path is already tracked; bootstrap never overwrites")
        if is_git_ignored(repository, policy_relative, git_runner=runner):
            raise ValueError("policy path must be trackable, not Git-ignored")
        for label, relative in (
            ("TODO path", todo_relative),
            ("review-ledger path", ledger_relative),
        ):
            if _git_tracked(repository, relative, runner):
                raise ValueError(f"{label} must not be tracked by Git")
            if not is_git_ignored(repository, relative, git_runner=runner):
                raise ValueError(f"{label} must be covered by Git ignore rules")
        root_after_git = os.stat(repository, follow_symlinks=False)
        if (root_after_git.st_dev, root_after_git.st_ino) != root_identity:
            raise RuntimeError("repository root identity changed during Git checks")
        validated_source_roots = _validate_roots(
            repository_descriptor, source_roots, "source root"
        )
        validated_test_roots = _validate_roots(repository_descriptor, test_roots, "test root")
        policy = _bootstrap_policy(
            todo_path=todo_relative,
            review_ledger_path=ledger_relative,
            source_roots=validated_source_roots,
            test_roots=validated_test_roots,
            source_line_threshold=source_line_threshold,
            test_line_threshold=test_line_threshold,
        )
        policy_text = (
            json.dumps(
                policy.to_dict(), ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False
            )
            + "\n"
        )
        policy_parent, policy_name = _open_parent(
            repository_descriptor, policy_relative, "policy path"
        )
        todo_parent, todo_name = _open_parent(repository_descriptor, todo_relative, "TODO path")
        ledger_parent, ledger_name = _open_parent(
            repository_descriptor, ledger_relative, "review-ledger path"
        )
        _require_absent(policy_parent, policy_name, "policy path")
        _require_absent(todo_parent, todo_name, "TODO path")
        _require_absent(ledger_parent, ledger_name, "review-ledger path")
        policy_identity = _create_text(
            policy_parent, policy_name, policy_text, mode=0o644, label="policy path"
        )
        todo_identity = _create_text(
            todo_parent, todo_name, _TODO_TEMPLATE, mode=0o600, label="TODO path"
        )
        root_after = os.stat(repository, follow_symlinks=False)
        if (root_after.st_dev, root_after.st_ino) != root_identity:
            raise RuntimeError("repository root identity changed during bootstrap")
        reopened_policy_parent, _ = _open_parent(
            repository_descriptor, policy_relative, "policy path"
        )
        try:
            if _directory_identity(reopened_policy_parent) != _directory_identity(policy_parent):
                raise RuntimeError("policy parent changed during bootstrap")
        finally:
            os.close(reopened_policy_parent)
        reopened_todo_parent, _ = _open_parent(repository_descriptor, todo_relative, "TODO path")
        try:
            if _directory_identity(reopened_todo_parent) != _directory_identity(todo_parent):
                raise RuntimeError("TODO parent changed during bootstrap")
        finally:
            os.close(reopened_todo_parent)
        reopened_ledger_parent, _ = _open_parent(
            repository_descriptor, ledger_relative, "review-ledger path"
        )
        try:
            if _directory_identity(reopened_ledger_parent) != _directory_identity(ledger_parent):
                raise RuntimeError("review-ledger parent changed during bootstrap")
        finally:
            os.close(reopened_ledger_parent)
        if _path_identity(policy_parent, policy_name) != policy_identity:
            raise RuntimeError("policy path changed during bootstrap")
        if _path_identity(todo_parent, todo_name) != todo_identity:
            raise RuntimeError("TODO path changed during bootstrap")
        _require_absent(ledger_parent, ledger_name, "review-ledger path")
        if _git_tracked(repository, policy_relative, runner) or is_git_ignored(
            repository, policy_relative, git_runner=runner
        ):
            raise RuntimeError("policy Git ownership changed during bootstrap")
        for label, relative in (
            ("TODO path", todo_relative),
            ("review-ledger path", ledger_relative),
        ):
            if _git_tracked(repository, relative, runner) or not is_git_ignored(
                repository, relative, git_runner=runner
            ):
                raise RuntimeError(f"{label} Git ownership changed during bootstrap")
        return BootstrapResult(
            policy_path=repository / policy_relative,
            todo_path=repository / todo_relative,
            policy_digest=policy.policy_digest,
        )
    finally:
        if ledger_parent is not None:
            os.close(ledger_parent)
        if todo_parent is not None:
            os.close(todo_parent)
        if policy_parent is not None:
            os.close(policy_parent)
        os.close(repository_descriptor)
