# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native Windows adopter bootstrap
"""Create adopter files through retained native NTFS directory resources."""

from __future__ import annotations

import json
import os
from contextlib import ExitStack
from pathlib import Path

from .bootstrap import (
    _TODO_TEMPLATE,
    BootstrapResult,
    _bootstrap_policy,
    _git_tracked,
    _relative_path,
)
from .git_inventory import is_git_ignored
from .git_provenance import GitRunner, GitTrustPolicy
from .windows_file_io import write_new_file_at
from .windows_handles import WindowsDirectory


def _relative(value: Path, label: str) -> Path:
    """Require a repository-relative Windows path without drive-relative ambiguity."""
    result = _relative_path(value, label)
    if result.drive or result.root:
        raise ValueError(f"{label} must have no Windows drive or rooted component")
    return result


def _roots(root: WindowsDirectory, values: tuple[Path, ...], label: str) -> tuple[str, ...]:
    """Validate unique existing roots relative to the retained repository."""
    if not values:
        raise ValueError(f"at least one {label} is required")
    relatives = tuple(_relative(value, label) for value in values)
    serialized = tuple(value.as_posix() for value in relatives)
    if len(set(serialized)) != len(serialized):
        raise ValueError(f"{label} values must be unique")
    for relative in relatives:
        with root.open_directory(relative):
            pass
    return serialized


def _absent(parent: WindowsDirectory, name: str, label: str) -> None:
    """Refuse every existing target before any bootstrap creation."""
    try:
        with parent.open_file(name):
            pass
    except FileNotFoundError:
        return
    raise ValueError(f"bootstrap never overwrites or adopts an existing {label}")


def _ownership(repository: Path, runner: GitRunner, paths: tuple[Path, Path, Path]) -> None:
    """Require an untracked trackable policy and two ignored untracked records."""
    policy, todo, ledger = paths
    if _git_tracked(repository, policy, runner):
        raise ValueError("policy path is already tracked; bootstrap never overwrites")
    if is_git_ignored(repository, policy, git_runner=runner):
        raise ValueError("policy path must be trackable, not Git-ignored")
    for label, relative in (("TODO path", todo), ("review-ledger path", ledger)):
        if _git_tracked(repository, relative, runner):
            raise ValueError(f"{label} must not be tracked by Git")
        if not is_git_ignored(repository, relative, git_runner=runner):
            raise ValueError(f"{label} must be covered by Git ignore rules")


def bootstrap_windows_repository(
    repository_root: Path,
    *,
    policy_path: Path,
    todo_path: Path,
    review_ledger_path: Path,
    source_roots: tuple[Path, ...],
    test_roots: tuple[Path, ...],
    source_line_threshold: int,
    test_line_threshold: int,
    git_trust_policy: GitTrustPolicy | None,
) -> BootstrapResult:
    """Bootstrap the exact Windows worktree without adopting existing objects.

    Parameters
    ----------
    repository_root : Path
        Existing absolute local NTFS Git worktree root.
    policy_path, todo_path, review_ledger_path : Path
        Distinct new repository-relative files with pre-existing parents.
    source_roots, test_roots : tuple[Path, ...]
        Explicit existing repository-relative code directories.
    source_line_threshold, test_line_threshold : int
        Positive policy limits validated by the shared policy model.
    git_trust_policy : GitTrustPolicy or None
        Existing caller-selected executable provenance policy.

    Returns
    -------
    BootstrapResult
        Newly created policy and TODO paths with the canonical policy digest.

    Raises
    ------
    ValueError, OSError, RuntimeError
        If worktree identity, ownership, object bindings or creation fail.
        Bootstrap never overwrites existing files or creates the review ledger.
    """
    lexical = repository_root.absolute()
    repository = repository_root.resolve(strict=True)
    if lexical != repository or not repository.is_dir():
        raise ValueError("repository root must be a real directory without symlink components")
    paths = (
        _relative(policy_path, "policy path"),
        _relative(todo_path, "TODO path"),
        _relative(review_ledger_path, "review-ledger path"),
    )
    if len(set(paths)) != 3:
        raise ValueError("policy, TODO, and review-ledger paths must be distinct")
    labels = ("policy path", "TODO path", "review-ledger path")
    with ExitStack() as resources:
        root = resources.enter_context(WindowsDirectory(repository))
        parents = tuple(
            resources.enter_context(root.open_directory(relative.parent)) for relative in paths
        )
        for parent in parents:
            _ = parent.identity
        runner = GitRunner(git_trust_policy)
        top = os.fsdecode(
            runner.run(
                repository,
                "-c",
                f"safe.directory={repository}",
                "rev-parse",
                "--show-toplevel",
            ).stdout.strip()
        )
        if Path(top).resolve(strict=True) != repository:
            raise ValueError("repository root must be the exact Git worktree root")
        _ownership(repository, runner, paths)
        policy = _bootstrap_policy(
            todo_path=paths[1],
            review_ledger_path=paths[2],
            source_roots=_roots(root, source_roots, "source root"),
            test_roots=_roots(root, test_roots, "test root"),
            source_line_threshold=source_line_threshold,
            test_line_threshold=test_line_threshold,
        )
        for parent, relative, label in zip(parents, paths, labels, strict=True):
            _absent(parent, relative.name, label)
        text = (
            json.dumps(
                policy.to_dict(), ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False
            )
            + "\n"
        )
        created = (
            write_new_file_at(parents[0], paths[0].name, text, private=False),
            write_new_file_at(parents[1], paths[1].name, _TODO_TEMPLATE),
        )
        # The property performs the native binding check before returning its cached identity.
        _ = root.identity
        for parent, relative in zip(parents, paths, strict=True):
            with root.open_directory(relative.parent) as reopened:
                _ = parent.identity
                _ = reopened.identity
        for parent, relative, identity in zip(parents[:2], paths[:2], created, strict=True):
            with parent.open_file(relative.name) as file:
                current = file.identity()
                if current.links != 1 or (current.volume, current.file_id) != identity:
                    raise RuntimeError("created bootstrap path identity changed")
        _absent(parents[2], paths[2].name, labels[2])
        _ownership(repository, runner, paths)
        return BootstrapResult(
            policy_path=repository / paths[0],
            todo_path=repository / paths[1],
            policy_digest=policy.policy_digest,
        )
