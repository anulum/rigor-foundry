# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — bounded repository file input observations
"""Observe baseline blobs and current Git-domain files without following links."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath

from .audit_primitives import require_integer
from .git_inventory import open_directory_no_follow, read_stable_regular_file_at
from .git_provenance import GitRunner
from .model_primitives import require_git_object
from .policy_read_budget import PolicyReadBudget1
from .repository_git_inputs import RepositoryGitInputs, observe_repository_git_inputs
from .repository_inventory_rows import RepositoryFileRow


@dataclass(frozen=True)
class RepositoryFileInputs:
    """Actual file observations within the observed Git path domain.

    Baseline deletions, every index stage and nonignored untracked paths remain
    represented. Null language and role require a separate classification owner.
    Configured ignored/generated roots, atomic snapshots, authenticated contexts
    and source-access permission are not established by these data.
    """

    git: RepositoryGitInputs
    baseline_files: tuple[RepositoryFileRow, ...]
    current_files: tuple[RepositoryFileRow, ...]
    source_bytes_read: int = field(default=0, compare=False)


@dataclass
class _ByteBudget:
    """Count both complete file observations under one transaction ceiling."""

    maximum_file: int
    remaining: int

    def limit(self) -> int:
        """Return the maximum remaining bytes available to one actual file read."""
        return min(self.maximum_file, self.remaining)

    def consume(self, size: int) -> None:
        """Count complete bytes and refuse an exhausted transaction."""
        if size > self.remaining or size > self.maximum_file:
            raise ValueError("repository file inputs exceed the byte budget")
        self.remaining -= size


def _blob_identity(payload: bytes, object_format: str) -> str:
    """Derive the Git blob identity from the same bytes used for SHA-256."""
    digest = hashlib.new(object_format)
    digest.update(f"blob {len(payload)}\0".encode("ascii"))
    digest.update(payload)
    return digest.hexdigest()


def _metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Select file identity fields that exclude read-induced access times."""
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


def _current_file(
    descriptor: int, relative: str, object_format: str, budget: _ByteBudget
) -> RepositoryFileRow:
    """Inspect a single actual leaf through retained no-follow parent descriptors."""
    parts = PurePosixPath(relative).parts
    parent = os.dup(descriptor)
    before: os.stat_result | None = None
    try:
        for component in parts[:-1]:
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent,
            )
            os.close(parent)
            parent = child
        name = parts[-1]
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if stat.S_ISREG(before.st_mode):
            read = read_stable_regular_file_at(
                parent,
                name,
                relative,
                object_format=object_format,
                buffer_limit=0,
                maximum_bytes=budget.limit(),
            )
            budget.consume(read.byte_size)
            row = RepositoryFileRow(
                relative,
                "regular",
                "100755" if before.st_mode & stat.S_IXUSR else "100644",
                require_git_object(read.git_blob_id, "observed current blob"),
                read.content_digest,
                read.byte_size,
                None,
                None,
            )
        elif stat.S_ISLNK(before.st_mode):
            payload = os.fsencode(os.readlink(name, dir_fd=parent))
            budget.consume(len(payload))
            row = RepositoryFileRow(
                relative,
                "symlink",
                "120000",
                _blob_identity(payload, object_format),
                hashlib.sha256(payload).hexdigest(),
                len(payload),
                None,
                None,
            )
        else:
            row = RepositoryFileRow(relative, "unsupported", None, None, None, None, None, None)
        after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if _metadata_identity(before) != _metadata_identity(after):
            raise ValueError("repository file metadata changed during observation")
        return row
    except FileNotFoundError as exc:
        if before is not None:
            raise ValueError("repository file disappeared during observation") from exc
        return RepositoryFileRow(relative, "deleted", None, None, None, None, None, None)
    except OSError as exc:
        raise RuntimeError(f"cannot inspect repository file path: {relative}") from exc
    finally:
        os.close(parent)


def _baseline_files(
    git: RepositoryGitInputs, descriptor: int, runner: GitRunner, budget: _ByteBudget
) -> tuple[RepositoryFileRow, ...]:
    """Read every baseline blob while retaining gitlinks as separate commit identities."""
    rows: list[RepositoryFileRow] = []
    for entry in git.baseline_entries.entries:
        if entry.mode == "160000":
            rows.append(
                RepositoryFileRow(
                    entry.relative_path,
                    "gitlink",
                    entry.mode,
                    entry.object_id,
                    None,
                    None,
                    None,
                    None,
                )
            )
            continue
        result = runner.run(
            Path(f"/proc/self/fd/{descriptor}"),
            "-c",
            f"safe.directory={git.root}",
            "cat-file",
            "blob",
            entry.object_id,
            output_limit=max(1, budget.limit()),
        )
        budget.consume(len(result.stdout) + len(result.stderr))
        payload = result.stdout
        if _blob_identity(payload, git.object_format) != entry.object_id:
            raise ValueError("baseline blob bytes differ from the Git object identity")
        rows.append(
            RepositoryFileRow(
                entry.relative_path,
                "symlink" if entry.mode == "120000" else "regular",
                entry.mode,
                entry.object_id,
                hashlib.sha256(payload).hexdigest(),
                len(payload),
                None,
                None,
            )
        )
    return tuple(rows)


def observe_repository_file_inputs(
    root: Path,
    *,
    baseline_head: str,
    runner: GitRunner,
    budget: PolicyReadBudget1,
    maximum_paths: int | None = None,
) -> RepositoryFileInputs:
    """Read complete baseline/current bytes within an already-authorised Git domain.

    Parameters
    ----------
    root:
        Exact canonical worktree root selected by the enclosing source owner.
    baseline_head:
        Full explicit baseline commit, independent of the current HEAD.
    runner:
        Actual Git runner already selected under the host's trust policy.
    budget:
        Explicit byte, depth and unique path ceilings, granting no source access.
    maximum_paths:
        Optional nonnegative remaining enclosing path allowance. This may only
        tighten the source/reference ceilings; zero permits an actual empty tree.

    Returns
    -------
    RepositoryFileInputs
        Two agreeing complete file observations and matching bounding Git state.
        Ignored/generated domain completeness and snapshot authority are absent.

    Raises
    ------
    ValueError
        If paths, budgets, Git objects or repeated observations disagree.
    RuntimeError
        If a bounded read, Git command or no-follow traversal refuses.
    """
    if type(budget) is not PolicyReadBudget1 or type(runner) is not GitRunner:
        raise ValueError("actual Git runner and policy read budget are required")
    checked = PolicyReadBudget1.from_dict(budget.to_dict())
    path_ceiling = min(checked.max_sources, checked.max_references)
    maximum = (
        path_ceiling
        if maximum_paths is None
        else require_integer(maximum_paths, "remaining repository paths", minimum=0)
    )
    if maximum > path_ceiling:
        raise ValueError("remaining repository paths exceed the original budget")
    descriptor = open_directory_no_follow(root)
    try:
        original = os.fstat(descriptor)
        git = observe_repository_git_inputs(
            root, baseline_head=baseline_head, runner=runner, budget=checked
        )
        file_budget = _ByteBudget(
            checked.max_source_bytes, checked.max_total_source_bytes - git.source_bytes_read
        )
        paths = tuple(
            sorted(
                {
                    entry.relative_path
                    for entry in (
                        *git.baseline_entries.entries,
                        *git.index.entries,
                    )
                }
                | set(git.untracked_paths)
            )
        )
        if len(paths) > maximum:
            raise ValueError("repository file inputs exceed the path budget")
        if any(len(PurePosixPath(path).parts) > checked.max_depth for path in paths):
            raise ValueError("repository file inputs exceed the path depth budget")

        def read() -> RepositoryFileInputs:
            """Consume the complete fixed path union without dropping unknown rows."""
            return RepositoryFileInputs(
                git,
                _baseline_files(git, descriptor, runner, file_budget),
                tuple(
                    _current_file(descriptor, path, git.object_format, file_budget)
                    for path in paths
                ),
            )

        first, second = read(), read()
        metadata = PolicyReadBudget1.build(
            max_document_bytes=checked.max_document_bytes,
            max_source_bytes=checked.max_source_bytes,
            max_total_source_bytes=file_budget.remaining,
            max_sources=checked.max_sources,
            max_rules=checked.max_rules,
            max_references=checked.max_references,
            max_depth=checked.max_depth,
        )
        closing = observe_repository_git_inputs(
            root, baseline_head=baseline_head, runner=runner, budget=metadata
        )
        with_root = open_directory_no_follow(root)
        try:
            current = os.fstat(with_root)
            if (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError("selected repository directory object changed")
        finally:
            os.close(with_root)
        if first != second or git != closing:
            raise ValueError("repository file input observations changed during capture")
        return replace(
            first,
            source_bytes_read=checked.max_total_source_bytes
            - file_budget.remaining
            + closing.source_bytes_read,
        )
    finally:
        os.close(descriptor)
