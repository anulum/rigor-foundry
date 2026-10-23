# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual repository Git input observations
"""Read complete Git index stages and baseline entries through bounded plumbing."""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path

from .git_inventory import open_directory_no_follow
from .git_provenance import GitExecutableProvenance, GitRunner
from .model_primitives import require_git_object
from .policy_read_budget import PolicyReadBudget1
from .repository_inventory_rows import (
    RepositoryIndexState,
    parse_git_index_state,
    require_inventory_path,
)


@dataclass(frozen=True)
class RepositoryGitInputs:
    """Observed Git preimages without file-byte completeness or admission authority.

    Baseline entries retain their exact Git modes and object identities. Current
    index entries retain unresolved stages. Untracked paths cover nonignored Git
    paths; configured ignored/generated roots require their own inventory owner.
    Equality across repeated observations does not prove an atomic filesystem
    snapshot or replace the enclosing host's retained source lifetimes.
    """

    root: Path
    baseline_head: str
    baseline_tree: str
    head: str
    head_tree: str
    object_format: str
    baseline_entries: RepositoryIndexState
    index: RepositoryIndexState
    untracked_paths: tuple[str, ...]
    status_bytes: bytes
    git_provenance: GitExecutableProvenance
    source_bytes_read: int = field(default=0, compare=False)


def parse_git_baseline_entries(
    payload: bytes, *, budget: PolicyReadBudget1
) -> RepositoryIndexState:
    """Parse bounded ``git ls-tree -r -z --full-tree`` bytes without discarding modes.

    The returned stage-zero entries describe the baseline tree, independently of
    the current index. No Git process, source selection or file traversal occurs.
    """
    if type(budget) is not PolicyReadBudget1:
        raise ValueError("policy read budget is required")
    budget = PolicyReadBudget1.from_dict(budget.to_dict())
    if not isinstance(payload, bytes) or len(payload) > budget.max_document_bytes:
        raise ValueError("Git baseline bytes exceed the document budget or have invalid type")
    if payload and not payload.endswith(b"\0"):
        raise ValueError("Git baseline tree output lacks its final NUL")
    if payload.count(b"\0") > budget.max_references:
        raise ValueError("Git baseline tree exceeds the reference budget")
    converted = bytearray()
    for row in payload.split(b"\0")[:-1]:
        metadata, separator, path = row.partition(b"\t")
        fields = metadata.split(b" ")
        if not separator or len(fields) != 3:
            raise ValueError("Git baseline tree has a malformed entry")
        mode, kind, identity = fields
        if kind != (b"commit" if mode == b"160000" else b"blob"):
            raise ValueError("Git baseline tree has an inconsistent object kind")
        converted.extend(mode + b" " + identity + b" 0\t" + path + b"\0")
    return parse_git_index_state(bytes(converted), budget=budget)


def parse_git_untracked_paths(payload: bytes, *, budget: PolicyReadBudget1) -> tuple[str, ...]:
    """Parse bounded ``git ls-files --others --exclude-standard -z`` output.

    Every returned portable path is retained. Ambiguous encodings, duplicates
    and incomplete or over-budget input refuse; no filesystem access occurs.
    """
    if type(budget) is not PolicyReadBudget1:
        raise ValueError("policy read budget is required")
    budget = PolicyReadBudget1.from_dict(budget.to_dict())
    if not isinstance(payload, bytes) or len(payload) > budget.max_document_bytes:
        raise ValueError("Git untracked bytes exceed the document budget or have invalid type")
    if payload and not payload.endswith(b"\0"):
        raise ValueError("Git untracked output lacks its final NUL")
    if payload.count(b"\0") > budget.max_references:
        raise ValueError("Git untracked paths exceed the reference budget")
    paths = tuple(require_inventory_path(raw.decode("utf-8")) for raw in payload.split(b"\0")[:-1])
    if len(paths) != len(set(paths)):
        raise ValueError("Git untracked paths contain duplicate entries")
    return tuple(sorted(paths))


def observe_repository_git_inputs(
    root: Path,
    *,
    baseline_head: str,
    runner: GitRunner,
    budget: PolicyReadBudget1,
) -> RepositoryGitInputs:
    """Observe an exact already-authorised root without stage-zero or path filters.

    Parameters
    ----------
    root:
        Canonical absolute Git worktree root selected by the owning host. The
        caller must already hold source-access permission and snapshot guards.
    baseline_head:
        Full explicit commit identity; an unborn or missing baseline refuses.
    runner:
        Actual installed Git runner selected under the host's trust policy.
    budget:
        Explicit per-command output and row ceilings. These grant no authority.

    Returns
    -------
    RepositoryGitInputs
        Two equal observations of baseline/current Git preimages. The result
        does not contain current file bytes or an inventory completeness proof.

    Raises
    ------
    ValueError
        If the explicit root, identity, budget or observations disagree.
    RuntimeError
        If bounded Git execution or component-safe traversal is unavailable.
    """
    if type(runner) is not GitRunner or type(budget) is not PolicyReadBudget1:
        raise ValueError("actual Git runner and policy read budget are required")
    budget = PolicyReadBudget1.from_dict(budget.to_dict())
    baseline = require_git_object(baseline_head, "baseline commit")
    if not root.is_absolute() or ".." in root.parts:
        raise ValueError("repository root must be an exact absolute path")
    descriptor = open_directory_no_follow(root)
    try:
        original = os.fstat(descriptor)
        cwd = Path(f"/proc/self/fd/{descriptor}")
        total = 0

        def read() -> RepositoryGitInputs:
            """Read actual plumbing from the same retained directory object."""

            def command(*arguments: str) -> bytes:
                """Count complete outputs under both per-document and transaction ceilings."""
                nonlocal total
                result = runner.run(
                    cwd,
                    "-c",
                    f"safe.directory={root}",
                    *arguments,
                    output_limit=budget.max_document_bytes,
                )
                total += len(result.stdout) + len(result.stderr)
                if total > budget.max_total_source_bytes:
                    raise ValueError("Git input transaction exceeds the total byte budget")
                return result.stdout

            def identity(expression: str) -> str:
                """Resolve a full object through Git without revision-name fallback."""
                return require_git_object(
                    command("rev-parse", "--verify", "--end-of-options", expression)
                    .decode("ascii")
                    .removesuffix("\n"),
                    "observed Git object",
                )

            if command("rev-parse", "--show-toplevel").decode("utf-8").removesuffix("\n") != str(
                root
            ):
                raise ValueError("selected path differs from the actual Git worktree root")
            if identity(baseline + "^{commit}") != baseline:
                raise ValueError("baseline must identify the exact commit object")
            head = identity("HEAD^{commit}")
            head_tree = identity(head + "^{tree}")
            baseline_tree = identity(baseline + "^{tree}")
            object_format = command("rev-parse", "--show-object-format").decode("ascii").strip()
            if object_format not in {"sha1", "sha256"} or any(
                len(value) != (40 if object_format == "sha1" else 64)
                for value in (baseline, baseline_tree, head, head_tree)
            ):
                raise ValueError("repository Git object identities have inconsistent formats")
            return RepositoryGitInputs(
                root,
                baseline,
                baseline_tree,
                head,
                head_tree,
                object_format,
                parse_git_baseline_entries(
                    command("ls-tree", "-r", "-z", "--full-tree", baseline), budget=budget
                ),
                parse_git_index_state(command("ls-files", "--stage", "-z"), budget=budget),
                parse_git_untracked_paths(
                    command("ls-files", "--others", "--exclude-standard", "-z"), budget=budget
                ),
                command("status", "--porcelain=v1", "-z", "--untracked-files=all"),
                runner.provenance,
            )

        first, second = read(), read()
        current_descriptor = open_directory_no_follow(root)
        try:
            current = os.fstat(current_descriptor)
            if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
                raise ValueError("selected repository directory object changed")
        finally:
            os.close(current_descriptor)
        if first != second:
            raise ValueError("Git input observations changed during capture")
        return replace(first, source_bytes_read=total)
    finally:
        os.close(descriptor)
