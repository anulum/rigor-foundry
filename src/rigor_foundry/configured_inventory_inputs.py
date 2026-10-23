# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete configured root input collection
"""Collect every declared Git/directory root without claiming host admission."""

from __future__ import annotations

import os
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath

from .audit_primitives import canonical_digest
from .context_owner_implementation import OwnerImplementationSnapshot, observe_owner_implementation
from .context_source_lease import RetainedContextSource
from .directory_file_inputs import DirectoryFileInputs, observe_directory_file_inputs
from .git_inventory import open_directory_no_follow
from .git_provenance import GitRunner
from .inventory_classification import InventoryFileClassifier
from .inventory_domain import InventoryDomain1, InventoryDomainRoot
from .inventory_source_selection import read_inventory_domain_selection
from .model_primitives import require_git_object, require_identifier
from .policy_read_budget import PolicyReadBudget1
from .repository_file_inputs import RepositoryFileInputs, observe_repository_file_inputs
from .repository_inventory_rows import RepositoryFileRow
from .typed_object_reference import TypedObjectRef1


@dataclass(frozen=True)
class InventoryGitBaseline:
    """One explicit Git baseline; it never supplies directory or generator history."""

    root_id: str
    head: str

    def __post_init__(self) -> None:
        """Refuse malformed root IDs and abbreviated or non-Git commit identities."""
        require_identifier(self.root_id, "inventory baseline root")
        require_git_object(self.head, "inventory baseline commit")


@dataclass(frozen=True)
class ConfiguredRootInput:
    """All original observations for one declared root, including nested duplicates."""

    root: InventoryDomainRoot
    inputs: RepositoryFileInputs | DirectoryFileInputs


@dataclass(frozen=True)
class InventoryPathOwner:
    """Longest declared root for one observed monorepo-relative file or directory.

    This namespace relation does not authenticate an owner, establish generation
    provenance, supply missing history or grant access to a physical source.
    """

    canonical_path: str
    root_id: str


@dataclass(frozen=True)
class ConfiguredInventoryInputs:
    """Every declared root captured under the same retained source selection.

    Captures agree within their own bounded reads, not an atomic cross-root
    snapshot. Directory baselines, generated provenance, required host-domain
    completeness and authenticated context admission remain separate obligations.
    """

    roots: tuple[ConfiguredRootInput, ...]
    path_owners: tuple[InventoryPathOwner, ...]
    domain_reference: TypedObjectRef1
    registry_reference: TypedObjectRef1
    contract_reference: TypedObjectRef1
    source_snapshot_digest: str
    file_source_bytes_read: int


@dataclass
class _CollectionBudget:
    """Bound combined root-capture bytes and retained current topology entries."""

    limits: PolicyReadBudget1
    remaining_bytes: int
    remaining_entries: int

    def git_limits(self) -> PolicyReadBudget1:
        """Give Git only the actual remaining combined capture-byte allowance."""
        if self.remaining_bytes == 0:
            raise ValueError("configured Git inputs exhaust the total byte budget")
        limits = self.limits
        return PolicyReadBudget1.build(
            max_document_bytes=limits.max_document_bytes,
            max_source_bytes=limits.max_source_bytes,
            max_total_source_bytes=self.remaining_bytes,
            max_sources=limits.max_sources,
            max_rules=limits.max_rules,
            max_references=limits.max_references,
            max_depth=limits.max_depth,
        )

    def consume(self, size: int, entries: int) -> None:
        """Keep all actual capture costs within the unchanged combined ceilings."""
        if size > self.remaining_bytes:
            raise ValueError("configured inventory exceeds the combined input budget")
        self.remaining_bytes -= size
        self.remaining_entries -= entries


def _ignored(
    root: InventoryDomainRoot,
    roots: tuple[tuple[InventoryDomainRoot, RepositoryFileInputs], ...],
    monorepo_root: Path,
    runner: GitRunner,
    budget: _CollectionBudget,
) -> None:
    """Require a real containing Git root, untracked scope and actual ignore result."""
    path = PurePosixPath(root.canonical_path)
    containing = tuple(
        item for item in roots if path.is_relative_to(PurePosixPath(item[0].canonical_path))
    )
    if not containing:
        raise ValueError("ignored inventory root has no declared containing Git root")
    parent, inputs = max(
        containing, key=lambda item: len(PurePosixPath(item[0].canonical_path).parts)
    )
    relative = path.relative_to(PurePosixPath(parent.canonical_path))
    if any(
        PurePosixPath(entry.relative_path).is_relative_to(relative)
        for entry in inputs.git.index.entries
    ):
        raise ValueError("ignored inventory root overlaps actual tracked index paths")
    result = runner.run(
        monorepo_root / parent.canonical_path,
        "-c",
        f"safe.directory={monorepo_root / parent.canonical_path}",
        "check-ignore",
        "--quiet",
        "--no-index",
        "--",
        relative.as_posix(),
        check=False,
        output_limit=max(1, min(budget.limits.max_document_bytes, budget.remaining_bytes)),
    )
    budget.consume(len(result.stdout) + len(result.stderr), 0)
    if result.returncode != 0:
        raise ValueError("declared ignored inventory root is not actually ignored")


def _path_owners(
    domain: InventoryDomain1, roots: tuple[ConfiguredRootInput, ...], budget: PolicyReadBudget1
) -> tuple[InventoryPathOwner, ...]:
    """Retain duplicates and refuse disagreeing physical byte/topology observations."""
    files: dict[str, RepositoryFileRow] = {}
    directories: set[str] = set()
    paths: set[str] = set()
    for item in roots:
        base = item.root.canonical_path
        directories.add(base)
        rows = (
            item.inputs.current_files
            if isinstance(item.inputs, RepositoryFileInputs)
            else item.inputs.files
        )
        for row in rows:
            path = base + "/" + row.relative_path
            normalized = replace(row, relative_path=path, object_id=None, language=None, role=None)
            if path in files and files[path] != normalized:
                raise ValueError("overlapping configured roots disagree on current file inputs")
            files[path] = normalized
        if isinstance(item.inputs, DirectoryFileInputs):
            directories.update(base + "/" + name for name in item.inputs.directories)
        paths.update(files)
        paths.update(directories)
        if len(paths) > budget.max_references:
            raise ValueError("configured path ownership exceeds the reference budget")
    if any(path in files and files[path].kind != "unsupported" for path in directories):
        raise ValueError("configured roots disagree on file and directory topology")
    return tuple(
        InventoryPathOwner(
            path,
            max(
                (
                    root
                    for root in domain.roots
                    if PurePosixPath(path).is_relative_to(PurePosixPath(root.canonical_path))
                ),
                key=lambda root: len(PurePosixPath(root.canonical_path).parts),
            ).root_id,
        )
        for path in sorted(paths)
    )


def observe_configured_inventory_inputs(
    *,
    baselines: tuple[InventoryGitBaseline, ...],
    monorepo_root: Path,
    domain_source: RetainedContextSource,
    registry_source: RetainedContextSource,
    contract_source: RetainedContextSource,
    implementation: OwnerImplementationSnapshot,
    runner: GitRunner,
    budget: PolicyReadBudget1,
) -> ConfiguredInventoryInputs:
    """Capture every actual declared root and preserve its complete original inputs.

    Parameters
    ----------
    baselines:
        Sorted exact baseline set for every and only declared Git root.
    monorepo_root:
        Already-authorised canonical physical host root, selected outside requests.
    domain_source, registry_source, contract_source:
        Actual borrowed retained selections, shared with the single-root observer.
    implementation:
        Prior complete package/interpreter observation checked before and after.
    runner:
        Actual Git runner under the enclosing host's executable trust policy.
    budget:
        Unchanged combined file/Git capture bytes, current topology entries and
        path-owner references. Separate code/source reads each retain their own
        original budget; enclosing whole-host resource guards remain required.

    Returns
    -------
    ConfiguredInventoryInputs
        Every declared Git, ignored and generated root, with original baseline/
        index data, current topology and root-specific path labels. Missing roots
        refuse. Directory history and generator provenance are not fabricated;
        path labels do not verify content syntax or qualify language adapters.
    """
    if type(budget) is not PolicyReadBudget1 or type(runner) is not GitRunner:
        raise ValueError("actual Git runner and policy read budget are required")
    limits = PolicyReadBudget1.from_dict(budget.to_dict())
    if type(implementation) is not OwnerImplementationSnapshot:
        raise ValueError("complete inventory implementation observation is required")
    actual = observe_owner_implementation(Path(__file__).absolute().parent, budget=limits)
    if implementation != actual:
        raise ValueError("selected inventory implementation or source identity changed")
    sources = (domain_source, registry_source, contract_source)
    domain = read_inventory_domain_selection(*sources, actual)
    if type(baselines) is not tuple or any(
        type(item) is not InventoryGitBaseline for item in baselines
    ):
        raise ValueError("actual immutable inventory Git baselines are required")
    for baseline in baselines:
        baseline.__post_init__()
    keys = tuple(item.root_id for item in baselines)
    if keys != tuple(sorted(set(keys))) or set(keys) != {
        root.root_id for root in domain.roots if root.source_kind == "git"
    }:
        raise ValueError("baseline roots differ from the complete configured Git selection")
    if not monorepo_root.is_absolute() or ".." in monorepo_root.parts:
        raise ValueError("host monorepo root must be an exact absolute path")
    descriptor = open_directory_no_follow(monorepo_root)
    try:
        opening = os.fstat(descriptor)
        costs = _CollectionBudget(
            limits, limits.max_total_source_bytes, min(limits.max_sources, limits.max_references)
        )
        classifier = InventoryFileClassifier(domain, limits)
        heads = {item.root_id: item.head for item in baselines}
        captured: dict[str, ConfiguredRootInput] = {}
        git_inputs: list[tuple[InventoryDomainRoot, RepositoryFileInputs]] = []
        for root in domain.roots:
            if root.source_kind == "git":
                files = observe_repository_file_inputs(
                    monorepo_root / root.canonical_path,
                    baseline_head=heads[root.root_id],
                    runner=runner,
                    budget=costs.git_limits(),
                    maximum_paths=costs.remaining_entries,
                )
                costs.consume(files.source_bytes_read, len(files.current_files))
                git_inputs.append((root, files))
                captured[root.root_id] = ConfiguredRootInput(
                    root,
                    replace(
                        files,
                        baseline_files=classifier.classify(
                            files.baseline_files, root_id=root.root_id
                        ),
                        current_files=classifier.classify(
                            files.current_files, root_id=root.root_id
                        ),
                    ),
                )
        git_roots = tuple(git_inputs)
        for root in domain.roots:
            if root.source_kind != "git":
                if root.source_kind == "ignored":
                    _ignored(root, git_roots, monorepo_root, runner, costs)
                directory = observe_directory_file_inputs(
                    monorepo_root / root.canonical_path,
                    budget=limits,
                    maximum_total_bytes=costs.remaining_bytes,
                    maximum_entries=costs.remaining_entries,
                )
                costs.consume(
                    directory.source_bytes_read, len(directory.files) + len(directory.directories)
                )
                captured[root.root_id] = ConfiguredRootInput(
                    root,
                    replace(
                        directory,
                        files=classifier.classify(directory.files, root_id=root.root_id),
                    ),
                )
                if root.source_kind == "ignored":
                    _ignored(root, git_roots, monorepo_root, runner, costs)
        roots = tuple(captured[root.root_id] for root in domain.roots)
        owners = _path_owners(domain, roots, limits)
        read_inventory_domain_selection(*sources, actual)
        if observe_owner_implementation(Path(__file__).absolute().parent, budget=limits) != actual:
            raise ValueError("inventory implementation changed during observation")
        closing_descriptor = open_directory_no_follow(monorepo_root)
        try:
            closing = os.fstat(closing_descriptor)
            if (opening.st_dev, opening.st_ino) != (closing.st_dev, closing.st_ino):
                raise ValueError("selected host monorepo directory object changed")
        finally:
            os.close(closing_descriptor)
        snapshot = canonical_digest(
            {
                "implementation_snapshot": actual.snapshot_digest,
                "sources": [
                    {"reference": source.reference.to_dict(), "snapshot_id": source.snapshot_id}
                    for source in sources
                ],
                "root_ids": [root.root.root_id for root in roots],
            }
        )
        return ConfiguredInventoryInputs(
            roots,
            owners,
            domain_source.reference,
            registry_source.reference,
            contract_source.reference,
            snapshot,
            limits.max_total_source_bytes - costs.remaining_bytes,
        )
    finally:
        os.close(descriptor)
