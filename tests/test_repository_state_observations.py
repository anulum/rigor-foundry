# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual complete baseline and repository state tests
"""Retain earlier directory history while observing real later Git and file changes."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict, cast

import pytest
from repository_audit_git_repository import GitRepository
from test_configured_inventory_inputs import CollectionArguments, arguments, declared, private_tree
from test_context_owner_implementation import implementation_budget
from test_inventory_source_observations import SelectedInventory, selection

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.configured_inventory_inputs import InventoryGitBaseline
from rigor_foundry.context_owner_implementation import OwnerImplementationSnapshot
from rigor_foundry.context_producer_contract import ContextProducerContract1
from rigor_foundry.context_source_lease import RetainedContextSource
from rigor_foundry.git_provenance import GitRunner, GitTrustPolicy
from rigor_foundry.inventory_baseline import InventoryBaseline1
from rigor_foundry.inventory_domain import InventoryDomain1, InventoryDomainRoot
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.repository_file_inputs import RepositoryFileInputs
from rigor_foundry.repository_state import RepositoryState1
from rigor_foundry.repository_state_observations import (
    capture_inventory_baseline,
    observe_repository_state,
)
from rigor_foundry.typed_object_reference import TypedObjectRef1


class StateArguments(TypedDict):
    """Exact original retained selections for the public state observer."""

    root_id: str
    baseline_source: RetainedContextSource
    monorepo_root: Path
    domain_source: RetainedContextSource
    registry_source: RetainedContextSource
    contract_source: RetainedContextSource
    implementation: OwnerImplementationSnapshot
    runner: GitRunner
    budget: PolicyReadBudget1


@dataclass(frozen=True)
class StateSelection:
    """Real fixture roots and independently retained earlier baseline source."""

    arguments: StateArguments
    capture_arguments: CollectionArguments
    chosen: SelectedInventory
    baseline: InventoryBaseline1
    baseline_path: Path
    private_file: Path


def retain(
    path: Path, value: InventoryBaseline1 | ContextProducerContract1, budget: PolicyReadBudget1
) -> RetainedContextSource:
    """Write one real source before borrowing its independently selected descriptors."""
    path.parent.mkdir(parents=True)
    payload = json.dumps(value.to_dict()).encode()
    path.write_bytes(payload)
    return RetainedContextSource(
        path,
        reference=TypedObjectRef1.from_dict(value.reference()),
        raw_digest=hashlib.sha256(payload).hexdigest(),
        budget=budget,
    )


@contextmanager
def selected_state(
    root: Path, *, kind: str = "ignored", baseline_format: bool = True, second_git: bool = False
) -> Iterator[StateSelection]:
    """Capture real before-images, then borrow them outside other retained parents."""
    root.mkdir()
    domain = declared(kind=kind)
    if second_git:
        domain = InventoryDomain1.build(
            domain_id=domain.domain_id,
            project_id=domain.project_id,
            roots=(
                *domain.roots,
                InventoryDomainRoot(
                    "secondary",
                    domain.roots[0].canonical_path + "/secondary",
                    "git",
                ),
            ),
            rules=domain.rules,
            budget=implementation_budget(),
        )
    with selection(root / "selection", declared_domain=domain) as chosen:
        private = private_tree(chosen, ignored=kind == "ignored")
        original = arguments(chosen)
        if second_git:
            nested = GitRepository.create(chosen.repository.root / "secondary")
            nested.write_text("secondary.py", "VALUE = 3\n")
            secondary_head = nested.commit()
            ignore = chosen.repository.root / ".gitignore"
            ignore.write_text(ignore.read_text() + "\nsecondary/\n")
            original["baselines"] = (
                *original["baselines"],
                InventoryGitBaseline("secondary", secondary_head),
            )
        data = chosen.arguments["contract_source"].read().to_dict()
        if baseline_format:
            formats = cast(list[dict[str, object]], data["source_formats"])
            formats.append({"kind": "inventory-baseline", "format_version": "1.0"})
            formats.sort(key=lambda item: cast(str, item["kind"]))
        data.pop("contract_digest")
        data["contract_digest"] = canonical_digest(data)
        contract = ContextProducerContract1.from_dict(data, budget=original["budget"])
        with retain(
            root / "contract/source.json", contract, original["budget"]
        ) as contract_source:
            capture_args: CollectionArguments = {**original, "contract_source": contract_source}
            before = capture_inventory_baseline(baseline_id="before-change", **capture_args)
            before_path = root / "baseline/source.json"
            with retain(before_path, before, original["budget"]) as baseline_source:
                state_args: StateArguments = {
                    "root_id": "core",
                    "baseline_source": baseline_source,
                    "monorepo_root": original["monorepo_root"],
                    "domain_source": original["domain_source"],
                    "registry_source": original["registry_source"],
                    "contract_source": contract_source,
                    "implementation": original["implementation"],
                    "runner": original["runner"],
                    "budget": original["budget"],
                }
                yield StateSelection(
                    state_args, capture_args, chosen, before, before_path, private
                )


@pytest.mark.parametrize("kind", ("ignored", "generated"))
def test_actual_state_preserves_all_declared_before_and_current_preimages(
    tmp_path: Path, kind: str
) -> None:
    """Independent directory history, Git preimages and empty topology stay observable."""
    with selected_state(tmp_path / "case", kind=kind) as chosen:
        first = observe_repository_state(**chosen.arguments)
        second = observe_repository_state(**chosen.arguments)
        assert first == second
        assert first.baseline == chosen.baseline
        assert first.state.baseline_inventory_digest == chosen.baseline.baseline_digest
        assert first.state.baseline_head == chosen.chosen.arguments["baseline_head"]
        assert (
            first.state.head
            == chosen.chosen.repository.git_command("rev-parse", "HEAD").stdout.strip()
        )
        assert RepositoryState1.from_dict(first.state.to_dict()) == first.state
        assert tuple(item.root.root_id for item in first.inputs.roots) == ("core", "private")
        assert first.baseline.roots[1].directories == ("scripts", "scripts/empty")
        before_bytes = first.baseline.roots[1].files[0].byte_digest
        chosen.private_file.write_text("VALUE = 20\n")
        changed = observe_repository_state(**chosen.arguments)
        assert changed.baseline.roots[1].files[0].byte_digest == before_bytes
        assert changed.state.baseline_inventory_digest == first.state.baseline_inventory_digest
        assert changed.state.worktree_state_digest != first.state.worktree_state_digest
        assert changed.source_snapshot_digest != first.source_snapshot_digest
        assert (changed.state.generated_state_digest != first.state.generated_state_digest) is (
            kind == "generated"
        )
        chosen.private_file.unlink()
        removed = observe_repository_state(**chosen.arguments)
        assert removed.baseline == first.baseline
        assert removed.state.worktree_state_digest != changed.state.worktree_state_digest
        assert removed.baseline.roots[1].files


def test_git_changes_have_separate_staged_untracked_head_and_before_identities(
    tmp_path: Path,
) -> None:
    """Actual edits, staging, commits and deleted before-images cannot share stale state."""
    with selected_state(tmp_path / "case") as chosen:
        initial = observe_repository_state(**chosen.arguments)
        repository = chosen.chosen.repository
        module = repository.root / "src/module.py"
        module.write_text("VALUE = 5\n")
        edited = observe_repository_state(**chosen.arguments)
        assert edited.state.worktree_state_digest != initial.state.worktree_state_digest
        assert edited.state.index_state_digest == initial.state.index_state_digest
        repository.git_command("add", "src/module.py")
        staged = observe_repository_state(**chosen.arguments)
        assert staged.state.index_state_digest != edited.state.index_state_digest
        repository.write_text("src/new.py", "VALUE = 7\n")
        untracked = observe_repository_state(**chosen.arguments)
        assert untracked.state.untracked_state_digest != staged.state.untracked_state_digest
        repository.write_text("src/new.py", "VALUE = 8\n")
        modified_untracked = observe_repository_state(**chosen.arguments)
        assert (
            modified_untracked.state.untracked_state_digest
            != untracked.state.untracked_state_digest
        )
        head = repository.commit()
        committed = observe_repository_state(**chosen.arguments)
        assert committed.state.head == head != initial.state.head
        assert committed.state.head_tree != initial.state.head_tree
        assert committed.state.baseline_head == initial.state.baseline_head
        module.unlink()
        deleted = observe_repository_state(**chosen.arguments)
        git_inputs = deleted.inputs.roots[0].inputs
        assert isinstance(git_inputs, RepositoryFileInputs)
        assert (
            next(
                row for row in git_inputs.current_files if row.relative_path == "src/module.py"
            ).kind
            == "deleted"
        )
        assert any(row.relative_path == "src/module.py" for row in deleted.baseline.roots[0].files)


def test_topology_unsupported_leaves_and_unknown_labels_are_not_filtered(tmp_path: Path) -> None:
    """A directory-only change and an actual FIFO affect state without reading the FIFO."""
    with selected_state(tmp_path / "case") as chosen:
        initial = observe_repository_state(**chosen.arguments)
        assert any(row.language is None for row in initial.baseline.roots[0].files)
        (chosen.private_file.parent / "new-empty").mkdir()
        changed = observe_repository_state(**chosen.arguments)
        assert changed.state.worktree_state_digest != initial.state.worktree_state_digest
        fifo = chosen.private_file.parent / "channel"
        os.mkfifo(fifo, 0o600)
        unsupported = observe_repository_state(**chosen.arguments)
        private = unsupported.inputs.roots[1].inputs
        assert not isinstance(private, RepositoryFileInputs)
        assert (
            next(row for row in private.files if row.relative_path == "scripts/channel").kind
            == "unsupported"
        )
        assert unsupported.state.worktree_state_digest != changed.state.worktree_state_digest


def test_equal_directory_bytes_do_not_reuse_another_captured_object_identity(
    tmp_path: Path,
) -> None:
    """A real directory replacement preserves content state but changes its source snapshot."""
    with selected_state(tmp_path / "case") as chosen:
        first = observe_repository_state(**chosen.arguments)
        private_root = chosen.private_file.parents[1]
        old = tmp_path / "original-private"
        private_root.rename(old)
        shutil.copytree(old, private_root, symlinks=True)
        changed = observe_repository_state(**chosen.arguments)
        assert changed.state == first.state
        assert changed.baseline == first.baseline
        assert changed.source_snapshot_digest != first.source_snapshot_digest
        before = first.inputs.roots[1].inputs
        after = changed.inputs.roots[1].inputs
        assert not isinstance(before, RepositoryFileInputs)
        assert not isinstance(after, RepositoryFileInputs)
        assert before.root_inode != after.root_inode
        assert before.files == after.files


def test_selecting_another_git_root_preserves_the_entire_domain(tmp_path: Path) -> None:
    """A second real Git root changes its own head fields without narrowing other inputs."""
    with selected_state(tmp_path / "case", second_git=True) as chosen:
        first = observe_repository_state(**chosen.arguments)
        state_args = chosen.arguments.copy()
        state_args["root_id"] = "secondary"
        second = observe_repository_state(**state_args)
        assert first.inputs == second.inputs
        assert tuple(item.root.root_id for item in second.inputs.roots) == (
            "core",
            "private",
            "secondary",
        )
        assert first.state.head != second.state.head
        assert first.state.baseline_inventory_digest == second.state.baseline_inventory_digest
        assert first.state.index_state_digest == second.state.index_state_digest
        assert first.state.worktree_state_digest == second.state.worktree_state_digest


@pytest.mark.parametrize("root_id", ("unknown", "private"))
def test_state_selection_refuses_a_missing_or_non_git_root(tmp_path: Path, root_id: str) -> None:
    """A directory root cannot be relabelled as a fabricated Git state."""
    with selected_state(tmp_path / "case") as chosen:
        state_args = chosen.arguments.copy()
        state_args["root_id"] = root_id
        with pytest.raises(ValueError, match="actually captured declared Git root"):
            observe_repository_state(**state_args)


def test_missing_baseline_format_and_wrong_source_kinds_refuse(tmp_path: Path) -> None:
    """The installed source-format relation remains mandatory even for valid bytes."""
    with selected_state(tmp_path / "case", baseline_format=False) as chosen:
        with pytest.raises(ValueError, match="excludes the selected baseline"):
            observe_repository_state(**chosen.arguments)
        state_args = chosen.arguments.copy()
        state_args["baseline_source"] = chosen.arguments["domain_source"]
        with pytest.raises(ValueError, match="wrong owning kind"):
            observe_repository_state(**state_args)
        state_args["baseline_source"] = cast(RetainedContextSource, {})
        with pytest.raises(ValueError, match="actual retained baseline"):
            observe_repository_state(**state_args)
        state_args = chosen.arguments.copy()
        state_args["budget"] = cast(PolicyReadBudget1, {})
        with pytest.raises(ValueError, match="actual retained baseline"):
            observe_repository_state(**state_args)
        chosen.arguments["baseline_source"].close()
        with pytest.raises(ValueError, match="lease is closed"):
            observe_repository_state(**chosen.arguments)


@pytest.mark.parametrize(
    "fault", ("project", "domain", "registry", "root-set", "root-path", "git-bytes")
)
def test_selected_rehashed_baseline_cannot_replace_actual_scope_or_git_history(
    tmp_path: Path, fault: str
) -> None:
    """Actual complete source comparison follows parsing of independently retained bytes."""
    with selected_state(tmp_path / "case") as chosen:
        before = chosen.baseline
        data = before.to_dict()
        if fault in {"domain", "registry"}:
            field = "domain_reference" if fault == "domain" else "registry_reference"
            old = before.domain_reference if fault == "domain" else before.registry_reference
            data[field] = TypedObjectRef1.build(
                kind=old.kind,
                format_version=old.format_version,
                object_id="foreign",
                object_digest=old.object_digest,
            ).to_dict()
        elif fault == "root-set":
            data["roots"] = cast(list[object], data["roots"])[:1]
        elif fault == "root-path":
            roots = cast(list[dict[str, object]], data["roots"])
            descriptor = cast(dict[str, object], roots[1]["root"])
            roots[1]["root"] = {
                **descriptor,
                "canonical_path": cast(str, descriptor["canonical_path"]) + "/other",
            }
        elif fault == "git-bytes":
            roots = cast(list[dict[str, object]], data["roots"])
            row = cast(list[dict[str, object]], roots[0]["files"])[0]
            row["byte_digest"] = "0" * 64
        else:
            data["project_id"] = "FOREIGN"
        data.pop("baseline_digest")
        data["baseline_digest"] = canonical_digest(data)
        wrong = InventoryBaseline1.from_dict(data, budget=chosen.arguments["budget"])
        with retain(tmp_path / "foreign/source.json", wrong, chosen.arguments["budget"]) as source:
            state_args = chosen.arguments.copy()
            state_args["baseline_source"] = source
            with pytest.raises(ValueError, match=r"baseline.*(differs|preimages differ)"):
                observe_repository_state(**state_args)


def test_late_real_git_process_mutation_is_rejected_by_the_baseline_closing_read(
    tmp_path: Path,
) -> None:
    """A baseline changed after its first read cannot produce a returned state."""
    with selected_state(tmp_path / "case") as chosen:
        tools = tmp_path / "tools"
        tools.mkdir()
        executable = tools / "git"
        trigger = tmp_path / "mutate-now"
        executable.write_text(
            "#!/bin/sh\n"
            f'if [ -f {shlex.quote(str(trigger))} ] && [ "$1" != "--version" ]; then\n'
            f'  printf " " >> {shlex.quote(str(chosen.baseline_path))}\n'
            f"  /usr/bin/rm {shlex.quote(str(trigger))}\n"
            'fi\nexec /usr/bin/git "$@"\n'
        )
        executable.chmod(0o755)
        runner = GitRunner(GitTrustPolicy(trusted_roots=(str(tools),)))
        trigger.write_text("one actual mutation")
        state_args = chosen.arguments.copy()
        state_args["runner"] = runner
        with pytest.raises(ValueError, match="context source file identity changed"):
            observe_repository_state(**state_args)
        assert not trigger.exists()
        with pytest.raises(ValueError, match="context source file identity changed"):
            chosen.arguments["baseline_source"].close()
