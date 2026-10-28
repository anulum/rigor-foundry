# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual maintained inventory source owner tests
"""Keep real retained before/current inputs and verify their actual owning entry."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TypedDict, cast

import pytest
from test_configured_inventory_inputs import arguments, declared, private_tree
from test_context_owner_implementation import implementation_budget, package
from test_inventory_source_observations import SelectedInventory, selection

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.context_owner_implementation import (
    OwnerImplementationSnapshot,
    observe_owner_implementation,
)
from rigor_foundry.context_producer_contract import ContextProducerContract1, ContextRootBinding
from rigor_foundry.context_source_lease import RetainedContextSource
from rigor_foundry.git_provenance import GitRunner
from rigor_foundry.inventory_baseline import InventoryBaseline1
from rigor_foundry.inventory_domain import InventoryClassificationRule, InventoryDomain1
from rigor_foundry.inventory_source_owner import InventorySourceOwner, OwnedMaintainedInventory
from rigor_foundry.maintained_inventory import MaintainedInventory1
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.repository_state import RepositoryState1
from rigor_foundry.repository_state_observations import (
    RepositoryStateObservation,
    capture_inventory_baseline,
    observe_repository_state,
)
from rigor_foundry.task_definition import TaskDefinition1
from rigor_foundry.task_registry_source_owners import (
    OwnedSourceObservations,
    TaskRegistrySourceOwners,
)
from rigor_foundry.typed_object_reference import TypedObjectRef1


@dataclass(frozen=True)
class OwnerSelection:
    """Actual original sources and fixed owner entries used by public integrations."""

    owner: InventorySourceOwner
    tasks: TaskRegistrySourceOwners
    chosen: SelectedInventory
    private_file: Path
    budget: PolicyReadBudget1
    sources: tuple[RetainedContextSource, ...]


class OwnerArguments(TypedDict):
    """Exact public owner constructor inputs for deliberately invalid boundary cases."""

    monorepo_root: Path
    domain_source: RetainedContextSource
    registry_source: RetainedContextSource
    contract_source: RetainedContextSource
    baseline_source: RetainedContextSource
    state_source: RetainedContextSource
    implementation: OwnerImplementationSnapshot
    runner: GitRunner
    budget: PolicyReadBudget1


def owner_arguments(chosen: OwnerSelection) -> OwnerArguments:
    """Use original actual selections without accessing a production owner's internals."""
    args = chosen.chosen.arguments
    return {
        "monorepo_root": args["monorepo_root"],
        "domain_source": args["domain_source"],
        "registry_source": args["registry_source"],
        "contract_source": chosen.sources[0],
        "baseline_source": chosen.sources[1],
        "state_source": chosen.sources[2],
        "implementation": args["implementation"],
        "runner": args["runner"],
        "budget": chosen.budget,
    }


def retain_source(
    path: Path,
    target: InventoryBaseline1 | ContextProducerContract1 | RepositoryState1 | TaskDefinition1,
    budget: PolicyReadBudget1,
) -> RetainedContextSource:
    """Persist a source outside other held parents before borrowing its exact bytes."""
    path.parent.mkdir(parents=True)
    payload = json.dumps(target.to_dict()).encode()
    path.write_bytes(payload)
    return RetainedContextSource(
        path,
        reference=TypedObjectRef1.from_dict(target.reference()),
        raw_digest=hashlib.sha256(payload).hexdigest(),
        budget=budget,
    )


@contextmanager
def owner_selection(
    root: Path, *, fault: str = "", generated: bool = False
) -> Iterator[OwnerSelection]:
    """Create actual Git/private roots and independently retained baseline/state sources."""
    root.mkdir()
    domain = declared(kind="generated" if generated else "ignored")
    rules = (
        domain.rules
        if fault == "unclassified"
        else (
            *domain.rules,
            InventoryClassificationRule("core", "language", "exact", "unclassified", "text"),
            InventoryClassificationRule("core", "role", "exact", "unclassified", "fixture"),
            InventoryClassificationRule("core", "role", "prefix", "tools", "tool"),
        )
    )
    domain = InventoryDomain1.build(
        domain_id=domain.domain_id,
        project_id=domain.project_id,
        roots=domain.roots,
        rules=tuple(
            sorted(
                rules,
                key=lambda item: (item.root_id, item.field, item.selector_kind, item.selector),
            )
        ),
        budget=implementation_budget(),
    )
    with selection(root / "selected", declared_domain=domain) as chosen, ExitStack() as stack:
        private = private_tree(chosen, ignored=not generated)
        original = arguments(chosen)
        limits = original["budget"]
        data = chosen.arguments["contract_source"].read().to_dict()
        formats = cast(list[dict[str, object]], data["source_formats"])
        formats.append({"kind": "inventory-baseline", "format_version": "1.0"})
        formats.sort(key=lambda row: cast(str, row["kind"]))
        if fault == "state-format":
            data["source_formats"] = [row for row in formats if row["kind"] != "repository-state"]
        if fault == "subjects":
            data["subject_kinds"] = ["repository-state"]
        data["fact_references"] = (
            []
            if fault == "inventory-facts"
            else sorted(
                [
                    "inventory.roots",
                    "inventory.languages",
                    "inventory.roles",
                    "inventory.changed_paths",
                    "inventory.repository_state",
                ]
            )
        )
        if fault == "owner-collision":
            data["owner_id"] = "task-owner"
        data.pop("contract_digest")
        data["contract_digest"] = canonical_digest(data)
        contract = ContextProducerContract1.from_dict(data, budget=limits)
        contract_source = stack.enter_context(
            retain_source(root / "inventory-contract/source.json", contract, limits)
        )
        capture_arguments = original.copy()
        capture_arguments["contract_source"] = contract_source
        before = capture_inventory_baseline(baseline_id="before-change", **capture_arguments)
        if fault == "before-unclassified":
            earlier = before.to_dict()
            roots = cast(list[dict[str, object]], earlier["roots"])
            files = cast(list[dict[str, object]], roots[1]["files"])
            files[0]["language"] = None
            earlier.pop("baseline_digest")
            earlier["baseline_digest"] = canonical_digest(earlier)
            before = InventoryBaseline1.from_dict(earlier, budget=limits)
        if fault == "removed":
            private.unlink()
        if fault == "staged":
            module = chosen.repository.root / "src/module.py"
            module.write_text("VALUE = 9\n")
            chosen.repository.git_command("add", "src/module.py")
            module.write_text("VALUE = 1\n")
        if fault == "missing-bytes":
            new = chosen.repository.write_text("src/staged.py", "VALUE = 3\n")
            chosen.repository.git_command("add", "src/staged.py")
            new.unlink()
        if fault == "symlink":
            (chosen.repository.root / "src/alias.py").symlink_to("module.py")
        if fault == "unsupported":
            os.mkfifo(private.parent / "channel")
        if fault == "unknown-role":
            chosen.repository.write_text("root.py", "VALUE = 1\n")
        if fault == "unmerged":
            oid = chosen.repository.git_command("rev-parse", "HEAD:src/module.py").stdout.strip()
            payload = (
                "0 "
                + "0" * 40
                + "\tsrc/module.py\n"
                + "".join(f"100644 {oid} {stage}\tsrc/module.py\n" for stage in (1, 2, 3))
            )
            subprocess.run(
                [
                    chosen.repository.git,
                    "-C",
                    str(chosen.repository.root),
                    "update-index",
                    "--index-info",
                ],
                input=payload,
                text=True,
                capture_output=True,
                check=True,
                timeout=5,
            )
        baseline = stack.enter_context(
            retain_source(root / "baseline/source.json", before, limits)
        )
        state = observe_repository_state(
            root_id="core",
            baseline_source=baseline,
            monorepo_root=original["monorepo_root"],
            domain_source=original["domain_source"],
            registry_source=original["registry_source"],
            contract_source=contract_source,
            implementation=original["implementation"],
            runner=original["runner"],
            budget=limits,
        ).state
        state_source = stack.enter_context(
            retain_source(root / "state/source.json", state, limits)
        )
        task = TaskDefinition1.build(
            task_id="source-work",
            revision="1",
            actor_ids=("actor",),
            project_id="PROJECT-A",
            group_id="GROUP-A",
            root_ids=("core",),
            statement="Verify all maintained project sources.",
            lifecycle="active",
            budget=limits,
        )
        task_source = stack.enter_context(retain_source(root / "task/source.json", task, limits))
        task_facts = tuple(
            sorted(
                [
                    "task.id",
                    "task.revision",
                    "task.actor",
                    "task.project",
                    "task.group",
                    "task.root",
                    "task.lifecycle",
                ]
            )
        )
        registry_facts = tuple(
            sorted(
                [
                    "project.id",
                    "project.group",
                    "project.lifecycle",
                    "project.target_kind",
                    "project.visibility",
                    "project.memory_state",
                    "registry.generation",
                    "registry.digest",
                ]
            )
        )
        task_roots = tuple(
            ContextRootBinding(
                row.root_id,
                row.project_id,
                row.group_id,
                row.canonical_path + "/alternate" if fault == "root-path" else row.canonical_path,
                "a" * 64 if fault == "root-scope" else row.configured_scope_digest,
            )
            for row in contract.root_bindings
        )
        task_contract = ContextProducerContract1.build(
            contract_id="task-contract",
            owner_id="task-owner",
            owner_class="task",
            implementation_id="builtin.task-definition.v1",
            implementation_digest=original["implementation"].implementation_digest,
            source_formats=(
                ("project-registry", "gotm-project-registry.v1"),
                ("task-definition", "1.0"),
            ),
            subject_kinds=("task-identity",),
            fact_references=() if fault == "task-facts" else task_facts,
            root_bindings=task_roots,
            budget=limits,
        )
        registry_contract = ContextProducerContract1.build(
            contract_id="registry-contract",
            owner_id="registry-owner",
            owner_class="registry",
            implementation_id="builtin.project-registry.v1",
            implementation_digest=original["implementation"].implementation_digest,
            source_formats=(("project-registry", "gotm-project-registry.v1"),),
            subject_kinds=("registry-generation",),
            fact_references=() if fault == "registry-facts" else registry_facts,
            root_bindings=task_roots,
            budget=limits,
        )
        task_contract_source = stack.enter_context(
            retain_source(root / "task-contract/source.json", task_contract, limits)
        )
        registry_contract_source = stack.enter_context(
            retain_source(root / "registry-contract/source.json", registry_contract, limits)
        )
        tasks = stack.enter_context(
            TaskRegistrySourceOwners(
                task_source=task_source,
                registry_source=original["registry_source"],
                task_contract=task_contract_source,
                registry_contract=registry_contract_source,
                implementation=original["implementation"],
                budget=limits,
            )
        )
        owner = InventorySourceOwner(
            monorepo_root=original["monorepo_root"],
            domain_source=original["domain_source"],
            registry_source=original["registry_source"],
            contract_source=contract_source,
            baseline_source=baseline,
            state_source=state_source,
            implementation=original["implementation"],
            runner=original["runner"],
            budget=limits,
        )
        yield OwnerSelection(
            owner, tasks, chosen, private, limits, (contract_source, baseline, state_source)
        )
        owner.close()


@pytest.mark.parametrize("generated", (False, True))
def test_actual_owner_preserves_every_root_and_generates_verifiable_proof_preimages(
    tmp_path: Path, generated: bool
) -> None:
    """Full actual before/current roots survive metadata generation and round-trip."""
    with owner_selection(tmp_path / "case", generated=generated) as chosen:
        first = chosen.owner.observe()
        chosen.owner.verify(first)
        assert first.inventory.root_ids == ("core", "private")
        assert (
            MaintainedInventory1.from_dict(first.inventory.to_dict(), budget=chosen.budget)
            == first.inventory
        )
        assert (
            first.inventory.repository_state_digest == first.capture.state.repository_state_digest
        )
        assert first.inventory.baseline_inventory_digest == first.capture.baseline.baseline_digest
        assert first.change.proof.subject_digest != first.inventory.inventory_digest
        assert first.completeness.proof.subject_digest != first.inventory.inventory_digest
        first.change.observation.verify_proof_binding(first.change.proof, budget=chosen.budget)
        first.completeness.observation.verify_proof_binding(
            first.completeness.proof, budget=chosen.budget
        )
        assert any(
            item.root_id == "private" and item.relative_path == "scripts/tool.py"
            for item in first.inventory.surfaces
        )
        assert first.capture.baseline.roots[1].directories == ("scripts", "scripts/empty")
        assert chosen.owner.observe() == first


@pytest.mark.parametrize("fault", ("removed", "staged"))
def test_real_deleted_before_image_and_index_only_change_remain_in_acceptance(
    tmp_path: Path, fault: str
) -> None:
    """Deletion keeps earlier bytes; staged divergence cannot disappear behind equal worktree bytes."""
    with owner_selection(tmp_path / "case", fault=fault) as chosen:
        result = chosen.owner.observe()
        values = {item.reference: item.value for item in result.change.observation.observations}
        changed = cast(tuple[str, ...], values["inventory.changed_paths"])
        if fault == "removed":
            surface = next(item for item in result.inventory.surfaces if item.root_id == "private")
            assert (
                surface.content_digest
                == surface.baseline_content_digest
                == hashlib.sha256(b"VALUE = 2\n").hexdigest()
            )
            assert any(path.endswith("scripts/tool.py") for path in changed)
        else:
            assert any(path.endswith("src/module.py") for path in changed)
            surface = next(
                item for item in result.inventory.surfaces if item.relative_path == "src/module.py"
            )
            assert surface.content_digest == surface.baseline_content_digest


@pytest.mark.parametrize("fault", ("unclassified", "before-unclassified", "unknown-role"))
def test_unknown_classification_holds_instead_of_shrinking_the_inventory(
    tmp_path: Path, fault: str
) -> None:
    """An actual included unclassified file refuses even when the task names another path."""
    with owner_selection(tmp_path / "case", fault=fault) as chosen:
        with pytest.raises(ValueError, match="classification is unresolved"):
            chosen.owner.observe()
        with pytest.raises(ValueError, match="classification is unresolved"):
            chosen.owner.close()
        chosen.owner.close()
        with pytest.raises(ValueError, match="selection is closed"):
            chosen.owner.observe()


def test_changed_real_root_refuses_a_previously_retained_state_and_proof(tmp_path: Path) -> None:
    """Actual current bytes, not a matching self-digest, determine state currency."""
    with owner_selection(tmp_path / "case") as chosen:
        previous = chosen.owner.observe()
        chosen.private_file.write_text("VALUE = 77\n")
        with pytest.raises(ValueError, match="state differs from actual"):
            chosen.owner.verify(previous)
        with pytest.raises(ValueError, match="state differs from actual"):
            chosen.owner.close()
        retained = chosen.sources[2].read()
        assert type(retained) is RepositoryState1
        assert retained.repository_state_digest == previous.inventory.repository_state_digest


@pytest.mark.parametrize("field", ("budget", "runner", "domain_source", "implementation"))
def test_constructor_requires_actual_borrowed_source_runner_code_and_budget_types(
    tmp_path: Path, field: str
) -> None:
    """Request metadata cannot replace a fixed source object or executable owner."""
    with owner_selection(tmp_path / "case") as chosen:
        invalid = cast(OwnerArguments, {**owner_arguments(chosen), field: {}})
        with pytest.raises(ValueError):
            InventorySourceOwner(**invalid)


def test_wrong_state_kind_and_other_real_implementation_selection_refuse(tmp_path: Path) -> None:
    """A valid foreign source or a genuinely observed different package is still wrong."""
    with owner_selection(tmp_path / "case") as chosen:
        args = owner_arguments(chosen)
        args["state_source"] = args["domain_source"]
        with pytest.raises(ValueError, match="wrong fixed owning kind"):
            InventorySourceOwner(**args)
        args = owner_arguments(chosen)
        args["implementation"] = observe_owner_implementation(
            package(tmp_path / "another-package"), budget=chosen.budget
        )
        with pytest.raises(ValueError, match="owner implementation changed"):
            InventorySourceOwner(**args)


def test_inventory_metadata_forgery_foreign_entry_and_context_lifetime_refuse(
    tmp_path: Path,
) -> None:
    """Public verification recomputes actual sources and retains owner-entry identity."""
    with owner_selection(tmp_path / "case") as chosen:
        original = chosen.owner.observe()
        with pytest.raises(ValueError, match="actual owned maintained"):
            chosen.owner.verify(cast(OwnedMaintainedInventory, {}))
        invalid_values = (
            replace(original, inventory=cast(MaintainedInventory1, {})),
            replace(original, change=cast(OwnedSourceObservations, {})),
            replace(original, completeness=cast(OwnedSourceObservations, {})),
        )
        for invalid in invalid_values:
            with pytest.raises(ValueError, match="actual owned maintained"):
                chosen.owner.verify(invalid)
        data = original.inventory.to_dict()
        data.pop("inventory_digest")
        data["registry_generation_id"] = "foreign-generation"
        data["inventory_digest"] = canonical_digest(data)
        changed = MaintainedInventory1.from_dict(data, budget=chosen.budget)
        with pytest.raises(ValueError, match="actual selected source owner"):
            chosen.owner.verify(replace(original, inventory=changed))
        with pytest.raises(ValueError, match="actual selected source owner"):
            chosen.owner.verify(replace(original, capture=cast(RepositoryStateObservation, {})))
        with InventorySourceOwner(**owner_arguments(chosen)) as other:
            assert other is not chosen.owner
            with pytest.raises(ValueError, match="actual selected source owner"):
                other.verify(original)
        with pytest.raises(ValueError, match="selection is closed"):
            other.observe()


@pytest.mark.parametrize(
    ("fault", "message"),
    [
        ("missing-bytes", "byte history is unresolved"),
        ("unsupported", "byte history is unresolved"),
        ("unmerged", "unmerged inventory stages"),
    ],
)
def test_actual_missing_subjects_bytes_or_unmerged_index_hold_ready_inventory(
    tmp_path: Path, fault: str, message: str
) -> None:
    """Original Git stages and actual retained contract domains cannot be waived."""
    with owner_selection(tmp_path / "case", fault=fault) as chosen:
        with pytest.raises(ValueError, match=message):
            chosen.owner.observe()
        with pytest.raises(ValueError, match=message):
            chosen.owner.close()


@pytest.mark.parametrize(
    ("fault", "message"),
    [
        ("state-format", "requires a repository state source format"),
        ("subjects", "subject kinds differ"),
    ],
)
def test_required_inventory_formats_and_subjects_refuse_at_the_original_parser(
    tmp_path: Path, fault: str, message: str
) -> None:
    """The real public setup cannot produce an owner with an invalid fixed contract."""
    with ExitStack() as stack, pytest.raises(ValueError, match=message):
        stack.enter_context(owner_selection(tmp_path / "case", fault=fault))


def test_actual_symlink_surface_binds_link_bytes_without_dereferencing_target(
    tmp_path: Path,
) -> None:
    """The maintained path identifies the observed link rather than its target's code."""
    with owner_selection(tmp_path / "case", fault="symlink") as chosen:
        value = chosen.owner.observe()
        link = next(
            item for item in value.inventory.surfaces if item.relative_path == "src/alias.py"
        )
        assert link.content_digest == hashlib.sha256(b"module.py").hexdigest()
        assert link.content_digest != hashlib.sha256(b"VALUE = 1\n").hexdigest()
        assert link.baseline_content_digest is None
        assert (chosen.chosen.repository.root / "src/alias.py").is_symlink()
