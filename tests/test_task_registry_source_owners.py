# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real task and registry source ownership tests
"""Verify generated values against actual retained sources and complete code inputs."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

import pytest
from test_context_owner_implementation import implementation_budget
from test_project_registry_models import registry

import rigor_foundry.task_registry_source_owners as source_owners_module
from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.context_owner_implementation import (
    OwnerImplementationSnapshot,
    observe_owner_implementation,
)
from rigor_foundry.context_owner_observations import OwnerObservation
from rigor_foundry.context_owner_proof import OwnerProof1
from rigor_foundry.context_producer_contract import ContextProducerContract1, ContextRootBinding
from rigor_foundry.context_source_lease import RetainedContextSource
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.task_definition import TaskDefinition1
from rigor_foundry.task_registry_source_owners import (
    OwnedSourceObservations,
    TaskRegistrySourceOwners,
)
from rigor_foundry.typed_object_reference import TypedObjectRef1


@dataclass(frozen=True)
class SelectedSources:
    """Actual host fixture inputs whose paths remain outside the request wire."""

    owners: TaskRegistrySourceOwners
    sources: tuple[RetainedContextSource, ...]
    paths: tuple[Path, ...]
    implementation: OwnerImplementationSnapshot


@contextmanager
def selection(root: Path, *, fault: str = "") -> Iterator[SelectedSources]:
    """Construct actual canonical registry/task/contracts and retain all four sources."""
    root.mkdir()
    limits = implementation_budget()
    code = observe_owner_implementation(Path(source_owners_module.__file__).parent, budget=limits)
    registered = registry()
    task = TaskDefinition1.build(
        task_id="general-work",
        revision="1",
        actor_ids=("actor",),
        project_id="FOREIGN" if fault == "missing-project" else "PROJECT-A",
        group_id="GROUP-B" if fault == "task-group" else "GROUP-A",
        root_ids=("foreign",) if fault == "task-root" else ("code", "tests"),
        statement="Verify registered work.",
        lifecycle="active",
        budget=limits,
    )
    bindings = tuple(
        ContextRootBinding(
            identity,
            "PROJECT-A",
            "GROUP-B" if fault == "binding-group" else "GROUP-A",
            "unrelated/src"
            if fault == "binding-path"
            else f"03_CODE/GROUP-A/repositories/PROJECT-A/{part}",
            "b" * 64,
        )
        for identity, part in [("code", "src"), ("tests", "tests")]
    )
    task_facts = tuple(
        sorted(
            (
                "task.id",
                "task.revision",
                "task.actor",
                "task.project",
                "task.group",
                "task.root",
                "task.lifecycle",
            )
        )
    )
    registry_facts = tuple(
        sorted(
            (
                "project.id",
                "project.group",
                "project.lifecycle",
                "project.target_kind",
                "project.visibility",
                "project.memory_state",
                "registry.generation",
                "registry.digest",
            )
        )
    )
    task_contract = ContextProducerContract1.build(
        contract_id="task-contract",
        owner_id="task-owner",
        owner_class="task",
        implementation_id="builtin.task-definition.v1",
        implementation_digest="a" * 64
        if fault == "implementation"
        else code.implementation_digest,
        source_formats=(
            ("project-registry", "gotm-project-registry.v1"),
            ("task-definition", "1.0"),
        ),
        subject_kinds=("task-identity",),
        fact_references=() if fault == "identity-only" else task_facts,
        root_bindings=bindings,
        budget=limits,
    )
    registry_contract = ContextProducerContract1.build(
        contract_id="registry-contract",
        owner_id="task-owner" if fault == "same-owner" else "registry-owner",
        owner_class="registry",
        implementation_id="builtin.project-registry.v1",
        implementation_digest=code.implementation_digest,
        source_formats=(
            (
                "project-registry",
                "project-registry.v2"
                if fault == "registry-format"
                else "gotm-project-registry.v1",
            ),
        ),
        subject_kinds=("registry-generation",),
        fact_references=registry_facts,
        root_bindings=bindings[:1] if fault == "binding-set" else bindings,
        budget=limits,
    )
    targets = (
        task,
        registered,
        registry_contract if fault == "contract-role" else task_contract,
        registry_contract,
    )
    refs = (
        TypedObjectRef1.from_dict(task.reference()),
        TypedObjectRef1.build(
            kind="project-registry",
            format_version="gotm-project-registry.v1",
            object_id=registered.generation_id,
            object_digest=registered.registry_sha256,
        ),
        TypedObjectRef1.from_dict(targets[2].reference()),
        TypedObjectRef1.from_dict(registry_contract.reference()),
    )
    payloads = (
        json.dumps(task.to_dict()).encode(),
        registered.to_bytes(),
        json.dumps(targets[2].to_dict()).encode(),
        json.dumps(registry_contract.to_dict()).encode(),
    )
    paths = tuple(root / f"source-{index}.json" for index in range(4))
    for path, payload in zip(paths, payloads, strict=True):
        path.write_bytes(payload)
    with ExitStack() as stack:
        sources = tuple(
            stack.enter_context(
                RetainedContextSource(
                    path,
                    reference=ref,
                    raw_digest=hashlib.sha256(payload).hexdigest(),
                    budget=limits,
                )
            )
            for path, ref, payload in zip(paths, refs, payloads, strict=True)
        )
        owners = stack.enter_context(
            TaskRegistrySourceOwners(
                task_source=sources[1] if fault == "source-kind" else sources[0],
                registry_source=sources[1],
                task_contract=sources[2],
                registry_contract=sources[3],
                implementation=replace(code, implementation_digest="0" * 64)
                if fault == "code-selection"
                else code,
                budget=limits,
            )
        )
        yield SelectedSources(owners, sources, paths, code)


def test_actual_generated_task_and_registry_values_and_original_proofs(tmp_path: Path) -> None:
    """Actual owners derive complete selected domains from original held sources."""
    with selection(tmp_path / "sources") as chosen:
        task = chosen.owners.observe(actor_id="actor", root_id="code", owner_class="task")
        current_registry = chosen.owners.observe(
            actor_id="actor", root_id="code", owner_class="registry"
        )
        assert {item.reference: item.value for item in task.observation.observations}[
            "task.id"
        ] == "general-work"
        assert {item.reference: item.value for item in current_registry.observation.observations}[
            "project.group"
        ] == "GROUP-A"
        assert task.proof.source_object == chosen.sources[0].reference
        assert current_registry.proof.source_object == chosen.sources[1].reference
        assert task.observation.subject_kind == "task-identity"
        assert current_registry.observation.subject_kind == "registry-generation"
        for role, value in (("task", task), ("registry", current_registry)):
            chosen.owners.verify(value, actor_id="actor", root_id="code", owner_class=role)
        with (
            TaskRegistrySourceOwners(
                task_source=chosen.sources[0],
                registry_source=chosen.sources[1],
                task_contract=chosen.sources[2],
                registry_contract=chosen.sources[3],
                implementation=chosen.implementation,
                budget=implementation_budget(),
            ) as other,
            pytest.raises(ValueError, match="actual selected"),
        ):
            other.verify(task, actor_id="actor", root_id="code", owner_class="task")
    chosen.owners.close()
    with pytest.raises(ValueError, match="closed"):
        chosen.owners.observe(actor_id="actor", root_id="code", owner_class="task")


def test_rehashed_forged_value_cannot_replace_actual_source_observation(tmp_path: Path) -> None:
    """Correct metadata digests cannot make an invented fact pass the actual owning reader."""
    with selection(tmp_path / "sources") as chosen:
        actual = chosen.owners.observe(actor_id="actor", root_id="code", owner_class="task")
        changed = tuple(
            OwnerObservation(
                item.reference,
                "known",
                "invented" if item.reference == "task.id" else item.value,
                item.subject_digest,
            )
            for item in actual.observation.observations
        )
        observation = replace(actual.observation, observations=changed)
        body = actual.proof.to_dict()
        body.pop("proof_digest")
        body["observation_digest"] = observation.digest(budget=implementation_budget())
        forged = OwnerProof1.from_dict(
            {**body, "proof_digest": canonical_digest(body)}, budget=implementation_budget()
        )
        observation.verify_proof_binding(forged, budget=implementation_budget())
        with pytest.raises(ValueError, match="actual selected"):
            chosen.owners.verify(
                OwnedSourceObservations(observation, forged),
                actor_id="actor",
                root_id="code",
                owner_class="task",
            )


@pytest.mark.parametrize(
    "fault",
    [
        "missing-project",
        "task-group",
        "task-root",
        "binding-group",
        "binding-path",
        "implementation",
        "same-owner",
        "registry-format",
        "binding-set",
        "contract-role",
        "source-kind",
        "code-selection",
    ],
)
def test_actual_wrong_source_contract_code_and_registry_bindings_refuse(
    tmp_path: Path, fault: str
) -> None:
    """Fixed implementations reject mismatched actual identities before emitting any facts."""
    with ExitStack() as stack, pytest.raises(ValueError):
        stack.enter_context(selection(tmp_path / "sources", fault=fault))


def test_identity_only_membership_unknown_owner_and_wrong_runtime_objects(tmp_path: Path) -> None:
    """Declared empty domains are retained, while membership and installed roles stay closed."""
    with selection(tmp_path / "sources", fault="identity-only") as chosen:
        assert (
            chosen.owners.observe(
                actor_id="actor", root_id="code", owner_class="task"
            ).observation.observations
            == ()
        )
        for actor, root, role in [
            ("foreign", "code", "task"),
            ("actor", "foreign", "registry"),
            ("actor", "code", "fact"),
        ]:
            with pytest.raises(ValueError):
                chosen.owners.observe(actor_id=actor, root_id=root, owner_class=role)
        with pytest.raises(ValueError, match="actual owned"):
            chosen.owners.verify(
                cast(OwnedSourceObservations, {}),
                actor_id="actor",
                root_id="code",
                owner_class="task",
            )


def test_actual_closing_mutation_refuses_the_source_owner_context(tmp_path: Path) -> None:
    """Source checks stay bound to the original reader through final context closure."""
    with (
        pytest.raises(ValueError, match="identity changed"),
        selection(tmp_path / "sources") as chosen,
    ):
        chosen.owners.observe(actor_id="actor", root_id="code", owner_class="task")
        chosen.paths[0].write_bytes(chosen.paths[0].read_bytes() + b" ")
        with pytest.raises(ValueError, match="identity changed"):
            chosen.owners.observe(actor_id="actor", root_id="code", owner_class="task")


def test_complete_root_bindings_revalidate_the_original_selected_sources(tmp_path: Path) -> None:
    """Return actual complete paths and refuse the same entry after closing."""
    with selection(tmp_path / "sources") as chosen:
        bindings = chosen.owners.root_bindings()
        assert tuple(item.root_id for item in bindings) == ("code", "tests")
        assert tuple(item.canonical_path for item in bindings) == (
            "03_CODE/GROUP-A/repositories/PROJECT-A/src",
            "03_CODE/GROUP-A/repositories/PROJECT-A/tests",
        )
        chosen.owners.close()
        with pytest.raises(ValueError, match="closed"):
            chosen.owners.root_bindings()


def test_constructor_has_no_budget_source_or_implementation_fallback(tmp_path: Path) -> None:
    """Each invalid host input refuses before it can appoint a source owner."""
    for budget in (cast(PolicyReadBudget1, {}), implementation_budget()):
        with pytest.raises(ValueError):
            TaskRegistrySourceOwners(
                task_source=cast(RetainedContextSource, {}),
                registry_source=cast(RetainedContextSource, {}),
                task_contract=cast(RetainedContextSource, {}),
                registry_contract=cast(RetainedContextSource, {}),
                implementation=cast(OwnerImplementationSnapshot, {}),
                budget=budget,
            )
    with (
        selection(tmp_path / "sources") as chosen,
        pytest.raises(ValueError, match="complete implementation"),
    ):
        TaskRegistrySourceOwners(
            task_source=chosen.sources[0],
            registry_source=chosen.sources[1],
            task_contract=chosen.sources[2],
            registry_contract=chosen.sources[3],
            implementation=cast(OwnerImplementationSnapshot, {}),
            budget=implementation_budget(),
        )
