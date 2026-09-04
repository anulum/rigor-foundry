# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project registry cutover tests
"""Exercise real filesystem registry commits, rollback and state verification."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from test_project_registry_models import authority, consumers, group, project, registry

import rigor_foundry.project_registry_cutover as cutover_module
from rigor_foundry.project_registry_cutover import (
    ProjectRegistryConsumerUpdate,
    ProjectRegistryCutoverInvalid,
    ProjectRegistryCutoverPlan,
    apply_project_registry_cutover,
    load_project_registry_state,
    validate_project_registry_transition,
)
from rigor_foundry.project_registry_models import (
    ProjectRegistration,
    ProjectRegistry,
    ProjectRegistryAlias,
    ProjectRegistryConsumer,
    project_registry_canonical_json,
)
from rigor_foundry.project_registry_views import (
    ProjectRegistryConsumerOutput,
    build_registry_consumer_outputs,
)

REGISTRY_PATH = "agentic-shared/memory/projects/registry/project_registry.json"


def filesystem(tmp_path: Path, candidate: ProjectRegistry) -> tuple[Path, Path]:
    """Create real target parents for one registry transaction."""
    root = tmp_path / "monorepo"
    root.mkdir()
    (root / "agentic-shared/memory/projects/registry").mkdir(parents=True)
    transaction_root = root / "private-transactions"
    transaction_root.mkdir(mode=0o700)
    for item in candidate.groups:
        (root / item.root_path / "agentic_group_memory").mkdir(parents=True)
        (root / item.repositories_path).mkdir(exist_ok=True)
    for item in candidate.projects:
        if item.memory_state != "absent":
            (root / item.canonical_path / "agentic_project_memory").mkdir(parents=True)
    return root, transaction_root


def plan(
    candidate: ProjectRegistry,
    *,
    previous_outputs: tuple[ProjectRegistryConsumerOutput, ...] = (),
) -> ProjectRegistryCutoverPlan:
    """Build one complete plan from generated outputs and prior self-digests."""
    previous = {output.consumer_id: output for output in previous_outputs}
    outputs = build_registry_consumer_outputs(candidate, {})
    updates = tuple(
        ProjectRegistryConsumerUpdate.build(
            output,
            expected_sha256=(
                previous[output.consumer_id].output_sha256
                if output.consumer_id in previous
                else None
            ),
        )
        for output in outputs
    )
    return ProjectRegistryCutoverPlan.build(
        candidate,
        expected_registry_sha256=candidate.previous_registry_sha256,
        updates=updates,
    )


def test_initial_cutover_commits_registry_and_every_consumer(tmp_path: Path) -> None:
    """The initial logical commit writes consumers first and validates final state."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    cutover = plan(candidate)

    receipt = apply_project_registry_cutover(root, REGISTRY_PATH, transactions, cutover)

    assert receipt.outcome == "committed"
    assert load_project_registry_state(root, REGISTRY_PATH) == candidate
    for update in cutover.updates:
        target = root / update.output.target_path
        assert target.read_bytes() == update.output.to_bytes()
        assert target.stat().st_mode & 0o777 == 0o600
    assert (root / REGISTRY_PATH).stat().st_mode & 0o777 == 0o600
    transaction = transactions / f"{candidate.generation_id}_{candidate.registry_sha256}"
    stored_receipt = json.loads((transaction / "receipt.json").read_text())
    assert stored_receipt["outcome"] == "committed"
    assert (transaction / "prior").stat().st_mode & 0o777 == 0o700


def test_successor_cutover_requires_and_replaces_exact_prior_digests(tmp_path: Path) -> None:
    """A successor advances only from the exact current registry and outputs."""
    first = registry()
    root, transactions = filesystem(tmp_path, first)
    first_plan = plan(first)
    apply_project_registry_cutover(root, REGISTRY_PATH, transactions, first_plan)
    first_outputs = tuple(update.output for update in first_plan.updates)
    changed_value = first.projects[0].to_dict()
    changed_value["visibility"] = "public"
    changed = ProjectRegistration.from_dict(changed_value, "project")
    second = ProjectRegistry.build(
        generated_at="2026-09-04T12:01:00.000000Z",
        previous_registry_sha256=first.registry_sha256,
        authority=authority(),
        groups=first.groups,
        projects=(changed,),
        consumers=first.consumers,
    )

    receipt = apply_project_registry_cutover(
        root,
        REGISTRY_PATH,
        transactions,
        plan(second, previous_outputs=first_outputs),
    )

    assert receipt.previous_registry_sha256 == first.registry_sha256
    assert load_project_registry_state(root, REGISTRY_PATH).projects[0].visibility == "public"


def test_consumer_failure_restores_every_written_target(tmp_path: Path) -> None:
    """A real second-consumer write failure removes the first write and keeps no registry."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    cutover = plan(candidate)
    failing_parent = root / candidate.projects[0].canonical_path / "agentic_project_memory"
    failing_parent.chmod(0o500)
    try:
        with pytest.raises(ProjectRegistryCutoverInvalid, match="prior state was restored"):
            apply_project_registry_cutover(root, REGISTRY_PATH, transactions, cutover)
    finally:
        failing_parent.chmod(0o700)

    assert not (root / REGISTRY_PATH).exists()
    assert all(not (root / update.output.target_path).exists() for update in cutover.updates)
    transaction = transactions / f"{candidate.generation_id}_{candidate.registry_sha256}"
    receipt = json.loads((transaction / "receipt.json").read_text())
    assert receipt["outcome"] == "rolled-back"


def test_cutover_rejects_stale_registry_and_consumer_preconditions(tmp_path: Path) -> None:
    """A stale writer cannot replace a current registry or consumer."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    valid_plan = plan(candidate)
    (root / REGISTRY_PATH).write_bytes(candidate.to_bytes())
    os.chmod(root / REGISTRY_PATH, 0o600)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="registry digest precondition"):
        apply_project_registry_cutover(root, REGISTRY_PATH, transactions, valid_plan)

    (root / REGISTRY_PATH).unlink()
    first_update = valid_plan.updates[0]
    target = root / first_update.output.target_path
    target.write_bytes(first_update.output.to_bytes())
    target.chmod(0o600)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="consumer digest precondition"):
        apply_project_registry_cutover(root, REGISTRY_PATH, transactions, valid_plan)


def test_transition_preserves_projects_groups_consumers_and_aliases() -> None:
    """Successors cannot erase stable identities or historical path evidence."""
    groups = (group("GROUP-A"), group("GROUP-B"))
    projects = (project("PROJECT-A", "GROUP-A"), project("PROJECT-B", "GROUP-A"))
    global_consumer = ProjectRegistryConsumer.from_dict(
        {
            "consumer_id": "boot-resolver",
            "kind": "boot-resolver",
            "path": "agentic-shared/memory/projects/registry_boot.json",
            "group_id": None,
            "project_id": None,
        },
        "consumer",
    )
    first_consumers = tuple(
        sorted((*consumers(projects, groups), global_consumer), key=lambda item: item.consumer_id)
    )
    first = ProjectRegistry.build(
        generated_at="2026-09-04T12:00:00.000000Z",
        previous_registry_sha256=None,
        authority=authority(),
        groups=groups,
        projects=projects,
        consumers=first_consumers,
    )
    candidates = (
        (
            ProjectRegistry.build(
                generated_at="2026-09-04T12:01:00.000000Z",
                previous_registry_sha256=first.registry_sha256,
                authority=authority(),
                groups=(groups[0],),
                projects=projects,
                consumers=consumers(projects, (groups[0],)),
            ),
            "delete a group",
        ),
        (
            ProjectRegistry.build(
                generated_at="2026-09-04T12:01:00.000000Z",
                previous_registry_sha256=first.registry_sha256,
                authority=authority(),
                groups=groups,
                projects=(projects[0],),
                consumers=consumers((projects[0],), groups),
            ),
            "delete a project",
        ),
        (
            ProjectRegistry.build(
                generated_at="2026-09-04T12:01:00.000000Z",
                previous_registry_sha256=first.registry_sha256,
                authority=authority(),
                groups=groups,
                projects=projects,
                consumers=consumers(projects, groups),
            ),
            "delete a consumer",
        ),
    )
    for candidate, match in candidates:
        with pytest.raises(ProjectRegistryCutoverInvalid, match=match):
            validate_project_registry_transition(first, candidate)


def test_canonical_move_requires_previous_path_alias() -> None:
    """Changing owning group without retaining the old path is rejected."""
    groups = (group("GROUP-A"), group("GROUP-B"))
    first_project = project()
    first = ProjectRegistry.build(
        generated_at="2026-09-04T12:00:00.000000Z",
        previous_registry_sha256=None,
        authority=authority(),
        groups=groups,
        projects=(first_project,),
        consumers=consumers((first_project,), groups),
    )
    moved = project("PROJECT-A", "GROUP-B")
    second = ProjectRegistry.build(
        generated_at="2026-09-04T12:01:00.000000Z",
        previous_registry_sha256=first.registry_sha256,
        authority=authority(),
        groups=groups,
        projects=(moved,),
        consumers=consumers((moved,), groups),
    )
    with pytest.raises(ProjectRegistryCutoverInvalid, match="become an alias"):
        validate_project_registry_transition(first, second)

    alias = ProjectRegistryAlias.from_dict(
        {
            "path": first_project.canonical_path,
            "valid_from": "2026-01-01T00:00:00.000000Z",
            "retired_at": "2026-09-04T12:00:30.000000Z",
            "source_sha256": "b" * 64,
        },
        "alias",
    )
    moved_value = moved.to_dict()
    moved_value["aliases"] = [alias.to_dict()]
    moved_with_alias = ProjectRegistration.from_dict(moved_value, "project")
    accepted = ProjectRegistry.build(
        generated_at="2026-09-04T12:01:00.000000Z",
        previous_registry_sha256=first.registry_sha256,
        authority=authority(),
        groups=groups,
        projects=(moved_with_alias,),
        consumers=consumers((moved_with_alias,), groups),
    )
    validate_project_registry_transition(first, accepted)


def test_load_state_rejects_missing_or_changed_consumer(tmp_path: Path) -> None:
    """The registry alone cannot claim an accepted all-consumer state."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    cutover = plan(candidate)
    apply_project_registry_cutover(root, REGISTRY_PATH, transactions, cutover)
    target = root / cutover.updates[0].output.target_path
    target.write_text("{}", encoding="utf-8")
    target.chmod(0o600)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="registry state is invalid"):
        load_project_registry_state(root, REGISTRY_PATH)


def test_plan_rejects_incomplete_or_foreign_consumer_outputs() -> None:
    """A cutover plan must contain exactly every candidate consumer once."""
    candidate = registry()
    outputs = build_registry_consumer_outputs(candidate, {})
    one = ProjectRegistryConsumerUpdate.build(outputs[0], expected_sha256=None)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="every consumer"):
        ProjectRegistryCutoverPlan.build(
            candidate,
            expected_registry_sha256=None,
            updates=(one,),
        )

    changed = outputs[0].to_dict()
    changed["consumer_kind"] = "boot-resolver"
    unsigned = {key: item for key, item in changed.items() if key != "output_sha256"}
    changed["output_sha256"] = hashlib.sha256(
        project_registry_canonical_json(unsigned)
    ).hexdigest()
    foreign_output = ProjectRegistryConsumerOutput.from_dict(changed)
    updates = (
        ProjectRegistryConsumerUpdate.build(foreign_output, expected_sha256=None),
        ProjectRegistryConsumerUpdate.build(outputs[1], expected_sha256=None),
    )
    with pytest.raises(ProjectRegistryCutoverInvalid, match="does not match registry"):
        ProjectRegistryCutoverPlan.build(
            candidate,
            expected_registry_sha256=None,
            updates=updates,
        )


def test_plan_rejects_invalid_digests_identity_and_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every precondition and update identity is bounded before filesystem access."""
    candidate = registry()
    outputs = build_registry_consumer_outputs(candidate, {})
    with pytest.raises(ProjectRegistryCutoverInvalid, match="digest is invalid"):
        ProjectRegistryConsumerUpdate.build(outputs[0], expected_sha256="bad")
    with pytest.raises(ProjectRegistryCutoverInvalid, match="registry digest is invalid"):
        ProjectRegistryCutoverPlan.build(
            candidate,
            expected_registry_sha256="bad",
            updates=tuple(
                ProjectRegistryConsumerUpdate.build(output, expected_sha256=None)
                for output in outputs
            ),
        )

    updates = tuple(
        ProjectRegistryConsumerUpdate.build(output, expected_sha256=None) for output in outputs
    )
    mismatched = replace(updates[0], consumer_id="different")
    with pytest.raises(ProjectRegistryCutoverInvalid, match="every consumer"):
        ProjectRegistryCutoverPlan.build(
            candidate,
            expected_registry_sha256=None,
            updates=(mismatched, *updates[1:]),
        )

    identity_mismatch = replace(updates[0], output=updates[1].output)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="identity does not match"):
        ProjectRegistryCutoverPlan.build(
            candidate,
            expected_registry_sha256=None,
            updates=(identity_mismatch, updates[1]),
        )

    monkeypatch.setattr(cutover_module, "PROJECT_REGISTRY_MAX_TRANSACTION_BYTES", 1)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="exceeds"):
        ProjectRegistryCutoverPlan.build(
            candidate,
            expected_registry_sha256=None,
            updates=updates,
        )


def test_transition_rejects_bad_chain_clock_target_kind_and_alias_loss() -> None:
    """Successor generations are time-ordered and preserve project identity history."""
    first = registry()
    names_predecessor = ProjectRegistry.build(
        generated_at="2026-09-04T12:01:00.000000Z",
        previous_registry_sha256="0" * 64,
        authority=authority(),
        groups=first.groups,
        projects=first.projects,
        consumers=first.consumers,
    )
    with pytest.raises(ProjectRegistryCutoverInvalid, match="initial registry"):
        validate_project_registry_transition(None, names_predecessor)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="current registry"):
        validate_project_registry_transition(first, names_predecessor)

    same_time = ProjectRegistry.build(
        generated_at=first.generated_at,
        previous_registry_sha256=first.registry_sha256,
        authority=authority(),
        groups=first.groups,
        projects=first.projects,
        consumers=first.consumers,
    )
    with pytest.raises(ProjectRegistryCutoverInvalid, match="time must increase"):
        validate_project_registry_transition(first, same_time)

    changed_value = first.projects[0].to_dict()
    changed_value["target_kind"] = "non-git-project"
    changed = ProjectRegistration.from_dict(changed_value, "project")
    changed_kind = ProjectRegistry.build(
        generated_at="2026-09-04T12:01:00.000000Z",
        previous_registry_sha256=first.registry_sha256,
        authority=authority(),
        groups=first.groups,
        projects=(changed,),
        consumers=first.consumers,
    )
    with pytest.raises(ProjectRegistryCutoverInvalid, match="target kind"):
        validate_project_registry_transition(first, changed_kind)

    alias = ProjectRegistryAlias.from_dict(
        {
            "path": "03_CODE/OLD/PROJECT-A",
            "valid_from": "2026-01-01T00:00:00.000000Z",
            "retired_at": "2026-09-01T00:00:00.000000Z",
            "source_sha256": "b" * 64,
        },
        "alias",
    )
    first_with_alias = registry(projects=(project(aliases=(alias,)),))
    successor_without_alias = ProjectRegistry.build(
        generated_at="2026-09-04T12:01:00.000000Z",
        previous_registry_sha256=first_with_alias.registry_sha256,
        authority=authority(),
        groups=first_with_alias.groups,
        projects=(project(),),
        consumers=first_with_alias.consumers,
    )
    with pytest.raises(ProjectRegistryCutoverInvalid, match="cannot change or disappear"):
        validate_project_registry_transition(first_with_alias, successor_without_alias)


def test_transition_rejects_changed_consumer_identity() -> None:
    """Existing global and project consumers retain their semantic identity."""
    groups = (group("GROUP-A"), group("GROUP-B"))
    projects = (project("PROJECT-A", "GROUP-A"), project("PROJECT-B", "GROUP-B"))
    global_consumer = ProjectRegistryConsumer.from_dict(
        {
            "consumer_id": "boot-resolver",
            "kind": "boot-resolver",
            "path": "agentic-shared/memory/projects/registry_boot.json",
            "group_id": None,
            "project_id": None,
        },
        "consumer",
    )
    original_consumers = tuple(
        sorted((*consumers(projects, groups), global_consumer), key=lambda item: item.consumer_id)
    )
    first = ProjectRegistry.build(
        generated_at="2026-09-04T12:00:00.000000Z",
        previous_registry_sha256=None,
        authority=authority(),
        groups=groups,
        projects=projects,
        consumers=original_consumers,
    )

    changed_global = replace(global_consumer, kind="backup-selector")
    changed_consumers = tuple(
        sorted(
            (
                *(item for item in original_consumers if item.consumer_id != "boot-resolver"),
                changed_global,
            ),
            key=lambda item: item.consumer_id,
        )
    )
    changed = ProjectRegistry.build(
        generated_at="2026-09-04T12:01:00.000000Z",
        previous_registry_sha256=first.registry_sha256,
        authority=authority(),
        groups=groups,
        projects=projects,
        consumers=changed_consumers,
    )
    with pytest.raises(ProjectRegistryCutoverInvalid, match="kind is immutable"):
        validate_project_registry_transition(first, changed)

    swapped: list[ProjectRegistryConsumer] = []
    for item in original_consumers:
        if item.kind == "project-index":
            other_id = "PROJECT-B" if item.project_id == "PROJECT-A" else "PROJECT-A"
            other = next(project for project in projects if project.project_id == other_id)
            swapped.append(
                replace(
                    item,
                    project_id=other_id,
                    path=f"{other.canonical_path}/agentic_project_memory/registry_binding.json",
                )
            )
        else:
            swapped.append(item)
    swapped_registry = ProjectRegistry.build(
        generated_at="2026-09-04T12:01:00.000000Z",
        previous_registry_sha256=first.registry_sha256,
        authority=authority(),
        groups=groups,
        projects=projects,
        consumers=tuple(sorted(swapped, key=lambda item: item.consumer_id)),
    )
    with pytest.raises(ProjectRegistryCutoverInvalid, match="project-index identity"):
        validate_project_registry_transition(first, swapped_registry)

    moved_global = replace(
        global_consumer,
        path="agentic-shared/memory/projects/other_boot.json",
    )
    moved_consumers = tuple(
        sorted(
            (
                *(item for item in original_consumers if item.consumer_id != "boot-resolver"),
                moved_global,
            ),
            key=lambda item: item.consumer_id,
        )
    )
    moved_registry = ProjectRegistry.build(
        generated_at="2026-09-04T12:01:00.000000Z",
        previous_registry_sha256=first.registry_sha256,
        authority=authority(),
        groups=groups,
        projects=projects,
        consumers=moved_consumers,
    )
    with pytest.raises(ProjectRegistryCutoverInvalid, match="paths are immutable"):
        validate_project_registry_transition(first, moved_registry)

    changed_group = replace(first.groups[0], root_path="03_CODE/OTHER")
    structurally_invalid_candidate = replace(
        first,
        generated_at="2026-09-04T12:01:00.000000Z",
        previous_registry_sha256=first.registry_sha256,
        groups=(changed_group, first.groups[1]),
    )
    with pytest.raises(ProjectRegistryCutoverInvalid, match="group identity paths"):
        validate_project_registry_transition(first, structurally_invalid_candidate)


def test_cutover_rejects_symlink_parent_and_reused_transaction(tmp_path: Path) -> None:
    """Target ancestry and generation snapshots cannot be redirected or reused."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    cutover = plan(candidate)
    parent = root / candidate.groups[0].root_path / "agentic_group_memory"
    parent.rmdir()
    elsewhere = root / "elsewhere"
    elsewhere.mkdir()
    parent.symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="not a real directory"):
        apply_project_registry_cutover(root, REGISTRY_PATH, transactions, cutover)

    parent.unlink()
    parent.mkdir()
    transaction = transactions / f"{candidate.generation_id}_{candidate.registry_sha256}"
    transaction.mkdir(mode=0o700)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="already has a snapshot"):
        apply_project_registry_cutover(root, REGISTRY_PATH, transactions, cutover)


def test_cutover_rejects_invalid_current_registry_and_missing_consumer(tmp_path: Path) -> None:
    """Neither corrupt prior state nor a registry-only state can be accepted."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    registry_target = root / REGISTRY_PATH
    registry_target.write_text("{}", encoding="utf-8")
    registry_target.chmod(0o600)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="current registry is invalid"):
        apply_project_registry_cutover(root, REGISTRY_PATH, transactions, plan(candidate))

    registry_target.unlink()
    cutover = plan(candidate)
    apply_project_registry_cutover(root, REGISTRY_PATH, transactions, cutover)
    (root / cutover.updates[0].output.target_path).unlink()
    with pytest.raises(ProjectRegistryCutoverInvalid, match="consumer output is absent"):
        load_project_registry_state(root, REGISTRY_PATH)


def test_load_state_rejects_absent_registry(tmp_path: Path) -> None:
    """No registry file means there is no accepted registry state."""
    candidate = registry()
    root, _ = filesystem(tmp_path, candidate)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="registry is absent"):
        load_project_registry_state(root, REGISTRY_PATH)


def test_cutover_rejects_missing_expected_prior_objects(tmp_path: Path) -> None:
    """Non-null registry and consumer preconditions require the exact prior object."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    outputs = build_registry_consumer_outputs(candidate, {})
    registry_expected = ProjectRegistryCutoverPlan.build(
        candidate,
        expected_registry_sha256="a" * 64,
        updates=tuple(
            ProjectRegistryConsumerUpdate.build(output, expected_sha256=None) for output in outputs
        ),
    )
    with pytest.raises(ProjectRegistryCutoverInvalid, match="registry digest precondition"):
        apply_project_registry_cutover(root, REGISTRY_PATH, transactions, registry_expected)

    previous = registry()
    previous_outputs = build_registry_consumer_outputs(previous, {})
    (root / REGISTRY_PATH).write_bytes(previous.to_bytes())
    (root / REGISTRY_PATH).chmod(0o600)
    second = ProjectRegistry.build(
        generated_at="2026-09-04T12:01:00.000000Z",
        previous_registry_sha256=previous.registry_sha256,
        authority=authority(),
        groups=previous.groups,
        projects=previous.projects,
        consumers=previous.consumers,
    )
    second_outputs = build_registry_consumer_outputs(second, {})
    successor = ProjectRegistryCutoverPlan.build(
        second,
        expected_registry_sha256=previous.registry_sha256,
        updates=tuple(
            ProjectRegistryConsumerUpdate.build(
                output,
                expected_sha256=previous_output.output_sha256,
            )
            for output, previous_output in zip(second_outputs, previous_outputs, strict=True)
        ),
    )
    with pytest.raises(ProjectRegistryCutoverInvalid, match="consumer digest precondition"):
        apply_project_registry_cutover(root, REGISTRY_PATH, transactions, successor)


def test_snapshot_bound_and_storage_failures_are_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Runtime snapshot and lock failures leave live targets untouched."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    cutover = plan(candidate)
    monkeypatch.setattr(cutover_module, "PROJECT_REGISTRY_MAX_TRANSACTION_BYTES", 1)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="snapshot exceeds"):
        apply_project_registry_cutover(root, REGISTRY_PATH, transactions, cutover)
    assert not (root / REGISTRY_PATH).exists()

    monkeypatch.undo()
    (transactions / ".cutover.lock").unlink()
    (transactions / ".cutover.lock").mkdir()
    with pytest.raises(ProjectRegistryCutoverInvalid, match="lock or storage failed"):
        apply_project_registry_cutover(root, REGISTRY_PATH, transactions, cutover)


def test_verification_failure_restores_successor_registry_and_consumers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A post-write verification failure restores every exact predecessor byte."""
    first = registry()
    root, transactions = filesystem(tmp_path, first)
    first_plan = plan(first)
    apply_project_registry_cutover(root, REGISTRY_PATH, transactions, first_plan)
    first_outputs = tuple(update.output for update in first_plan.updates)
    changed_value = first.projects[0].to_dict()
    changed_value["visibility"] = "public"
    changed = ProjectRegistration.from_dict(changed_value, "project")
    second = ProjectRegistry.build(
        generated_at="2026-09-04T12:01:00.000000Z",
        previous_registry_sha256=first.registry_sha256,
        authority=authority(),
        groups=first.groups,
        projects=(changed,),
        consumers=first.consumers,
    )
    second_plan = plan(second, previous_outputs=first_outputs)

    def reject_verification(*_arguments: object) -> None:
        raise ProjectRegistryCutoverInvalid("simulated verification failure")

    monkeypatch.setattr(cutover_module, "_verify_live_state", reject_verification)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="prior state was restored"):
        apply_project_registry_cutover(root, REGISTRY_PATH, transactions, second_plan)

    assert (root / REGISTRY_PATH).read_bytes() == first.to_bytes()
    for output in first_outputs:
        assert (root / output.target_path).read_bytes() == output.to_bytes()
