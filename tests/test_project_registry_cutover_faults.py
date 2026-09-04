# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project registry cutover fault-injection tests
"""Exercise durable evidence and rollback faults through the public cutover API."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_project_registry_cutover import REGISTRY_PATH, filesystem, plan
from test_project_registry_models import authority, registry

import rigor_foundry.project_registry_cutover as cutover_module
from rigor_foundry.project_registry_cutover import (
    ProjectRegistryCutoverInvalid,
    apply_project_registry_cutover,
)
from rigor_foundry.project_registry_models import ProjectRegistration, ProjectRegistry


@pytest.mark.parametrize(
    ("scenario", "match"),
    [
        ("snapshot-write", "snapshot could not be created"),
        ("journal-absent", "journal is absent"),
        ("journal-digest", "digest does not close"),
        ("journal-shape", "journal is malformed"),
        ("journal-state-write", "state cannot be updated"),
    ],
)
def test_cutover_rejects_snapshot_and_journal_storage_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario: str,
    match: str,
) -> None:
    """The public cutover reports every durable-evidence preparation failure."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    cutover = plan(candidate)
    original_write = cutover_module.write_new_text
    original_replace = cutover_module.atomic_replace_text

    def injected_write(path: Path, text: str) -> None:
        if scenario == "snapshot-write":
            raise OSError("injected snapshot write failure")
        if path.name != "journal.json":
            original_write(path, text)
            return
        if scenario == "journal-absent":
            return
        if scenario == "journal-digest":
            value = json.loads(text)
            value["journal_sha256"] = "0" * 64
            original_write(path, json.dumps(value, sort_keys=True, separators=(",", ":")))
            return
        if scenario == "journal-shape":
            original_write(path, "[]")
            return
        original_write(path, text)

    def injected_replace(path: Path, text: str) -> None:
        if scenario == "journal-state-write" and path.name == "journal.json":
            raise OSError("injected journal state failure")
        original_replace(path, text)

    monkeypatch.setattr(cutover_module, "write_new_text", injected_write)
    monkeypatch.setattr(cutover_module, "atomic_replace_text", injected_replace)

    with pytest.raises(ProjectRegistryCutoverInvalid, match=match):
        apply_project_registry_cutover(root, REGISTRY_PATH, transactions, cutover)


def test_cutover_rejects_registry_consumer_overlap(tmp_path: Path) -> None:
    """The canonical registry can never alias a declared consumer target."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    cutover = plan(candidate)
    registry_path = cutover.updates[0].output.target_path

    with pytest.raises(ProjectRegistryCutoverInvalid, match="overlaps a target"):
        apply_project_registry_cutover(root, registry_path, transactions, cutover)


@pytest.mark.parametrize(
    ("skipped_target", "match"),
    [("registry", "current registry"), ("consumer", "current consumer")],
)
def test_cutover_detects_atomic_write_that_did_not_change_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    skipped_target: str,
    match: str,
) -> None:
    """Post-write verification catches a storage layer that reports a false success."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    cutover = plan(candidate)
    registry_target = root / REGISTRY_PATH
    consumer_target = root / cutover.updates[0].output.target_path
    original_replace = cutover_module.atomic_replace_text

    def skip_one_target(path: Path, text: str) -> None:
        selected = registry_target if skipped_target == "registry" else consumer_target
        if path == selected:
            return
        original_replace(path, text)

    monkeypatch.setattr(cutover_module, "atomic_replace_text", skip_one_target)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="prior state was restored") as caught:
        apply_project_registry_cutover(root, REGISTRY_PATH, transactions, cutover)
    assert match in str(caught.value.__cause__)


def test_initial_verification_failure_removes_candidate_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rollback removes a newly written registry when final verification fails."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)

    def reject_verification(*_arguments: object) -> None:
        raise ProjectRegistryCutoverInvalid("injected final verification failure")

    monkeypatch.setattr(cutover_module, "_verify_live_state", reject_verification)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="prior state was restored"):
        apply_project_registry_cutover(root, REGISTRY_PATH, transactions, plan(candidate))
    assert not (root / REGISTRY_PATH).exists()


def test_invalid_prior_consumer_is_rejected_before_successor_snapshot(tmp_path: Path) -> None:
    """A successor never snapshots an invalid current consumer as trusted prior state."""
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
    target = root / first_outputs[0].target_path
    target.write_text("{}", encoding="utf-8")
    target.chmod(0o600)

    with pytest.raises(ProjectRegistryCutoverInvalid, match="current consumer output is invalid"):
        apply_project_registry_cutover(
            root,
            REGISTRY_PATH,
            transactions,
            plan(second, previous_outputs=first_outputs),
        )


@pytest.mark.parametrize("external_registry", [False, True])
def test_cutover_surfaces_rollback_storage_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    external_registry: bool,
) -> None:
    """A failed application never conceals failure to restore exact prior state."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    cutover = plan(candidate)
    first_target = root / cutover.updates[0].output.target_path
    second_target = root / cutover.updates[1].output.target_path
    registry_target = root / REGISTRY_PATH
    original_atomic_replace = cutover_module.atomic_replace_text
    original_unlink = Path.unlink

    def fail_second_write(path: Path, text: str) -> None:
        if path == second_target:
            if external_registry:
                original_atomic_replace(registry_target, "external-owner-write")
            raise OSError("injected second consumer failure")
        original_atomic_replace(path, text)

    def fail_first_rollback(path: Path, *args: object, **kwargs: object) -> None:
        if not external_registry and path == first_target:
            raise OSError("injected rollback unlink failure")
        original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(cutover_module, "atomic_replace_text", fail_second_write)
    monkeypatch.setattr(Path, "unlink", fail_first_rollback)

    with pytest.raises(ProjectRegistryCutoverInvalid, match="exact rollback also failed"):
        apply_project_registry_cutover(root, REGISTRY_PATH, transactions, cutover)
