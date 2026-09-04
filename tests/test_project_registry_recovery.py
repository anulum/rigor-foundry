# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — interrupted project registry recovery tests
"""Exercise serial real-process crash recovery at both sides of the commit point."""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
from collections.abc import Callable
from pathlib import Path

import pytest
from test_project_registry_cutover import REGISTRY_PATH, filesystem, plan
from test_project_registry_models import authority, registry

import rigor_foundry.project_registry_cutover as cutover_module
import rigor_foundry.project_registry_recovery as recovery_module
from rigor_foundry.project_registry_cutover import (
    ProjectRegistryCutoverInvalid,
    ProjectRegistryCutoverPlan,
    apply_project_registry_cutover,
    load_project_registry_state,
)
from rigor_foundry.project_registry_models import (
    ProjectRegistration,
    ProjectRegistry,
)
from rigor_foundry.project_registry_primitives import project_registry_canonical_json
from rigor_foundry.project_registry_recovery import recover_project_registry_cutover

_CRASH_EXIT = 79


def crash_after_replacement(
    root: Path,
    transaction_root: Path,
    cutover: ProjectRegistryCutoverPlan,
    ordinal: int,
) -> None:
    """Exit without cleanup immediately after one exact replacement ordinal."""
    original = cutover_module._replace
    replacements = 0

    def crash_injected_replace(path: Path, payload: bytes) -> None:
        nonlocal replacements
        original(path, payload)
        replacements += 1
        if replacements == ordinal:
            os._exit(_CRASH_EXIT)

    cutover_module._replace = crash_injected_replace
    apply_project_registry_cutover(root, REGISTRY_PATH, transaction_root, cutover)


def run_crash_worker(
    root: Path,
    transaction_root: Path,
    cutover: ProjectRegistryCutoverPlan,
    ordinal: int,
) -> None:
    """Run and join exactly one forked crash worker."""
    process = multiprocessing.get_context("fork").Process(
        target=crash_after_replacement,
        args=(root, transaction_root, cutover, ordinal),
    )
    process.start()
    process.join(timeout=10)
    assert not process.is_alive()
    assert process.exitcode == _CRASH_EXIT


def transaction_directory(transaction_root: Path, cutover: ProjectRegistryCutoverPlan) -> Path:
    """Return the exact immutable identity directory for a plan fixture."""
    candidate = cutover.candidate
    return transaction_root / f"{candidate.generation_id}_{candidate.registry_sha256}"


def successor(first: ProjectRegistry) -> ProjectRegistry:
    """Return a valid successor with observably different consumer bytes."""
    changed_value = first.projects[0].to_dict()
    changed_value["visibility"] = "public"
    changed = ProjectRegistration.from_dict(changed_value, "project")
    return ProjectRegistry.build(
        generated_at="2026-09-04T12:01:00.000000Z",
        previous_registry_sha256=first.registry_sha256,
        authority=authority(),
        groups=first.groups,
        projects=(changed,),
        consumers=first.consumers,
    )


def closed_mutation(
    payload: bytes,
    digest_field: str,
    mutation: Callable[[dict[str, object]], None],
) -> bytes:
    """Mutate structured evidence and recompute its canonical digest closure."""
    value = json.loads(payload)
    mutation(value)
    unsigned = {key: item for key, item in value.items() if key != digest_field}
    value[digest_field] = hashlib.sha256(project_registry_canonical_json(unsigned)).hexdigest()
    return project_registry_canonical_json(value)


def rewrite_closed_evidence(
    path: Path,
    digest_field: str,
    mutation: Callable[[dict[str, object]], None],
) -> None:
    """Replace one owner-only evidence file with a canonically closed mutation."""
    path.write_bytes(closed_mutation(path.read_bytes(), digest_field, mutation))
    path.chmod(0o600)


def mutate_first_consumer(field: str, replacement: object) -> Callable[[dict[str, object]], None]:
    """Return a journal mutation for one first-consumer boundary field."""

    def mutation(value: dict[str, object]) -> None:
        consumers = value["consumers"]
        assert isinstance(consumers, list)
        first = consumers[0]
        assert isinstance(first, dict)
        first[field] = replacement

    return mutation


def reverse_consumer_order(value: dict[str, object]) -> None:
    """Reverse journal identities while keeping per-index snapshot names coherent."""
    consumers = value["consumers"]
    assert isinstance(consumers, list)
    consumers.reverse()
    for index, consumer in enumerate(consumers):
        assert isinstance(consumer, dict)
        consumer_id = consumer["consumer_id"]
        consumer["snapshot_name"] = f"{index:04d}_{consumer_id}.json"


@pytest.mark.parametrize(
    ("crash_ordinal", "expected_outcome"),
    [(1, "rolled-back"), (3, "committed")],
)
def test_serial_process_death_resolves_at_registry_commit_point(
    tmp_path: Path,
    crash_ordinal: int,
    expected_outcome: str,
) -> None:
    """A real process death rolls back before registry write and commits after it."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    cutover = plan(candidate)
    sentinel = root / "03_CODE/UNCONSOLIDATED/owner-sentinel.bin"
    sentinel.parent.mkdir()
    sentinel.write_bytes(b"outside-the-explicit-consumer-graph")

    run_crash_worker(root, transactions, cutover, crash_ordinal)
    transaction = transaction_directory(transactions, cutover)
    journal = json.loads((transaction / "journal.json").read_text(encoding="utf-8"))
    assert journal["state"] == "applying"
    assert not (transaction / "receipt.json").exists()

    receipt = recover_project_registry_cutover(
        root,
        REGISTRY_PATH,
        transactions,
        candidate.generation_id,
        candidate.registry_sha256,
    )
    assert receipt.outcome == expected_outcome
    assert sentinel.read_bytes() == b"outside-the-explicit-consumer-graph"
    assert transaction.stat().st_mode & 0o777 == 0o700
    assert all(
        path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600)
        for path in transaction.rglob("*")
    )

    repeated = recover_project_registry_cutover(
        root,
        REGISTRY_PATH,
        transactions,
        candidate.generation_id,
        candidate.registry_sha256,
    )
    assert repeated == receipt
    if expected_outcome == "committed":
        assert load_project_registry_state(root, REGISTRY_PATH) == candidate
    else:
        assert not (root / REGISTRY_PATH).exists()
        assert all(not (root / update.output.target_path).exists() for update in cutover.updates)


def test_recovery_rejects_tampered_journal_snapshot_and_live_target(tmp_path: Path) -> None:
    """Closed evidence and exact live bytes prevent guessed or external recovery."""
    candidate = registry()

    journal_scenario = tmp_path / "journal"
    journal_scenario.mkdir()
    root, transactions = filesystem(journal_scenario, candidate)
    cutover = plan(candidate)
    run_crash_worker(root, transactions, cutover, 1)
    transaction = transaction_directory(transactions, cutover)
    journal_path = transaction / "journal.json"
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    journal["state"] = "prepared"
    journal_path.write_text(
        json.dumps(journal, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    journal_path.chmod(0o600)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="evidence is invalid"):
        recover_project_registry_cutover(
            root,
            REGISTRY_PATH,
            transactions,
            candidate.generation_id,
            candidate.registry_sha256,
        )

    snapshot_scenario = tmp_path / "snapshot"
    snapshot_scenario.mkdir()
    root, transactions = filesystem(snapshot_scenario, candidate)
    cutover = plan(candidate)
    run_crash_worker(root, transactions, cutover, 1)
    transaction = transaction_directory(transactions, cutover)
    snapshot = next(
        path for path in (transaction / "candidate").iterdir() if path.name != "registry.json"
    )
    snapshot.write_text("{}", encoding="utf-8")
    snapshot.chmod(0o600)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="evidence is invalid"):
        recover_project_registry_cutover(
            root,
            REGISTRY_PATH,
            transactions,
            candidate.generation_id,
            candidate.registry_sha256,
        )

    live_scenario = tmp_path / "live"
    live_scenario.mkdir()
    root, transactions = filesystem(live_scenario, candidate)
    cutover = plan(candidate)
    run_crash_worker(root, transactions, cutover, 1)
    target = root / cutover.updates[0].output.target_path
    target.write_text("external-owner-write", encoding="utf-8")
    target.chmod(0o600)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="outside the cutover transaction"):
        recover_project_registry_cutover(
            root,
            REGISTRY_PATH,
            transactions,
            candidate.generation_id,
            candidate.registry_sha256,
        )


@pytest.mark.parametrize(
    ("crash_ordinal", "expected_outcome"),
    [(1, "rolled-back"), (3, "committed")],
)
def test_successor_recovery_preserves_exact_prior_or_candidate_generation(
    tmp_path: Path,
    crash_ordinal: int,
    expected_outcome: str,
) -> None:
    """Recovery retains real predecessor bytes on either side of the commit point."""
    first = registry()
    root, transactions = filesystem(tmp_path, first)
    first_plan = plan(first)
    apply_project_registry_cutover(root, REGISTRY_PATH, transactions, first_plan)
    first_outputs = tuple(update.output for update in first_plan.updates)
    second = successor(first)
    second_plan = plan(second, previous_outputs=first_outputs)

    run_crash_worker(root, transactions, second_plan, crash_ordinal)
    receipt = recover_project_registry_cutover(
        root,
        REGISTRY_PATH,
        transactions,
        second.generation_id,
        second.registry_sha256,
    )

    expected_registry = second if expected_outcome == "committed" else first
    expected_outputs = (
        tuple(update.output for update in second_plan.updates)
        if expected_outcome == "committed"
        else first_outputs
    )
    assert receipt.outcome == expected_outcome
    assert load_project_registry_state(root, REGISTRY_PATH) == expected_registry
    assert all(
        (root / output.target_path).read_bytes() == output.to_bytes()
        for output in expected_outputs
    )


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (lambda value: value.update(extra=True), "fields"),
        (lambda value: value.update(schema_version="unsupported"), "version"),
        (lambda value: value.update(state="guess"), "state"),
        (lambda value: value.update(generation_id="bad"), "generation"),
        (lambda value: value.update(consumers=[]), "count"),
        (reverse_consumer_order, "identity ordered"),
        (mutate_first_consumer("extra", True), "fields"),
        (mutate_first_consumer("snapshot_name", "wrong.json"), "snapshot name"),
        (mutate_first_consumer("was_present", "yes"), "presence flag"),
        (mutate_first_consumer("expected_sha256", "a" * 64), "presence disagrees"),
    ],
)
def test_recovery_rejects_closed_journal_structural_substitution(
    tmp_path: Path,
    mutation: Callable[[dict[str, object]], None],
    match: str,
) -> None:
    """Public recovery rejects re-digested journal schema substitutions."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    cutover = plan(candidate)
    run_crash_worker(root, transactions, cutover, 1)
    journal_path = transaction_directory(transactions, cutover) / "journal.json"
    rewrite_closed_evidence(journal_path, "journal_sha256", mutation)

    with pytest.raises(ProjectRegistryCutoverInvalid, match="evidence is invalid") as caught:
        recover_project_registry_cutover(
            root,
            REGISTRY_PATH,
            transactions,
            candidate.generation_id,
            candidate.registry_sha256,
        )
    assert match in str(caught.value.__cause__)


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (lambda value: value.update(extra=True), "fields"),
        (lambda value: value.update(schema_version="unsupported"), "version"),
        (lambda value: value.update(consumer_ids="not-a-list"), "consumers"),
        (lambda value: value.update(outcome="unknown"), "outcome"),
    ],
)
def test_recovery_rejects_closed_receipt_structural_substitution(
    tmp_path: Path,
    mutation: Callable[[dict[str, object]], None],
    match: str,
) -> None:
    """Public recovery rejects re-digested receipt schema substitutions."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    cutover = plan(candidate)
    apply_project_registry_cutover(root, REGISTRY_PATH, transactions, cutover)
    receipt_path = transaction_directory(transactions, cutover) / "receipt.json"
    rewrite_closed_evidence(receipt_path, "receipt_sha256", mutation)

    with pytest.raises(ProjectRegistryCutoverInvalid, match="evidence is invalid") as caught:
        recover_project_registry_cutover(
            root,
            REGISTRY_PATH,
            transactions,
            candidate.generation_id,
            candidate.registry_sha256,
        )
    assert match in str(caught.value.__cause__)


@pytest.mark.parametrize("evidence_name", ["journal.json", "receipt.json"])
def test_recovery_requires_exact_canonical_evidence_bytes(
    tmp_path: Path,
    evidence_name: str,
) -> None:
    """Public recovery rejects whitespace variants of closed JSON evidence."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    cutover = plan(candidate)
    apply_project_registry_cutover(root, REGISTRY_PATH, transactions, cutover)
    evidence_path = transaction_directory(transactions, cutover) / evidence_name
    evidence_path.write_bytes(evidence_path.read_bytes() + b"\n")
    evidence_path.chmod(0o600)

    with pytest.raises(ProjectRegistryCutoverInvalid, match="evidence is invalid"):
        recover_project_registry_cutover(
            root,
            REGISTRY_PATH,
            transactions,
            candidate.generation_id,
            candidate.registry_sha256,
        )


@pytest.mark.parametrize(
    ("scenario", "match"),
    [
        ("journal-identity", "identity does not match"),
        ("candidate-identity", "candidate registry identity"),
        ("prior-registry", "prior registry does not match"),
        ("journal-coverage", "does not cover every consumer"),
        ("candidate-extra", "candidate snapshot set"),
        ("prior-extra", "prior snapshot set"),
        ("candidate-record", "consumer snapshot does not match"),
        ("candidate-absent", "candidate registry snapshot is absent"),
        ("external-registry", "registry changed outside"),
    ],
)
def test_recovery_rejects_identity_snapshot_and_external_state_substitution(
    tmp_path: Path,
    scenario: str,
    match: str,
) -> None:
    """Every persisted identity and live commit-point state remains fail-closed."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    cutover = plan(candidate)
    run_crash_worker(root, transactions, cutover, 1)
    transaction = transaction_directory(transactions, cutover)
    journal_path = transaction / "journal.json"

    if scenario == "journal-identity":
        rewrite_closed_evidence(
            journal_path,
            "journal_sha256",
            lambda value: value.update(registry_sha256="b" * 64),
        )
    elif scenario == "candidate-identity":
        candidate_path = transaction / "candidate/registry.json"
        candidate_path.write_bytes(successor(candidate).to_bytes())
        candidate_path.chmod(0o600)
    elif scenario == "prior-registry":
        prior_path = transaction / "prior/registry.json"
        prior_path.write_bytes(candidate.to_bytes())
        prior_path.chmod(0o600)
    elif scenario == "journal-coverage":
        rewrite_closed_evidence(
            journal_path,
            "journal_sha256",
            lambda value: value.update(consumers=value["consumers"][:-1]),
        )
    elif scenario == "candidate-extra":
        extra = transaction / "candidate/undeclared.json"
        extra.write_text("{}", encoding="utf-8")
        extra.chmod(0o600)
    elif scenario == "prior-extra":
        extra = transaction / "prior/undeclared.json"
        extra.write_text("{}", encoding="utf-8")
        extra.chmod(0o600)
    elif scenario == "candidate-record":
        rewrite_closed_evidence(
            journal_path,
            "journal_sha256",
            mutate_first_consumer("target_path", "03_CODE/GROUP-A/other.json"),
        )
    elif scenario == "candidate-absent":
        (transaction / "candidate/registry.json").unlink()
    else:
        registry_target = root / REGISTRY_PATH
        registry_target.write_text("external-owner-write", encoding="utf-8")
        registry_target.chmod(0o600)

    with pytest.raises(ProjectRegistryCutoverInvalid, match=match):
        recover_project_registry_cutover(
            root,
            REGISTRY_PATH,
            transactions,
            candidate.generation_id,
            candidate.registry_sha256,
        )


@pytest.mark.parametrize(
    ("crash_ordinal", "contradictory_state", "match"),
    [
        (1, "committed", "committed journal has prior state"),
        (3, "rolled-back", "rolled-back journal has candidate state"),
    ],
)
def test_recovery_rejects_final_journal_state_that_contradicts_commit_point(
    tmp_path: Path,
    crash_ordinal: int,
    contradictory_state: str,
    match: str,
) -> None:
    """A final journal label cannot override exact live registry bytes."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    cutover = plan(candidate)
    run_crash_worker(root, transactions, cutover, crash_ordinal)
    journal_path = transaction_directory(transactions, cutover) / "journal.json"
    rewrite_closed_evidence(
        journal_path,
        "journal_sha256",
        lambda value: value.update(state=contradictory_state),
    )

    with pytest.raises(ProjectRegistryCutoverInvalid, match=match):
        recover_project_registry_cutover(
            root,
            REGISTRY_PATH,
            transactions,
            candidate.generation_id,
            candidate.registry_sha256,
        )


@pytest.mark.parametrize("reclose", [False, True])
def test_recovery_rejects_tampered_or_conflicting_existing_receipt(
    tmp_path: Path,
    reclose: bool,
) -> None:
    """An existing receipt must retain both digest closure and exact outcome."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    cutover = plan(candidate)
    run_crash_worker(root, transactions, cutover, 3)
    recover_project_registry_cutover(
        root,
        REGISTRY_PATH,
        transactions,
        candidate.generation_id,
        candidate.registry_sha256,
    )
    receipt_path = transaction_directory(transactions, cutover) / "receipt.json"
    if reclose:
        rewrite_closed_evidence(
            receipt_path,
            "receipt_sha256",
            lambda value: value.update(outcome="rolled-back"),
        )
        match = "conflicts with recovery outcome"
    else:
        value = json.loads(receipt_path.read_bytes())
        value["outcome"] = "rolled-back"
        receipt_path.write_bytes(project_registry_canonical_json(value))
        receipt_path.chmod(0o600)
        match = "evidence is invalid"

    with pytest.raises(ProjectRegistryCutoverInvalid, match=match):
        recover_project_registry_cutover(
            root,
            REGISTRY_PATH,
            transactions,
            candidate.generation_id,
            candidate.registry_sha256,
        )


def test_recovery_rejects_wrong_identity_and_unprepared_transaction(tmp_path: Path) -> None:
    """Recovery never discovers a transaction or substitutes another identity."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="malformed"):
        recover_project_registry_cutover(root, REGISTRY_PATH, transactions, "bad", "a" * 64)
    with pytest.raises(
        ProjectRegistryCutoverInvalid, match="transaction directory is unavailable"
    ):
        recover_project_registry_cutover(
            root,
            REGISTRY_PATH,
            transactions,
            candidate.generation_id,
            candidate.registry_sha256,
        )


def test_successor_recovery_rejects_prior_consumer_digest_substitution(tmp_path: Path) -> None:
    """A re-closed journal cannot rename exact predecessor consumer bytes."""
    first = registry()
    root, transactions = filesystem(tmp_path, first)
    first_plan = plan(first)
    apply_project_registry_cutover(root, REGISTRY_PATH, transactions, first_plan)
    second = successor(first)
    second_plan = plan(
        second,
        previous_outputs=tuple(update.output for update in first_plan.updates),
    )
    run_crash_worker(root, transactions, second_plan, 1)
    journal_path = transaction_directory(transactions, second_plan) / "journal.json"
    rewrite_closed_evidence(
        journal_path,
        "journal_sha256",
        mutate_first_consumer("expected_sha256", "a" * 64),
    )

    with pytest.raises(ProjectRegistryCutoverInvalid, match="prior consumer digest"):
        recover_project_registry_cutover(
            root,
            REGISTRY_PATH,
            transactions,
            second.generation_id,
            second.registry_sha256,
        )


def test_recovery_rejects_oversized_transaction_and_lock_storage_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Recovery enforces its aggregate bound and reports an unusable lock path."""
    candidate = registry()

    bound_scenario = tmp_path / "bound"
    bound_scenario.mkdir()
    root, transactions = filesystem(bound_scenario, candidate)
    cutover = plan(candidate)
    run_crash_worker(root, transactions, cutover, 1)
    monkeypatch.setattr(recovery_module, "PROJECT_REGISTRY_MAX_TRANSACTION_BYTES", 1)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="exceeds its byte bound"):
        recover_project_registry_cutover(
            root,
            REGISTRY_PATH,
            transactions,
            candidate.generation_id,
            candidate.registry_sha256,
        )

    monkeypatch.undo()
    lock_scenario = tmp_path / "lock"
    lock_scenario.mkdir()
    root, transactions = filesystem(lock_scenario, candidate)
    cutover = plan(candidate)
    run_crash_worker(root, transactions, cutover, 1)
    lock_path = transactions / ".cutover.lock"
    lock_path.unlink()
    lock_path.mkdir()
    with pytest.raises(ProjectRegistryCutoverInvalid, match="lock or storage failed"):
        recover_project_registry_cutover(
            root,
            REGISTRY_PATH,
            transactions,
            candidate.generation_id,
            candidate.registry_sha256,
        )
