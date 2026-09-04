# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — interrupted project registry transaction recovery
"""Resolve one exact interrupted registry transaction from closed snapshots."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .internal_storage import exclusive_lock, write_new_text
from .project_registry_cutover import (
    PROJECT_REGISTRY_CUTOVER_JOURNAL_SCHEMA,
    PROJECT_REGISTRY_CUTOVER_RECEIPT_SCHEMA,
    PROJECT_REGISTRY_MAX_TRANSACTION_BYTES,
    ProjectRegistryCutoverInvalid,
    ProjectRegistryCutoverReceipt,
    _PriorTarget,
    _read_optional,
    _resolve_path,
    _restore_targets,
    _set_journal_state,
    _validate_root,
    validate_project_registry_transition,
)
from .project_registry_models import (
    PROJECT_REGISTRY_MAX_BYTES,
    PROJECT_REGISTRY_MAX_CONSUMER_BYTES,
    PROJECT_REGISTRY_MAX_CONSUMERS,
    ProjectRegistry,
    ProjectRegistryInvalid,
)
from .project_registry_primitives import (
    _GENERATION_ID,
    _digest,
    _identifier,
    _mapping,
    _relative_path,
    _string,
    project_registry_canonical_json,
    project_registry_strict_json,
)
from .project_registry_views import (
    ProjectRegistryConsumerOutput,
    validate_consumer_output_for_registry,
)

_RECOVERABLE_STATES = frozenset({"prepared", "applying"})
_FINAL_STATES = frozenset({"committed", "rolled-back"})
_JOURNAL_FIELDS = frozenset(
    {
        "schema_version",
        "state",
        "generation_id",
        "registry_sha256",
        "expected_registry_sha256",
        "consumers",
        "journal_sha256",
    }
)
_CONSUMER_FIELDS = frozenset(
    {
        "consumer_id",
        "target_path",
        "expected_sha256",
        "candidate_sha256",
        "snapshot_name",
        "was_present",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "generation_id",
        "registry_sha256",
        "previous_registry_sha256",
        "outcome",
        "consumer_ids",
        "receipt_sha256",
    }
)


@dataclass(frozen=True)
class _RecoveryConsumer:
    consumer_id: str
    target_path: str
    expected_sha256: str | None
    candidate_sha256: str
    snapshot_name: str
    was_present: bool


@dataclass(frozen=True)
class _RecoveryJournal:
    state: str
    generation_id: str
    registry_sha256: str
    expected_registry_sha256: str | None
    consumers: tuple[_RecoveryConsumer, ...]


@dataclass(frozen=True)
class _RecoveryBundle:
    journal: _RecoveryJournal
    candidate: ProjectRegistry
    previous: ProjectRegistry | None
    registry_prior: bytes | None
    priors: tuple[_PriorTarget, ...]


def _optional_digest(value: object, field: str) -> str | None:
    return None if value is None else _digest(value, field)


def _parse_journal(payload: bytes) -> _RecoveryJournal:
    value = project_registry_strict_json(payload)
    if project_registry_canonical_json(value) != payload:
        raise ProjectRegistryInvalid("transaction journal is not canonical")
    data = _mapping(value, "transaction journal")
    if set(data) != _JOURNAL_FIELDS:
        raise ProjectRegistryInvalid("transaction journal fields do not match its schema")
    if data.get("schema_version") != PROJECT_REGISTRY_CUTOVER_JOURNAL_SCHEMA:
        raise ProjectRegistryInvalid("transaction journal schema version is unsupported")
    digest = _digest(data.get("journal_sha256"), "transaction journal digest")
    unsigned = {key: item for key, item in data.items() if key != "journal_sha256"}
    if hashlib.sha256(project_registry_canonical_json(unsigned)).hexdigest() != digest:
        raise ProjectRegistryInvalid("transaction journal digest does not close")
    state = _string(data.get("state"), "transaction journal state", 32)
    if state not in _RECOVERABLE_STATES | _FINAL_STATES:
        raise ProjectRegistryInvalid("transaction journal state is unsupported")
    generation_id = _string(data.get("generation_id"), "generation_id", 35)
    if _GENERATION_ID.fullmatch(generation_id) is None:
        raise ProjectRegistryInvalid("transaction journal generation is malformed")
    raw_consumers = data.get("consumers")
    if (
        not isinstance(raw_consumers, list)
        or not 1 <= len(raw_consumers) <= PROJECT_REGISTRY_MAX_CONSUMERS
    ):
        raise ProjectRegistryInvalid("transaction journal consumer count is out of bounds")
    consumers = tuple(
        _parse_consumer(item, index)
        for index, item in enumerate(cast(list[object], raw_consumers))
    )
    identities = tuple(item.consumer_id for item in consumers)
    if identities != tuple(sorted(identities)) or len(identities) != len(set(identities)):
        raise ProjectRegistryInvalid("transaction journal consumers are not identity ordered")
    return _RecoveryJournal(
        state=state,
        generation_id=generation_id,
        registry_sha256=_digest(data.get("registry_sha256"), "registry digest"),
        expected_registry_sha256=_optional_digest(
            data.get("expected_registry_sha256"),
            "expected registry digest",
        ),
        consumers=consumers,
    )


def _parse_consumer(value: object, index: int) -> _RecoveryConsumer:
    field = f"transaction journal consumers[{index}]"
    data = _mapping(value, field)
    if set(data) != _CONSUMER_FIELDS:
        raise ProjectRegistryInvalid(f"{field} fields do not match its schema")
    consumer_id = _identifier(data.get("consumer_id"), f"{field}.consumer_id")
    expected_name = f"{index:04d}_{consumer_id}.json"
    snapshot_name = _string(data.get("snapshot_name"), f"{field}.snapshot_name", 160)
    if snapshot_name != expected_name:
        raise ProjectRegistryInvalid("transaction consumer snapshot name is inconsistent")
    was_present = data.get("was_present")
    if not isinstance(was_present, bool):
        raise ProjectRegistryInvalid("transaction consumer presence flag is malformed")
    expected_sha256 = _optional_digest(
        data.get("expected_sha256"),
        f"{field}.expected_sha256",
    )
    if was_present != (expected_sha256 is not None):
        raise ProjectRegistryInvalid("transaction consumer presence disagrees with precondition")
    return _RecoveryConsumer(
        consumer_id=consumer_id,
        target_path=_relative_path(data.get("target_path"), f"{field}.target_path"),
        expected_sha256=expected_sha256,
        candidate_sha256=_digest(
            data.get("candidate_sha256"),
            f"{field}.candidate_sha256",
        ),
        snapshot_name=snapshot_name,
        was_present=was_present,
    )


def _load_bundle(
    root: Path,
    transaction_directory: Path,
    generation_id: str,
    registry_sha256: str,
) -> _RecoveryBundle:
    candidate_root = _validate_root(
        transaction_directory / "candidate",
        "candidate snapshot root",
        owner_only=True,
    )
    prior_root = _validate_root(
        transaction_directory / "prior",
        "prior snapshot root",
        owner_only=True,
    )
    journal_payload = _read_required(
        transaction_directory / "journal.json",
        PROJECT_REGISTRY_MAX_BYTES,
        "transaction journal",
    )
    journal = _parse_journal(journal_payload)
    if journal.generation_id != generation_id or journal.registry_sha256 != registry_sha256:
        raise ProjectRegistryCutoverInvalid("transaction identity does not match its journal")
    candidate_payload = _read_required(
        candidate_root / "registry.json",
        PROJECT_REGISTRY_MAX_BYTES,
        "candidate registry snapshot",
    )
    candidate = ProjectRegistry.from_bytes(candidate_payload)
    if candidate.generation_id != generation_id or candidate.registry_sha256 != registry_sha256:
        raise ProjectRegistryCutoverInvalid(
            "candidate registry identity does not match transaction"
        )
    registry_prior = _read_optional(
        prior_root / "registry.json",
        PROJECT_REGISTRY_MAX_BYTES,
        "prior registry snapshot",
    )
    previous = None if registry_prior is None else ProjectRegistry.from_bytes(registry_prior)
    if (
        previous.registry_sha256 if previous is not None else None
    ) != journal.expected_registry_sha256:
        raise ProjectRegistryCutoverInvalid("prior registry does not match journal precondition")
    validate_project_registry_transition(previous, candidate)
    declared = tuple(consumer.consumer_id for consumer in candidate.consumers)
    if tuple(item.consumer_id for item in journal.consumers) != declared:
        raise ProjectRegistryCutoverInvalid("transaction journal does not cover every consumer")

    candidate_names = {"registry.json", *(item.snapshot_name for item in journal.consumers)}
    prior_names = {
        *(("registry.json",) if registry_prior is not None else ()),
        *(item.snapshot_name for item in journal.consumers if item.was_present),
    }
    if {path.name for path in candidate_root.iterdir()} != candidate_names:
        raise ProjectRegistryCutoverInvalid("candidate snapshot set does not match journal")
    if {path.name for path in prior_root.iterdir()} != prior_names:
        raise ProjectRegistryCutoverInvalid("prior snapshot set does not match journal")

    priors: list[_PriorTarget] = []
    total = len(journal_payload) + len(candidate_payload) + len(registry_prior or b"")
    for record in journal.consumers:
        candidate_consumer = _read_required(
            candidate_root / record.snapshot_name,
            PROJECT_REGISTRY_MAX_CONSUMER_BYTES,
            "candidate consumer snapshot",
        )
        output = ProjectRegistryConsumerOutput.from_bytes(candidate_consumer)
        validate_consumer_output_for_registry(candidate, output)
        if (
            output.consumer_id != record.consumer_id
            or output.target_path != record.target_path
            or hashlib.sha256(candidate_consumer).hexdigest() != record.candidate_sha256
        ):
            raise ProjectRegistryCutoverInvalid(
                "candidate consumer snapshot does not match journal"
            )
        prior_consumer = _read_optional(
            prior_root / record.snapshot_name,
            PROJECT_REGISTRY_MAX_CONSUMER_BYTES,
            "prior consumer snapshot",
        )
        if record.was_present:
            if (  # pragma: no cover - snapshot disappearance after closed-set listing
                prior_consumer is None or previous is None
            ):
                raise ProjectRegistryCutoverInvalid("required prior consumer snapshot is absent")
            prior_output = ProjectRegistryConsumerOutput.from_bytes(prior_consumer)
            validate_consumer_output_for_registry(previous, prior_output)
            if prior_output.output_sha256 != record.expected_sha256:
                raise ProjectRegistryCutoverInvalid("prior consumer digest does not match journal")
        elif (  # pragma: no cover - snapshot appearance after closed-set listing
            prior_consumer is not None
        ):
            raise ProjectRegistryCutoverInvalid("unexpected prior consumer snapshot is present")
        target = _resolve_path(root, record.target_path, "recovery consumer path")
        priors.append(_PriorTarget(target, prior_consumer, candidate_consumer))
        total += len(candidate_consumer) + len(prior_consumer or b"")
    if total > PROJECT_REGISTRY_MAX_TRANSACTION_BYTES:
        raise ProjectRegistryCutoverInvalid("recovery transaction exceeds its byte bound")
    return _RecoveryBundle(journal, candidate, previous, registry_prior, tuple(priors))


def _read_required(path: Path, maximum: int, label: str) -> bytes:
    payload = _read_optional(path, maximum, label)
    if payload is None:
        raise ProjectRegistryCutoverInvalid(f"{label} is absent")
    return payload


def _verify_prior_state(registry_target: Path, bundle: _RecoveryBundle) -> None:
    if (  # pragma: no cover - concurrent registry change after commit-point read
        _read_optional(registry_target, PROJECT_REGISTRY_MAX_BYTES, "recovered registry")
        != bundle.registry_prior
    ):
        raise ProjectRegistryCutoverInvalid("recovered registry does not match prior state")
    for prior in bundle.priors:
        if (  # pragma: no cover - concurrent consumer change after commit-point read
            _read_optional(
                prior.path,
                PROJECT_REGISTRY_MAX_CONSUMER_BYTES,
                "recovered consumer",
            )
            != prior.payload
        ):
            raise ProjectRegistryCutoverInvalid("recovered consumer does not match prior state")


def _verify_candidate_state(registry_target: Path, bundle: _RecoveryBundle) -> None:
    if (  # pragma: no cover - concurrent registry change after commit-point read
        _read_optional(registry_target, PROJECT_REGISTRY_MAX_BYTES, "recovered registry")
        != bundle.candidate.to_bytes()
    ):
        raise ProjectRegistryCutoverInvalid("committed registry does not match candidate")
    for prior in bundle.priors:
        if (  # pragma: no cover - concurrent consumer change after commit-point read
            _read_optional(
                prior.path,
                PROJECT_REGISTRY_MAX_CONSUMER_BYTES,
                "recovered consumer",
            )
            != prior.candidate_payload
        ):
            raise ProjectRegistryCutoverInvalid("committed consumer does not match candidate")


def _parse_receipt(payload: bytes) -> ProjectRegistryCutoverReceipt:
    value = project_registry_strict_json(payload)
    if project_registry_canonical_json(value) != payload:
        raise ProjectRegistryInvalid("transaction receipt is not canonical")
    data = _mapping(value, "transaction receipt")
    if set(data) != _RECEIPT_FIELDS:
        raise ProjectRegistryInvalid("transaction receipt fields do not match its schema")
    if data.get("schema_version") != PROJECT_REGISTRY_CUTOVER_RECEIPT_SCHEMA:
        raise ProjectRegistryInvalid("transaction receipt schema version is unsupported")
    digest = _digest(data.get("receipt_sha256"), "transaction receipt digest")
    unsigned = {key: item for key, item in data.items() if key != "receipt_sha256"}
    if hashlib.sha256(project_registry_canonical_json(unsigned)).hexdigest() != digest:
        raise ProjectRegistryInvalid("transaction receipt digest does not close")
    raw_consumer_ids = data.get("consumer_ids")
    if not isinstance(raw_consumer_ids, list):
        raise ProjectRegistryInvalid("transaction receipt consumers are malformed")
    consumer_ids = tuple(
        _identifier(item, f"transaction receipt consumers[{index}]")
        for index, item in enumerate(cast(list[object], raw_consumer_ids))
    )
    outcome = _string(data.get("outcome"), "transaction receipt outcome", 32)
    if outcome not in {"committed", "rolled-back"}:
        raise ProjectRegistryInvalid("transaction receipt outcome is unsupported")
    return ProjectRegistryCutoverReceipt(
        generation_id=_string(data.get("generation_id"), "generation_id", 35),
        registry_sha256=_digest(data.get("registry_sha256"), "registry digest"),
        previous_registry_sha256=_optional_digest(
            data.get("previous_registry_sha256"),
            "previous registry digest",
        ),
        outcome=outcome,
        consumer_ids=consumer_ids,
    )


def _finalize_receipt(
    transaction_directory: Path,
    bundle: _RecoveryBundle,
    outcome: str,
) -> ProjectRegistryCutoverReceipt:
    receipt = ProjectRegistryCutoverReceipt(
        generation_id=bundle.candidate.generation_id,
        registry_sha256=bundle.candidate.registry_sha256,
        previous_registry_sha256=bundle.journal.expected_registry_sha256,
        outcome=outcome,
        consumer_ids=tuple(item.consumer_id for item in bundle.journal.consumers),
    )
    receipt_path = transaction_directory / "receipt.json"
    existing = _read_optional(
        receipt_path,
        PROJECT_REGISTRY_MAX_BYTES,
        "transaction receipt",
    )
    if existing is None:
        write_new_text(receipt_path, receipt.to_bytes().decode("utf-8"))
    elif _parse_receipt(existing) != receipt:
        raise ProjectRegistryCutoverInvalid("transaction receipt conflicts with recovery outcome")
    return receipt


def recover_project_registry_cutover(
    monorepo_root: Path,
    registry_path: str,
    transaction_root: Path,
    generation_id: str,
    registry_sha256: str,
) -> ProjectRegistryCutoverReceipt:
    """Resolve one exact interrupted transaction at the registry commit point."""
    root = _validate_root(monorepo_root, "monorepo root")
    transactions = _validate_root(transaction_root, "transaction root", owner_only=True)
    generation = _string(generation_id, "generation_id", 35)
    if _GENERATION_ID.fullmatch(generation) is None:
        raise ProjectRegistryCutoverInvalid("recovery generation is malformed")
    digest = _digest(registry_sha256, "recovery registry digest")
    registry_target = _resolve_path(root, registry_path, "registry path")
    transaction_directory = transactions / f"{generation}_{digest}"
    lock_path = transactions / ".cutover.lock"
    try:
        with exclusive_lock(lock_path):
            transaction_directory = _validate_root(
                transaction_directory,
                "transaction directory",
                owner_only=True,
            )
            bundle = _load_bundle(root, transaction_directory, generation, digest)
            live_registry = _read_optional(
                registry_target,
                PROJECT_REGISTRY_MAX_BYTES,
                "recovery registry target",
            )
            candidate_bytes = bundle.candidate.to_bytes()
            if live_registry == candidate_bytes:
                if bundle.journal.state == "rolled-back":
                    raise ProjectRegistryCutoverInvalid("rolled-back journal has candidate state")
                _verify_candidate_state(registry_target, bundle)
                outcome = "committed"
            elif live_registry == bundle.registry_prior:
                if bundle.journal.state == "committed":
                    raise ProjectRegistryCutoverInvalid("committed journal has prior state")
                _restore_targets(
                    registry_target,
                    bundle.registry_prior,
                    candidate_bytes,
                    bundle.priors,
                )
                _verify_prior_state(registry_target, bundle)
                outcome = "rolled-back"
            else:
                raise ProjectRegistryCutoverInvalid(
                    "registry changed outside the interrupted transaction"
                )
            receipt = _finalize_receipt(transaction_directory, bundle, outcome)
            final_state = outcome
            if bundle.journal.state != final_state:
                _set_journal_state(transaction_directory, final_state)
            return receipt
    except ProjectRegistryCutoverInvalid:
        raise
    except ProjectRegistryInvalid as exc:
        raise ProjectRegistryCutoverInvalid("registry recovery evidence is invalid") from exc
    except (OSError, RuntimeError, ValueError) as exc:
        raise ProjectRegistryCutoverInvalid("registry recovery lock or storage failed") from exc
