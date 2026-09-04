# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project registry consumer cutover
"""Apply an all-consumer project registry transaction with synchronous rollback."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .internal_storage import atomic_replace_text, exclusive_lock, fsync_directory, write_new_text
from .project_registry_models import (
    PROJECT_REGISTRY_MAX_BYTES,
    PROJECT_REGISTRY_MAX_CONSUMER_BYTES,
    ProjectRegistration,
    ProjectRegistry,
    ProjectRegistryInvalid,
)
from .project_registry_primitives import (
    _digest,
    _relative_path,
    project_registry_canonical_json,
    project_registry_strict_json,
)
from .project_registry_views import (
    ProjectRegistryConsumerOutput,
    validate_consumer_output_for_registry,
)

PROJECT_REGISTRY_MAX_TRANSACTION_BYTES = 32 * 1024 * 1024
PROJECT_REGISTRY_CUTOVER_RECEIPT_SCHEMA = "gotm-project-registry-cutover-receipt.v1"
PROJECT_REGISTRY_CUTOVER_JOURNAL_SCHEMA = "gotm-project-registry-cutover-journal.v1"
_ABSENT = "ABSENT"


class ProjectRegistryCutoverInvalid(RuntimeError):
    """The registry transaction cannot complete or restore exact prior state."""


def _normalise_digest(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    try:
        return _digest(value, field)
    except ProjectRegistryInvalid as exc:
        raise ProjectRegistryCutoverInvalid(f"{field} is invalid") from exc


def _validate_root(path: Path, label: str, *, owner_only: bool = False) -> Path:
    try:
        resolved = path.resolve(strict=True)
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise ProjectRegistryCutoverInvalid(f"{label} is unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or (owner_only and stat.S_IMODE(metadata.st_mode) != 0o700)
    ):
        raise ProjectRegistryCutoverInvalid(f"{label} is not a safe owned directory")
    return resolved


def _resolve_path(root: Path, relative: str, label: str) -> Path:
    try:
        normalised = _relative_path(relative, label)
    except ProjectRegistryInvalid as exc:
        raise ProjectRegistryCutoverInvalid(f"{label} is invalid") from exc
    candidate = root / PurePosixPath(normalised)
    cursor = root
    for part in PurePosixPath(normalised).parts[:-1]:
        cursor /= part
        try:
            metadata = cursor.stat(follow_symlinks=False)
        except OSError as exc:
            raise ProjectRegistryCutoverInvalid(f"{label} parent is unavailable") from exc
        if cursor.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise ProjectRegistryCutoverInvalid(f"{label} parent is not a real directory")
    try:
        candidate.resolve(strict=False).relative_to(root)
    except (OSError, ValueError) as exc:
        raise ProjectRegistryCutoverInvalid(f"{label} escapes the monorepo") from exc
    return candidate


def _read_optional(path: Path, maximum: int, label: str) -> bytes | None:
    if not path.exists() and not path.is_symlink():
        return None
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size > maximum
        ):
            raise ProjectRegistryCutoverInvalid(f"{label} is not a bounded owner-only file")
        payload = bytearray()
        while True:
            chunk = os.read(descriptor, min(65_536, maximum + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > maximum:
                raise ProjectRegistryCutoverInvalid(f"{label} exceeds its byte bound")
        after = os.fstat(descriptor)
        current = path.stat(follow_symlinks=False)
        if (
            (after.st_dev, after.st_ino) != identity
            or (current.st_dev, current.st_ino) != identity
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
        ):
            raise ProjectRegistryCutoverInvalid(f"{label} changed while being read")
        return bytes(payload)
    except OSError as exc:
        raise ProjectRegistryCutoverInvalid(f"{label} cannot be read safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _replace(path: Path, payload: bytes) -> None:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProjectRegistryCutoverInvalid("registry transaction payload is not UTF-8") from exc
    try:
        atomic_replace_text(path, text)
    except (OSError, ValueError) as exc:
        raise ProjectRegistryCutoverInvalid(
            "registry transaction atomic replacement failed"
        ) from exc


def _remove_created(path: Path) -> None:
    try:
        path.unlink()
        fsync_directory(path.parent)
    except OSError as exc:
        raise ProjectRegistryCutoverInvalid(
            "registry rollback could not remove a new target"
        ) from exc


@dataclass(frozen=True)
class ProjectRegistryConsumerUpdate:
    """One expected prior digest and exact candidate consumer output."""

    consumer_id: str
    expected_sha256: str | None
    output: ProjectRegistryConsumerOutput

    @classmethod
    def build(
        cls,
        output: ProjectRegistryConsumerOutput,
        *,
        expected_sha256: str | None,
    ) -> ProjectRegistryConsumerUpdate:
        """Build one consumer update with a normalised prior-state precondition."""
        return cls(
            consumer_id=output.consumer_id,
            expected_sha256=_normalise_digest(expected_sha256, "expected consumer digest"),
            output=ProjectRegistryConsumerOutput.from_bytes(output.to_bytes()),
        )


@dataclass(frozen=True)
class ProjectRegistryCutoverPlan:
    """A complete, ordered candidate registry and all declared consumer writes."""

    candidate: ProjectRegistry
    expected_registry_sha256: str | None
    updates: tuple[ProjectRegistryConsumerUpdate, ...]

    @classmethod
    def build(
        cls,
        candidate: ProjectRegistry,
        *,
        expected_registry_sha256: str | None,
        updates: tuple[ProjectRegistryConsumerUpdate, ...],
    ) -> ProjectRegistryCutoverPlan:
        """Validate one all-consumer cutover plan."""
        candidate = ProjectRegistry.from_bytes(candidate.to_bytes())
        expected = _normalise_digest(expected_registry_sha256, "expected registry digest")
        ordered = tuple(sorted(updates, key=lambda update: update.consumer_id))
        identities = tuple(update.consumer_id for update in ordered)
        declared = tuple(consumer.consumer_id for consumer in candidate.consumers)
        if identities != declared or len(identities) != len(set(identities)):
            raise ProjectRegistryCutoverInvalid("cutover updates do not match every consumer")
        total = len(candidate.to_bytes())
        for update in ordered:
            if update.consumer_id != update.output.consumer_id:
                raise ProjectRegistryCutoverInvalid(
                    "consumer update identity does not match output"
                )
            try:
                validate_consumer_output_for_registry(candidate, update.output)
            except ProjectRegistryInvalid as exc:
                raise ProjectRegistryCutoverInvalid(
                    "consumer output does not match registry"
                ) from exc
            total += len(update.output.to_bytes())
        if total > PROJECT_REGISTRY_MAX_TRANSACTION_BYTES:
            raise ProjectRegistryCutoverInvalid("candidate transaction exceeds its byte bound")
        return cls(candidate, expected, ordered)


def validate_project_registry_transition(
    previous: ProjectRegistry | None,
    candidate: ProjectRegistry,
) -> None:
    """Require append-only identities, aliases and exact predecessor chaining."""
    if previous is None:
        if candidate.previous_registry_sha256 is not None:
            raise ProjectRegistryCutoverInvalid("initial registry cannot name a predecessor")
        return
    if candidate.previous_registry_sha256 != previous.registry_sha256:
        raise ProjectRegistryCutoverInvalid("candidate does not name the current registry")
    if candidate.generated_at <= previous.generated_at:
        raise ProjectRegistryCutoverInvalid("registry generation time must increase")
    previous_groups = {group.group_id: group for group in previous.groups}
    candidate_groups = {group.group_id: group for group in candidate.groups}
    if not previous_groups.keys() <= candidate_groups.keys():
        raise ProjectRegistryCutoverInvalid("a registry generation cannot delete a group")
    for group_id, old_group in previous_groups.items():
        new_group = candidate_groups[group_id]
        if (
            old_group.root_path != new_group.root_path
            or old_group.repositories_path != new_group.repositories_path
            or old_group.memory_index_path != new_group.memory_index_path
        ):
            raise ProjectRegistryCutoverInvalid("group identity paths are immutable in v1")
    previous_projects = {project.project_id: project for project in previous.projects}
    candidate_projects = {project.project_id: project for project in candidate.projects}
    if not previous_projects.keys() <= candidate_projects.keys():
        raise ProjectRegistryCutoverInvalid("a registry generation cannot delete a project")
    for project_id, old_project in previous_projects.items():
        _validate_project_transition(old_project, candidate_projects[project_id])
    previous_consumers = {consumer.consumer_id: consumer for consumer in previous.consumers}
    candidate_consumers = {consumer.consumer_id: consumer for consumer in candidate.consumers}
    if not previous_consumers.keys() <= candidate_consumers.keys():
        raise ProjectRegistryCutoverInvalid("a registry generation cannot delete a consumer")
    for consumer_id, old_consumer in previous_consumers.items():
        new_consumer = candidate_consumers[consumer_id]
        if old_consumer.kind != new_consumer.kind:
            raise ProjectRegistryCutoverInvalid("consumer kind is immutable in v1")
        if old_consumer.kind == "project-index":
            if old_consumer.project_id != new_consumer.project_id:
                raise ProjectRegistryCutoverInvalid("project-index identity is immutable in v1")
        elif old_consumer != new_consumer:
            raise ProjectRegistryCutoverInvalid(
                "global and group consumer paths are immutable in v1"
            )


def _validate_project_transition(
    old: ProjectRegistration,
    new: ProjectRegistration,
) -> None:
    if old.target_kind != new.target_kind:
        raise ProjectRegistryCutoverInvalid("project target kind is immutable")
    old_aliases = {alias.path: alias for alias in old.aliases}
    new_aliases = {alias.path: alias for alias in new.aliases}
    if not old_aliases.items() <= new_aliases.items():
        raise ProjectRegistryCutoverInvalid(
            "historical project aliases cannot change or disappear"
        )
    if old.canonical_path != new.canonical_path:
        retained = new_aliases.get(old.canonical_path)
        if retained is None:
            raise ProjectRegistryCutoverInvalid("a moved canonical path must become an alias")


@dataclass(frozen=True)
class ProjectRegistryCutoverReceipt:
    """Content-free result of one committed or restored registry transaction."""

    generation_id: str
    registry_sha256: str
    previous_registry_sha256: str | None
    outcome: str
    consumer_ids: tuple[str, ...]

    def to_bytes(self) -> bytes:
        """Return canonical receipt bytes with a digest closure."""
        value: dict[str, object] = {
            "schema_version": PROJECT_REGISTRY_CUTOVER_RECEIPT_SCHEMA,
            "generation_id": self.generation_id,
            "registry_sha256": self.registry_sha256,
            "previous_registry_sha256": self.previous_registry_sha256,
            "outcome": self.outcome,
            "consumer_ids": list(self.consumer_ids),
        }
        value["receipt_sha256"] = hashlib.sha256(
            project_registry_canonical_json(value)
        ).hexdigest()
        return project_registry_canonical_json(value)


@dataclass(frozen=True)
class _PriorTarget:
    path: Path
    payload: bytes | None
    candidate_payload: bytes


def _transaction_directory(transaction_root: Path, plan: ProjectRegistryCutoverPlan) -> Path:
    return transaction_root / f"{plan.candidate.generation_id}_{plan.candidate.registry_sha256}"


def _write_transaction_snapshot(
    transaction_directory: Path,
    registry_prior: bytes | None,
    consumer_priors: tuple[_PriorTarget, ...],
    plan: ProjectRegistryCutoverPlan,
) -> None:
    try:
        transaction_directory.mkdir(mode=0o700)
        (transaction_directory / "prior").mkdir(mode=0o700)
        (transaction_directory / "candidate").mkdir(mode=0o700)
        write_new_text(
            transaction_directory / "candidate/registry.json",
            plan.candidate.to_bytes().decode("utf-8"),
        )
        if registry_prior is not None:
            write_new_text(
                transaction_directory / "prior/registry.json",
                registry_prior.decode("utf-8"),
            )
        snapshots: list[dict[str, object]] = []
        for index, (prior, update) in enumerate(zip(consumer_priors, plan.updates, strict=True)):
            name = f"{index:04d}_{update.consumer_id}.json"
            write_new_text(
                transaction_directory / "candidate" / name,
                update.output.to_bytes().decode("utf-8"),
            )
            if prior.payload is not None:
                write_new_text(
                    transaction_directory / "prior" / name,
                    prior.payload.decode("utf-8"),
                )
            snapshots.append(
                {
                    "consumer_id": update.consumer_id,
                    "target_path": update.output.target_path,
                    "expected_sha256": update.expected_sha256,
                    "candidate_sha256": hashlib.sha256(prior.candidate_payload).hexdigest(),
                    "snapshot_name": name,
                    "was_present": prior.payload is not None,
                }
            )
        journal: dict[str, object] = {
            "schema_version": PROJECT_REGISTRY_CUTOVER_JOURNAL_SCHEMA,
            "state": "prepared",
            "generation_id": plan.candidate.generation_id,
            "registry_sha256": plan.candidate.registry_sha256,
            "expected_registry_sha256": plan.expected_registry_sha256,
            "consumers": snapshots,
        }
        journal["journal_sha256"] = hashlib.sha256(
            project_registry_canonical_json(journal)
        ).hexdigest()
        write_new_text(
            transaction_directory / "journal.json",
            project_registry_canonical_json(journal).decode("utf-8"),
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise ProjectRegistryCutoverInvalid("transaction snapshot could not be created") from exc


def _set_journal_state(transaction_directory: Path, state: str) -> None:
    journal_path = transaction_directory / "journal.json"
    payload = _read_optional(journal_path, PROJECT_REGISTRY_MAX_BYTES, "transaction journal")
    if payload is None:
        raise ProjectRegistryCutoverInvalid("transaction journal is absent")
    try:
        value = project_registry_strict_json(payload)
        journal = _mapping_for_cutover(value)
        raw_digest = journal.pop("journal_sha256", None)
        digest = _normalise_digest(
            raw_digest if isinstance(raw_digest, str) else None,
            "transaction journal digest",
        )
        expected = hashlib.sha256(project_registry_canonical_json(journal)).hexdigest()
        if digest != expected:
            raise ProjectRegistryCutoverInvalid("transaction journal digest does not close")
        journal["state"] = state
        journal["journal_sha256"] = hashlib.sha256(
            project_registry_canonical_json(journal)
        ).hexdigest()
        atomic_replace_text(journal_path, project_registry_canonical_json(journal).decode("utf-8"))
    except (OSError, UnicodeError, ValueError, ProjectRegistryInvalid) as exc:
        raise ProjectRegistryCutoverInvalid("transaction journal state cannot be updated") from exc


def _mapping_for_cutover(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ProjectRegistryCutoverInvalid("transaction journal is malformed")
    return dict(value)


def _restore_targets(
    registry_path: Path,
    registry_prior: bytes | None,
    registry_candidate: bytes,
    priors: tuple[_PriorTarget, ...],
) -> None:
    for prior in reversed(priors):
        current = _read_optional(
            prior.path,
            PROJECT_REGISTRY_MAX_CONSUMER_BYTES,
            "consumer rollback target",
        )
        if current not in {prior.payload, prior.candidate_payload}:
            raise ProjectRegistryCutoverInvalid("consumer changed outside the cutover transaction")
        if current == prior.payload:
            continue
        if prior.payload is None:
            _remove_created(prior.path)
        else:
            _replace(prior.path, prior.payload)
    current_registry = _read_optional(
        registry_path,
        PROJECT_REGISTRY_MAX_BYTES,
        "registry rollback target",
    )
    if current_registry not in {registry_prior, registry_candidate}:
        raise ProjectRegistryCutoverInvalid("registry changed outside the cutover transaction")
    if current_registry == registry_prior:
        return
    if registry_prior is None:
        _remove_created(registry_path)
    else:
        _replace(registry_path, registry_prior)


def _verify_live_state(
    registry_path: Path,
    plan: ProjectRegistryCutoverPlan,
    priors: tuple[_PriorTarget, ...],
) -> None:
    registry_payload = _read_optional(
        registry_path, PROJECT_REGISTRY_MAX_BYTES, "current registry"
    )
    if registry_payload != plan.candidate.to_bytes():
        raise ProjectRegistryCutoverInvalid("current registry does not match the candidate")
    for prior, update in zip(priors, plan.updates, strict=True):
        payload = _read_optional(
            prior.path,
            PROJECT_REGISTRY_MAX_CONSUMER_BYTES,
            "current consumer output",
        )
        if payload != update.output.to_bytes():
            raise ProjectRegistryCutoverInvalid("current consumer does not match the candidate")


def apply_project_registry_cutover(
    monorepo_root: Path,
    registry_path: str,
    transaction_root: Path,
    plan: ProjectRegistryCutoverPlan,
) -> ProjectRegistryCutoverReceipt:
    """Apply one all-consumer transaction and restore all prior bytes on failure.

    Parameters
    ----------
    monorepo_root:
        Canonical existing monorepo root that bounds every target.
    registry_path:
        Monorepo-relative canonical registry file, replaced after consumers.
    transaction_root:
        Existing owner-only directory retaining the transaction snapshot.
    plan:
        Candidate generation and an exact update for every declared consumer.

    Returns
    -------
    ProjectRegistryCutoverReceipt
        A content-free committed result. Failed transactions raise after an
        exact rollback and retain a rolled-back receipt beside their snapshot.

    Raises
    ------
    ProjectRegistryCutoverInvalid
        If validation, application, verification or rollback fails.
    """
    root = _validate_root(monorepo_root, "monorepo root")
    transactions = _validate_root(transaction_root, "transaction root", owner_only=True)
    registry_target = _resolve_path(root, registry_path, "registry path")
    transaction_directory = _transaction_directory(transactions, plan)
    if transaction_directory.exists():
        raise ProjectRegistryCutoverInvalid("transaction generation already has a snapshot")
    consumer_paths = tuple(
        _resolve_path(root, update.output.target_path, "consumer path") for update in plan.updates
    )
    if registry_target in consumer_paths or any(
        transaction_directory == path or transaction_directory in path.parents
        for path in (registry_target, *consumer_paths)
    ):
        raise ProjectRegistryCutoverInvalid("transaction metadata overlaps a target")
    lock_path = transactions / ".cutover.lock"
    try:
        with exclusive_lock(lock_path):
            registry_prior = _read_optional(
                registry_target,
                PROJECT_REGISTRY_MAX_BYTES,
                "current registry",
            )
            previous = None
            if registry_prior is None:
                if plan.expected_registry_sha256 is not None:
                    raise ProjectRegistryCutoverInvalid(
                        "current registry digest precondition failed"
                    )
            else:
                try:
                    previous = ProjectRegistry.from_bytes(registry_prior)
                except ProjectRegistryInvalid as exc:
                    raise ProjectRegistryCutoverInvalid("current registry is invalid") from exc
                if previous.registry_sha256 != plan.expected_registry_sha256:
                    raise ProjectRegistryCutoverInvalid(
                        "current registry digest precondition failed"
                    )
            validate_project_registry_transition(previous, plan.candidate)
            priors: list[_PriorTarget] = []
            total = len(plan.candidate.to_bytes()) + len(registry_prior or b"")
            for path, update in zip(consumer_paths, plan.updates, strict=True):
                payload = _read_optional(
                    path,
                    PROJECT_REGISTRY_MAX_CONSUMER_BYTES,
                    "current consumer output",
                )
                if payload is None:
                    if update.expected_sha256 is not None:
                        raise ProjectRegistryCutoverInvalid("consumer digest precondition failed")
                else:
                    try:
                        current_output = ProjectRegistryConsumerOutput.from_bytes(payload)
                        if previous is not None:
                            validate_consumer_output_for_registry(previous, current_output)
                    except ProjectRegistryInvalid as exc:
                        raise ProjectRegistryCutoverInvalid(
                            "current consumer output is invalid"
                        ) from exc
                    if current_output.output_sha256 != update.expected_sha256:
                        raise ProjectRegistryCutoverInvalid("consumer digest precondition failed")
                candidate_payload = update.output.to_bytes()
                priors.append(_PriorTarget(path, payload, candidate_payload))
                total += len(payload or b"") + len(update.output.to_bytes())
            if total > PROJECT_REGISTRY_MAX_TRANSACTION_BYTES:
                raise ProjectRegistryCutoverInvalid("transaction snapshot exceeds its byte bound")
            prior_targets = tuple(priors)
            _write_transaction_snapshot(
                transaction_directory,
                registry_prior,
                prior_targets,
                plan,
            )
            _set_journal_state(transaction_directory, "applying")
            try:
                for path, update in zip(consumer_paths, plan.updates, strict=True):
                    _replace(path, update.output.to_bytes())
                _replace(registry_target, plan.candidate.to_bytes())
                _verify_live_state(registry_target, plan, prior_targets)
            except (OSError, RuntimeError, ValueError) as exc:
                try:
                    _restore_targets(
                        registry_target,
                        registry_prior,
                        plan.candidate.to_bytes(),
                        prior_targets,
                    )
                    _set_journal_state(transaction_directory, "rolled-back")
                    receipt = ProjectRegistryCutoverReceipt(
                        plan.candidate.generation_id,
                        plan.candidate.registry_sha256,
                        plan.expected_registry_sha256,
                        "rolled-back",
                        tuple(update.consumer_id for update in plan.updates),
                    )
                    write_new_text(
                        transaction_directory / "receipt.json",
                        receipt.to_bytes().decode("utf-8"),
                    )
                except (OSError, RuntimeError, ValueError) as rollback_exc:
                    raise ProjectRegistryCutoverInvalid(
                        "registry cutover failed and exact rollback also failed"
                    ) from rollback_exc
                raise ProjectRegistryCutoverInvalid(
                    "registry cutover failed and prior state was restored"
                ) from exc
            _set_journal_state(transaction_directory, "committed")
            receipt = ProjectRegistryCutoverReceipt(
                plan.candidate.generation_id,
                plan.candidate.registry_sha256,
                plan.expected_registry_sha256,
                "committed",
                tuple(update.consumer_id for update in plan.updates),
            )
            write_new_text(
                transaction_directory / "receipt.json",
                receipt.to_bytes().decode("utf-8"),
            )
            return receipt
    except ProjectRegistryCutoverInvalid:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise ProjectRegistryCutoverInvalid("registry cutover lock or storage failed") from exc


def load_project_registry_state(monorepo_root: Path, registry_path: str) -> ProjectRegistry:
    """Load the current registry and verify every declared consumer output."""
    root = _validate_root(monorepo_root, "monorepo root")
    registry_target = _resolve_path(root, registry_path, "registry path")
    payload = _read_optional(registry_target, PROJECT_REGISTRY_MAX_BYTES, "current registry")
    if payload is None:
        raise ProjectRegistryCutoverInvalid("current registry is absent")
    try:
        registry = ProjectRegistry.from_bytes(payload)
        for consumer in registry.consumers:
            target = _resolve_path(root, consumer.path, "consumer path")
            output_payload = _read_optional(
                target,
                PROJECT_REGISTRY_MAX_CONSUMER_BYTES,
                "current consumer output",
            )
            if output_payload is None:
                raise ProjectRegistryCutoverInvalid("current consumer output is absent")
            output = ProjectRegistryConsumerOutput.from_bytes(output_payload)
            validate_consumer_output_for_registry(registry, output)
    except ProjectRegistryInvalid as exc:
        raise ProjectRegistryCutoverInvalid("registry state is invalid") from exc
    return registry
