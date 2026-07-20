# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — safe append-only CRA repository storage
"""Persist and replay ignored CRA records with fail-closed integrity checks."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, TypeVar

from .cra_advisories import FixedVulnerabilityAdvisory, validate_advisory_successor
from .cra_events import SecurityEventRevision, validate_revision_successor
from .cra_payloads import PreparedPayload, validate_prepared_payload
from .cra_protocol import Stage, require_cra_timestamp, require_stage
from .cra_registration import ProductRegistration
from .cra_submissions import (
    StageDraft,
    StageSkip,
    SubmissionReceipt,
    UserNoticeDraft,
    validate_receipt_binding,
    validate_skip_binding,
)
from .git_inventory import (
    StableReadError,
    open_directory_no_follow,
    read_stable_regular_file_at,
)
from .internal_storage import (
    exclusive_lock,
    fsync_directory,
    resolve_ignored_path,
    write_new_text,
)
from .model_primitives import require_identifier
from .version import __version__

_ROOT = Path(".rigor/cra")
_MAX_RECORD_BYTES = 1_048_576
_MAX_EVIDENCE_BYTES = 64 * 1024 * 1024


class _JsonRecord(Protocol):
    """Describe strict records with canonical JSON serialisation."""

    def to_json(self) -> str:
        """Return the record's canonical JSON bytes as text."""


_Record = TypeVar("_Record", bound=_JsonRecord)


class _HasStage(Protocol):
    """Describe records keyed by one reporting stage."""

    @property
    def stage(self) -> Stage:
        """Return the record's reporting stage."""


_StageRecord = TypeVar("_StageRecord", bound=_HasStage)


def _safe_directory(path: Path, *, label: str) -> None:
    """Require one existing non-symlink directory."""
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{label} must be a non-symlink directory")


def _mkdir(path: Path) -> None:
    """Create one directory and synchronise its parent, or validate it."""
    try:
        os.mkdir(path, 0o700)
        fsync_directory(path.parent)
    except FileExistsError:
        _safe_directory(path, label="CRA storage component")


def _mkdirs(root: Path, relative: Path) -> Path:
    """Create validated descendants below an already validated CRA root."""
    cursor = root
    for part in relative.parts:
        cursor /= part
        _mkdir(cursor)
    return cursor


def _read_text(path: Path) -> str:
    """Read one bounded, regular, single-link file without following symlinks."""
    absolute = Path(os.path.abspath(path))
    parent: int | None = None
    try:
        parent = open_directory_no_follow(absolute.parent)
        observed = read_stable_regular_file_at(
            parent,
            absolute.name,
            str(path),
            buffer_limit=_MAX_RECORD_BYTES,
            maximum_bytes=_MAX_RECORD_BYTES,
            require_single_link=True,
        )
    except StableReadError as exc:
        if exc.reason == "limit-exceeded":
            raise ValueError(f"CRA record exceeds the byte limit: {path}") from exc
        raise ValueError(f"CRA record must be a stable single-link regular file: {path}") from exc
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"CRA record path is inaccessible or unsafe: {path}") from exc
    finally:
        if parent is not None:
            os.close(parent)
    if observed.payload is None:
        raise ValueError(f"CRA record exceeds the byte limit: {path}")
    try:
        return observed.payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"CRA record is not valid UTF-8: {path}") from exc


def _evidence_digest(path: Path, *, label: str) -> str:
    """Rehash one bounded single-link evidence file through a stable descriptor."""
    absolute = Path(os.path.abspath(path))
    parent: int | None = None
    try:
        parent = open_directory_no_follow(absolute.parent)
        observed = read_stable_regular_file_at(
            parent,
            absolute.name,
            label,
            buffer_limit=0,
            maximum_bytes=_MAX_EVIDENCE_BYTES,
            require_single_link=True,
        )
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{label} is unavailable or unsafe: {path}") from exc
    finally:
        if parent is not None:
            os.close(parent)
    return observed.content_digest


def _parse_records(
    directory: Path,
    parser: Callable[[object], _Record],
    digest_name: str,
) -> tuple[_Record, ...]:
    """Parse every JSON record and bind its filename to its embedded digest."""
    if not directory.exists():
        return ()
    _safe_directory(directory, label="CRA record directory")
    records: list[_Record] = []
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        if path.suffix != ".json":
            raise ValueError(f"unexpected CRA storage entry: {path}")
        text = _read_text(path)
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"CRA record is not valid JSON: {path}") from exc
        record = parser(value)
        digest = getattr(record, digest_name, None)
        if path.stem != digest:
            raise ValueError(f"CRA filename does not match embedded digest: {path}")
        if text != record.to_json():
            raise ValueError(f"CRA record bytes are not canonical: {path}")
        records.append(record)
    return tuple(records)


def _write_once_or_verify(path: Path, text: str) -> None:
    """Create immutable bytes or accept only a byte-identical crash replay."""
    try:
        write_new_text(path, text)
    except ValueError as exc:
        if "already exists" not in str(exc) or _read_text(path) != text:
            raise


def _single_by_stage(
    records: tuple[_StageRecord, ...],
    *,
    label: str,
) -> tuple[_StageRecord, ...]:
    """Reject multiple current records for the same reporting stage."""
    seen: set[object] = set()
    for record in records:
        stage = record.stage
        if stage in seen:
            raise ValueError(f"multiple current {label} records exist for stage {stage}")
        seen.add(stage)
    return records


@dataclass(frozen=True)
class CraEventState:
    """Carry one verified current event and its bound stage evidence."""

    event: SecurityEventRevision
    drafts: tuple[StageDraft, ...]
    receipts: tuple[SubmissionReceipt, ...]
    skips: tuple[StageSkip, ...]
    revision_digests: frozenset[str]


def _select_advisory_tip(
    revisions: tuple[FixedVulnerabilityAdvisory, ...],
) -> FixedVulnerabilityAdvisory:
    """Select one complete, unforked advisory revision-chain tip."""
    by_digest = {item.advisory_digest: item for item in revisions}
    if len(by_digest) != len(revisions):
        raise ValueError("advisory revision chain contains duplicate digests")
    roots = tuple(item for item in revisions if item.previous_advisory_digest is None)
    if len(roots) != 1:
        raise ValueError("advisory revision chain has multiple roots")
    current = roots[0]
    visited = {current.advisory_digest}
    while True:
        children = tuple(
            item for item in revisions if item.previous_advisory_digest == current.advisory_digest
        )
        if len(children) > 1:
            raise ValueError("advisory revision chain is forked")
        if not children:
            break
        validate_advisory_successor(current, children[0])
        current = children[0]
        visited.add(current.advisory_digest)
    if len(visited) != len(revisions):
        raise ValueError("advisory revision chain is disconnected")
    return current


def _verify_advisory_evidence(
    repository_root: Path,
    revision: FixedVulnerabilityAdvisory,
) -> None:
    """Replay every external byte identity bound by one advisory revision."""
    if (
        _evidence_digest(
            repository_root / revision.advisory_path,
            label="stored advisory content",
        )
        != revision.advisory_sha256
    ):
        raise ValueError("stored advisory digest does not match its current bytes")
    if revision.publication_evidence_path is not None and (
        _evidence_digest(
            repository_root / revision.publication_evidence_path,
            label="stored advisory publication evidence",
        )
        != revision.publication_evidence_sha256
    ):
        raise ValueError(
            "stored advisory publication evidence digest does not match its current bytes"
        )
    if revision.delay_evidence_path is not None and (
        _evidence_digest(
            repository_root / revision.delay_evidence_path,
            label="stored advisory delay evidence",
        )
        != revision.delay_evidence_sha256
    ):
        raise ValueError("stored advisory delay evidence digest does not match its current bytes")


class CraRepository:
    """Manage one repository's ignored append-only CRA evidence tree."""

    def __init__(self, repository_root: Path, storage_root: Path) -> None:
        """Initialise a validated repository and storage root pair."""
        self.repository_root = repository_root
        self.storage_root = storage_root
        self._lock_path = storage_root / ".lock"

    @property
    def lock_path(self) -> Path:
        """Expose the internal lock identity for one atomic read snapshot."""
        return self._lock_path

    @classmethod
    def bootstrap(
        cls,
        repository_root: Path,
        registration: ProductRegistration,
    ) -> CraRepository:
        """Create fresh ignored CRA state and its initial registration.

        Parameters
        ----------
        repository_root:
            Existing Git worktree root.
        registration:
            Initial operator-declared product registration.

        Returns
        -------
        CraRepository
            Open storage containing the immutable registration.

        Raises
        ------
        ValueError
            If CRA state already exists or the path is unsafe or tracked.

        """
        repository = repository_root.resolve(strict=True)
        registration = ProductRegistration.from_dict(registration.to_dict())
        storage = resolve_ignored_path(repository, _ROOT, label="CRA storage")
        if storage.exists():
            raise ValueError("CRA storage already exists")
        _mkdir(storage.parent)
        os.mkdir(storage, 0o700)
        fsync_directory(storage.parent)
        instance = cls(repository, storage)
        with exclusive_lock(instance._lock_path):
            _mkdirs(storage, Path("registrations") / registration.product_key)
            _mkdirs(storage, Path("events"))
            _mkdirs(storage, Path("outbox"))
            path = (
                storage
                / "registrations"
                / registration.product_key
                / f"{registration.registration_digest}.json"
            )
            write_new_text(path, registration.to_json())
        return instance

    @classmethod
    def open(cls, repository_root: Path) -> CraRepository:
        """Open existing ignored CRA state after path validation.

        Parameters
        ----------
        repository_root:
            Existing Git worktree root.

        Returns
        -------
        CraRepository
            Validated storage handle.

        """
        repository = repository_root.resolve(strict=True)
        storage = resolve_ignored_path(repository, _ROOT, label="CRA storage")
        _safe_directory(storage, label="CRA storage")
        return cls(repository, storage)

    def current_registration(self, product_key: str) -> ProductRegistration:
        """Return the unique verified registration for one product."""
        product_key = require_identifier(product_key, "product_key")
        records = _parse_records(
            self.storage_root / "registrations" / product_key,
            ProductRegistration.from_dict,
            "registration_digest",
        )
        if len(records) != 1:
            raise ValueError("product must have exactly one verified registration")
        return records[0]

    def registrations(self) -> tuple[ProductRegistration, ...]:
        """Return all unique verified product registrations."""
        root = self.storage_root / "registrations"
        _safe_directory(root, label="CRA registration root")
        result: list[ProductRegistration] = []
        for directory in sorted(root.iterdir(), key=lambda item: item.name):
            _safe_directory(directory, label="CRA product registration directory")
            result.append(self.current_registration(directory.name))
        return tuple(result)

    def append_event(self, event: SecurityEventRevision) -> Path:
        """Append one initial event or successor of the verified current tip."""
        with exclusive_lock(self._lock_path):
            event = SecurityEventRevision.from_dict(event.to_dict())
            self.current_registration(event.product_key)
            revisions = self._event_revisions(event.event_key)
            if revisions:
                validate_revision_successor(self.select_event_tip(revisions), event)
            elif event.previous_revision_digest is not None:
                raise ValueError("initial event revision must not name a predecessor")
            directory = _mkdirs(
                self.storage_root,
                Path("events") / event.event_key / "revisions",
            )
            path = directory / f"{event.revision_digest}.json"
            write_new_text(path, event.to_json())
            return path

    def current_event(self, event_key: str) -> SecurityEventRevision:
        """Return the unique tip of a complete linear event revision chain."""
        event_key = require_identifier(event_key, "event_key")
        records = self._event_revisions(event_key)
        if not records:
            raise ValueError("event has no verified revisions")
        return self.select_event_tip(records)

    def event_keys(self) -> tuple[str, ...]:
        """Return every stored event key in deterministic order."""
        root = self.storage_root / "events"
        _safe_directory(root, label="CRA event root")
        keys: list[str] = []
        for directory in sorted(root.iterdir(), key=lambda item: item.name):
            _safe_directory(directory, label="CRA event directory")
            self.current_event(directory.name)
            keys.append(directory.name)
        return tuple(keys)

    def event_state(self, event_key: str) -> CraEventState:
        """Replay the current event's unambiguous draft, receipt, and skip state."""
        event_key = require_identifier(event_key, "event_key")
        revisions = self._event_revisions(event_key)
        if not revisions:
            raise ValueError("event has no verified revisions")
        event = self.select_event_tip(revisions)
        revision_digests = frozenset(revision.revision_digest for revision in revisions)
        base = self.storage_root / "events" / event_key
        drafts = tuple(
            record
            for stage in ("early-warning", "notification", "final-report", "intermediate")
            for record in _parse_records(
                base / "drafts" / stage,
                StageDraft.from_dict,
                "draft_digest",
            )
        )
        for draft in drafts:
            if (
                draft.product_key,
                draft.event_key,
                draft.track,
            ) != (event.product_key, event.event_key, event.track):
                raise ValueError("draft belongs to another event")
            if draft.revision_digest not in revision_digests:
                raise ValueError("draft names an unknown event revision")
            self._verify_draft_payloads(draft)
        drafts = _single_by_stage(drafts, label="draft")
        draft_digests = {draft.draft_digest for draft in drafts}
        receipts = tuple(
            record
            for stage in ("early-warning", "notification", "final-report", "intermediate")
            for record in _parse_records(
                base / "receipts" / stage,
                SubmissionReceipt.from_dict,
                "receipt_digest",
            )
        )
        if any(
            (record.product_key, record.event_key, record.track)
            != (event.product_key, event.event_key, event.track)
            for record in receipts
        ):
            raise ValueError("receipt belongs to another event")
        receipts = _single_by_stage(receipts, label="receipt")
        for receipt in receipts:
            if receipt.draft_digest not in draft_digests:
                raise ValueError("receipt has no available event draft")
            match = next(draft for draft in drafts if draft.draft_digest == receipt.draft_digest)
            validate_receipt_binding(match, receipt)
        skips = tuple(
            record
            for stage in ("notification", "final-report")
            for record in _parse_records(
                base / "skips" / stage,
                StageSkip.from_dict,
                "skip_digest",
            )
        )
        if any(
            (record.product_key, record.event_key, record.track)
            != (event.product_key, event.event_key, event.track)
            for record in skips
        ):
            raise ValueError("skip belongs to another event")
        skips = _single_by_stage(skips, label="skip")
        for skip in skips:
            validate_skip_binding(skip, receipts)
        notices = _parse_records(
            base / "user-notices",
            UserNoticeDraft.from_dict,
            "notice_digest",
        )
        for notice in notices:
            if (
                notice.product_key,
                notice.event_key,
                notice.track,
            ) != (event.product_key, event.event_key, event.track):
                raise ValueError("user notice belongs to another event")
            if notice.revision_digest not in revision_digests:
                raise ValueError("user notice names an unknown event revision")
            self._verify_notice_payloads(notice)
        return CraEventState(event, drafts, receipts, skips, revision_digests)

    def append_draft(
        self,
        event: SecurityEventRevision,
        stage: Stage,
        generated_at: str,
        payload: PreparedPayload,
    ) -> StageDraft:
        """Persist payload bytes first and their exact draft record last."""
        with exclusive_lock(self._lock_path):
            validate_prepared_payload(payload)
            event = SecurityEventRevision.from_dict(event.to_dict())
            stage = require_stage(stage)
            generated_at = require_cra_timestamp(generated_at, "generated_at")
            if self.current_event(event.event_key) != event:
                raise ValueError("draft event is not the current verified revision")
            outbox = _mkdirs(
                self.storage_root,
                Path("outbox") / event.event_key / stage,
            )
            json_path = outbox / f"{payload.json_digest}.json"
            markdown_path = outbox / f"{payload.markdown_digest}.md"
            draft = StageDraft.build(
                product_key=event.product_key,
                event_key=event.event_key,
                track=event.track,
                stage=stage,
                revision_digest=event.revision_digest,
                payload_path=json_path.relative_to(self.repository_root).as_posix(),
                payload_digest=payload.json_digest,
                markdown_path=markdown_path.relative_to(self.repository_root).as_posix(),
                markdown_payload_digest=payload.markdown_digest,
                generated_at=generated_at,
                tool_version=__version__,
            )
            existing = tuple(
                item for item in self.event_state(event.event_key).drafts if item.stage == stage
            )
            if existing:
                if existing == (draft,):
                    return draft
                raise ValueError("stage already has a different draft")
            _write_once_or_verify(json_path, payload.json_text)
            _write_once_or_verify(markdown_path, payload.markdown_text)
            directory = _mkdirs(
                self.storage_root,
                Path("events") / event.event_key / "drafts" / stage,
            )
            _write_once_or_verify(directory / f"{draft.draft_digest}.json", draft.to_json())
            return draft

    def append_receipt(self, receipt: SubmissionReceipt) -> Path:
        """Append one receipt after exact binding to the current stage draft."""
        with exclusive_lock(self._lock_path):
            receipt = SubmissionReceipt.from_dict(receipt.to_dict())
            state = self.event_state(receipt.event_key)
            matches = tuple(
                draft for draft in state.drafts if draft.draft_digest == receipt.draft_digest
            )
            if len(matches) != 1:
                raise ValueError("receipt must select exactly one current draft")
            validate_receipt_binding(matches[0], receipt)
            if any(item.stage == receipt.stage for item in state.receipts):
                raise ValueError("stage already has a receipt")
            if any(item.stage == receipt.stage for item in state.skips):
                raise ValueError("stage already has a skip")
            directory = _mkdirs(
                self.storage_root,
                Path("events") / receipt.event_key / "receipts" / receipt.stage,
            )
            path = directory / f"{receipt.receipt_digest}.json"
            write_new_text(path, receipt.to_json())
            return path

    def append_skip(self, skip: StageSkip) -> Path:
        """Append one explicit already-provided skip after receipt validation."""
        with exclusive_lock(self._lock_path):
            skip = StageSkip.from_dict(skip.to_dict())
            state = self.event_state(skip.event_key)
            validate_skip_binding(skip, state.receipts)
            if any(item.stage == skip.stage for item in state.receipts):
                raise ValueError("stage already has a receipt")
            if any(item.stage == skip.stage for item in state.skips):
                raise ValueError("stage already has a skip")
            directory = _mkdirs(
                self.storage_root,
                Path("events") / skip.event_key / "skips" / skip.stage,
            )
            path = directory / f"{skip.skip_digest}.json"
            write_new_text(path, skip.to_json())
            return path

    def append_user_notice(
        self,
        event: SecurityEventRevision,
        notice: UserNoticeDraft,
        payload: PreparedPayload,
    ) -> Path:
        """Persist a prepare-only user-notice payload pair and binding record."""
        with exclusive_lock(self._lock_path):
            validate_prepared_payload(payload)
            event = SecurityEventRevision.from_dict(event.to_dict())
            notice = UserNoticeDraft.from_dict(notice.to_dict())
            if self.current_event(event.event_key) != event:
                raise ValueError("notice event is not the current verified revision")
            if (
                notice.product_key,
                notice.event_key,
                notice.track,
                notice.revision_digest,
                notice.json_payload_digest,
                notice.markdown_payload_digest,
            ) != (
                event.product_key,
                event.event_key,
                event.track,
                event.revision_digest,
                payload.json_digest,
                payload.markdown_digest,
            ):
                raise ValueError("notice record does not bind the selected event and payload")
            outbox = _mkdirs(
                self.storage_root,
                Path("outbox") / event.event_key / "user-notice",
            )
            _write_once_or_verify(outbox / f"{payload.json_digest}.json", payload.json_text)
            _write_once_or_verify(outbox / f"{payload.markdown_digest}.md", payload.markdown_text)
            directory = _mkdirs(
                self.storage_root,
                Path("events") / event.event_key / "user-notices",
            )
            path = directory / f"{notice.notice_digest}.json"
            _write_once_or_verify(path, notice.to_json())
            return path

    def advisory(self, event_key: str) -> FixedVulnerabilityAdvisory | None:
        """Return the verified advisory-chain tip for an event, when present."""
        event_key = require_identifier(event_key, "event_key")
        records = _parse_records(
            self.storage_root / "events" / event_key / "advisories",
            FixedVulnerabilityAdvisory.from_dict,
            "advisory_digest",
        )
        if not records:
            return None
        event_revisions = self._event_revisions(event_key)
        if not event_revisions:
            raise ValueError("advisory event has no verified revisions")
        event = self.select_event_tip(event_revisions)
        revision_digests = {item.revision_digest for item in event_revisions}
        for revision in records:
            if (revision.product_key, revision.event_key) != (
                event.product_key,
                event.event_key,
            ):
                raise ValueError("advisory belongs to another event")
            if revision.revision_digest not in revision_digests:
                raise ValueError("advisory names an unknown event revision")
        advisory = _select_advisory_tip(records)
        for revision in records:
            _verify_advisory_evidence(self.repository_root, revision)
        return advisory

    def append_advisory(self, advisory: FixedVulnerabilityAdvisory) -> Path:
        """Append one advisory revision after binding it to current event state."""
        with exclusive_lock(self._lock_path):
            advisory = FixedVulnerabilityAdvisory.from_dict(advisory.to_dict())
            event = self.current_event(advisory.event_key)
            if (event.product_key, event.revision_digest) != (
                advisory.product_key,
                advisory.revision_digest,
            ):
                raise ValueError("advisory does not bind the current event revision")
            previous = self.advisory(advisory.event_key)
            if previous is None:
                if advisory.state != "draft" or advisory.previous_advisory_digest is not None:
                    raise ValueError("initial advisory revision must be a root draft")
            else:
                validate_advisory_successor(previous, advisory)
            _verify_advisory_evidence(self.repository_root, advisory)
            directory = _mkdirs(
                self.storage_root,
                Path("events") / advisory.event_key / "advisories",
            )
            path = directory / f"{advisory.advisory_digest}.json"
            write_new_text(path, advisory.to_json())
            return path

    def _event_revisions(self, event_key: str) -> tuple[SecurityEventRevision, ...]:
        """Load every verified revision for one event."""
        return _parse_records(
            self.storage_root / "events" / event_key / "revisions",
            SecurityEventRevision.from_dict,
            "revision_digest",
        )

    def _verify_draft_payloads(self, draft: StageDraft) -> None:
        """Replay exact draft payload paths and byte digests."""
        expected_json = (
            _ROOT / "outbox" / draft.event_key / draft.stage / f"{draft.payload_digest}.json"
        )
        expected_markdown = (
            _ROOT
            / "outbox"
            / draft.event_key
            / draft.stage
            / f"{draft.markdown_payload_digest}.md"
        )
        if (
            Path(draft.payload_path) != expected_json
            or Path(draft.markdown_path) != expected_markdown
        ):
            raise ValueError("draft payload path does not match its event, stage, and digest")
        self._verify_payload_bytes(expected_json, draft.payload_digest)
        self._verify_payload_bytes(expected_markdown, draft.markdown_payload_digest)

    def _verify_notice_payloads(self, notice: UserNoticeDraft) -> None:
        """Replay exact implicit user-notice payload paths and byte digests."""
        root = _ROOT / "outbox" / notice.event_key / "user-notice"
        self._verify_payload_bytes(
            root / f"{notice.json_payload_digest}.json", notice.json_payload_digest
        )
        self._verify_payload_bytes(
            root / f"{notice.markdown_payload_digest}.md",
            notice.markdown_payload_digest,
        )

    def _verify_payload_bytes(self, relative: Path, expected_digest: str) -> None:
        """Require one stored payload's exact UTF-8 bytes to match its address."""
        text = _read_text(self.repository_root / relative)
        observed = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if observed != expected_digest:
            raise ValueError(f"CRA payload digest does not match its bytes: {relative}")

    @staticmethod
    def select_event_tip(
        revisions: tuple[SecurityEventRevision, ...],
    ) -> SecurityEventRevision:
        """Select one tip only when all revisions form one complete linear chain.

        Parameters
        ----------
        revisions:
            Strictly parsed event revisions from one event namespace.

        Returns
        -------
        SecurityEventRevision
            The unique verified chain tip.

        Raises
        ------
        ValueError
            If the revisions are duplicated, incomplete, forked, or disconnected.

        """
        by_digest = {item.revision_digest: item for item in revisions}
        if len(by_digest) != len(revisions):
            raise ValueError("event revision chain contains duplicate digests")
        children: dict[str, list[SecurityEventRevision]] = {digest: [] for digest in by_digest}
        roots: list[SecurityEventRevision] = []
        for revision in revisions:
            parent = revision.previous_revision_digest
            if parent is None:
                roots.append(revision)
            elif parent not in by_digest:
                raise ValueError("event revision chain has a missing parent")
            else:
                children[parent].append(revision)
        if len(roots) != 1 or any(len(items) > 1 for items in children.values()):
            raise ValueError("event revision chain is forked or has multiple roots")
        current = roots[0]
        visited = {current.revision_digest}
        while children[current.revision_digest]:
            successor = children[current.revision_digest][0]
            validate_revision_successor(current, successor)
            current = successor
            visited.add(current.revision_digest)
        if len(visited) != len(revisions):
            raise ValueError("event revision chain has multiple tips")
        return current
