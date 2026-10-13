# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — effect-journal operation replay
"""Derive open operation targets from verified journal and anchor closures."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import cast

from .effect_journal_records_v2 import (
    JOURNAL_GENESIS_V2,
    EffectJournalRecordV2,
    parse_effect_journal_frame_v2,
    parse_effect_target_ref_v2,
)
from .effect_journal_v2 import EffectJournalSnapshotV2
from .effect_target_overlap_v2 import TargetKeyV2, _effect_targets_overlap_v2
from .effect_vocabulary_v2 import EFFECT_CLASSES_V2

_CLOSURES = frozenset({"operation-complete", "operation-rolled-back", "operation-reconciled"})
_STATUS = frozenset(
    {"terminated", "overrun", "unkillable", "adopted-after-restart", "ended-unknown"}
)
_LEAF = frozenset({"cleared-orphan-leaf", "removed-empty-leaf"})
_REPLAYABLE = (
    _CLOSURES
    | _STATUS
    | _LEAF
    | frozenset(
        {
            "operation-intent",
            "effect-intent",
            "effect-complete",
            "effect-failed",
            "journal-tail-recovery",
        }
    )
)


@dataclass(frozen=True)
class OperationReplayV2:
    """One operation's derived part progress and anchored closure state.

    Attributes
    ----------
    permit_id, cgroup_id : str
        Operation identity and execution group from its retained original intent.
    targets : tuple[TargetKeyV2, ...]
        Canonical targets recorded by the operation, in part order.
    part_states : tuple[str, ...]
        Replayed not-started, in-progress, complete or failed states.
    honoured_closure_digest : str | None
        Closure selected by a separately verified anchor, or none while blocked.
    pending_closure_digests : tuple[str, ...]
        Recorded closures still awaiting independent anchor selection.
    """

    permit_id: str
    cgroup_id: str
    targets: tuple[TargetKeyV2, ...]
    part_states: tuple[str, ...]
    honoured_closure_digest: str | None
    pending_closure_digests: tuple[str, ...]

    @property
    def open(self) -> bool:
        """Return whether this operation still blocks every listed target.

        Returns
        -------
        bool
            True until an independently selected closure has been honoured.
        """
        return self.honoured_closure_digest is None


@dataclass(frozen=True)
class EffectJournalStateV2:
    """Derived operation set and target blocks from one verified chain.

    Attributes
    ----------
    operations : tuple[OperationReplayV2, ...]
        Replayed operations in original intent order.
    open_targets : frozenset[TargetKeyV2]
        Targets still blocked by open operations or unanchored closures.
    head_digest : str
        Exact verified journal head used for this replay.

    Notes
    -----
    This snapshot authenticates neither current file custody nor effect permission.
    """

    operations: tuple[OperationReplayV2, ...]
    open_targets: frozenset[TargetKeyV2]
    head_digest: str

    def blocks(self, *, effect_class: str, target_ref: object) -> bool:
        """Check whether an extracted target overlaps an open intent.

        Parameters
        ----------
        effect_class
            Known extracted class; open target blocks apply across effect classes.
        target_ref
            Canonical target mapping from actual extraction.

        Returns
        -------
        bool
            True for exact or ancestor/descendant target overlap.

        Raises
        ------
        ValueError
            Class or target reference is malformed or unsupported.
        """
        if effect_class not in EFFECT_CLASSES_V2:
            raise ValueError("effect journal class is unknown")
        target = parse_effect_target_ref_v2(target_ref)
        return any(_effect_targets_overlap_v2(target, item) for item in self.open_targets)


@dataclass
class _Progress:
    """Mutable progress for one verified intent during a single replay.

    Attributes
    ----------
    permit_id, cgroup_id : str
        Original intent's operation and execution-group identities.
    atomicity : str
        Declared atomicity checked when replaying a rollback closure.
    targets : tuple[TargetKeyV2, ...]
        Original ordered part targets retained until an honoured closure.
    parts : list[str]
        In-progress mutable part states, frozen before returning a replay result.
    honoured : str | None
        Exact independently selected closure digest, absent while blocked.
    pending : list[str]
        Unanchored closures that require explicit reconciliation before further effects.
    """

    permit_id: str
    cgroup_id: str
    atomicity: str
    targets: tuple[TargetKeyV2, ...]
    parts: list[str]
    honoured: str | None = None
    pending: list[str] = field(default_factory=list)

    def frozen(self) -> OperationReplayV2:
        """Freeze one replay result before returning it to the caller.

        Returns
        -------
        OperationReplayV2
            Immutable copy of current progress and retained closure identities.
        """
        return OperationReplayV2(
            permit_id=self.permit_id,
            cgroup_id=self.cgroup_id,
            targets=self.targets,
            part_states=tuple(self.parts),
            honoured_closure_digest=self.honoured,
            pending_closure_digests=tuple(self.pending),
        )


def _record_chain(snapshot: EffectJournalSnapshotV2) -> tuple[EffectJournalRecordV2, ...]:
    """Recheck supplied frames so a forged in-memory record cannot steer replay."""
    head = JOURNAL_GENESIS_V2
    checked: list[EffectJournalRecordV2] = []
    for seq, record in enumerate(snapshot.records, start=1):
        parsed = parse_effect_journal_frame_v2(record.frame, previous_head=head, expected_seq=seq)
        if parsed != record:
            raise PermissionError("effect journal replay record differs from its frame")
        checked.append(parsed)
        head = bytes.fromhex(parsed.record_head)
    if head.hex() != snapshot.head_digest:
        raise PermissionError("effect journal replay head differs")
    if snapshot.selected_record_count > len(checked) or snapshot.selected_record_count < 0:
        raise PermissionError("effect journal selected count differs")
    selected = (
        JOURNAL_GENESIS_V2.hex()
        if snapshot.selected_record_count == 0
        else checked[snapshot.selected_record_count - 1].record_head
    )
    if selected != snapshot.selected_head_digest:
        raise PermissionError("effect journal selected prefix differs")
    return tuple(checked)


def replay_effect_journal_v2(
    snapshot: EffectJournalSnapshotV2, *, honoured_closure_digests: frozenset[str]
) -> EffectJournalStateV2:
    """Replay part order and block targets until a verified anchor honours closure.

    Parameters
    ----------
    snapshot
        Actual selected file snapshot with complete frame bytes and prefix proof.
    honoured_closure_digests
        Exact closures from a separately verified anchor chain; recorded closure
        bytes alone cannot unblock targets.

    Returns
    -------
    EffectJournalStateV2
        Ordered operation progress, open targets and the verified journal head.

    Raises
    ------
    ValueError
        A retained frame violates the canonical journal grammar.
    PermissionError
        Frame or prefix consistency, operation order, target overlap, closure
        selection or this consumer's supported event vocabulary refuses.

    Notes
    -----
    The caller retains actual file and anchor custody. This consumer refuses
    partial-operation, target-reconciliation and trust-lifecycle events whose
    semantics it does not implement; it never treats them as harmless leaves.
    Replay supplies no effect authority or permission to change journal bytes.
    """
    records = _record_chain(snapshot)
    operations: dict[str, _Progress] = {}
    open_targets: set[TargetKeyV2] = set()
    unmatched_closures = set(honoured_closure_digests)
    for record in records:
        kind = record.kind
        body = record.body
        if kind not in _REPLAYABLE:
            raise PermissionError("effect journal record kind is not replayable")
        if kind == "operation-intent":
            permit_id = cast(str, body["permit_id"])
            if permit_id in operations:
                raise PermissionError("effect journal operation intent repeats")
            parts = cast(list[dict[str, object]], body["parts"])
            targets = tuple(parse_effect_target_ref_v2(part["target_ref"]) for part in parts)
            if len(set(targets)) != len(targets) or any(
                _effect_targets_overlap_v2(target, existing)
                for target in targets
                for existing in open_targets
            ):
                raise PermissionError("effect journal operation targets overlap")
            operations[permit_id] = _Progress(
                permit_id=permit_id,
                cgroup_id=cast(str, body["cgroup_id"]),
                atomicity=cast(str, body["atomicity"]),
                targets=targets,
                parts=["not-started"] * len(parts),
            )
            open_targets.update(targets)
            continue
        if kind in _LEAF or kind == "journal-tail-recovery":
            continue
        permit_id = cast(str, body["permit_id"])
        operation = operations.get(permit_id)
        if operation is None:
            raise PermissionError("effect journal event names an unknown operation")
        if kind in _STATUS:
            if body["cgroup_id"] != operation.cgroup_id:
                raise PermissionError("effect journal status cgroup differs")
            continue
        if operation.honoured is not None:
            raise PermissionError("effect journal closed operation changed")
        if kind in ("effect-intent", "effect-complete", "effect-failed"):
            if operation.pending:
                raise PermissionError("effect journal pending closure needs reconciliation")
            index = cast(int, body["part_index"])
            if index >= len(operation.parts):
                raise PermissionError("effect journal part index is absent")
            prior = operation.parts[index]
            if kind == "effect-intent" and prior == "not-started":
                operation.parts[index] = "in-progress"
            elif kind == "effect-complete" and prior == "in-progress":
                operation.parts[index] = "complete"
            elif kind == "effect-failed" and prior == "in-progress":
                operation.parts[index] = "failed"
            else:
                raise PermissionError("effect journal part transition differs")
            continue
        if operation.pending and kind != "operation-reconciled":
            raise PermissionError("effect journal pending closure needs new reconciliation")
        if kind == "operation-complete" and any(state != "complete" for state in operation.parts):
            raise PermissionError("effect journal completion lacks completed parts")
        if kind == "operation-rolled-back" and operation.atomicity != "all-or-nothing-journalled":
            raise PermissionError("effect journal rollback atomicity differs")
        if record.record_digest in unmatched_closures:
            if record.seq > snapshot.selected_record_count:
                raise PermissionError("effect journal closure lies outside selected prefix")
            unmatched_closures.remove(record.record_digest)
            operation.honoured = record.record_digest
            open_targets.difference_update(operation.targets)
        else:
            operation.pending.append(record.record_digest)
    if unmatched_closures:
        raise PermissionError("effect journal anchor names a missing closure")
    return EffectJournalStateV2(
        operations=tuple(progress.frozen() for progress in operations.values()),
        open_targets=frozenset(open_targets),
        head_digest=snapshot.head_digest,
    )
