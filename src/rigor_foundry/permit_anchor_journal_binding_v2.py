# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — V2.4 anchor and V2.1 journal binding
"""Bind anchor journal heads and honoured closures to verified frame positions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from .effect_journal_records_v2 import (
    JOURNAL_GENESIS_V2,
    EffectJournalRecordV2,
    parse_effect_journal_frame_v2,
)
from .effect_journal_state_v2 import EffectJournalStateV2, replay_effect_journal_v2
from .effect_journal_v2 import EffectJournalSnapshotV2
from .permit_anchor_records_v2 import (
    ANCHOR_GENESIS_V24,
    AnchorSelectionV24,
    advance_anchor_selection_v24,
    parse_anchor_record_v24,
)

_CLOSURES = frozenset({"operation-complete", "operation-rolled-back", "operation-reconciled"})


@dataclass(frozen=True)
class LedgerAdmissionBindingV24:
    """One ledger-derived consumption expected in an ordinary anchor advance.

    Attributes
    ----------
    record_count : int
        Ledger prefix length after this ordinary consumption.
    permit_id : str
        Canonical consumed permit UUID.
    permit_digest : str
        Digest of the consumed signed permit.
    ledger_head : str
        Selected ledger prefix head, inherited across recovery.

    """

    record_count: int
    permit_id: str
    permit_digest: str
    ledger_head: str


@dataclass(frozen=True)
class AnchorJournalBindingV24:
    """Intrinsic anchor selection plus its frame-proven journal operation state.

    Attributes
    ----------
    selection : AnchorSelectionV24
        Verified intrinsic ledger and journal selection.
    journal_state : EffectJournalStateV2
        Operation state replayed with only anchored closure authority.
    honoured_closure_digests : frozenset[str]
        New exact closure frame digests selected by kind-3 records.

    """

    selection: AnchorSelectionV24
    journal_state: EffectJournalStateV2
    honoured_closure_digests: frozenset[str]


def _journal_prefixes(
    snapshot: EffectJournalSnapshotV2,
) -> tuple[tuple[EffectJournalRecordV2, ...], dict[bytes, int]]:
    """Reparse all supplied frames and index their actual chain heads."""
    if (
        snapshot.selected_head_digest != JOURNAL_GENESIS_V2.hex()
        or snapshot.selected_record_count != 0
    ):
        raise PermissionError("anchor binding needs journal genesis selection")
    head = JOURNAL_GENESIS_V2
    heads = {head: 0}
    records: list[EffectJournalRecordV2] = []
    for index, record in enumerate(snapshot.records, start=1):
        parsed = parse_effect_journal_frame_v2(
            record.frame, previous_head=head, expected_seq=index
        )
        if parsed != record:
            raise PermissionError("anchor binding journal record differs")
        head = bytes.fromhex(parsed.record_head)
        if head in heads:
            raise PermissionError("anchor binding journal head repeats")
        heads[head] = index
        records.append(parsed)
    if head.hex() != snapshot.head_digest:
        raise PermissionError("anchor binding journal head differs")
    return tuple(records), heads


def verify_anchor_journal_binding_v24(
    raw_anchor_records: tuple[bytes, ...],
    *,
    journal: EffectJournalSnapshotV2,
    admissions: tuple[LedgerAdmissionBindingV24, ...],
) -> AnchorJournalBindingV24:
    """Check exact journal-prefix movement, admission intents and closure references.

    The caller must obtain both file snapshots under selected protected locks
    and independently verify every ledger record and recovery evidence object.
    This function supplies no custody or operator authority by itself.

    Parameters
    ----------
    raw_anchor_records : tuple[bytes, ...]
        Complete anchor records in file order, starting at genesis.
    journal : EffectJournalSnapshotV2
        Held verified journal snapshot, or its file store for storage operations.
    admissions : tuple[LedgerAdmissionBindingV24, ...]
        Ledger-derived ordinary consumptions; recovery records are excluded.

    Returns
    -------
    AnchorJournalBindingV24
        Verified monotone journal prefixes and only the newly honoured closures.

    Raises
    ------
    PermissionError
        Selected chain, commitment, pending-intent or file custody checks refuse.

    """
    journal_records, prefixes = _journal_prefixes(journal)
    bindings = {binding.record_count: binding for binding in admissions}
    if len(bindings) != len(admissions):
        raise PermissionError("anchor admission binding count repeats")
    prior: AnchorSelectionV24 | None = None
    previous_index = 0
    honoured: set[str] = set()
    seen_intents: set[str] = set()
    for raw in raw_anchor_records:
        prior_head = ANCHOR_GENESIS_V24 if prior is None else prior.anchor_head
        record = parse_anchor_record_v24(raw, previous_head=prior_head)
        selection = advance_anchor_selection_v24(prior, record)
        new_index = prefixes.get(record.journal_head)
        if new_index is None or new_index < previous_index:
            raise PermissionError("anchor journal head is not a monotone verified prefix")
        segment = journal_records[previous_index:new_index]
        prior_intents = seen_intents.copy()
        new_intents = [event for event in segment if event.kind == "operation-intent"]
        if (
            record.kind == 0
            and prior is not None
            and record.ledger_record_count == prior.ledger_record_count
            and new_intents
        ):
            raise PermissionError("journal-only anchor cannot admit an operation intent")
        if record.kind == 3 and new_intents:
            raise PermissionError("closure anchor cannot admit an operation intent")
        for event in segment:
            if event.kind == "operation-intent":
                permit_id = cast(str, event.body["permit_id"])
                if permit_id in seen_intents:
                    raise PermissionError("anchor journal intent repeats")
                seen_intents.add(permit_id)
        if record.kind == 2 and prior is not None:
            adopted = {
                count: binding
                for count, binding in bindings.items()
                if prior.ledger_record_count < count <= record.ledger_record_count
            }
            for event in new_intents:
                matching = [
                    binding
                    for binding in adopted.values()
                    if event.body["permit_id"] == binding.permit_id
                    and event.body["permit_digest"] == binding.permit_digest
                    and event.body["ledger_head"] == binding.ledger_head
                ]
                if len(matching) != 1:
                    raise PermissionError(
                        "anchor adoption intent lacks matching adopted ledger consumption"
                    )
        if (
            prior is not None
            and record.kind == 0
            and record.ledger_record_count > prior.ledger_record_count
        ):
            expected = bindings.get(record.ledger_record_count)
            matches = new_intents if expected is not None else []
            if (
                expected is None
                or expected.ledger_head != record.digest.hex()
                or len(matches) != 1
                or matches[0] != segment[-1]
                or matches[0].body["permit_id"] != expected.permit_id
                or matches[0].body["permit_digest"] != expected.permit_digest
                or matches[0].body["ledger_head"] != expected.ledger_head
            ):
                raise PermissionError("anchor admission lacks exactly matching journal intent")
        if record.kind == 3:
            closure = segment[-1]
            permit_id = cast(str, closure.body.get("permit_id"))
            if (
                closure.kind not in _CLOSURES
                or closure.record_digest != record.event_digest.hex()
                or permit_id not in prior_intents
                or closure.record_digest in honoured
            ):
                raise PermissionError("anchor closure does not name a new open operation")
            honoured.add(closure.record_digest)
        prior = selection
        previous_index = new_index
    if prior is None:
        raise PermissionError("anchor initial record is absent")
    selected_snapshot = EffectJournalSnapshotV2(
        identity=journal.identity,
        records=journal.records,
        head_digest=journal.head_digest,
        selected_head_digest=prior.journal_head.hex(),
        selected_record_count=previous_index,
    )
    state = replay_effect_journal_v2(
        selected_snapshot, honoured_closure_digests=frozenset(honoured)
    )
    return AnchorJournalBindingV24(prior, state, frozenset(honoured))
