# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — retained V2.4 anchor prefix verification
"""Verify one locked retained anchor prefix and report pending recovery evidence."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .effect_journal_v2 import EffectJournalSnapshotV2
from .permit_anchor_journal_binding_v2 import (
    AnchorJournalBindingV24,
    LedgerAdmissionBindingV24,
    verify_anchor_journal_binding_v24,
)
from .permit_anchor_records_v2 import (
    ANCHOR_GENESIS_V24,
    AnchorSelectionV24,
    advance_anchor_selection_v24,
    parse_anchor_record_v24,
)
from .permit_consumption_ledger_v2 import LedgerSnapshotV2
from .recovery_anchor_intent_chain_v2 import (
    pending_anchor_intents_v24,
    verify_anchor_intent_chain_v24,
)
from .recovery_evidence_binding_v2 import verify_adoption_evidence_v24
from .recovery_journal_intent_binding_v2 import unresolved_journal_intents_v21


@dataclass(frozen=True)
class AnchorPrefixVerificationV24:
    """Proof of retained file chains plus unresolved operator intents.

    Attributes
    ----------
    binding : AnchorJournalBindingV24
        Verified ledger/journal relationship and honoured closure replay.
    pending_anchor_intents : frozenset[str]
        Uncommitted selected anchor recovery intents that block admission.
    pending_journal_intents : frozenset[str]
        Selected journal intents without matching anchored audit frames.
    """

    binding: AnchorJournalBindingV24
    pending_anchor_intents: frozenset[str]
    pending_journal_intents: frozenset[str]


def _admissions(snapshot: LedgerSnapshotV2) -> tuple[LedgerAdmissionBindingV24, ...]:
    """Derive ordinary admission bindings from fully verified ledger bytes."""
    bindings: list[LedgerAdmissionBindingV24] = []
    for count, record in enumerate(snapshot.records, start=1):
        if record.kind == 0:
            if record.permit_id is None or record.permit_digest is None:
                raise PermissionError("verified ledger consumption fields are absent")
            bindings.append(
                LedgerAdmissionBindingV24(
                    count,
                    record.permit_id,
                    record.permit_digest,
                    record.head_digest,
                )
            )
    return tuple(bindings)


def verify_anchor_prefix_v24(
    raw_records: tuple[bytes, ...],
    *,
    objects: dict[str, bytes],
    anchor_path: Path,
    anchor_stat: os.stat_result,
    ledger_path: Path,
    ledger: LedgerSnapshotV2,
    journal_path: Path,
    journal: EffectJournalSnapshotV2,
) -> AnchorPrefixVerificationV24:
    """Bind all retained anchor records to exact opened ledger/journal state.

    This assumes the caller holds the ordered anchor → ledger → journal locks.
    It reports pending intents so ordinary admission can refuse and the
    authenticated operator can resume one exact recovery transaction.

    Parameters
    ----------
    raw_records : tuple[bytes, ...]
        Complete retained anchor records in file order, starting at genesis.
    objects : dict[str, bytes]
        Digest-to-canonical-bytes map obtained from the bounded evidence store.
    anchor_path : Path
        Exact absolute selected anchor path, without normalisation or aliases.
    anchor_stat : os.stat_result
        Stat of the held selected anchor descriptor, used to bind device and inode.
    ledger_path : Path
        Exact absolute path of the held selected ledger.
    ledger : LedgerSnapshotV2
        Held and fully verified ledger snapshot, or its file store for storage operations.
    journal_path : Path
        Exact absolute path of the held selected effect journal.
    journal : EffectJournalSnapshotV2
        Held verified journal snapshot, or its file store for storage operations.

    Returns
    -------
    AnchorPrefixVerificationV24
        Bound ledger/journal selection and unresolved intents that block admission.

    Raises
    ------
    PermissionError
        Selected chain, commitment, pending-intent or file custody checks refuse.
    """
    if not raw_records:
        raise PermissionError("permit anchor initial record is absent")
    resolved: set[str] = set()
    anchor_heads: set[str] = set()
    prior: AnchorSelectionV24 | None = None
    for prior_count, raw in enumerate(raw_records):
        prior_head = ANCHOR_GENESIS_V24 if prior is None else prior.anchor_head
        record = parse_anchor_record_v24(raw, previous_head=prior_head)
        if prior is not None and record.kind == 1:
            resolved.update(
                verify_anchor_intent_chain_v24(
                    objects,
                    record=record,
                    previous=prior,
                    prior_anchor_record_count=prior_count,
                    anchor_path=anchor_path,
                    anchor_stat=anchor_stat,
                    ledger_path=ledger_path,
                    ledger=ledger,
                    journal_path=journal_path,
                    journal=journal,
                )
            )
        elif prior is not None and record.kind == 2:
            data = objects.get(record.event_digest.hex())
            if data is None:
                raise PermissionError("permit anchor adoption evidence is missing")
            verify_adoption_evidence_v24(
                data,
                record=record,
                previous=prior,
                ledger=ledger,
                journal=journal,
                anchor_path=anchor_path,
                anchor_stat=anchor_stat,
                ledger_path=ledger_path,
                journal_path=journal_path,
            )
        prior = advance_anchor_selection_v24(prior, record)
        anchor_heads.add(prior.anchor_head.hex())
    if prior is None or prior.ledger_identity != ledger.identity:
        raise PermissionError("permit anchor selected ledger identity differs")
    pending_anchor = pending_anchor_intents_v24(
        objects,
        resolved=frozenset(resolved),
        anchor_path=anchor_path,
        anchor_stat=anchor_stat,
        ledger_path=ledger_path,
        ledger=ledger,
        journal_path=journal_path,
        journal=journal,
    )
    pending_journal = unresolved_journal_intents_v21(
        objects,
        anchor_heads=frozenset(anchor_heads),
        selected_journal_head=prior.journal_head.hex(),
        anchor_path=anchor_path,
        anchor_stat=anchor_stat,
        ledger_path=ledger_path,
        ledger=ledger,
        journal_path=journal_path,
        journal=journal,
    )
    binding = verify_anchor_journal_binding_v24(
        raw_records,
        journal=journal,
        admissions=_admissions(ledger),
    )
    return AnchorPrefixVerificationV24(binding, pending_anchor, pending_journal)
