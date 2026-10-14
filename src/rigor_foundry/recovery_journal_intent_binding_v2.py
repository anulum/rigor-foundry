# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — V2.1 journal terminal recovery intent binding
"""Resolve immutable journal-tail intents only through anchored audit frames."""

from __future__ import annotations

import os
from hashlib import sha256
from pathlib import Path
from typing import cast

from .effect_journal_records_v2 import JOURNAL_MAGIC_V2
from .effect_journal_v2 import EffectJournalSnapshotV2
from .permit_consumption_ledger_v2 import LedgerSnapshotV2
from .recovery_evidence_binding_v2 import _expected_file, _journal_positions
from .recovery_evidence_fields_v2 import parse_canonical_object_bytes
from .recovery_evidence_schema_v2 import validate_recovery_evidence_bytes_v2

_DOMAIN = "rigor.effect-journal-tail-recovery.v2.1"


def unresolved_journal_intents_v21(
    objects: dict[str, bytes],
    *,
    anchor_heads: frozenset[str],
    selected_journal_head: str,
    anchor_path: Path,
    anchor_stat: os.stat_result,
    ledger_path: Path,
    ledger: LedgerSnapshotV2,
    journal_path: Path,
    journal: EffectJournalSnapshotV2,
) -> frozenset[str]:
    """Find selected journal intents without one matching anchored recovery frame.

    The caller holds the anchor → ledger → journal descriptors and has fully
    verified their chains. A published unresolved intent blocks admission.

    Parameters
    ----------
    objects : dict[str, bytes]
        Digest-to-canonical-bytes map obtained from the bounded evidence store.
        Every content digest is rechecked before selecting journal intents.
    anchor_heads : frozenset[str]
        Heads of the verified retained anchor prefixes.
    selected_journal_head : str
        Exact anchored journal prefix head; later audit frames remain inert.
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
    frozenset[str]
        Selected intents lacking a matching audit in the anchored journal prefix.

    Raises
    ------
    PermissionError
        Selected chain, commitment, pending-intent or file custody checks refuse.
    """
    anchor_file = _expected_file(anchor_path, anchor_stat.st_dev, anchor_stat.st_ino)
    ledger_file = _expected_file(ledger_path, ledger.identity.device, ledger.identity.inode)
    journal_file = _expected_file(journal_path, journal.identity.device, journal.identity.inode)
    positions = _journal_positions(journal)
    selected_index = positions.get(selected_journal_head)
    if selected_index is None:
        raise PermissionError("journal recovery selected head is not verified")
    intents: dict[str, dict[str, object]] = {}
    for object_digest, data in objects.items():
        if sha256(data).hexdigest() != object_digest:
            raise PermissionError("journal recovery object filename differs")
        if validate_recovery_evidence_bytes_v2(data) != _DOMAIN:
            continue
        value = parse_canonical_object_bytes(data)
        if (
            value["anchor_file"] == anchor_file
            and value["ledger_file"] == ledger_file
            and value["journal_file"] == journal_file
        ):
            intents[object_digest] = value
    for event in journal.records[:selected_index]:
        if (
            event.kind == "journal-tail-recovery"
            and event.body["recovery_intent_digest"] not in intents
        ):
            raise PermissionError("journal recovery audit lacks selected immutable intent")
    for object_digest, value in intents.items():
        parent = value["parent_intent_digest"]
        if parent is not None and parent not in intents:
            raise PermissionError("journal recovery parent intent is missing")
        seen = {object_digest}
        while parent is not None:
            parent_digest = cast(str, parent)
            if parent_digest in seen:
                raise PermissionError("journal recovery intent cycle differs")
            seen.add(parent_digest)
            parent = intents[parent_digest]["parent_intent_digest"]
    unresolved: set[str] = set()
    parents: set[str] = set()
    fragments: set[tuple[object, object, object, object]] = set()
    for object_digest, value in intents.items():
        if value["selected_anchor_head"] not in anchor_heads:
            raise PermissionError("journal recovery anchor boundary differs")
        start = positions.get(cast(str, value["selected_journal_head"]))
        end = positions.get(cast(str, value["last_complete_journal_head"]))
        if start is None or end is None or start > end:
            raise PermissionError("journal recovery prefix boundary differs")
        frame_offset = len(JOURNAL_MAGIC_V2) + sum(
            len(item.frame) for item in journal.records[:end]
        )
        if value["frame_offset"] != frame_offset:
            raise PermissionError("journal recovery frame offset differs")
        matches = [
            event
            for event in journal.records[:selected_index]
            if event.kind == "journal-tail-recovery"
            and event.body["recovery_intent_digest"] == object_digest
        ]
        if len(matches) > 1:
            raise PermissionError("journal recovery audit frame repeats")
        if matches:
            body = matches[0].body
            if (
                body["removed_digest"] != value["removed_digest"]
                or body["removed_length"] != value["removed_length"]
                or body["operator_identity"] != value["operator_identity"]
            ):
                raise PermissionError("journal recovery audit frame differs")
            continue
        unresolved.add(object_digest)
        parent = value["parent_intent_digest"]
        if parent is not None:
            parent_digest = cast(str, parent)
            if parent_digest in parents:
                raise PermissionError("journal recovery live child branch differs")
            parents.add(parent_digest)
        fragment = (
            value["last_complete_journal_head"],
            value["frame_offset"],
            value["old_size"],
            value["removed_digest"],
        )
        if fragment in fragments:
            raise PermissionError("journal recovery live terminal fragment repeats")
        fragments.add(fragment)
    return frozenset(unresolved)
