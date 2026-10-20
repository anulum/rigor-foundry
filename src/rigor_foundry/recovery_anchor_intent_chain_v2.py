# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — V2.4 anchor final-tail intent chain
"""Verify a kind-1 commitment to immutable root and child recovery intents."""

from __future__ import annotations

import base64
import os
from hashlib import sha256
from pathlib import Path
from typing import cast

from .effect_journal_v2 import EffectJournalSnapshotV2
from .permit_anchor_records_v2 import (
    ANCHOR_MAGIC_V24,
    ANCHOR_RECORD_V24,
    AnchorRecordV24,
    AnchorSelectionV24,
)
from .permit_consumption_ledger_v2 import LedgerSnapshotV2
from .recovery_evidence_binding_v2 import _expected_file
from .recovery_evidence_fields_v2 import parse_canonical_object_bytes
from .recovery_evidence_schema_v2 import (
    exact_recovery_stamp_us_v2,
    validate_anchor_final_intent_v2,
    validate_recovery_evidence_bytes_v2,
)

_DOMAIN = "rigor.permit-anchor-final-recovery.v2.4"


def _intent_objects(objects: dict[str, bytes]) -> dict[str, dict[str, object]]:
    """Parse all exact published kind-1 objects and their digest filenames."""
    intents: dict[str, dict[str, object]] = {}
    for object_digest, data in objects.items():
        if sha256(data).hexdigest() != object_digest:
            raise PermissionError("anchor recovery object filename differs")
        domain = validate_recovery_evidence_bytes_v2(data)
        if domain == _DOMAIN:
            item = parse_canonical_object_bytes(data)
            validate_anchor_final_intent_v2(item)
            intents[object_digest] = item
    return intents


def _matching(
    value: dict[str, object],
    *,
    anchor_file: dict[str, object],
    ledger_file: dict[str, object],
    journal_file: dict[str, object],
) -> bool:
    """Match all three opened file identities, never only a path string."""
    return (
        value["anchor_file"] == anchor_file
        and value["ledger_file"] == ledger_file
        and value["journal_file"] == journal_file
    )


def verify_anchor_intent_chain_v24(
    objects: dict[str, bytes],
    *,
    record: AnchorRecordV24,
    previous: AnchorSelectionV24,
    prior_anchor_record_count: int,
    anchor_path: Path,
    anchor_stat: os.stat_result,
    ledger_path: Path,
    ledger: LedgerSnapshotV2,
    journal_path: Path,
    journal: EffectJournalSnapshotV2,
) -> frozenset[str]:
    """Resolve the exact last-to-root intent chain committed by one kind-1 record.

    The caller retains anchor → ledger → journal locks and verifies the full
    retained prefixes before this function runs. All referenced objects must
    come from the bounded owner-only evidence store scan.

    Parameters
    ----------
    objects : dict[str, bytes]
        Digest-to-canonical-bytes map obtained from the bounded evidence store.
    record : AnchorRecordV24
        Parsed successor record whose selected boundaries must match the held files.
    previous : AnchorSelectionV24
        Verified selection preceding this record; None only at genesis.
    prior_anchor_record_count : int
        Number of complete verified anchor records preceding the recovery record.
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
        Exact connected intent digests resolved by the committed recovery record.

    Raises
    ------
    ValueError
        The record is not kind 1, or fewer than one complete anchor record
        precedes it.
    PermissionError
        Selected chain, commitment, pending-intent or file custody checks refuse.

    """
    if record.kind != 1 or prior_anchor_record_count < 1:
        raise ValueError("anchor recovery record position differs")
    anchor_file = _expected_file(anchor_path, anchor_stat.st_dev, anchor_stat.st_ino)
    ledger_file = _expected_file(ledger_path, ledger.identity.device, ledger.identity.inode)
    journal_file = _expected_file(journal_path, journal.identity.device, journal.identity.inode)
    if (
        record.previous_head != previous.anchor_head
        or record.ledger_record_count != previous.ledger_record_count
        or record.ledger_identity != ledger.identity
        or record.journal_head != previous.journal_head
    ):
        raise PermissionError("anchor recovery selected prefix differs")
    intents = _intent_objects(objects)
    last_digest = record.event_digest.hex()
    matching = {
        digest: item
        for digest, item in intents.items()
        if _matching(
            item,
            anchor_file=anchor_file,
            ledger_file=ledger_file,
            journal_file=journal_file,
        )
    }
    if last_digest not in matching:
        raise PermissionError("anchor recovery last intent is missing")
    offset = len(ANCHOR_MAGIC_V24) + ANCHOR_RECORD_V24.size * prior_anchor_record_count
    boundary = {
        digest: item
        for digest, item in matching.items()
        if item["prior_anchor_head"] == previous.anchor_head.hex()
        and item["tail_offset"] == offset
    }
    roots = [digest for digest, item in boundary.items() if item["parent_intent_digest"] is None]
    children: dict[str, str] = {}
    for digest, item in boundary.items():
        parent = item["parent_intent_digest"]
        if parent is not None:
            parent_digest = cast(str, parent)
            if parent_digest in children:
                raise PermissionError("anchor recovery intent branch differs")
            children[parent_digest] = digest
    if len(roots) != 1:
        raise PermissionError("anchor recovery roots at one boundary differ")
    chain: list[tuple[str, dict[str, object]]] = []
    seen: set[str] = set()
    current = last_digest
    while current in boundary:
        if current in seen:
            raise PermissionError("anchor recovery intent cycle differs")
        seen.add(current)
        value = boundary[current]
        chain.append((current, value))
        parent = value["parent_intent_digest"]
        if parent is None:
            break
        current = cast(str, parent)
    if current != roots[0] or len(chain) != len(boundary):
        raise PermissionError("anchor recovery chain is missing or ambiguous")
    chain.reverse()
    root = chain[0][1]
    if (
        record.digest.hex() != root["removed_digest"]
        or record.metadata != root["tail_length"]
        or record.stamp_us != exact_recovery_stamp_us_v2(chain[-1][1]["host_time"])
    ):
        raise PermissionError("anchor recovery root/last commitment differs")
    for index, (_digest, value) in enumerate(chain):
        if (
            value["prior_anchor_head"] != previous.anchor_head.hex()
            or value["prior_anchor_record_count"] != prior_anchor_record_count
            or value["prior_ledger_record_count"] != previous.ledger_record_count
            or value["prior_ledger_head"] != previous.ledger_head.hex()
            or value["prior_journal_head"] != previous.journal_head.hex()
            or value["tail_offset"] != offset
        ):
            raise PermissionError("anchor recovery intent selected boundary differs")
        if index == 0:
            continue
        parent_digest, parent = chain[index - 1]
        attempted = ANCHOR_RECORD_V24.pack(
            1,
            previous.ledger_record_count,
            bytes.fromhex(root["removed_digest"]),
            bytes.fromhex(ledger.identity.path_digest),
            ledger.identity.device,
            ledger.identity.inode,
            exact_recovery_stamp_us_v2(parent["host_time"]),
            root["tail_length"],
            previous.journal_head,
            bytes.fromhex(parent_digest),
            previous.anchor_head,
        )
        captured = base64.b64decode(cast(str, value["removed_bytes_b64"]), validate=True)
        if (
            value["parent_intent_digest"] != parent_digest
            or value["failure_class"] != "partial-tail"
            or len(captured) == ANCHOR_RECORD_V24.size
            or captured != attempted[: len(captured)]
        ):
            raise PermissionError("anchor recovery child does not capture torn kind-1 bytes")
    return frozenset(digest for digest, _ in chain)


def pending_anchor_intents_v24(
    objects: dict[str, bytes],
    *,
    resolved: frozenset[str],
    anchor_path: Path,
    anchor_stat: os.stat_result,
    ledger_path: Path,
    ledger: LedgerSnapshotV2,
    journal_path: Path,
    journal: EffectJournalSnapshotV2,
) -> frozenset[str]:
    """Find published intents for this selected file triple without a committed chain.

    Parameters
    ----------
    objects : dict[str, bytes]
        Digest-to-canonical-bytes map obtained from the bounded evidence store.
    resolved : frozenset[str]
        Intent digests already committed by a verified anchor recovery chain.
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
        Selected file-triple intents without a committed recovery chain.

    Raises
    ------
    PermissionError
        Selected chain, commitment, pending-intent or file custody checks refuse.

    """
    anchor_file = _expected_file(anchor_path, anchor_stat.st_dev, anchor_stat.st_ino)
    ledger_file = _expected_file(ledger_path, ledger.identity.device, ledger.identity.inode)
    journal_file = _expected_file(journal_path, journal.identity.device, journal.identity.inode)
    return frozenset(
        digest
        for digest, value in _intent_objects(objects).items()
        if digest not in resolved
        and _matching(
            value,
            anchor_file=anchor_file,
            ledger_file=ledger_file,
            journal_file=journal_file,
        )
    )
