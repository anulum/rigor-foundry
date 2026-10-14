# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — recovery evidence and selected file binding
"""Bind immutable recovery objects to held V2.4 anchor, ledger and journal state."""

from __future__ import annotations

import os
from hashlib import sha256
from pathlib import Path
from typing import cast

from ._permit_ledger_records_v2 import _INITIAL_HEAD
from .effect_journal_records_v2 import JOURNAL_GENESIS_V2, canonical_journal_json_v2
from .effect_journal_v2 import EffectJournalSnapshotV2
from .models import canonical_digest
from .permit_anchor_records_v2 import AnchorRecordV24, AnchorSelectionV24
from .permit_consumption_ledger_v2 import LedgerSnapshotV2
from .recovery_evidence_fields_v2 import parse_canonical_object_bytes
from .recovery_evidence_schema_v2 import (
    exact_recovery_stamp_us_v2,
    validate_anchor_adoption_evidence_v2,
)

_UUID_DOMAIN = b"rigor.permit-anchor-consumed-uuids.v2.4\x00"


def consumed_uuids_digest_v24(snapshot: LedgerSnapshotV2, start: int, stop: int) -> str:
    """Commit both consumed IDs in one complete selected ledger suffix.

    Parameters
    ----------
    snapshot : LedgerSnapshotV2
        Fully verified ledger records from the caller-held selected file.
    start : int
        Inclusive zero-based index of the adopted ledger suffix.
    stop : int
        Exclusive index of the adopted ledger suffix; bounded by the record list.

    Returns
    -------
    str
        Domain-separated SHA-256 over sorted unique permit and single-use UUIDs.

    Raises
    ------
    PermissionError
        Selected chain, commitment, pending-intent or file custody checks refuse.
    """
    if (
        type(start) is not int
        or type(stop) is not int
        or not 0 <= start <= stop <= len(snapshot.records)
    ):
        raise ValueError("adopted ledger suffix bounds differ")
    ids = [
        item
        for record in snapshot.records[start:stop]
        if record.kind == 0
        for item in (record.permit_id, record.single_use_id)
        if item is not None
    ]
    if len(ids) != len(set(ids)):
        raise PermissionError("adopted ledger UUID repeats")
    return sha256(_UUID_DOMAIN + canonical_journal_json_v2(sorted(ids))).hexdigest()


def _expected_file(path: Path, device: int, inode: int) -> dict[str, object]:
    """Build the exact opened-descriptor identity required by the schema."""
    if not isinstance(path, Path) or not path.is_absolute() or inode <= 0:
        raise ValueError("selected recovery file identity differs")
    selected_path = str(path)
    return {
        "path": selected_path,
        "path_digest": canonical_digest(selected_path),
        "device": str(device),
        "inode": str(inode),
    }


def _journal_positions(snapshot: EffectJournalSnapshotV2) -> dict[str, int]:
    """Index unique verified journal heads, starting with genesis."""
    positions = {JOURNAL_GENESIS_V2.hex(): 0}
    for index, event in enumerate(snapshot.records, start=1):
        if event.record_head in positions:
            raise PermissionError("recovery journal head repeats")
        positions[event.record_head] = index
    last_head = snapshot.records[-1].record_head if snapshot.records else JOURNAL_GENESIS_V2.hex()
    if snapshot.head_digest != last_head:
        raise PermissionError("recovery journal selected file head differs")
    return positions


def verify_adoption_evidence_v24(
    data: bytes,
    *,
    record: AnchorRecordV24,
    previous: AnchorSelectionV24,
    ledger: LedgerSnapshotV2,
    journal: EffectJournalSnapshotV2,
    anchor_path: Path,
    anchor_stat: os.stat_result,
    ledger_path: Path,
    journal_path: Path,
) -> None:
    """Verify kind-2 exact evidence against all three held file descriptors.

    The caller must already hold anchor → ledger → journal locks and have
    fully verified both file chains. This does not grant operator authority.

    Parameters
    ----------
    data : bytes
        Exact canonical UTF-8 evidence bytes; whitespace and duplicate-key aliases refuse.
    record : AnchorRecordV24
        Parsed successor record whose selected boundaries must match the held files.
    previous : AnchorSelectionV24
        Verified selection preceding this record; None only at genesis.
    ledger : LedgerSnapshotV2
        Held and fully verified ledger snapshot, or its file store for storage operations.
    journal : EffectJournalSnapshotV2
        Held verified journal snapshot, or its file store for storage operations.
    anchor_path : Path
        Exact absolute selected anchor path, without normalisation or aliases.
    anchor_stat : os.stat_result
        Stat of the held selected anchor descriptor, used to bind device and inode.
    ledger_path : Path
        Exact absolute path of the held selected ledger.
    journal_path : Path
        Exact absolute path of the held selected effect journal.

    Raises
    ------
    PermissionError
        Selected chain, commitment, pending-intent or file custody checks refuse.
    """
    value = parse_canonical_object_bytes(data)
    validate_anchor_adoption_evidence_v2(value)
    if record.kind != 2 or sha256(data).digest() != record.event_digest:
        raise PermissionError("anchor adoption evidence reference differs")
    if (
        record.stamp_us != exact_recovery_stamp_us_v2(value["host_time"])
        or value["anchor_file"]
        != _expected_file(anchor_path, anchor_stat.st_dev, anchor_stat.st_ino)
        or value["ledger_file"]
        != _expected_file(ledger_path, ledger.identity.device, ledger.identity.inode)
        or value["journal_file"]
        != _expected_file(journal_path, journal.identity.device, journal.identity.inode)
        or ledger.identity.path_digest != canonical_digest(str(ledger_path))
        or journal.identity.path_digest != canonical_digest(str(journal_path))
    ):
        raise PermissionError("anchor adoption file identity or timestamp differs")
    old_count = previous.ledger_record_count
    new_count = record.ledger_record_count
    if (
        value["old_anchor_head"] != previous.anchor_head.hex()
        or value["old_ledger_record_count"] != old_count
        or value["new_ledger_record_count"] != new_count
        or value["old_ledger_head"] != previous.ledger_head.hex()
        or value["new_ledger_head"] != record.digest.hex()
        or value["old_journal_head"] != previous.journal_head.hex()
        or value["new_journal_head"] != record.journal_head.hex()
        or record.metadata != new_count - old_count
        or not 0 <= old_count < new_count <= len(ledger.records)
        or ledger.record_count != len(ledger.records)
        or ledger.head_digest != ledger.records[-1].head_digest
    ):
        raise PermissionError("anchor adoption selected boundary differs")
    old_head = ledger.records[old_count - 1].head_digest if old_count else _INITIAL_HEAD.hex()
    if (
        old_head != previous.ledger_head.hex()
        or ledger.records[new_count - 1].head_digest != record.digest.hex()
        or record.ledger_identity != ledger.identity
    ):
        raise PermissionError("anchor adoption ledger chain differs")
    adopted = [item.record_digest for item in ledger.records[old_count:new_count]]
    if value["adopted_ledger_record_digests"] != adopted:
        raise PermissionError("anchor adoption ledger record digest list differs")
    positions = _journal_positions(journal)
    old_position = positions.get(previous.journal_head.hex())
    new_position = positions.get(record.journal_head.hex())
    if old_position is None or new_position is None or new_position < old_position:
        raise PermissionError("anchor adoption journal boundary differs")
    included = [item.record_digest for item in journal.records[old_position:new_position]]
    if value["included_journal_record_digests"] != included:
        raise PermissionError("anchor adoption journal record digest list differs")
    expected_uuids = consumed_uuids_digest_v24(ledger, old_count, new_count)
    if cast(str, value["consumed_uuids_digest"]) != expected_uuids:
        raise PermissionError("anchor adoption consumed UUID commitment differs")
