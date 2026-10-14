# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — recovery evidence selected-chain binding tests
"""Check adoption proof fields against exact selected descriptor identities."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path

import pytest

from rigor_foundry._permit_ledger_records_v2 import _INITIAL_HEAD
from rigor_foundry.effect_journal_records_v2 import JOURNAL_GENESIS_V2, EffectJournalRecordV2
from rigor_foundry.effect_journal_v2 import EffectJournalFileIdentityV2, EffectJournalSnapshotV2
from rigor_foundry.models import canonical_digest
from rigor_foundry.permit_anchor_records_v2 import AnchorRecordV24, AnchorSelectionV24
from rigor_foundry.permit_consumption_ledger_v2 import (
    LedgerFileIdentityV2,
    LedgerRecordV2,
    LedgerSnapshotV2,
)
from rigor_foundry.recovery_evidence_binding_v2 import (
    consumed_uuids_digest_v24,
    verify_adoption_evidence_v24,
)
from rigor_foundry.recovery_evidence_schema_v2 import (
    exact_recovery_stamp_us_v2,
    validate_anchor_adoption_evidence_v2,
)

_DIGEST = "a" * 64
_HOST_TIME = "2026-09-23T03:00:00Z"


def _identity(path: Path) -> dict[str, object]:
    """Use the real test file descriptor identity and selected absolute path."""
    entry = path.stat()
    return {
        "path": str(path),
        "path_digest": canonical_digest(str(path)),
        "device": str(entry.st_dev),
        "inode": str(entry.st_ino),
    }


@dataclass(frozen=True)
class _Case:
    """One structurally valid recovery-only suffix adoption transition."""

    data: bytes
    record: AnchorRecordV24
    previous: AnchorSelectionV24
    ledger: LedgerSnapshotV2
    journal: EffectJournalSnapshotV2
    anchor_path: Path
    ledger_path: Path
    journal_path: Path

    def verify(self) -> None:
        """Apply the production binding to the held test identities."""
        verify_adoption_evidence_v24(
            self.data,
            record=self.record,
            previous=self.previous,
            ledger=self.ledger,
            journal=self.journal,
            anchor_path=self.anchor_path,
            anchor_stat=self.anchor_path.stat(),
            ledger_path=self.ledger_path,
            journal_path=self.journal_path,
        )


def _case(tmp_path: Path) -> _Case:
    """Construct an exact kind-2 object from a complete recovery-only suffix."""
    anchor = tmp_path / "anchor.bin"
    ledger_path = tmp_path / "ledger.bin"
    journal_path = tmp_path / "journal.bin"
    for path in (anchor, ledger_path, journal_path):
        path.write_bytes(b"fixture")
    ledger_stat = ledger_path.stat()
    journal_stat = journal_path.stat()
    ledger_identity = LedgerFileIdentityV2(
        canonical_digest(str(ledger_path)), ledger_stat.st_dev, ledger_stat.st_ino
    )
    journal_identity = EffectJournalFileIdentityV2(
        canonical_digest(str(journal_path)), journal_stat.st_dev, journal_stat.st_ino
    )
    prior = AnchorSelectionV24(
        0, _INITIAL_HEAD, ledger_identity, JOURNAL_GENESIS_V2, bytes.fromhex(_DIGEST)
    )
    recovered = LedgerRecordV2(1, None, None, None, "b" * 64, "c" * 64)
    ledger = LedgerSnapshotV2(1, recovered.head_digest, ledger_identity, (recovered,))
    journal = EffectJournalSnapshotV2(
        journal_identity, (), JOURNAL_GENESIS_V2.hex(), JOURNAL_GENESIS_V2.hex(), 0
    )
    value: dict[str, object] = {
        "domain": "rigor.permit-anchor-recovery.v2.4",
        "anchor_file": _identity(anchor),
        "ledger_file": _identity(ledger_path),
        "journal_file": _identity(journal_path),
        "old_anchor_head": prior.anchor_head.hex(),
        "old_ledger_record_count": 0,
        "new_ledger_record_count": 1,
        "old_ledger_head": _INITIAL_HEAD.hex(),
        "new_ledger_head": recovered.head_digest,
        "old_journal_head": JOURNAL_GENESIS_V2.hex(),
        "new_journal_head": JOURNAL_GENESIS_V2.hex(),
        "adopted_ledger_record_digests": [recovered.record_digest],
        "included_journal_record_digests": [],
        "consumed_uuids_digest": consumed_uuids_digest_v24(ledger, 0, 1),
        "recovery_code_digest": _DIGEST,
        "host_time": _HOST_TIME,
    }
    data = validate_anchor_adoption_evidence_v2(value)
    record = AnchorRecordV24(
        2,
        1,
        bytes.fromhex(recovered.head_digest),
        ledger_identity,
        exact_recovery_stamp_us_v2(_HOST_TIME),
        1,
        JOURNAL_GENESIS_V2,
        sha256(data).digest(),
        prior.anchor_head,
        b"h" * 32,
        b"",
    )
    return _Case(data, record, prior, ledger, journal, anchor, ledger_path, journal_path)


def _changed_evidence(case: _Case, **changes: object) -> _Case:
    """Resign only the object reference after one schema-valid field change."""
    value = json.loads(case.data)
    assert isinstance(value, dict)
    value.update(changes)
    data = validate_anchor_adoption_evidence_v2(value)
    return replace(
        case, data=data, record=replace(case.record, event_digest=sha256(data).digest())
    )


def test_recovery_only_suffix_adoption_binds_exact_object(tmp_path: Path) -> None:
    """An empty consumed-ID set is valid when the suffix contains only recovery."""
    case = _case(tmp_path)
    case.verify()
    expected = sha256(b"rigor.permit-anchor-consumed-uuids.v2.4\x00[]").hexdigest()
    assert consumed_uuids_digest_v24(case.ledger, 0, 1) == expected


def test_dual_ids_are_sorted_and_domain_separated(tmp_path: Path) -> None:
    """Both IDs from a consumption record enter the exact UUID commitment."""
    case = _case(tmp_path)
    second = "11111111-1111-4111-8111-111111111111"
    first = "00000000-0000-4000-8000-000000000001"
    consumed = LedgerRecordV2(0, second, first, _DIGEST, "d" * 64, "e" * 64)
    ledger = replace(
        case.ledger,
        record_count=2,
        head_digest=consumed.head_digest,
        records=(*case.ledger.records, consumed),
    )
    expected_array = json.dumps([first, second], separators=(",", ":")).encode("ascii")
    expected = sha256(b"rigor.permit-anchor-consumed-uuids.v2.4\x00" + expected_array).hexdigest()
    assert consumed_uuids_digest_v24(ledger, 0, 2) == expected
    with pytest.raises(ValueError, match="bounds"):
        consumed_uuids_digest_v24(ledger, 2, 1)
    repeated = replace(ledger, records=(consumed, consumed))
    with pytest.raises(PermissionError, match="UUID repeats"):
        consumed_uuids_digest_v24(repeated, 0, 2)


def test_adoption_rejects_tampered_reference_boundary_and_identity(tmp_path: Path) -> None:
    """Digest, count, opened path and timestamp cannot be changed independently."""
    case = _case(tmp_path)
    changed = json.loads(case.data)
    assert isinstance(changed, dict)
    changed["recovery_code_digest"] = "b" * 64
    with pytest.raises(PermissionError, match="reference"):
        replace(case, data=validate_anchor_adoption_evidence_v2(changed)).verify()
    with pytest.raises(PermissionError, match="file identity or timestamp"):
        replace(case, record=replace(case.record, stamp_us=case.record.stamp_us + 1)).verify()
    with pytest.raises(PermissionError, match="file identity or timestamp"):
        replace(case, journal_path=tmp_path / "other.journal").verify()
    with pytest.raises(PermissionError, match="selected boundary"):
        replace(case, record=replace(case.record, metadata=2)).verify()
    changed_ledger = replace(
        case.ledger,
        head_digest="d" * 64,
        records=(replace(case.ledger.records[0], head_digest="d" * 64),),
    )
    with pytest.raises(PermissionError, match="ledger chain"):
        replace(case, ledger=changed_ledger).verify()


def test_adoption_rejects_changed_suffix_and_uuid_commitments(tmp_path: Path) -> None:
    """Rehashing the proof cannot hide a changed complete ledger record list."""
    case = _case(tmp_path)
    with pytest.raises(PermissionError, match="ledger record digest list"):
        _changed_evidence(case, adopted_ledger_record_digests=["d" * 64]).verify()
    with pytest.raises(PermissionError, match="UUID commitment"):
        _changed_evidence(case, consumed_uuids_digest="b" * 64).verify()
    with pytest.raises(ValueError, match="identity"):
        replace(case, journal_path=Path("relative")).verify()


def test_adoption_binds_included_journal_frame_range(tmp_path: Path) -> None:
    """A journal suffix is named in file order and its new head must exist."""
    case = _case(tmp_path)
    event = EffectJournalRecordV2(
        1,
        "journal-tail-recovery",
        {},
        _HOST_TIME,
        JOURNAL_GENESIS_V2.hex(),
        "f" * 64,
        "e" * 64,
        b"",
    )
    journal = replace(case.journal, records=(event,), head_digest=event.record_head)
    case = replace(
        case,
        journal=journal,
        record=replace(case.record, journal_head=bytes.fromhex(event.record_head)),
    )
    case = _changed_evidence(
        case,
        new_journal_head=event.record_head,
        included_journal_record_digests=[event.record_digest],
    )
    case.verify()
    with pytest.raises(PermissionError, match="journal record digest list"):
        _changed_evidence(case, included_journal_record_digests=[]).verify()
    missing = _changed_evidence(case, new_journal_head="b" * 64)
    missing = replace(
        missing, record=replace(missing.record, journal_head=bytes.fromhex("b" * 64))
    )
    with pytest.raises(PermissionError, match="journal boundary"):
        missing.verify()
    with pytest.raises(PermissionError, match="journal head repeats"):
        repeated = replace(event, record_head=JOURNAL_GENESIS_V2.hex())
        replace(
            case, journal=replace(journal, records=(repeated,), head_digest=repeated.record_head)
        ).verify()
    with pytest.raises(PermissionError, match="selected file head"):
        replace(case, journal=replace(journal, head_digest=JOURNAL_GENESIS_V2.hex())).verify()
