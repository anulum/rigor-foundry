# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — v2 permit-consumption ledger tests
"""Exercise durable nonce replay refusal through a real local file."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from struct import Struct
from threading import Barrier
from uuid import UUID

import pytest

from rigor_foundry.permit_consumption_ledger_v2 import ConsumedPermitLedgerV2

_FIRST = "01a09a66-7b5c-7a2e-93f0-b726808737d4"
_SECOND = "01a09a66-7b5c-7a2e-93f0-b726808737d5"
_SINGLE_USE = "01a09a66-7b5c-7a2e-93f0-b726808737d6"
_DIGEST = "a" * 64
_EXPIRY = "2026-09-23T03:00:00Z"
_RECOVERY = "2026-09-23T02:30:00Z"
_RECORD = Struct(">B3x16s16s32sQI32s")
_HEADER = b"RIGOR-PERMIT-LEDGER-V2.2\n"


def _ledger(root: Path) -> ConsumedPermitLedgerV2:
    """Provision only a disposable owner-only local test ledger."""
    root.chmod(0o700)
    ledger = ConsumedPermitLedgerV2(root / "consumed.bin")
    ledger.initialize()
    return ledger


def test_consumed_nonce_is_durable_and_cannot_be_replayed(tmp_path: Path) -> None:
    """A fresh ledger instance sees durable consumption and refuses reuse."""
    ledger = _ledger(tmp_path)
    initial_size = ledger.path.stat().st_size
    first_head = ledger.consume(permit_id=_FIRST, permit_digest=_DIGEST, expires_at=_EXPIRY)
    assert ledger.path.stat().st_size == initial_size + _RECORD.size
    assert len(first_head) == 64
    with pytest.raises(PermissionError, match="already consumed"):
        ConsumedPermitLedgerV2(ledger.path).consume(
            permit_id=_FIRST, permit_digest="b" * 64, expires_at=_EXPIRY
        )
    second_head = ledger.consume(permit_id=_SECOND, permit_digest="b" * 64, expires_at=_EXPIRY)
    assert ledger.path.stat().st_size == initial_size + 2 * _RECORD.size
    assert first_head != second_head
    first_record = ledger.path.read_bytes()[initial_size : initial_size + _RECORD.size]
    expected_expiry = int(
        (datetime(2026, 9, 23, 3, tzinfo=UTC) - datetime(1970, 1, 1, tzinfo=UTC)).total_seconds()
        * 1_000_000
    )
    assert _RECORD.unpack(first_record)[4] == expected_expiry


def test_locked_snapshot_exposes_verified_consumption_bytes(tmp_path: Path) -> None:
    """The anchor can derive exact UUID, digest and head while the ledger stays locked."""
    ledger = _ledger(tmp_path)
    genesis = sha256(_HEADER).hexdigest()
    first_head = ledger.consume(
        permit_id=_FIRST,
        single_use_id=_SINGLE_USE,
        permit_digest=_DIGEST,
        expires_at=_EXPIRY,
    )
    second_head = ledger.consume(
        permit_id=_SECOND,
        permit_digest="b" * 64,
        expires_at=_EXPIRY,
    )
    with ledger.locked_snapshot(selected_count=1, selected_head_digest=first_head) as snapshot:
        assert snapshot.record_count == 2
        assert snapshot.head_digest == second_head
        assert snapshot.identity.inode == ledger.path.stat().st_ino
        assert snapshot.records[0].permit_id == _FIRST
        assert snapshot.records[0].single_use_id == _SINGLE_USE
        assert snapshot.records[0].permit_digest == _DIGEST
        assert snapshot.records[0].head_digest == first_head
        assert (
            snapshot.records[0].record_digest
            == sha256(
                ledger.path.read_bytes()[len(_HEADER) : len(_HEADER) + _RECORD.size]
            ).hexdigest()
        )
        assert snapshot.records[1].permit_id == _SECOND
        assert snapshot.records[1].single_use_id is None
    with (
        pytest.raises(PermissionError, match="protected anchor"),
        ledger.locked_snapshot(selected_count=1, selected_head_digest="c" * 64),
    ):
        pass
    with (
        pytest.raises(ValueError, match="selected count"),
        ledger.locked_snapshot(selected_count=-1, selected_head_digest=genesis),
    ):
        pass


def test_ledger_requires_exact_selected_modes(tmp_path: Path) -> None:
    """Owner-only but noncanonical modes are refused before ledger inspection."""
    ledger = _ledger(tmp_path)
    ledger.path.chmod(0o700)
    with (
        pytest.raises(PermissionError, match="identity or length"),
        ledger.locked_snapshot(selected_count=0, selected_head_digest=sha256(_HEADER).hexdigest()),
    ):
        pass
    ledger.path.chmod(0o600)
    tmp_path.chmod(0o500)
    with pytest.raises(PermissionError, match="directory is not owner-only"):
        ledger.verify_anchor(record_count=0, head_digest=sha256(_HEADER).hexdigest())


def test_locked_snapshot_refuses_torn_and_short_selected_file(tmp_path: Path) -> None:
    """A locked prefix check cannot excuse an incomplete or rolled-back ledger."""
    ledger = _ledger(tmp_path)
    genesis = sha256(_HEADER).hexdigest()
    first = ledger.consume(permit_id=_FIRST, permit_digest=_DIGEST, expires_at=_EXPIRY)
    with ledger.path.open("ab") as writer:
        writer.write(b"x")
    with (
        pytest.raises(PermissionError, match="incomplete tail"),
        ledger.locked_snapshot(selected_count=1, selected_head_digest=first),
    ):
        pass
    with ledger.path.open("r+b") as writer:
        writer.truncate(len(_HEADER))
    with (
        pytest.raises(PermissionError, match="shorter than its protected anchor"),
        ledger.locked_snapshot(selected_count=1, selected_head_digest=first),
    ):
        pass
    with ledger.locked_snapshot(selected_count=0, selected_head_digest=genesis) as snapshot:
        assert snapshot.record_count == 0


def test_locked_admission_consumes_once_under_one_descriptor(tmp_path: Path) -> None:
    """The transaction can retain the ledger lock through a fsynced dual-ID append."""
    ledger = _ledger(tmp_path)
    genesis = sha256(_HEADER).hexdigest()
    with ledger.locked_admission(selected_count=0, selected_head_digest=genesis) as lease:
        assert lease.snapshot.record_count == 0
        consumed = lease.consume(
            permit_id=_FIRST,
            single_use_id=_SINGLE_USE,
            permit_digest=_DIGEST,
            expires_at=_EXPIRY,
        )
        assert consumed.permit_id == _FIRST
        assert consumed.single_use_id == _SINGLE_USE
        assert consumed.head_digest == lease.snapshot.head_digest
        assert (
            consumed.record_digest == sha256(ledger.path.read_bytes()[-_RECORD.size :]).hexdigest()
        )
        with pytest.raises(PermissionError, match="already consumed"):
            lease.consume(permit_id=_SECOND, permit_digest=_DIGEST, expires_at=_EXPIRY)
    with pytest.raises(PermissionError, match="already consumed"):
        ledger.consume(permit_id=_SINGLE_USE, permit_digest=_DIGEST, expires_at=_EXPIRY)


def test_locked_admission_refuses_unanchored_or_changed_file(tmp_path: Path) -> None:
    """The existing selected prefix cannot be advanced through a crash suffix."""
    ledger = _ledger(tmp_path)
    genesis = sha256(_HEADER).hexdigest()
    ledger.consume(permit_id=_FIRST, permit_digest=_DIGEST, expires_at=_EXPIRY)
    with (
        pytest.raises(PermissionError, match="unanchored suffix"),
        ledger.locked_admission(selected_count=0, selected_head_digest=genesis),
    ):
        pass
    ledger.path.write_bytes(_HEADER)
    with (
        pytest.raises(PermissionError, match="changed during locked operation"),
        ledger.locked_admission(selected_count=0, selected_head_digest=genesis) as lease,
    ):
        with ledger.path.open("ab") as writer:
            writer.write(b"x")
            writer.flush()
            os.fsync(writer.fileno())
        assert lease.snapshot.record_count == 0


def test_locked_admission_replay_and_invalid_binding_refuse(tmp_path: Path) -> None:
    """The held descriptor validates both UUIDs and the exact selected head."""
    ledger = _ledger(tmp_path)
    genesis = sha256(_HEADER).hexdigest()
    first = ledger.consume(
        permit_id=_FIRST,
        single_use_id=_SINGLE_USE,
        permit_digest=_DIGEST,
        expires_at=_EXPIRY,
    )
    with ledger.locked_admission(selected_count=1, selected_head_digest=first) as lease:
        with pytest.raises(ValueError, match="must differ"):
            lease.consume(
                permit_id=_SECOND,
                single_use_id=_SECOND,
                permit_digest=_DIGEST,
                expires_at=_EXPIRY,
            )
        with pytest.raises(PermissionError, match="already consumed"):
            lease.consume(permit_id=_SINGLE_USE, permit_digest=_DIGEST, expires_at=_EXPIRY)
        with pytest.raises(PermissionError, match="already consumed"):
            lease.consume(
                permit_id=_SECOND,
                single_use_id=_FIRST,
                permit_digest=_DIGEST,
                expires_at=_EXPIRY,
            )
    with (
        pytest.raises(ValueError, match="selected count"),
        ledger.locked_admission(selected_count=-1, selected_head_digest=genesis),
    ):
        pass
    with (
        pytest.raises(PermissionError, match="protected anchor"),
        ledger.locked_admission(selected_count=1, selected_head_digest="c" * 64),
    ):
        pass


def test_locked_admission_refuses_torn_tail_and_out_of_lock_growth(tmp_path: Path) -> None:
    """A torn file or uncooperative writer cannot be silently consumed."""
    ledger = _ledger(tmp_path)
    genesis = sha256(_HEADER).hexdigest()
    with ledger.path.open("ab") as writer:
        writer.write(b"x")
    with (
        pytest.raises(PermissionError, match="incomplete tail"),
        ledger.locked_admission(selected_count=0, selected_head_digest=genesis),
    ):
        pass
    ledger.path.write_bytes(_HEADER)
    with (
        pytest.raises(PermissionError),
        ledger.locked_admission(selected_count=0, selected_head_digest=genesis) as lease,
    ):
        with ledger.path.open("ab") as writer:
            writer.write(b"x")
            writer.flush()
            os.fsync(writer.fileno())
        lease.consume(permit_id=_FIRST, permit_digest=_DIGEST, expires_at=_EXPIRY)
    assert ledger.path.read_bytes() == _HEADER + b"x"


def test_two_concurrent_consumers_cannot_both_win(tmp_path: Path) -> None:
    """Separate file descriptors serialize one exact nonce under flock."""
    ledger = _ledger(tmp_path)
    start = Barrier(2)

    def race() -> str:
        """Attempt one consumption as a concurrent service worker."""
        start.wait()
        try:
            ledger.consume(permit_id=_FIRST, permit_digest=_DIGEST, expires_at=_EXPIRY)
        except PermissionError as exc:
            assert "already consumed" in str(exc)
            return "replay"
        return "consumed"

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(race)
        second = pool.submit(race)
        assert sorted((first.result(), second.result())) == ["consumed", "replay"]


def test_single_use_uuid_is_burned_across_both_fields(tmp_path: Path) -> None:
    """One record burns its permit and owner authorization UUID for every later attempt."""
    ledger = _ledger(tmp_path)
    ledger.consume(
        permit_id=_FIRST,
        single_use_id=_SINGLE_USE,
        permit_digest=_DIGEST,
        expires_at=_EXPIRY,
    )
    data = ledger.path.read_bytes()
    record = _RECORD.unpack(data[-_RECORD.size :])
    assert record[1] != record[2]
    with pytest.raises(PermissionError, match="already consumed"):
        ledger.consume(
            permit_id=_SECOND,
            single_use_id=_SINGLE_USE,
            permit_digest=_DIGEST,
            expires_at=_EXPIRY,
        )
    with pytest.raises(PermissionError, match="already consumed"):
        ledger.consume(permit_id=_SINGLE_USE, permit_digest=_DIGEST, expires_at=_EXPIRY)
    with pytest.raises(ValueError, match="must differ"):
        ledger.consume(
            permit_id=_SECOND,
            single_use_id=_SECOND,
            permit_digest=_DIGEST,
            expires_at=_EXPIRY,
        )
    assert ledger.path.read_bytes() == data


def test_concurrent_distinct_permits_cannot_reuse_single_use_uuid(tmp_path: Path) -> None:
    """The file lock serialises two permits competing for one owner authorization record."""
    ledger = _ledger(tmp_path)
    start = Barrier(2)

    def race(permit_id: str) -> str:
        """Consume the shared owner authorization UUID from an independent file descriptor."""
        start.wait()
        try:
            ConsumedPermitLedgerV2(ledger.path).consume(
                permit_id=permit_id,
                single_use_id=_SINGLE_USE,
                permit_digest=_DIGEST,
                expires_at=_EXPIRY,
            )
        except PermissionError as exc:
            assert "already consumed" in str(exc)
            return "replay"
        return "consumed"

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(race, _FIRST)
        second = pool.submit(race, _SECOND)
        assert sorted((first.result(), second.result())) == ["consumed", "replay"]
    assert ledger.path.stat().st_size == len(_HEADER) + _RECORD.size


def test_chain_valid_cross_field_duplicate_refuses_all_later_access(tmp_path: Path) -> None:
    """A valid chain cannot excuse reusing a permit UUID as a owner authorization UUID."""
    ledger = _ledger(tmp_path)
    first_head = ledger.consume(permit_id=_FIRST, permit_digest=_DIGEST, expires_at=_EXPIRY)
    first_record = _RECORD.unpack(ledger.path.read_bytes()[-_RECORD.size :])
    duplicate = _RECORD.pack(
        0,
        UUID(_SECOND).bytes,
        UUID(_FIRST).bytes,
        bytes.fromhex(_DIGEST),
        first_record[4],
        0,
        bytes.fromhex(first_head),
    )
    with ledger.path.open("ab") as stream:
        stream.write(duplicate)
    corrupted = ledger.path.read_bytes()
    with pytest.raises(PermissionError, match="UUID appears more than once"):
        ledger.verify_anchor(record_count=1, head_digest=first_head)
    with pytest.raises(PermissionError, match="UUID appears more than once"):
        ledger.consume(permit_id=_SINGLE_USE, permit_digest=_DIGEST, expires_at=_EXPIRY)
    assert ledger.path.read_bytes() == corrupted


def test_nonzero_reserved_record_byte_refuses_before_append(tmp_path: Path) -> None:
    """A valid sized record with nonzero padding cannot be replayed as wire V2.2."""
    ledger = _ledger(tmp_path)
    ledger.consume(permit_id=_FIRST, permit_digest=_DIGEST, expires_at=_EXPIRY)
    with ledger.path.open("r+b") as stream:
        stream.seek(len(_HEADER) + 1)
        stream.write(b"X")
    corrupted = ledger.path.read_bytes()
    with pytest.raises(PermissionError, match="reserved bytes"):
        ledger.consume(permit_id=_SECOND, permit_digest=_DIGEST, expires_at=_EXPIRY)
    assert ledger.path.read_bytes() == corrupted


def test_file_custody_and_append_integrity_fail_closed(tmp_path: Path) -> None:
    """A torn, changed, linked, permissive or substituted file is refused."""
    ledger = _ledger(tmp_path)
    ledger.path.chmod(0o644)
    with pytest.raises(PermissionError, match=r"owner-only|identity"):
        ledger.consume(permit_id=_FIRST, permit_digest=_DIGEST, expires_at=_EXPIRY)
    ledger.path.chmod(0o600)
    linked = tmp_path / "linked.bin"
    linked.hardlink_to(ledger.path)
    with pytest.raises(PermissionError, match="identity"):
        ledger.consume(permit_id=_FIRST, permit_digest=_DIGEST, expires_at=_EXPIRY)
    linked.unlink()
    with ledger.path.open("ab") as stream:
        stream.write(b"x")
    with pytest.raises(PermissionError, match="incomplete tail"):
        ledger.consume(permit_id=_FIRST, permit_digest=_DIGEST, expires_at=_EXPIRY)
    ledger.path.unlink()
    ledger.initialize()
    with ledger.path.open("r+b") as stream:
        stream.write(b"X")
    with pytest.raises(PermissionError, match="header"):
        ledger.consume(permit_id=_FIRST, permit_digest=_DIGEST, expires_at=_EXPIRY)
    ledger.path.unlink()
    ledger.path.symlink_to(tmp_path / "target")
    with pytest.raises(OSError):
        ledger.consume(permit_id=_FIRST, permit_digest=_DIGEST, expires_at=_EXPIRY)


def test_parent_custody_existing_file_and_invalid_inputs_refuse(tmp_path: Path) -> None:
    """No implicit file creation, replacement, weak parent or invalid ID."""
    ledger = ConsumedPermitLedgerV2(tmp_path / "consumed.bin")
    tmp_path.chmod(0o700)
    with pytest.raises(FileNotFoundError):
        ledger.consume(permit_id=_FIRST, permit_digest=_DIGEST, expires_at=_EXPIRY)
    ledger.initialize()
    with pytest.raises(FileExistsError):
        ledger.initialize()
    with pytest.raises(ValueError, match="canonical UUID"):
        ledger.consume(permit_id="bad-id", permit_digest=_DIGEST, expires_at=_EXPIRY)
    with pytest.raises(ValueError, match="canonical UUID"):
        ledger.consume(permit_id=_FIRST.upper(), permit_digest=_DIGEST, expires_at=_EXPIRY)
    before = ledger.path.read_bytes()
    for reserved in (
        "00000000-0000-0000-0000-000000000000",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
    ):
        with pytest.raises(ValueError, match="non-reserved canonical UUID"):
            ledger.consume(permit_id=reserved, permit_digest=_DIGEST, expires_at=_EXPIRY)
        with pytest.raises(ValueError, match="non-reserved canonical UUID"):
            ledger.consume(
                permit_id=_FIRST,
                single_use_id=reserved,
                permit_digest=_DIGEST,
                expires_at=_EXPIRY,
            )
        assert ledger.path.read_bytes() == before
    with pytest.raises(ValueError):
        ledger.consume(permit_id=_FIRST, permit_digest="invalid", expires_at=_EXPIRY)
    with pytest.raises(ValueError, match="absolute path"):
        ConsumedPermitLedgerV2(Path("relative.bin")).initialize()
    tmp_path.chmod(0o755)
    with pytest.raises(PermissionError, match="directory is not owner-only"):
        ledger.consume(permit_id=_FIRST, permit_digest=_DIGEST, expires_at=_EXPIRY)


def test_explicit_tail_recovery_keeps_consumed_nonce_and_audits_bytes(tmp_path: Path) -> None:
    """A short final record needs explicit recovery and preserves prior replay state."""
    ledger = _ledger(tmp_path)
    first_head = ledger.consume(permit_id=_FIRST, permit_digest=_DIGEST, expires_at=_EXPIRY)
    complete = ledger.path.read_bytes()
    torn = b"torn-write"
    with ledger.path.open("ab") as stream:
        stream.write(torn)
    with pytest.raises(PermissionError, match="incomplete tail"):
        ledger.consume(permit_id=_SECOND, permit_digest=_DIGEST, expires_at=_EXPIRY)
    new_head = ledger.recover_torn_tail(recovered_at=_RECOVERY)
    assert len(new_head) == 64
    data = ledger.path.read_bytes()
    assert data.startswith(complete)
    assert len(data) == len(complete) + _RECORD.size
    kind, nonce, single_use_id, digest, stamp, removed, previous = _RECORD.unpack(
        data[-_RECORD.size :]
    )
    assert kind == 1
    assert nonce == b"\x00" * 16
    assert single_use_id == b"\x00" * 16
    assert digest == sha256(torn).digest()
    assert stamp > 0
    assert removed == len(torn)
    assert previous == bytes.fromhex(first_head)
    with pytest.raises(PermissionError, match="already consumed"):
        ledger.consume(permit_id=_FIRST, permit_digest=_DIGEST, expires_at=_EXPIRY)
    ledger.consume(permit_id=_SECOND, permit_digest=_DIGEST, expires_at=_EXPIRY)
    with pytest.raises(ValueError, match="no incomplete tail"):
        ledger.recover_torn_tail(recovered_at=_RECOVERY)


def test_recovery_refuses_bad_header_and_corrupt_complete_record(tmp_path: Path) -> None:
    """A short tail does not excuse tampering with complete ledger history."""
    ledger = _ledger(tmp_path)
    ledger.consume(permit_id=_FIRST, permit_digest=_DIGEST, expires_at=_EXPIRY)
    with ledger.path.open("ab") as stream:
        stream.write(b"x")
    good = ledger.path.read_bytes()
    with ledger.path.open("r+b") as stream:
        stream.write(b"X")
    with pytest.raises(PermissionError, match="header"):
        ledger.recover_torn_tail(recovered_at=_RECOVERY)
    with ledger.path.open("r+b") as stream:
        stream.write(good)
        stream.seek(len(_HEADER))
        stream.write(b"X")
    with pytest.raises(PermissionError, match="record kind differs"):
        ledger.recover_torn_tail(recovered_at=_RECOVERY)


def test_hash_chain_detects_rewritten_complete_history(tmp_path: Path) -> None:
    """A later record binds the previous record when the ledger is scanned."""
    ledger = _ledger(tmp_path)
    ledger.consume(permit_id=_FIRST, permit_digest=_DIGEST, expires_at=_EXPIRY)
    ledger.consume(permit_id=_SECOND, permit_digest=_DIGEST, expires_at=_EXPIRY)
    with ledger.path.open("r+b") as stream:
        stream.seek(len(_HEADER) + 24)
        stream.write(b"X")
    with pytest.raises(PermissionError, match="hash chain differs"):
        ledger.consume(
            permit_id="01a09a66-7b5c-7a2e-93f0-b726808737d6",
            permit_digest=_DIGEST,
            expires_at=_EXPIRY,
        )


def test_invalid_record_fields_and_pre_epoch_expiry_refuse(tmp_path: Path) -> None:
    """A forged complete record and an unrepresentable expiry cannot be used."""
    ledger = _ledger(tmp_path)
    with pytest.raises(ValueError, match="outside the ledger time range"):
        ledger.consume(permit_id=_FIRST, permit_digest=_DIGEST, expires_at="1969-12-31T23:59:59Z")
    ledger.consume(permit_id=_FIRST, permit_digest=_DIGEST, expires_at=_EXPIRY)
    original = ledger.path.read_bytes()
    with ledger.path.open("r+b") as stream:
        stream.seek(len(_HEADER) + 4)
        stream.write(b"\x00" * 16)
    with pytest.raises(PermissionError, match="consumption record differs"):
        ledger.consume(permit_id=_SECOND, permit_digest=_DIGEST, expires_at=_EXPIRY)
    with ledger.path.open("r+b") as stream:
        stream.write(original)
    with ledger.path.open("ab") as stream:
        stream.write(b"x")
    ledger.recover_torn_tail(recovered_at=_RECOVERY)
    with ledger.path.open("r+b") as stream:
        stream.seek(-_RECORD.size + 76, os.SEEK_END)
        stream.write(b"\x00" * 4)
    with pytest.raises(PermissionError, match="recovery record differs"):
        ledger.consume(permit_id=_SECOND, permit_digest=_DIGEST, expires_at=_EXPIRY)


def test_protected_prefix_anchor_survives_append_and_detects_rewrite(tmp_path: Path) -> None:
    """An older external head remains checkable after later valid consumption."""
    ledger = _ledger(tmp_path)
    empty = sha256(_HEADER).hexdigest()
    assert ledger.verify_anchor(record_count=0, head_digest=empty) == (0, empty)
    first = ledger.consume(permit_id=_FIRST, permit_digest=_DIGEST, expires_at=_EXPIRY)
    second = ledger.consume(permit_id=_SECOND, permit_digest=_DIGEST, expires_at=_EXPIRY)
    assert ledger.verify_anchor(record_count=1, head_digest=first) == (2, second)
    assert ledger.verify_anchor(record_count=2, head_digest=second) == (2, second)
    with pytest.raises(PermissionError, match="protected anchor"):
        ledger.verify_anchor(record_count=1, head_digest="0" * 64)
    with ledger.path.open("r+b") as stream:
        stream.seek(-_RECORD.size + 24, os.SEEK_END)
        stream.write(b"X")
    with pytest.raises(PermissionError, match="protected anchor"):
        ledger.verify_anchor(record_count=2, head_digest=second)


def test_anchor_refuses_truncation_torn_tail_and_invalid_selection(tmp_path: Path) -> None:
    """A protected count blocks rollback and an incomplete write blocks inspection."""
    ledger = _ledger(tmp_path)
    first = ledger.consume(permit_id=_FIRST, permit_digest=_DIGEST, expires_at=_EXPIRY)
    with pytest.raises(ValueError, match="record count"):
        ledger.verify_anchor(record_count=-1, head_digest=first)
    with pytest.raises(ValueError, match="record count"):
        ledger.verify_anchor(record_count=True, head_digest=first)
    with pytest.raises(PermissionError, match="shorter than its protected anchor"):
        ledger.verify_anchor(record_count=2, head_digest=first)
    with ledger.path.open("ab") as stream:
        stream.write(b"x")
    with pytest.raises(PermissionError, match="incomplete tail"):
        ledger.verify_anchor(record_count=1, head_digest=first)
    with ledger.path.open("r+b") as stream:
        stream.truncate(len(_HEADER))
    with pytest.raises(PermissionError, match="shorter than its protected anchor"):
        ledger.verify_anchor(record_count=1, head_digest=first)
