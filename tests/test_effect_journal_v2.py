# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — protected effect-journal file tests
"""Exercise selected journal prefix verification against real owner-only files."""

from __future__ import annotations

import os
import struct
from dataclasses import replace
from pathlib import Path

import pytest

from rigor_foundry.effect_journal_records_v2 import JOURNAL_GENESIS_V2, JOURNAL_MAGIC_V2
from rigor_foundry.effect_journal_v2 import EffectJournalStoreV2

_PERMIT_ID = "123e4567-e89b-12d3-a456-426614174000"
_DIGEST = "a" * 64
_TIME = "2026-09-23T03:00:00Z"
_BODY: dict[str, object] = {
    "permit_id": _PERMIT_ID,
    "part_index": 0,
    "pre_state_digest": None,
}


def _store(tmp_path: Path) -> EffectJournalStoreV2:
    """Create one mode-0700 fixture custody directory and its journal path."""
    parent = tmp_path / "custody"
    parent.mkdir(mode=0o700)
    return EffectJournalStoreV2(parent / "effect.journal")


def test_real_file_append_preserves_selected_prefix_and_exact_head(tmp_path: Path) -> None:
    """One fsynced event extends the chain while the earlier selected head remains a prefix."""
    store = _store(tmp_path)
    genesis = store.initialize()
    assert genesis == JOURNAL_GENESIS_V2.hex()
    assert store.path.read_bytes() == JOURNAL_MAGIC_V2
    with store.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        assert lease.snapshot.records == ()
        first = lease.append_from_host(kind="effect-intent", body=_BODY, host_time=_TIME)
        assert lease.snapshot.head_digest == first.record_head
        assert lease.snapshot.selected_record_count == 0
    snapshot = store.snapshot(selected_head_digest=genesis, max_bytes=100000)
    assert snapshot.records == (first,)
    assert snapshot.head_digest == first.record_head
    assert snapshot.selected_record_count == 0
    assert snapshot.identity.device == store.path.stat().st_dev
    assert snapshot.identity.inode == store.path.stat().st_ino
    assert (
        store.snapshot(
            selected_head_digest=first.record_head, max_bytes=100000
        ).selected_record_count
        == 1
    )
    assert store.path.read_bytes() == JOURNAL_MAGIC_V2 + first.frame


def test_selected_head_must_be_an_actual_prefix_of_same_file(tmp_path: Path) -> None:
    """An arbitrary digest cannot select journal content by assertion alone."""
    store = _store(tmp_path)
    genesis = store.initialize()
    with store.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        lease.append_from_host(kind="effect-intent", body=_BODY, host_time=_TIME)
    with pytest.raises(PermissionError, match="verified prefix"):
        store.snapshot(selected_head_digest="b" * 64, max_bytes=100000)


def test_partial_or_invalid_terminal_frame_refuses_without_truncation(tmp_path: Path) -> None:
    """A torn or malformed final frame holds admission and keeps forensic bytes."""
    store = _store(tmp_path)
    genesis = store.initialize()
    with store.path.open("ab") as handle:
        handle.write(b"\x00\x00")
        handle.flush()
        os.fsync(handle.fileno())
    before = store.path.read_bytes()
    with pytest.raises(PermissionError, match="incomplete tail"):
        store.snapshot(selected_head_digest=genesis, max_bytes=100000)
    assert store.path.read_bytes() == before
    store.path.write_bytes(JOURNAL_MAGIC_V2 + b"\x00\x00\x00\x00")
    before = store.path.read_bytes()
    with pytest.raises(PermissionError, match="frame length"):
        store.snapshot(selected_head_digest=genesis, max_bytes=100000)
    assert store.path.read_bytes() == before


def test_old_magic_and_unselected_existing_file_refuse(tmp_path: Path) -> None:
    """An existing journal is never reinitialized under an anchor."""
    store = _store(tmp_path)
    store.path.write_bytes(b"RIGOR-EFFECT-JOURNAL-V1\n")
    with pytest.raises(FileExistsError):
        store.initialize()
    with pytest.raises(PermissionError):
        store.snapshot(selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000)


def test_symlink_or_permissive_journal_file_refuses(tmp_path: Path) -> None:
    """A swapped link or group-readable file cannot stand in for protected custody."""
    store = _store(tmp_path)
    store.initialize()
    store.path.chmod(0o644)
    with pytest.raises(PermissionError, match="identity or length"):
        store.snapshot(selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000)
    store.path.unlink()
    store.path.symlink_to(tmp_path / "other")
    with pytest.raises(OSError):
        store.snapshot(selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000)


def test_noncanonical_owner_only_modes_refuse(tmp_path: Path) -> None:
    """The selected journal requires exact 0600 and its parent exact 0700."""
    store = _store(tmp_path)
    genesis = store.initialize()
    store.path.chmod(0o700)
    with pytest.raises(PermissionError, match="identity or length"):
        store.snapshot(selected_head_digest=genesis, max_bytes=100000)
    store.path.chmod(0o600)
    store.path.parent.chmod(0o500)
    with pytest.raises(PermissionError, match="directory is not owner-only"):
        store.snapshot(selected_head_digest=genesis, max_bytes=100000)


def test_finite_file_budget_refuses_before_append(tmp_path: Path) -> None:
    """The selected byte budget cannot be exceeded by a protected append."""
    store = _store(tmp_path)
    genesis = store.initialize()
    with (
        store.locked(selected_head_digest=genesis, max_bytes=len(JOURNAL_MAGIC_V2)) as lease,
        pytest.raises(PermissionError, match="byte budget"),
    ):
        lease.append_from_host(kind="effect-intent", body=_BODY, host_time=_TIME)
    assert store.path.read_bytes() == JOURNAL_MAGIC_V2
    with pytest.raises(ValueError, match="byte budget"):
        store.snapshot(selected_head_digest=genesis, max_bytes=0)


def test_replaced_path_refuses_at_lock_exit(tmp_path: Path) -> None:
    """A path replacement while a descriptor is locked cannot pass post-check."""
    store = _store(tmp_path)
    genesis = store.initialize()
    replacement = store.path.parent / "replacement.journal"
    replacement.write_bytes(JOURNAL_MAGIC_V2)
    replacement.chmod(0o600)
    with (
        pytest.raises(PermissionError, match="changed during locked operation"),
        store.locked(selected_head_digest=genesis, max_bytes=100000),
    ):
        os.replace(replacement, store.path)


def test_changed_header_or_partial_declared_frame_refuses(tmp_path: Path) -> None:
    """A valid file length does not make a different header or torn payload admissible."""
    store = _store(tmp_path)
    genesis = store.initialize()
    store.path.write_bytes(b"X" + JOURNAL_MAGIC_V2[1:])
    with pytest.raises(PermissionError, match="header"):
        store.snapshot(selected_head_digest=genesis, max_bytes=100000)
    store.path.write_bytes(JOURNAL_MAGIC_V2 + struct.pack(">I", 100) + b"x")
    with pytest.raises(PermissionError, match="incomplete tail"):
        store.snapshot(selected_head_digest=genesis, max_bytes=100000)


def test_nonabsolute_path_and_permissive_parent_refuse(tmp_path: Path) -> None:
    """The journal cannot select a relative or group-readable custody parent."""
    with pytest.raises(ValueError, match="absolute path"):
        EffectJournalStoreV2(Path("relative.journal")).initialize()
    store = _store(tmp_path)
    store.path.parent.chmod(0o755)
    with pytest.raises(PermissionError, match="directory is not owner-only"):
        store.initialize()


def test_second_descriptor_growth_refuses_append_under_advisory_lock(tmp_path: Path) -> None:
    """An uncooperative writer cannot make an already scanned lease append blindly."""
    store = _store(tmp_path)
    genesis = store.initialize()
    with (
        pytest.raises(PermissionError),
        store.locked(selected_head_digest=genesis, max_bytes=100000) as lease,
        store.path.open("ab") as other,
    ):
        other.write(b"x")
        other.flush()
        os.fsync(other.fileno())
        lease.append_from_host(kind="effect-intent", body=_BODY, host_time=_TIME)
    assert store.path.read_bytes() == JOURNAL_MAGIC_V2 + b"x"


def test_recovery_lease_refuses_missing_or_replaced_journal_path(tmp_path: Path) -> None:
    """Recovery needs the selected inode throughout its held operator lease."""
    store = _store(tmp_path)
    with (
        pytest.raises(FileNotFoundError),
        store.locked_recovery(selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000),
    ):
        pytest.fail("missing journal unexpectedly opened")
    store.initialize()
    replacement = store.path.parent / "replacement.journal"
    replacement.write_bytes(JOURNAL_MAGIC_V2)
    replacement.chmod(0o600)
    with (
        pytest.raises(PermissionError, match="changed during locked recovery"),
        store.locked_recovery(
            selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000
        ) as lease,
    ):
        os.replace(replacement, store.path)
        lease.check(store.path)


@pytest.mark.parametrize(
    "case", ["permissions", "read-only-mode", "hardlink", "identity", "size", "budget"]
)
def test_retained_rescan_rejects_actual_descriptor_changes(tmp_path: Path, case: str) -> None:
    """A current journal read refuses changed mode, links, identity, size and byte budget."""
    store = _store(tmp_path)
    genesis = store.initialize()
    with (
        pytest.raises(PermissionError, match="retained descriptor differs"),
        store.locked(selected_head_digest=genesis, max_bytes=100000) as lease,
    ):
        if case == "permissions":
            store.path.chmod(0o644)
        elif case == "read-only-mode":
            store.path.chmod(0o400)
        elif case == "hardlink":
            os.link(store.path, store.path.parent / "another-name")
        elif case == "identity":
            lease.snapshot = replace(
                lease.snapshot,
                identity=replace(lease.snapshot.identity, inode=lease.snapshot.identity.inode + 1),
            )
        elif case == "size":
            with store.path.open("ab") as writer:
                writer.write(b"x")
                writer.flush()
                os.fsync(writer.fileno())
        else:
            lease.max_bytes = len(JOURNAL_MAGIC_V2) - 1
        lease.verified_snapshot()


def test_retained_rescan_rejects_forged_state_and_preserves_valid_appends(tmp_path: Path) -> None:
    """Complete descriptor bytes must equal retained metadata before a snapshot is returned."""
    store = _store(tmp_path)
    genesis = store.initialize()
    with store.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        assert lease.verified_snapshot() == lease.snapshot
        lease.append_from_host(kind="effect-intent", body=_BODY, host_time=_TIME)
        assert lease.verified_snapshot() == lease.snapshot
        lease.snapshot = replace(lease.snapshot, head_digest="b" * 64)
        with pytest.raises(PermissionError, match="retained bytes or state differ"):
            lease.verified_snapshot()


def test_recovery_lease_current_descriptor_check_accepts_actual_unchanged_file(
    tmp_path: Path,
) -> None:
    """A real selected recovery lease verifies its live unchanged path and descriptor."""
    parent = tmp_path / "recovery-custody"
    parent.mkdir(mode=0o700)
    store = EffectJournalStoreV2(parent / "effect.journal")
    genesis = store.initialize()
    with store.locked_recovery(selected_head_digest=genesis, max_bytes=100000) as lease:
        lease.check(store.path)


def test_actual_frame_bytes_override_a_mutated_decoded_body_cache(tmp_path: Path) -> None:
    """A fresh public rescan uses durable canonical bytes after caller cache mutation."""
    store = _store(tmp_path)
    genesis = store.initialize()
    with store.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        first = lease.append_from_host(kind="effect-intent", body=_BODY, host_time=_TIME)
        original_bytes = store.path.read_bytes()
        first.body["permit_id"] = "123e4567-e89b-12d3-a456-426614174001"
        observed = lease.verified_snapshot()
        assert observed.records[0].body == _BODY
        assert observed.records[0].frame == first.frame
        assert store.path.read_bytes() == original_bytes
        second = lease.append_from_host(
            kind="effect-intent", body={**_BODY, "part_index": 1}, host_time=_TIME
        )
        assert lease.verified_snapshot().records[0].body == _BODY
        assert store.path.read_bytes() == original_bytes + second.frame


@pytest.mark.parametrize(
    "field", ["kind", "seq", "host_time", "previous_head", "record_head", "record_digest", "frame"]
)
def test_retained_rescan_still_refuses_every_forged_immutable_record_field(
    tmp_path: Path, field: str
) -> None:
    """Every retained immutable record field must match the real parsed journal."""
    store = _store(tmp_path)
    genesis = store.initialize()
    with store.locked(selected_head_digest=genesis, max_bytes=100000) as lease:
        record = lease.append_from_host(kind="effect-intent", body=_BODY, host_time=_TIME)
        original = store.path.read_bytes()
        if field == "kind":
            altered = replace(record, kind="effect-failed")
        elif field == "seq":
            altered = replace(record, seq=2)
        elif field == "host_time":
            altered = replace(record, host_time="2026-09-23T03:00:01Z")
        elif field == "previous_head":
            altered = replace(record, previous_head="b" * 64)
        elif field == "record_head":
            altered = replace(record, record_head="b" * 64)
        elif field == "record_digest":
            altered = replace(record, record_digest="b" * 64)
        else:
            assert field == "frame"
            altered = replace(record, frame=b"altered-frame")
        lease.snapshot = replace(lease.snapshot, records=(altered,))
        with pytest.raises(PermissionError, match="retained bytes or state differ"):
            lease.verified_snapshot()
        assert store.path.read_bytes() == original
