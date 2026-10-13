# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — V2.1 final journal frame tests
"""Exercise locked final-frame classification through real owner-only files."""

from __future__ import annotations

import os
import struct
from hashlib import sha256
from pathlib import Path

import pytest

from rigor_foundry.effect_journal_records_v2 import (
    JOURNAL_GENESIS_V2,
    JOURNAL_MAGIC_V2,
    build_effect_journal_frame_v2,
)
from rigor_foundry.effect_journal_v2 import EffectJournalStoreV2

_TIME = "2026-09-23T03:00:00Z"
_ID = "123e4567-e89b-12d3-a456-426614174000"
_BODY: dict[str, object] = {
    "permit_id": _ID,
    "part_index": 0,
    "pre_state_digest": None,
}


def _store(tmp_path: Path) -> EffectJournalStoreV2:
    """Create a real journal beneath an owner-only custody directory."""
    parent = tmp_path / "custody"
    parent.mkdir(mode=0o700, parents=True)
    store = EffectJournalStoreV2(parent / "effect.journal")
    store.initialize()
    return store


def _valid_frame() -> bytes:
    """Build one canonical effect intent with the real V2.1 frame builder."""
    return build_effect_journal_frame_v2(
        kind="effect-intent",
        body=_BODY,
        host_time=_TIME,
        previous_head=JOURNAL_GENESIS_V2,
        seq=1,
    ).frame


def _append(store: EffectJournalStoreV2, data: bytes) -> None:
    """Fsync exact adversarial bytes while retaining the opened file inode."""
    with store.path.open("ab") as writer:
        writer.write(data)
        writer.flush()
        os.fsync(writer.fileno())


def test_partial_tail_is_classified_without_mutation(tmp_path: Path) -> None:
    """A torn length or payload after genesis stays available for audit."""
    for raw, declared in ((b"\x00\x00", None), (struct.pack(">I", 9) + b"x", 9)):
        store = _store(tmp_path / str(len(raw)))
        _append(store, raw)
        before = store.path.read_bytes()
        with pytest.raises(PermissionError):
            store.snapshot(selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000)
        with store.locked_recovery(
            selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000
        ) as lease:
            assert lease.scan.snapshot.records == ()
            assert lease.scan.tail is not None
            assert lease.scan.tail.offset == len(JOURNAL_MAGIC_V2)
            assert lease.scan.tail.raw == raw
            assert lease.scan.tail.failure_class == "partial"
            assert lease.scan.tail.declared_payload_length == declared
        assert store.path.read_bytes() == before


def test_sole_full_bad_head_and_noncanonical_frame_are_distinct(tmp_path: Path) -> None:
    """Only a final full frame gets the parser-order failure class."""
    bad_head = _valid_frame()[:-1] + b"X"
    payload = b"{}"
    length = struct.pack(">I", len(payload))
    noncanonical = length + payload + sha256(JOURNAL_GENESIS_V2 + length + payload).digest()
    for label, raw in (("bad-head", bad_head), ("noncanonical", noncanonical)):
        store = _store(tmp_path / label)
        _append(store, raw)
        with store.locked_recovery(
            selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000
        ) as lease:
            assert lease.scan.tail is not None
            assert lease.scan.tail.failure_class == label
            assert lease.scan.tail.declared_payload_length == len(raw) - 36
            assert lease.scan.tail.raw == raw


def test_anchored_and_interior_damage_never_classifies(tmp_path: Path) -> None:
    """Changing an anchored frame or adding bytes after an invalid frame refuses."""
    store = _store(tmp_path)
    frame = _valid_frame()
    _append(store, frame)
    selected = store.snapshot(
        selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000
    ).head_digest
    store.path.write_bytes(JOURNAL_MAGIC_V2 + frame[:-1] + b"X")
    with (
        pytest.raises(PermissionError, match="anchored or interior"),
        store.locked_recovery(selected_head_digest=selected, max_bytes=100000),
    ):
        pass
    store.path.write_bytes(JOURNAL_MAGIC_V2 + frame[:-1] + b"X" + b"more")
    with (
        pytest.raises(PermissionError, match="anchored or interior"),
        store.locked_recovery(selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000),
    ):
        pass


def test_invalid_length_and_unknown_selected_head_refuse(tmp_path: Path) -> None:
    """An ambiguous boundary or missing selected prefix cannot be recovered."""
    store = _store(tmp_path)
    _append(store, struct.pack(">I", 0))
    with (
        pytest.raises(PermissionError, match="ambiguous"),
        store.locked_recovery(selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000),
    ):
        pass
    store.path.write_bytes(JOURNAL_MAGIC_V2 + b"x")
    with (
        pytest.raises(PermissionError, match="anchored frame is incomplete"),
        store.locked_recovery(selected_head_digest="b" * 64, max_bytes=100000),
    ):
        pass


def test_valid_selected_prefix_then_partial_tail(tmp_path: Path) -> None:
    """A complete anchored frame stays selected while its successor tears."""
    store = _store(tmp_path)
    frame = _valid_frame()
    _append(store, frame + b"z")
    selected = sha256(JOURNAL_GENESIS_V2 + frame[:-32]).hexdigest()
    with store.locked_recovery(selected_head_digest=selected, max_bytes=100000) as lease:
        assert lease.scan.snapshot.selected_record_count == 1
        assert len(lease.scan.snapshot.records) == 1
        assert lease.scan.tail is not None
        assert lease.scan.tail.raw == b"z"


def test_clean_selected_prefix_and_unknown_head(tmp_path: Path) -> None:
    """A clean file is readable for recovery but cannot select an absent head."""
    store = _store(tmp_path)
    _append(store, _valid_frame())
    with store.locked_recovery(
        selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000
    ) as lease:
        assert lease.scan.tail is None
        assert len(lease.scan.snapshot.records) == 1
    with (
        pytest.raises(PermissionError, match="not a verified prefix"),
        store.locked_recovery(selected_head_digest="b" * 64, max_bytes=100000),
    ):
        pass


def test_recovery_reader_refuses_bad_header_and_identity(tmp_path: Path) -> None:
    """A changed header, mode or inode cannot enter the operator scan."""
    store = _store(tmp_path)
    store.path.write_bytes(b"X" + JOURNAL_MAGIC_V2[1:])
    with (
        pytest.raises(PermissionError, match="header differs"),
        store.locked_recovery(selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000),
    ):
        pass
    store.path.write_bytes(JOURNAL_MAGIC_V2)
    store.path.chmod(0o644)
    with (
        pytest.raises(PermissionError, match="identity or length"),
        store.locked_recovery(selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000),
    ):
        pass
    store.path.chmod(0o600)
    with (
        pytest.raises(ValueError, match="byte budget"),
        store.locked_recovery(selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=0),
    ):
        pass


def test_recovery_reader_refuses_uncooperative_growth(tmp_path: Path) -> None:
    """An unlocked writer changing file size while the lease is held is detected."""
    store = _store(tmp_path)
    with (
        pytest.raises(PermissionError, match="changed during locked recovery"),
        store.locked_recovery(selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000),
    ):
        _append(store, b"x")


def test_incomplete_selected_frame_and_nonfinal_damage_refuse(tmp_path: Path) -> None:
    """The selected head cannot be inferred through a torn or interior frame."""
    store = _store(tmp_path)
    _append(store, struct.pack(">I", 10) + b"x")
    with (
        pytest.raises(PermissionError, match="anchored frame is incomplete"),
        store.locked_recovery(selected_head_digest="b" * 64, max_bytes=100000),
    ):
        pass
    store.path.write_bytes(JOURNAL_MAGIC_V2 + _valid_frame()[:-1] + b"X" + b"tail")
    with (
        pytest.raises(PermissionError, match="anchored or interior"),
        store.locked_recovery(selected_head_digest=JOURNAL_GENESIS_V2.hex(), max_bytes=100000),
    ):
        pass
