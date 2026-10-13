# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real journal descriptor I/O boundaries
"""Exercise shared descriptor checks through the public physical journal store."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import FrameType

import pytest

from rigor_foundry.effect_intent_token_v2 import EffectIntentBindingV2
from rigor_foundry.effect_journal_records_v2 import JOURNAL_MAGIC_V2
from rigor_foundry.effect_journal_v2 import EffectJournalStoreV2


@pytest.mark.parametrize("mode", [0o710, 0o750, 0o777])
def test_real_group_or_world_accessible_parent_refuses(tmp_path: Path, mode: int) -> None:
    """Actual non-owner directory permissions cannot supply journal custody."""
    parent = tmp_path / "custody"
    parent.mkdir(mode=0o700)
    parent.chmod(mode)
    store = EffectJournalStoreV2(parent / "effect.journal")
    with pytest.raises(PermissionError):
        store.initialize()
    assert not store.path.exists()


@pytest.mark.parametrize("change", ["hardlink", "mode", "symlink"])
def test_real_relinked_or_accessible_journal_refuses(tmp_path: Path, change: str) -> None:
    """Public snapshots check actual mode, link count and no-follow descriptor identity."""
    parent = tmp_path / "custody"
    parent.mkdir(mode=0o700)
    store = EffectJournalStoreV2(parent / "effect.journal")
    head = store.initialize()
    original = store.path.read_bytes()
    if change == "hardlink":
        os.link(store.path, parent / "retained")
    elif change == "mode":
        store.path.chmod(0o640)
    else:
        retained = parent / "retained"
        store.path.rename(retained)
        store.path.symlink_to(retained)
    with pytest.raises((PermissionError, OSError)):
        store.snapshot(selected_head_digest=head, max_bytes=100000)
    assert store.path.read_bytes() == original


def test_actual_truncation_after_descriptor_sample_refuses_without_repair(tmp_path: Path) -> None:
    """A lock-ignoring writer causes real EOF during the public snapshot's selected read."""
    parent = tmp_path / "custody"
    parent.mkdir(mode=0o700)
    store = EffectJournalStoreV2(parent / "effect.journal")
    head = store.initialize()
    observed: list[str] = []

    def truncate_after_seek(frame: FrameType, event: str, arg: object) -> None:
        """Observe the actual scan seek and shorten its real file without replacing any call."""
        if event == "c_return" and arg is os.lseek and frame.f_code.co_name == "_scan":
            with store.path.open("r+b") as writer:
                writer.truncate(len(JOURNAL_MAGIC_V2) - 1)
                writer.flush()
                os.fsync(writer.fileno())
            observed.append("truncated")

    sys.setprofile(truncate_after_seek)
    try:
        with pytest.raises(PermissionError, match="record is torn"):
            store.snapshot(selected_head_digest=head, max_bytes=100000)
    finally:
        sys.setprofile(None)
    assert observed == ["truncated"]
    assert store.path.read_bytes() == JOURNAL_MAGIC_V2[:-1]


def test_real_inode_replacement_during_lease_refuses_at_close(tmp_path: Path) -> None:
    """Closing identity checks detect a replacement even when its contents and mode match."""
    parent = tmp_path / "custody"
    parent.mkdir(mode=0o700)
    store = EffectJournalStoreV2(parent / "effect.journal")
    head = store.initialize()
    original_inode = store.path.stat().st_ino
    retained = parent / "retained"
    with (
        pytest.raises(PermissionError, match="changed during locked operation"),
        store.locked(selected_head_digest=head, max_bytes=100000),
    ):
        store.path.rename(retained)
        descriptor = os.open(store.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            assert os.write(descriptor, JOURNAL_MAGIC_V2) == len(JOURNAL_MAGIC_V2)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    assert retained.stat().st_ino == original_inode
    assert store.path.stat().st_ino != original_inode
    assert retained.read_bytes() == store.path.read_bytes() == JOURNAL_MAGIC_V2


@pytest.mark.parametrize("change", ["group-read", "read-only", "hardlink"])
def test_recovery_rechecks_actual_custody_before_any_mutation(tmp_path: Path, change: str) -> None:
    """The public recovery check refuses changed mode/link custody before closing the lease."""
    parent = tmp_path / "custody"
    parent.mkdir(mode=0o700)
    store = EffectJournalStoreV2(parent / "effect.journal")
    head = store.initialize()
    original = store.path.read_bytes()
    with (
        pytest.raises(PermissionError, match="changed during locked recovery"),
        store.locked_recovery(selected_head_digest=head, max_bytes=100000) as lease,
    ):
        if change == "hardlink":
            os.link(store.path, parent / "retained-link")
        else:
            store.path.chmod(0o640 if change == "group-read" else 0o400)
        with pytest.raises(PermissionError, match="changed during locked recovery"):
            lease.check(store.path)
        assert store.path.read_bytes() == original
    assert store.path.read_bytes() == original


@pytest.mark.parametrize("action", ["append", "export"])
@pytest.mark.parametrize("change", ["group-read", "read-only", "hardlink", "same-size-corruption"])
def test_append_and_export_refuse_current_custody_or_byte_changes(
    tmp_path: Path, action: str, change: str
) -> None:
    """Real file changes must refuse before returning another token or receipt."""
    parent = tmp_path / "custody"
    parent.mkdir(mode=0o700)
    store = EffectJournalStoreV2(parent / "effect.journal")
    head = store.initialize()
    permit = "123e4567-e89b-12d3-a456-426614174000"
    with store.locked(selected_head_digest=head, max_bytes=100000) as lease:
        token = lease.append_effect_intent_from_host(
            body={"permit_id": permit, "part_index": 0, "pre_state_digest": None},
            host_time="2026-10-01T18:28:00Z",
        )
        current = EffectIntentBindingV2(permit, 0, lease.snapshot.records[-1].record_digest)
        original = store.path.read_bytes()
        if change == "hardlink":
            os.link(store.path, parent / "retained-link")
        elif change == "same-size-corruption":
            with store.path.open("r+b") as writer:
                assert writer.write(b"X") == 1
                writer.flush()
                os.fsync(writer.fileno())
        else:
            store.path.chmod(0o640 if change == "group-read" else 0o400)
        changed = store.path.read_bytes()
        before_snapshot = lease.snapshot
        try:
            with pytest.raises(PermissionError):
                if action == "append":
                    lease.append_effect_intent_from_host(
                        body={"permit_id": permit, "part_index": 1, "pre_state_digest": None},
                        host_time="2026-10-01T18:28:00Z",
                    )
                else:
                    lease.export_effect_intent_receipt_for_handler(
                        token,
                        current=current,
                        handler_operation_digest="a" * 64,
                        effect_context_digest="b" * 64,
                        ready_nonce=bytes(range(32)),
                    )
            assert store.path.read_bytes() == changed
            assert lease.snapshot == before_snapshot
            token.require_current(current)
        finally:
            store.path.chmod(0o600)
            if change == "hardlink":
                (parent / "retained-link").unlink()
            elif change == "same-size-corruption":
                with store.path.open("r+b") as writer:
                    assert writer.write(original) == len(original)
                    writer.flush()
                    os.fsync(writer.fileno())
