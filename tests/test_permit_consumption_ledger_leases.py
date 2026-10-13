# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — permit ledger admission lease regressions
"""Refuse real custody drift, stale descriptors and reserved ledger inputs."""

from __future__ import annotations

import copy
import os
import pickle
from pathlib import Path

import pytest

from rigor_foundry.permit_consumption_ledger_v2 import ConsumedPermitLedgerV2

_FIRST = "01a09a66-7b5c-7a2e-93f0-b726808737d4"
_SECOND = "01a09a66-7b5c-7a2e-93f0-b726808737d5"
_EXPIRY = "2026-09-23T03:00:00Z"


def _ledger(root: Path) -> tuple[ConsumedPermitLedgerV2, str]:
    """Create one actual owner-only ledger and retain its returned initial head."""
    root.mkdir(mode=0o700)
    ledger = ConsumedPermitLedgerV2(root / "consumed.bin")
    return ledger, ledger.initialize()


@pytest.mark.parametrize("operation", ["direct", "lease"])
def test_reserved_zero_digest_refuses_without_corrupting_history(
    tmp_path: Path, operation: str
) -> None:
    """A rejected wire sentinel leaves a verifiable ledger and reusable valid lease."""
    ledger, head = _ledger(tmp_path / operation)
    before = ledger.path.read_bytes()
    if operation == "direct":
        with pytest.raises(ValueError, match="reserved zero sentinel"):
            ledger.consume(permit_id=_FIRST, permit_digest="0" * 64, expires_at=_EXPIRY)
        assert ledger.path.read_bytes() == before
        assert ledger.verify_anchor(record_count=0, head_digest=head) == (0, head)
        ledger.consume(permit_id=_FIRST, permit_digest="a" * 64, expires_at=_EXPIRY)
    else:
        with ledger.locked_admission(selected_count=0, selected_head_digest=head) as lease:
            with pytest.raises(ValueError, match="reserved zero sentinel"):
                lease.consume(permit_id=_FIRST, permit_digest="0" * 64, expires_at=_EXPIRY)
            assert ledger.path.read_bytes() == before
            assert lease.used is False
            consumed = lease.consume(permit_id=_FIRST, permit_digest="a" * 64, expires_at=_EXPIRY)
            assert consumed.permit_id == _FIRST
    assert ledger.verify_anchor(record_count=0, head_digest=head)[0] == 1


@pytest.mark.parametrize("drift", ["mode", "hardlink", "path", "parent"])
def test_custody_drift_refuses_before_any_admission_append(tmp_path: Path, drift: str) -> None:
    """Mutating real held file custody cannot write through the old descriptor."""
    ledger, head = _ledger(tmp_path / drift)
    with (
        pytest.raises(PermissionError),
        ledger.locked_admission(selected_count=0, selected_head_digest=head) as lease,
    ):
        retained = ledger.path
        if drift == "mode":
            ledger.path.chmod(0o640)
        elif drift == "hardlink":
            (ledger.path.parent / "alias.bin").hardlink_to(ledger.path)
        elif drift == "path":
            retained = ledger.path.with_name("old.bin")
            ledger.path.rename(retained)
            ledger.path.write_bytes(retained.read_bytes())
            ledger.path.chmod(0o600)
        else:
            ledger.path.parent.chmod(0o750)
        before = retained.read_bytes()
        with pytest.raises(PermissionError, match="custody or identity changed"):
            lease.consume(permit_id=_FIRST, permit_digest="a" * 64, expires_at=_EXPIRY)
        assert retained.read_bytes() == before


def test_same_size_history_change_refuses_before_admission_append(tmp_path: Path) -> None:
    """The real stored prefix must still match the issued snapshot immediately before use."""
    ledger, initial = _ledger(tmp_path / "history")
    head = ledger.consume(permit_id=_FIRST, permit_digest="a" * 64, expires_at=_EXPIRY)
    with ledger.locked_admission(selected_count=1, selected_head_digest=head) as lease:
        with ledger.path.open("r+b") as writer:
            writer.seek(60)
            writer.write(b"X")
            writer.flush()
            os.fsync(writer.fileno())
        before = ledger.path.read_bytes()
        with pytest.raises(PermissionError, match="history differs"):
            lease.consume(permit_id=_SECOND, permit_digest="b" * 64, expires_at=_EXPIRY)
        assert ledger.path.read_bytes() == before
    with pytest.raises(PermissionError, match="protected anchor"):
        ledger.verify_anchor(record_count=1, head_digest=head)
    assert initial != head


def test_closed_issued_lease_refuses_naturally_reused_file_descriptor(tmp_path: Path) -> None:
    """An ordinary later open of another real ledger cannot revive a closed lease."""
    ledger, head = _ledger(tmp_path / "original")
    other, _ = _ledger(tmp_path / "other")
    original = ledger.path.read_bytes()
    before = other.path.read_bytes()
    with ledger.locked_admission(selected_count=0, selected_head_digest=head) as issued:
        target_descriptor = issued.descriptor
    descriptors: list[int] = []
    try:
        for _ in range(32):
            opened = os.open(other.path, os.O_RDWR | os.O_APPEND)
            descriptors.append(opened)
            if opened == target_descriptor:
                break
        assert descriptors[-1] == target_descriptor
        with pytest.raises(PermissionError, match="closed or inherited"):
            issued.consume(permit_id=_FIRST, permit_digest="a" * 64, expires_at=_EXPIRY)
        assert other.path.read_bytes() == before
        assert ledger.path.read_bytes() == original
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def test_exceptional_consumer_exit_closes_the_actual_issued_lease(tmp_path: Path) -> None:
    """A callback failure closes its issued lease without consuming or modifying the ledger."""
    ledger, head = _ledger(tmp_path / "exception")
    before = ledger.path.read_bytes()
    with (
        pytest.raises(LookupError, match="consumer stopped"),
        ledger.locked_admission(selected_count=0, selected_head_digest=head) as issued,
    ):
        raise LookupError("consumer stopped")
    with pytest.raises(PermissionError, match="closed or inherited"):
        issued.consume(permit_id=_FIRST, permit_digest="a" * 64, expires_at=_EXPIRY)
    assert ledger.path.read_bytes() == before


@pytest.mark.parametrize("operation", ["copy", "deepcopy", "pickle"])
def test_issued_live_lease_cannot_be_copied_or_serialised(tmp_path: Path, operation: str) -> None:
    """Real Python cloning refuses while the original issued lease remains usable."""
    ledger, head = _ledger(tmp_path / operation)
    before = ledger.path.read_bytes()
    with ledger.locked_admission(selected_count=0, selected_head_digest=head) as issued:
        with pytest.raises(PermissionError, match="cannot be copied or serialised"):
            if operation == "copy":
                copy.copy(issued)
            elif operation == "deepcopy":
                copy.deepcopy(issued)
            else:
                pickle.dumps(issued)
        assert ledger.path.read_bytes() == before
        consumed = issued.consume(permit_id=_FIRST, permit_digest="a" * 64, expires_at=_EXPIRY)
        assert consumed.permit_id == _FIRST


def test_fork_cannot_use_a_parent_issued_admission_lease(tmp_path: Path) -> None:
    """An actual child refuses its inherited live descriptor; the original parent can consume."""
    ledger, head = _ledger(tmp_path / "fork")
    before = ledger.path.read_bytes()
    reader, writer = os.pipe()
    with ledger.locked_admission(selected_count=0, selected_head_digest=head) as issued:
        child = os.fork()
        if child == 0:
            os.close(reader)
            try:
                issued.consume(permit_id=_FIRST, permit_digest="a" * 64, expires_at=_EXPIRY)
            except PermissionError as exc:
                os.write(writer, str(exc).encode())
                os.close(writer)
                os._exit(0)
            except BaseException:
                os.close(writer)
                os._exit(2)
            os.close(writer)
            os._exit(1)
        os.close(writer)
        try:
            message = os.read(reader, 4096)
            waited, status = os.waitpid(child, 0)
            assert waited == child
            assert os.waitstatus_to_exitcode(status) == 0
            assert b"closed or inherited" in message
            assert ledger.path.read_bytes() == before
            consumed = issued.consume(permit_id=_FIRST, permit_digest="a" * 64, expires_at=_EXPIRY)
            assert consumed.permit_id == _FIRST
        finally:
            os.close(reader)
