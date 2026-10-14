# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — immutable recovery evidence custody tests
"""Exercise real owner-only files and digest-named recovery object replay."""

from __future__ import annotations

import base64
import os
import stat
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

import pytest

from rigor_foundry.effect_journal_records_v2 import JOURNAL_MAGIC_V2
from rigor_foundry.models import canonical_digest
from rigor_foundry.permit_anchor_records_v2 import ANCHOR_MAGIC_V24
from rigor_foundry.recovery_evidence_schema_v2 import (
    validate_anchor_final_intent_v2,
    validate_journal_tail_intent_v2,
)
from rigor_foundry.recovery_evidence_store_v2 import RecoveryEvidenceStoreV2

_DIGEST = "a" * 64


def _identity(path: str) -> dict[str, object]:
    """Bind one selected path to its canonical digest and descriptor identity."""
    return {"path": path, "path_digest": canonical_digest(path), "device": "1", "inode": "2"}


def _object(raw: bytes = b"x") -> bytes:
    """Build one exact immutable final-anchor intent for file tests."""
    offset = len(ANCHOR_MAGIC_V24) + 200
    return validate_anchor_final_intent_v2(
        {
            "domain": "rigor.permit-anchor-final-recovery.v2.4",
            "anchor_file": _identity("/srv/rigor/anchor.bin"),
            "ledger_file": _identity("/srv/rigor/ledger.bin"),
            "journal_file": _identity("/srv/rigor/effect.journal"),
            "prior_anchor_head": _DIGEST,
            "prior_anchor_record_count": 1,
            "prior_ledger_record_count": 0,
            "prior_ledger_head": _DIGEST,
            "prior_journal_head": _DIGEST,
            "tail_offset": offset,
            "tail_length": len(raw),
            "captured_file_size": offset + len(raw),
            "removed_bytes_b64": base64.b64encode(raw).decode("ascii"),
            "removed_digest": sha256(raw).hexdigest(),
            "failure_class": "partial-tail",
            "operator_identity": "operator-1",
            "credential_proof_ref": _DIGEST,
            "recovery_code_digest": _DIGEST,
            "host_time": "2026-09-23T03:00:00Z",
            "parent_intent_digest": None,
        }
    )


def _store(
    tmp_path: Path, *, objects: int = 3, bytes_budget: int = 8192
) -> RecoveryEvidenceStoreV2:
    """Select an existing owner-only directory with explicit finite budgets."""
    directory = tmp_path / "evidence"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    return RecoveryEvidenceStoreV2(directory, objects, bytes_budget)


def _journal_object() -> bytes:
    """Build one exact terminal-fragment intent for no-replace publication."""
    raw = b"x"
    offset = len(JOURNAL_MAGIC_V2)
    return validate_journal_tail_intent_v2(
        {
            "domain": "rigor.effect-journal-tail-recovery.v2.1",
            "anchor_file": _identity("/srv/rigor/anchor.bin"),
            "ledger_file": _identity("/srv/rigor/ledger.bin"),
            "journal_file": _identity("/srv/rigor/effect.journal"),
            "selected_anchor_head": _DIGEST,
            "selected_journal_head": _DIGEST,
            "last_complete_journal_head": _DIGEST,
            "old_size": offset + len(raw),
            "frame_offset": offset,
            "declared_payload_length": None,
            "removed_length": len(raw),
            "removed_bytes_b64": base64.b64encode(raw).decode("ascii"),
            "removed_digest": sha256(raw).hexdigest(),
            "failure_class": "partial",
            "operator_identity": "operator-1",
            "credential_proof_ref": _DIGEST,
            "recovery_code_digest": _DIGEST,
            "host_time": "2026-09-23T03:00:00Z",
            "parent_intent_digest": None,
        }
    )


def test_publish_is_immutable_idempotent_and_owner_only(tmp_path: Path) -> None:
    """An exact object survives fsynced publication and repeated lookup."""
    store = _store(tmp_path)
    data = _object()
    digest = sha256(data).hexdigest()
    assert store.publish(data) == digest
    assert store.publish(data) == digest
    assert store.read(digest) == data
    assert store.scan() == {digest: data}
    entry = store.directory / f"{digest}.json"
    assert stat.S_IMODE(entry.stat().st_mode) == 0o600
    assert entry.stat().st_nlink == 1


def test_journal_publication_clears_staging_and_preserves_exact_object(tmp_path: Path) -> None:
    """Journal intent uses a staged no-replace rename before directory fsync."""
    store = _store(tmp_path)
    data = _journal_object()
    digest = store.publish(data)
    assert store.read(digest) == data
    assert [entry.name for entry in store.directory.iterdir()] == [f"{digest}.json"]
    assert (store.directory / f"{digest}.json").stat().st_nlink == 1


def test_journal_publication_refuses_missing_noreplace_syscall(tmp_path: Path) -> None:
    """Real kernel ENOSYS refuses publication and clears its staged object.

    This host libc exports renameat2, so its missing-export AttributeError
    cannot occur here without replacing the library. That guard stays
    uncovered. The nearest real public refusal uses a child-local fd-scoped
    seccomp filter; the child verifies raw ENOSYS and libc's allowed error
    translation, then checks exact cleanup. No userspace library is replaced.
    """
    from test_recovery_evidence_store_errno_real_v2 import _CHILD

    test_directory = Path(__file__).parent
    source = test_directory.parent / "src"
    completed = subprocess.run(
        [sys.executable, "-c", _CHILD, "rename-enosys", str(tmp_path)],
        env={**os.environ, "PYTHONPATH": os.pathsep.join((str(source), str(test_directory)))},
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr


def test_pending_scan_refuses_changed_or_hidden_published_object(tmp_path: Path) -> None:
    """Readers cannot skip a changed digest object or unknown directory entry."""
    store = _store(tmp_path)
    digest = store.publish(_object())
    path = store.directory / f"{digest}.json"
    path.chmod(0o644)
    with pytest.raises(PermissionError, match="custody"):
        store.read(digest)
    path.chmod(0o600)
    path.write_bytes(_object(b"y"))
    with pytest.raises(PermissionError, match="content"):
        store.scan()
    path.write_bytes(_object())
    (store.directory / "unknown").write_text("x", encoding="utf-8")
    with pytest.raises(PermissionError, match="unknown entry"):
        store.scan()


def test_file_symlink_and_extra_hardlink_refuse(tmp_path: Path) -> None:
    """No-follow and one-link checks prevent object substitution."""
    store = _store(tmp_path)
    digest = store.publish(_object())
    path = store.directory / f"{digest}.json"
    os.link(path, store.directory / "duplicate")
    with pytest.raises(PermissionError, match="custody"):
        store.scan()
    (store.directory / "duplicate").unlink()
    path.unlink()
    path.symlink_to(store.directory / "target")
    with pytest.raises(OSError):
        store.scan()


def test_budgets_staging_and_missing_digest(tmp_path: Path) -> None:
    """Staging has no authority and budgets count every directory entry."""
    store = _store(tmp_path, objects=2)
    (store.directory / ".staging-interrupted").write_bytes(b"inert")
    assert store.scan() == {}
    digest = store.publish(_object())
    assert store.read(digest) == _object()
    with pytest.raises(PermissionError, match="budget"):
        store.publish(_object(b"y"))
    with pytest.raises(FileNotFoundError):
        store.read("b" * 64)
    with pytest.raises(ValueError):
        store.read("bad")
    small = RecoveryEvidenceStoreV2(store.directory, 3, len(_object()) - 1)
    with pytest.raises(PermissionError):
        small.scan()


def test_directory_and_invalid_object_refuse_before_publication(tmp_path: Path) -> None:
    """A noncanonical object or unprotected directory cannot enter custody."""
    store = _store(tmp_path)
    with pytest.raises(ValueError):
        store.publish(b"{}")
    assert store.scan() == {}
    store.directory.chmod(0o755)
    with pytest.raises(PermissionError, match="directory"):
        store.scan()
    store.directory.chmod(0o700)
    with pytest.raises(ValueError, match="budgets"):
        RecoveryEvidenceStoreV2(store.directory, 0, 1).scan()


def test_relative_directory_selection_refuses() -> None:
    """A relative directory cannot select immutable recovery evidence custody."""
    with pytest.raises(ValueError, match="absolute"):
        RecoveryEvidenceStoreV2(Path("relative"), 1, 1024).scan()


def test_count_and_aggregate_byte_budgets_refuse(tmp_path: Path) -> None:
    """Many inert entries or individually valid objects cannot bypass selected budgets."""
    store = _store(tmp_path)
    for index in range(4):
        (store.directory / f".staging-{index}").write_bytes(b"inert")
    with pytest.raises(PermissionError, match="entry budget"):
        store.scan()
    for entry in store.directory.iterdir():
        entry.unlink()
    first = _object(b"x")
    second = _object(b"y")
    store.publish(first)
    store.publish(second)
    bounded = RecoveryEvidenceStoreV2(store.directory, 3, max(len(first), len(second)) + 1)
    with pytest.raises(PermissionError, match="byte budget"):
        bounded.scan()
    with pytest.raises(ValueError, match="byte budget"):
        RecoveryEvidenceStoreV2(store.directory, 3, len(first) - 1).publish(first)
