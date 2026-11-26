# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — the v2 durable stores import where POSIX file locks do not exist
"""Prove the v2 durable-store modules import without ``fcntl``, and their locks refuse by name.

The import witness runs in a fresh interpreter, because a module-level ``import fcntl`` has
already run in this one before any test could remove it. It fails on any of the four store
modules that imports ``fcntl`` when it is imported.
"""

from __future__ import annotations

import os
import subprocess
import sys
import types
from pathlib import Path

import pytest

from rigor_foundry._posix_lock_v2 import posix_lock_call

ROOT = Path(__file__).resolve().parents[1]
STORES = (
    "rigor_foundry.effect_journal_v2",
    "rigor_foundry.permit_anchor_store_v2",
    "rigor_foundry.permit_consumption_ledger_v2",
    "rigor_foundry.recovery_evidence_store_v2",
)


def test_the_durable_stores_import_without_fcntl() -> None:
    """Without ``fcntl``, as on Windows, every v2 durable-store module still imports."""
    source = str(ROOT / "src")
    path = os.pathsep.join(item for item in (source, os.environ.get("PYTHONPATH", "")) if item)
    program = "import importlib, sys\nsys.modules['fcntl'] = None\n" + "".join(
        f"importlib.import_module({name!r})\n" for name in STORES
    )
    done = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
        env={**os.environ, "PYTHONPATH": path},
    )
    assert done.returncode == 0, done.stderr


@pytest.mark.parametrize("control", [None, types.ModuleType("fcntl")])
def test_a_lock_without_posix_file_locks_is_refused_by_name(
    monkeypatch: pytest.MonkeyPatch, control: types.ModuleType | None
) -> None:
    """With no ``fcntl``, or one without ``flock``, a lock request is refused before any lock.

    Parameters
    ----------
    monkeypatch : pytest.MonkeyPatch
        Removes ``fcntl`` or its lock call for this test.
    control : types.ModuleType | None
        No ``fcntl`` at all, or a stand-in without ``flock``.
    """
    monkeypatch.setitem(sys.modules, "fcntl", control)
    with pytest.raises(RuntimeError, match="require POSIX advisory file locks"):
        posix_lock_call()


@pytest.mark.parametrize("shared", [False, True])
def test_a_real_posix_lock_is_taken_exclusive_or_shared(tmp_path: Path, shared: bool) -> None:
    """On a POSIX host the returned call takes a real lock that a second attempt observes.

    Parameters
    ----------
    tmp_path : Path
        Owned file allocation.
    shared : bool
        Whether the first lock is shared.
    """
    import fcntl

    path = tmp_path / "lock"
    first = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    second = os.open(path, os.O_RDWR)
    flock, shared_lock, exclusive_lock = posix_lock_call()
    assert (flock, shared_lock, exclusive_lock) == (fcntl.flock, fcntl.LOCK_SH, fcntl.LOCK_EX)
    try:
        flock(first, shared_lock if shared else exclusive_lock)
        with pytest.raises(BlockingIOError):
            fcntl.flock(second, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if shared:
            fcntl.flock(second, fcntl.LOCK_SH | fcntl.LOCK_NB)
    finally:
        os.close(second)
        os.close(first)


def _held(path: Path, *, directory: bool = False) -> int:
    """Open a second descriptor on a store path, to probe the lock another holder has."""
    flags = os.O_RDONLY | (os.O_DIRECTORY if directory else 0)
    return os.open(path, flags)


def _assert_exclusive(probe: int) -> None:
    """Require that a held exclusive lock refuses both shared and exclusive attempts."""
    import fcntl

    for operation in (fcntl.LOCK_SH, fcntl.LOCK_EX):
        with pytest.raises(BlockingIOError):
            fcntl.flock(probe, operation | fcntl.LOCK_NB)


@pytest.mark.parametrize("recovery", [False, True])
def test_the_effect_journal_holds_an_exclusive_lock(tmp_path: Path, recovery: bool) -> None:
    """Both journal leases hold the journal file exclusively while they are open.

    Parameters
    ----------
    tmp_path : Path
        Owned custody allocation.
    recovery : bool
        Whether the recovery lease is taken instead of the ordinary one.
    """
    from rigor_foundry.effect_journal_v2 import EffectJournalStoreV2

    parent = tmp_path / "custody"
    parent.mkdir(mode=0o700)
    store = EffectJournalStoreV2(parent / "effect.journal")
    head = store.initialize()
    lease = store.locked_recovery if recovery else store.locked
    probe = _held(store.path)
    try:
        with lease(selected_head_digest=head, max_bytes=100000):
            _assert_exclusive(probe)
    finally:
        os.close(probe)


def test_the_ledger_and_the_anchor_hold_exclusive_locks(tmp_path: Path) -> None:
    """The consumption ledger and the anchor store each lock their file exclusively.

    Parameters
    ----------
    tmp_path : Path
        Owned custody allocation.
    """
    from test_permit_anchor_store_v2 import _stores

    ledger, _, anchor = _stores(tmp_path)
    for store, path in ((ledger, ledger.path), (anchor, anchor.path)):
        probe = _held(path)
        try:
            with store._locked():
                _assert_exclusive(probe)
        finally:
            os.close(probe)


@pytest.mark.parametrize("exclusive", [True, False])
def test_the_recovery_store_holds_the_lock_kind_it_was_asked_for(
    tmp_path: Path, exclusive: bool
) -> None:
    """An exclusive request excludes every other lock; a shared one admits other readers.

    Parameters
    ----------
    tmp_path : Path
        Owned evidence allocation.
    exclusive : bool
        Whether the store opens its directory for exclusive use.
    """
    import fcntl

    from test_recovery_evidence_store_v2 import _store

    store = _store(tmp_path)
    probe = _held(store.directory, directory=True)
    try:
        with store._opened(exclusive=exclusive):
            if exclusive:
                _assert_exclusive(probe)
            else:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(probe, fcntl.LOCK_SH | fcntl.LOCK_NB)
                fcntl.flock(probe, fcntl.LOCK_UN)
    finally:
        os.close(probe)
