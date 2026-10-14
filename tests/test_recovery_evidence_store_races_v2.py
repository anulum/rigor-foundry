# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real immutable recovery evidence races
"""Exercise public evidence publication and scan against concurrent file changes."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from threading import Event, Thread
from types import FrameType

import pytest
from test_recovery_evidence_store_v2 import _journal_object, _object, _store

import rigor_foundry.recovery_evidence_store_v2 as evidence


@contextmanager
def _filesystem_change(
    action: Callable[[], None], match: Callable[[FrameType, str, object], bool]
) -> Iterator[None]:
    """Synchronize one real filesystem writer at an unpatched observation boundary."""
    started = Event()
    finished = Event()
    stopped = Event()
    errors: list[BaseException] = []
    reached = False
    previous = sys.getprofile()

    def mutate() -> None:
        """Perform the competing operation once the public operation reaches it."""
        if not started.wait(5) or stopped.is_set():
            return
        try:
            action()
        except BaseException as exc:
            errors.append(exc)
        finally:
            finished.set()

    def observe(frame: FrameType, event: str, arg: object) -> None:
        """Observe timing without changing production code, results or exceptions."""
        nonlocal reached
        if not reached and match(frame, event, arg):
            reached = True
            started.set()
            assert finished.wait(5), "filesystem mutation timed out"
            assert not errors, errors

    worker = Thread(target=mutate)
    worker.start()
    sys.setprofile(observe)
    try:
        yield
    finally:
        sys.setprofile(previous)
        stopped.set()
        started.set()
        worker.join(5)
        assert not worker.is_alive(), "filesystem worker did not terminate"
        assert reached, "public operation did not reach its observation boundary"
        assert not errors, errors


def test_journal_publication_refuses_competing_destination(tmp_path: Path) -> None:
    """Actual RENAME_NOREPLACE refuses an outside writer's competing destination."""
    store = _store(tmp_path)
    data = _journal_object()
    destination = store.directory / f"{sha256(data).hexdigest()}.json"

    def compete() -> None:
        """Create a real competing inode before the unpatched no-replace syscall."""
        destination.write_bytes(b"competing bytes")

    def before_rename(frame: FrameType, event: str, arg: object) -> bool:
        """Identify entry into the actual publication helper without calling it."""
        return frame.f_code is evidence._rename_noreplace.__code__ and event == "call"

    with _filesystem_change(compete, before_rename), pytest.raises(FileExistsError):
        store.publish(data)
    assert destination.read_bytes() == b"competing bytes"
    assert all(not entry.name.startswith(".staging-") for entry in store.directory.iterdir())


def test_journal_publication_detects_changed_object_after_rename(tmp_path: Path) -> None:
    """A real same-inode rewrite after rename invalidates public publication."""
    store = _store(tmp_path)
    data = _journal_object()
    destination = store.directory / f"{sha256(data).hexdigest()}.json"

    def rewrite() -> None:
        """Rewrite and fsync the published inode from an independent writer thread."""
        with destination.open("r+b") as writer:
            writer.write(b"!")
            writer.flush()
            os.fsync(writer.fileno())

    def after_rename(frame: FrameType, event: str, arg: object) -> bool:
        """Observe return after the actual kernel rename completed."""
        return frame.f_code is evidence._rename_noreplace.__code__ and event == "return"

    with (
        _filesystem_change(rewrite, after_rename),
        pytest.raises(PermissionError, match="content or identity changed"),
    ):
        store.publish(data)
    with pytest.raises(PermissionError, match="content or identity changed"):
        store.scan()
    assert all(not entry.name.startswith(".staging-") for entry in store.directory.iterdir())


def test_directory_change_during_scan_refuses(tmp_path: Path) -> None:
    """A real newly added entry after a value read invalidates scan enumeration."""
    store = _store(tmp_path)
    digest = store.publish(_object())

    def add_entry() -> None:
        """Publish an inert staging file while the public scan is in progress."""
        (store.directory / ".staging-late").write_bytes(b"inert")

    def after_read(frame: FrameType, event: str, arg: object) -> bool:
        """Observe completion of the unmodified object's real read."""
        return (
            frame.f_code is evidence.RecoveryEvidenceStoreV2._read.__code__ and event == "return"
        )

    with (
        _filesystem_change(add_entry, after_read),
        pytest.raises(PermissionError, match="changed during scan"),
    ):
        store.scan()
    assert store.read(digest) == _object()


def test_directory_path_swap_refuses_public_scan(tmp_path: Path) -> None:
    """A held old directory cannot authorise its newly substituted pathname."""
    store = _store(tmp_path)
    digest = store.publish(_object())
    old = tmp_path / "old-evidence"

    def replace_directory() -> None:
        """Move the actual directory and install a new owner-only inode at its path."""
        store.directory.rename(old)
        store.directory.mkdir(mode=0o700)
        store.directory.chmod(0o700)

    def before_enumeration(frame: FrameType, event: str, arg: object) -> bool:
        """Observe the first real directory enumeration in the public scan."""
        return (
            frame.f_code is evidence.RecoveryEvidenceStoreV2._names.__code__
            and event == "c_call"
            and arg is os.scandir
        )

    with (
        _filesystem_change(replace_directory, before_enumeration),
        pytest.raises(PermissionError, match="identity changed"),
    ):
        store.scan()
    assert (old / f"{digest}.json").read_bytes() == _object()
    assert list(store.directory.iterdir()) == []
