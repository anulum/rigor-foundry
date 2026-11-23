# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Windows ignored inventory lifecycle
"""Verify native bounds and scanner responses to real changes in owned NTFS inputs."""

from __future__ import annotations

import csv
import ctypes
import os
import subprocess
import sys
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from ctypes import wintypes
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry import scan_repository
from rigor_foundry.git_provenance import GitTrustPolicy
from rigor_foundry.ignored_inventory import IgnoredCapture, IgnoredInventoryEvidence, IgnoredReason
from rigor_foundry.windows_abi import windows_library
from rigor_foundry.windows_directory_inventory import WindowsDirectoryEntry
from rigor_foundry.windows_handles import (
    WindowsChildSnapshot,
    WindowsDirectory,
    WindowsFile,
    _IoStatus,
    _ObjectAttributes,
    _UnicodeString,
)

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="requires native NTFS handles")


def _repository(
    root: Path, path: str, capture: IgnoredCapture
) -> tuple[GitRepository, GitTrustPolicy]:
    """Prepare one tracked Git anchor and one explicit ignored declaration."""
    repository = GitRepository.create(root)
    repository.git_command("config", "core.autocrlf", "false")
    repository.write_text("src/pkg/value.py", "VALUE = 1\n")
    repository.write_policy(
        ignored_inventory=[{"evidence_id": "state", "path": path, "capture": capture}]
    )
    repository.commit()
    git = Path(repository.git)
    return repository, GitTrustPolicy(
        executable=git.as_posix(), trusted_roots=(git.parent.as_posix(),)
    )


def _observe(repository: GitRepository, trust: GitTrustPolicy) -> IgnoredInventoryEvidence:
    """Read the public scanner's sole declared ignored observation."""
    return scan_repository(repository.root, git_trust_policy=trust).ignored_inventory_evidence[0]


def _assert_unavailable(evidence: IgnoredInventoryEvidence, reason: IgnoredReason) -> None:
    """Require the specified finite refusal with no retained payload information."""
    assert (evidence.status, evidence.reason) == ("unavailable", reason)
    assert evidence.byte_size is None and evidence.content_sha256 is None


@pytest.fixture
def acl_principal() -> str:
    """Resolve the current account's isolated fixture DACL principal."""
    whoami = Path(os.environ["SYSTEMROOT"]) / "System32" / "whoami.exe"
    completed = subprocess.run(
        [str(whoami), "/user", "/fo", "csv", "/nh"],
        capture_output=True,
        check=True,
        text=True,
    )
    sid = next(csv.reader(completed.stdout.splitlines()))[-1]
    assert sid.startswith("S-1-")
    return "*" + sid


def _set_acl(path: Path, *arguments: str) -> None:
    """Apply an actual Windows ACL operation to one disposable fixture object."""
    icacls = Path(os.environ["SYSTEMROOT"]) / "System32" / "icacls.exe"
    result = subprocess.run([str(icacls), str(path), *arguments], check=False, capture_output=True)
    assert result.returncode == 0


def _delete_denied_directory(path: Path) -> None:
    """Delete one empty directory with a native open that requests only deletion.

    Win32 removal also requests the synchronise and read-attribute rights, which a
    read-and-execute denial removes. A delete-on-close open asks for nothing else,
    and deletion is not among the denied rights.
    """
    library = windows_library("ntdll")
    library.NtOpenFile.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.ULONG,
        ctypes.POINTER(_ObjectAttributes),
        ctypes.POINTER(_IoStatus),
        wintypes.ULONG,
        wintypes.ULONG,
    ]
    library.NtOpenFile.restype = wintypes.LONG
    library.NtClose.argtypes = [wintypes.HANDLE]
    library.NtClose.restype = wintypes.LONG
    name = "\\??\\" + str(path)
    buffer = ctypes.create_unicode_buffer(name)
    length = len(name.encode("utf-16-le"))
    string = _UnicodeString(length, length + 2, ctypes.cast(buffer, wintypes.LPWSTR))
    attributes = _ObjectAttributes(
        ctypes.sizeof(_ObjectAttributes), None, ctypes.pointer(string), 0x40, None, None
    )
    handle = wintypes.HANDLE()
    # DELETE; share read, write and delete; directory, delete on close, no reparse.
    status = library.NtOpenFile(
        ctypes.byref(handle),
        0x00010000,
        ctypes.byref(attributes),
        ctypes.byref(_IoStatus()),
        0x7,
        0x1 | 0x1000 | 0x200000,
    )
    assert status >= 0, hex(status & 0xFFFFFFFF)
    assert library.NtClose(handle) >= 0
    assert not path.exists()


@contextmanager
def _deny_data_reads(path: Path, principal: str) -> Iterator[None]:
    """Deny data and attribute reads while retaining normal DACL restoration."""
    _set_acl(path, "/deny", f"{principal}:(RA,RD)")
    try:
        yield
    finally:
        _set_acl(path, "/remove:d", principal)


@pytest.mark.parametrize("boundary", ["depth", "entries"])
def test_real_native_directory_limits(tmp_path: Path, boundary: str) -> None:
    """Exercise the configured depth and entry ceilings with actual NTFS trees."""
    repository, trust = _repository(tmp_path / "repository", ".rigor/tree", "directory-sha256")
    tree = repository.root / ".rigor/tree"
    if boundary == "depth":
        tree.joinpath(*("d",) * 65).mkdir(parents=True)
    else:
        tree.mkdir(parents=True)
        for index in range(10_001):
            (tree / f"{index}.dat").touch()
    _assert_unavailable(_observe(repository, trust), "limit-exceeded")


@pytest.mark.parametrize("recreate", [False, True])
def test_removed_or_recreated_native_directory_refuses_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recreate: bool
) -> None:
    """Reject both a disappeared parent and a directory whose identity has changed."""
    path = ".rigor/volatile" if recreate else ".rigor/volatile/value"
    repository, trust = _repository(tmp_path / "repository", path, "presence")
    directory = repository.root / ".rigor/volatile"
    directory.mkdir(parents=True)
    inspect = WindowsDirectory.inspect_child
    with monkeypatch.context() as scoped:

        def change_after_inspection(owner: WindowsDirectory, name: str) -> WindowsChildSnapshot:
            """Obtain the genuine metadata before the fixture's normal removal."""
            snapshot = inspect(owner, name)
            if owner.path == directory.parent and name == directory.name:
                scoped.setattr(WindowsDirectory, "inspect_child", inspect)
                directory.rmdir()
                if recreate:
                    directory.mkdir()
            return snapshot

        scoped.setattr(WindowsDirectory, "inspect_child", change_after_inspection)
        _assert_unavailable(_observe(repository, trust), "changed-while-read")
    recovered = _observe(repository, trust)
    assert recovered.reason == ("observed" if recreate else "missing-parent")


@pytest.mark.parametrize("replace_on_capture", [True, False])
def test_changed_directory_membership_refuses_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replace_on_capture: bool
) -> None:
    """Check entry identities during capture and equal-count membership at final validation."""
    repository, trust = _repository(tmp_path / "repository", ".rigor/tree", "directory-sha256")
    original = repository.write_bytes(".rigor/tree/value", b"initial data")
    replacing = original if replace_on_capture else original.with_name("new")
    enumerate_entries = WindowsDirectory.list_entries
    calls = 0

    def replace_entry() -> None:
        """Replace fixture bytes with normal Windows file operations."""
        original.unlink()
        replacing.write_bytes(b"new fixture data")

    with monkeypatch.context() as scoped:

        def enumerate_with_fixture_change(
            owner: WindowsDirectory, *, maximum_entries: int
        ) -> tuple[WindowsDirectoryEntry, ...]:
            """Return real directory pages and act at the selected observation boundary."""
            nonlocal calls
            assert owner.path == original.parent
            calls += 1
            if not replace_on_capture and calls == 2:
                replace_entry()
            entries = enumerate_entries(owner, maximum_entries=maximum_entries)
            if replace_on_capture and calls == 1:
                replace_entry()
            return entries

        scoped.setattr(WindowsDirectory, "list_entries", enumerate_with_fixture_change)
        _assert_unavailable(_observe(repository, trust), "changed-while-read")
    assert replacing.read_bytes() == b"new fixture data"
    assert _observe(repository, trust).status == "observed"


def test_real_directory_timestamp_change_before_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Detect a directory generation change even when its names and contents agree."""
    repository, trust = _repository(tmp_path / "repository", ".rigor/tree", "directory-sha256")
    path = repository.write_bytes(".rigor/tree/value", b"current data")
    tree = path.parent
    previous = tree.stat()
    first = _observe(repository, trust)
    enumerate_entries = WindowsDirectory.list_entries
    calls = 0

    def change_before_final_listing(
        owner: WindowsDirectory, *, maximum_entries: int
    ) -> tuple[WindowsDirectoryEntry, ...]:
        """Change only real directory metadata before the scanner's second listing."""
        nonlocal calls
        assert owner.path == tree
        calls += 1
        if calls == 2:
            os.utime(tree, ns=(previous.st_atime_ns, previous.st_mtime_ns + 2_000_000_000))
        return enumerate_entries(owner, maximum_entries=maximum_entries)

    with monkeypatch.context() as scoped:
        scoped.setattr(WindowsDirectory, "list_entries", change_before_final_listing)
        _assert_unavailable(_observe(repository, trust), "changed-while-read")
    assert calls == 2 and tree.stat().st_mtime_ns != previous.st_mtime_ns
    assert _observe(repository, trust).content_sha256 == first.content_sha256


@pytest.mark.parametrize("inside_tree", [False, True])
def test_unreadable_ntfs_entry_has_no_digest(
    tmp_path: Path, acl_principal: str, inside_tree: bool
) -> None:
    """Preserve native lookup denial for a declared parent or a file inside a tree.

    The denied read rights include the right to read the access list, so the denial
    cannot be reliably removed again. A denied file is deleted by the allocation cleanup
    through its parent. A denied parent cannot be listed by that cleanup, so the case
    deletes its own file by name and the parent with a delete-only native open.
    """
    with TemporaryDirectory(dir=tmp_path) as allocation:
        root = Path(allocation) / "repository"
        if inside_tree:
            repository, trust = _repository(root, ".rigor/tree", "directory-sha256")
            denied = repository.write_bytes(".rigor/tree/value", b"owned input")
            reason: IgnoredReason = "inaccessible"
        else:
            repository, trust = _repository(root, ".rigor/parent/value", "presence")
            denied = repository.write_bytes(".rigor/parent/value", b"owned input").parent
            reason = "inaccessible-parent"
        assert _observe(repository, trust).status == "observed"
        _set_acl(denied, "/deny", f"{acl_principal}:(RX)")
        try:
            _assert_unavailable(_observe(repository, trust), reason)
        finally:
            if not inside_tree:
                (denied / "value").unlink()
                _delete_denied_directory(denied)


def test_parent_access_changed_after_git_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, acl_principal: str
) -> None:
    """Invalidate a previously admitted parent when access changes before capture."""
    repository, trust = _repository(tmp_path / "repository", ".rigor/parent/value", "file-sha256")
    path = repository.write_bytes(".rigor/parent/value", b"controlled data")
    original = _observe(repository, trust)
    close = WindowsDirectory.close
    with ExitStack() as changed, monkeypatch.context() as scoped:

        def deny_after_closing(owner: WindowsDirectory) -> None:
            """Deny read data after the genuine first parent handle release."""
            close(owner)
            if owner.path == path.parent:
                scoped.setattr(WindowsDirectory, "close", close)
                changed.enter_context(_deny_data_reads(path.parent, acl_principal))

        scoped.setattr(WindowsDirectory, "close", deny_after_closing)
        _assert_unavailable(_observe(repository, trust), "changed-while-read")
    assert _observe(repository, trust) == original


@pytest.mark.parametrize("deny_access", [False, True])
def test_root_revalidation_refuses_a_changed_native_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, acl_principal: str, deny_access: bool
) -> None:
    """Reject both root identity drift and a root that cannot be reopened."""
    repository, trust = _repository(tmp_path / "repository", ".rigor/value", "file-sha256")
    original = repository.write_bytes(".rigor/value", b"controlled data")
    extra = repository.root / "new-root-entry"
    baseline = _observe(repository, trust)
    close = WindowsDirectory.close
    parent_releases = 0
    with ExitStack() as changed, monkeypatch.context() as scoped:

        def change_root_before_reopening(owner: WindowsDirectory) -> None:
            """Change only the owned root after the actual data observation closes."""
            nonlocal parent_releases
            close(owner)
            if owner.path == original.parent:
                parent_releases += 1
                if parent_releases == 2:
                    if deny_access:
                        changed.enter_context(_deny_data_reads(repository.root, acl_principal))
                    else:
                        extra.write_bytes(b"new root membership")
                        changed.callback(extra.unlink)

        scoped.setattr(WindowsDirectory, "close", change_root_before_reopening)
        with pytest.raises(RuntimeError, match="repository root changed"):
            _observe(repository, trust)
    assert parent_releases == 2 and _observe(repository, trust) == baseline


@pytest.mark.parametrize("release_parent", [False, True])
def test_parent_mutation_or_release_during_presence_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, release_parent: bool
) -> None:
    """Refuse evidence when a retained parent changes or ceases to be usable."""
    repository, trust = _repository(tmp_path / "repository", ".rigor/value", "presence")
    original = repository.write_bytes(".rigor/value", b"controlled data")
    extra = original.with_name("new-sibling")
    baseline = _observe(repository, trust)
    open_file = WindowsDirectory.open_file
    with monkeypatch.context() as scoped:

        def change_bound_resource(
            owner: WindowsDirectory, name: str, *, create: bool = False, private: bool = True
        ) -> WindowsFile:
            """Use the normal native operation after a genuine fixture change."""
            if owner.path == original.parent and name == original.name:
                if release_parent:
                    owner.close()
                else:
                    extra.write_bytes(b"new sibling")
            return open_file(owner, name, create=create, private=private)

        scoped.setattr(WindowsDirectory, "open_file", change_bound_resource)
        _assert_unavailable(_observe(repository, trust), "changed-while-read")
    assert _observe(repository, trust) == baseline
