# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native Windows directory enumeration
"""Verify handle-relative directory listings on an actual NTFS volume."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from rigor_foundry.windows_directory_inventory import file_change_token, list_directory_entries
from rigor_foundry.windows_handles import WindowsDirectory

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="requires native NTFS handles")


def test_retained_directory_lists_all_pages_and_restarts(tmp_path: Path) -> None:
    """Recover every native name and match returned IDs to handle-relative opens."""
    root = tmp_path / "native-directory"
    root.mkdir()
    names = {f"record-{index:03}-retained-enumeration.txt" for index in range(650)}
    sample = "súbor-🧪.dat"
    names.add(sample)
    for name in names:
        (root / name).write_bytes(b"test")
    (root / "nested").mkdir()
    with WindowsDirectory(root) as retained:
        entries = {entry.name: entry for entry in retained.list_entries(maximum_entries=652)}
        assert set(entries) == names | {"nested"}
        with retained.open_file(sample) as child:
            assert entries[sample].file_id == child.identity().file_id
            assert child.identity().size == 4
        with retained.open_directory(Path("nested")) as nested:
            assert entries["nested"].file_id == nested.identity[1]
            assert nested.list_entries(maximum_entries=0) == ()
        assert {
            entry.name: entry for entry in retained.list_entries(maximum_entries=652)
        } == entries


def test_retained_listing_observes_membership_changes_and_limits(tmp_path: Path) -> None:
    """A retained read handle permits membership changes and can recheck its entries."""
    root = tmp_path / "native-directory"
    root.mkdir()
    (root / "first").write_bytes(b"one")
    with WindowsDirectory(root) as retained:
        with pytest.raises(ValueError, match="nonnegative"):
            retained.list_entries(maximum_entries=-1)
        initial = retained.list_entries(maximum_entries=1)
        before = retained.change_token()
        (root / "added").write_bytes(b"two")
        with pytest.raises(OverflowError, match="entry limit"):
            retained.list_entries(maximum_entries=1)
        current = retained.list_entries(maximum_entries=2)
        assert retained.change_token() != before
        assert {entry.name for entry in initial} == {"first"}
        assert {entry.name for entry in current} == {"first", "added"}


def test_inspect_exact_child_identity_without_reading_target(tmp_path: Path) -> None:
    """Inspect owned native objects, including the metadata of a junction itself."""
    root = tmp_path / "native-directory"
    root.mkdir()
    target = tmp_path / "controlled-reparse-target"
    target.mkdir()
    (target / "private.txt").write_text("fixture", encoding="utf-8")
    (root / "Plain.dat").write_bytes(b"file")
    junction = root / "directory-link"
    subprocess.run(  # nosec B603
        [os.environ["COMSPEC"], "/d", "/c", "mklink", "/J", str(junction), str(target)],
        check=True,
        capture_output=True,
        shell=False,
    )
    try:
        with WindowsDirectory(root) as retained:
            plain = retained.inspect_child("Plain.dat")
            assert plain.identity.size == 4
            with retained.open_file("Plain.dat") as opened:
                assert opened.identity() == plain.identity
            with pytest.raises(FileNotFoundError):
                retained.inspect_child("absent.dat")
            with pytest.raises(ValueError, match="retained parent and name"):
                retained.inspect_child("plain.dat")
            link = retained.inspect_child("directory-link")
            assert link.identity.attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
            with WindowsDirectory(target) as opened_target:
                assert link.identity.file_id != opened_target.identity[1]
    finally:
        junction.rmdir()


def test_native_queries_refuse_wrong_kind_and_closed_handles(tmp_path: Path) -> None:
    """Preserve actual Windows errors for a file listing and a closed metadata handle."""
    (tmp_path / "entry").write_bytes(b"test")
    with WindowsDirectory(tmp_path) as retained:
        with retained.open_file("entry") as file:
            borrowed = file.handle
            with pytest.raises(OSError):
                list_directory_entries(borrowed, maximum_entries=1)
        with pytest.raises(OSError):
            file_change_token(borrowed)
