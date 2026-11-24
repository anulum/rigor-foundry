# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — original policy byte lifetime tests
"""Exercise real retained files, no-follow reads and actual closing boundaries."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import cast

import pytest
from test_context_owner_implementation import implementation_budget

from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.retained_policy_source import (
    RetainedPolicySource,
    directory_entry_digest,
    parent_directory_identity,
)
from rigor_foundry.stable_reads import StableReadError, open_directory_no_follow


def retained(path: Path, payload: bytes, **changes: int) -> RetainedPolicySource:
    """Select actual original bytes with explicit complete count and hash."""
    return RetainedPolicySource(
        path,
        byte_digest=hashlib.sha256(payload).hexdigest(),
        byte_count=len(payload),
        budget=implementation_budget(**changes),
    )


@pytest.mark.parametrize("payload", [b"", b"First\r\n\x00\xffLast\n", "Živý source".encode()])
def test_exact_original_bytes_and_distinct_real_selection_lifetimes(
    tmp_path: Path, payload: bytes
) -> None:
    """No decode/newline conversion occurs and reopening creates a distinct held selection."""
    path = tmp_path / "original.bin"
    path.write_bytes(payload)
    before = len(os.listdir("/proc/self/fd"))
    with retained(path, payload) as first, retained(path, payload) as second:
        assert first.path == path
        assert first.read() == second.read() == payload
        assert first.snapshot_id != second.snapshot_id
        assert first.snapshot_id == first.snapshot_id
    assert len(os.listdir("/proc/self/fd")) == before
    first.close()
    for operation in (first.read, lambda: first.path, lambda: first.snapshot_id, first.__enter__):
        with pytest.raises(ValueError, match="closed"):
            operation()


@pytest.mark.parametrize("case", ["edit", "mode", "parent-entry", "replace-parent"])
def test_actual_source_or_parent_change_refuses_and_close_releases(
    tmp_path: Path, case: str
) -> None:
    """Changed real byte/inode/parent state cannot reuse an earlier retained proof."""
    root = tmp_path / "source"
    root.mkdir()
    path = root / "original.bin"
    path.write_bytes(b"original")
    before = len(os.listdir("/proc/self/fd"))
    source = retained(path, b"original")
    if case == "edit":
        path.write_bytes(b"different")
    elif case == "mode":
        path.chmod(0o400)
    elif case == "parent-entry":
        (root / "added").write_bytes(b"new directory state")
    else:
        root.rename(tmp_path / "old-source")
        root.mkdir()
        path.write_bytes(b"original")
    with pytest.raises(ValueError, match="identity changed"):
        source.read()
    with pytest.raises(ValueError, match="identity changed"):
        source.close()
    source.close()
    assert len(os.listdir("/proc/self/fd")) == before


@pytest.mark.parametrize(
    "case",
    ["symlink", "symlink-parent", "hardlink", "fifo", "directory", "missing", "missing-parent"],
)
def test_unsupported_real_selections_refuse_without_descriptor_leak(
    tmp_path: Path, case: str
) -> None:
    """Concrete host files cannot bypass regular/single-link/no-follow selection rules."""
    path = tmp_path / "original"
    if case == "symlink":
        target = tmp_path / "target"
        target.write_bytes(b"original")
        path.symlink_to(target)
    elif case == "symlink-parent":
        target = tmp_path / "target"
        target.mkdir()
        (target / "original").write_bytes(b"original")
        alias = tmp_path / "alias"
        alias.symlink_to(target, target_is_directory=True)
        path = alias / "original"
    elif case == "hardlink":
        path.write_bytes(b"original")
        os.link(path, tmp_path / "alias")
    elif case == "fifo":
        os.mkfifo(path)
    elif case == "directory":
        path.mkdir()
    elif case == "missing-parent":
        path = tmp_path / "missing" / "original"
    before = len(os.listdir("/proc/self/fd"))
    with pytest.raises((ValueError, OSError)):
        retained(path, b"original")
    assert len(os.listdir("/proc/self/fd")) == before


def test_exact_original_count_digest_and_explicit_limits_refuse(tmp_path: Path) -> None:
    """A supplied label/hash or too-small budget cannot replace actual complete bytes."""
    path = tmp_path / "original"
    path.write_bytes(b"original")
    for expected in (b"otherone", b"original-extra"):
        with pytest.raises(ValueError, match="selected original bytes"):
            retained(path, expected)
    with pytest.raises(ValueError, match="byte budget"):
        retained(path, b"original", max_source_bytes=1)
    with pytest.raises(StableReadError):
        retained(path, b"x", max_source_bytes=1)
    with pytest.raises(ValueError, match="budget is required"):
        RetainedPolicySource(
            path, byte_digest="a" * 64, byte_count=8, budget=cast(PolicyReadBudget1, {})
        )
    for count in (-1, True):
        with pytest.raises(ValueError):
            RetainedPolicySource(
                path, byte_digest="a" * 64, byte_count=count, budget=implementation_budget()
            )
    with pytest.raises(ValueError):
        RetainedPolicySource(
            path, byte_digest="invalid", byte_count=8, budget=implementation_budget()
        )


_STAT_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_uid",
    "st_gid",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


def _change_sibling(root: Path, change: str) -> None:
    """Change one directory entry beside the retained source without touching the source."""
    if change == "added":
        (root / "added").write_bytes(b"new directory state")
    elif change == "removed":
        (root / "sibling").unlink()
    else:
        replacement = root / "replacement"
        replacement.write_bytes(b"sibling")
        replacement.replace(root / "sibling")


@pytest.mark.parametrize("change", ["added", "removed", "replaced"])
def test_every_sibling_entry_change_refuses_even_within_one_clock_tick(
    tmp_path: Path, change: str
) -> None:
    """An entry change right after selection refuses on every attempt, whatever the clock grain.

    A coarse directory timestamp can leave every parent ``stat`` field unchanged when an entry
    changes in the same clock tick as the selection. A replaced sibling keeps the same names.
    The bound entry list still differs, so each of the attempts must refuse.

    Parameters
    ----------
    tmp_path : Path
        Owned real directories, one per attempt.
    change : str
        The entry added, removed, or replaced under the same name.
    """
    for attempt in range(64):
        root = tmp_path / f"source-{attempt}"
        root.mkdir()
        (root / "sibling").write_bytes(b"sibling")
        path = root / "original.bin"
        path.write_bytes(b"original")
        source = retained(path, b"original")
        _change_sibling(root, change)
        with pytest.raises(ValueError, match="policy source directory identity changed"):
            source.read()
        with pytest.raises(ValueError, match="identity changed"):
            source.close()
        source.close()


def test_parent_identity_binds_metadata_and_entry_names_and_inodes(tmp_path: Path) -> None:
    """The parent identity is equal through any descriptor and changes with any name or inode.

    Parameters
    ----------
    tmp_path : Path
        Owned real directory.
    """
    root = tmp_path / "directory"
    root.mkdir()
    (root / "a").write_bytes(b"a")
    first = open_directory_no_follow(root)
    second = open_directory_no_follow(root)
    try:
        before = directory_entry_digest(first)
        assert directory_entry_digest(second) == before == directory_entry_digest(first)
        identity = parent_directory_identity(first)
        assert identity == parent_directory_identity(second)
        assert identity[-1] == before
        assert identity[:-1] == (*(getattr(os.fstat(first), field) for field in _STAT_FIELDS),)
        replacement = root / "b"
        replacement.write_bytes(b"a")
        assert directory_entry_digest(first) != before
        replacement.replace(root / "a")
        replaced = directory_entry_digest(second)
        assert replaced != before
        with os.scandir(root) as entries:
            (entry,) = list(entries)
        expected = hashlib.sha256(
            (1).to_bytes(8, "big") + b"a" + entry.inode().to_bytes(8, "big")
        ).hexdigest()
        assert replaced == expected
        assert parent_directory_identity(first)[-1] == replaced
    finally:
        os.close(first)
        os.close(second)
