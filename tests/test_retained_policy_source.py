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

from rigor_foundry.git_inventory import StableReadError
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.retained_policy_source import RetainedPolicySource


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
