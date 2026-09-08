# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — discovery source validation
"""Verify actual filesystem and hostile serialization refusal boundaries."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from discovery_source_support import cli, limits, records, sha, snapshot, write_manifest

from rigor_foundry.discovery_source_schema import DiscoveryReadError, DiscoveryValidationError
from rigor_foundry.discovery_source_validation import validate_discovery_sources


@pytest.mark.parametrize(
    "payload",
    [
        b'{"status":"a","status":"b"}',
        b'{"x":{"key":1,"key":2}}',
        b'{"x":"a","\\u0078":"b"}',
        b"NaN",
        b"Infinity",
        b"-Infinity",
        b"[",
        b"{} trailing",
        b"\xef\xbb\xbf{}",
        b"\xff",
        b"[]",
        b"[" * 17 + b"0" + b"]" * 17,
        b'{"x":' + b"9" * 5000 + b"}",
    ],
    ids=[
        "duplicate",
        "nested-duplicate",
        "escaped-duplicate",
        "nan",
        "infinity",
        "negative-infinity",
        "truncated",
        "trailing",
        "bom",
        "invalid-utf8",
        "array",
        "depth",
        "oversized-integer",
    ],
)
def test_strict_json(tmp_path: Path, payload: bytes) -> None:
    """Reject real malformed, duplicated, non-finite or overdeep capture bytes."""
    snapshot(tmp_path)
    (tmp_path / "manifest.json").write_bytes(payload)
    with pytest.raises(DiscoveryValidationError):
        validate_discovery_sources(tmp_path, "manifest.json", limits=limits(tmp_path))


def test_invalid_source_utf8(tmp_path: Path) -> None:
    """Refuse undecodable source bytes even when their recorded hash is correct."""
    manifest = snapshot(tmp_path)
    payload = b"\xff\n"
    (tmp_path / "source0.txt").write_bytes(payload)
    records(manifest, "sources")[0].update(bytes=len(payload), sha256=sha(payload), lines=1)
    write_manifest(tmp_path, manifest)
    with pytest.raises(DiscoveryValidationError, match="invalid-utf8"):
        validate_discovery_sources(tmp_path, "manifest.json", limits=limits(tmp_path))


@pytest.mark.parametrize("kind", ["symlink-file", "hardlink", "directory", "missing", "fifo"])
def test_capture_file_types(tmp_path: Path, kind: str) -> None:
    """Reject real special files promptly, without following or modifying targets."""
    snapshot(tmp_path)
    budget = limits(tmp_path)
    path = tmp_path / "source0.txt"
    original = path.read_bytes()
    path.unlink()
    canary = tmp_path / "canary"
    canary.write_bytes(original)
    if kind == "symlink-file":
        path.symlink_to(canary)
    elif kind == "hardlink":
        os.link(canary, path)
    elif kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        os.mkfifo(path)
    result = cli(tmp_path, budget)
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "discovery-error:capture-read-failed\n"
    assert canary.read_bytes() == original
    if kind != "fifo":
        with pytest.raises(DiscoveryReadError):
            validate_discovery_sources(tmp_path, "manifest.json", limits=budget)


@pytest.mark.parametrize("kind", ["symlink-root", "symlink-parent", "missing-root"])
def test_root_refusal(tmp_path: Path, kind: str) -> None:
    """Reject missing roots and symlinks at both leaf and parent components."""
    root = tmp_path / "real"
    root.mkdir()
    snapshot(root)
    budget = limits(root)
    if kind == "symlink-root":
        target = tmp_path / "alias"
        target.symlink_to(root, target_is_directory=True)
    elif kind == "symlink-parent":
        alias = tmp_path / "alias"
        alias.symlink_to(tmp_path, target_is_directory=True)
        target = alias / "real"
    else:
        target = tmp_path / "missing"
    with pytest.raises(DiscoveryReadError, match="capture-root-unavailable"):
        validate_discovery_sources(target, "manifest.json", limits=budget)


@pytest.mark.parametrize("root", [Path("relative"), Path("/tmp/../bad"), Path("/invalid\0root")])
def test_invalid_root_syntax(tmp_path: Path, root: Path) -> None:
    """Reject implicit cwd, lexical parent traversal and NUL before filesystem I/O."""
    snapshot(tmp_path)
    with pytest.raises(DiscoveryValidationError, match="invalid-root"):
        validate_discovery_sources(root, "manifest.json", limits=limits(tmp_path))


def test_descriptors_closed_after_failure(tmp_path: Path) -> None:
    """Check real descriptor counts after repeated malformed-input refusals."""
    snapshot(tmp_path)
    budget = limits(tmp_path)
    (tmp_path / "manifest.json").write_bytes(b"{")
    before = set(Path("/proc/self/fd").iterdir())
    for _ in range(12):
        with pytest.raises(DiscoveryValidationError):
            validate_discovery_sources(tmp_path, "manifest.json", limits=budget)
    assert set(Path("/proc/self/fd").iterdir()) == before
