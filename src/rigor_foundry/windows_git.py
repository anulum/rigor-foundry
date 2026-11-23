# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — pinned native Windows Git execution
"""Bind Git image bytes and native identity across a bounded owned process."""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path
from typing import TypeAlias

from .windows_handles import WindowsDirectory, WindowsFile
from .windows_process import run_windows_process

WindowsGitSnapshot: TypeAlias = tuple[int, int, int, int, int, int, int, str]


def _snapshot(image: WindowsFile) -> WindowsGitSnapshot:
    """Hash one already retained single-link image without trusting CRT synthetic modes."""
    before = image.identity()
    if before.links != 1:
        raise RuntimeError("trusted Git executable must have exactly one hard link")
    os.lseek(image.descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    count = 0
    # Each read asks for at most the bytes left plus one, so count never passes
    # before.size + 1. At that count the next read asks for zero bytes and ends
    # the loop, and the size and identity check below refuses the growth.
    while True:
        chunk = os.read(image.descriptor, min(1024 * 1024, before.size - count + 1))
        if not chunk:
            break
        count += len(chunk)
        digest.update(chunk)
    if count != before.size or image.identity() != before:
        raise RuntimeError("trusted Git executable changed while hashing")
    os.lseek(image.descriptor, 0, os.SEEK_SET)
    return (
        before.volume,
        before.file_id,
        before.attributes,
        before.links,
        before.size,
        before.written * 100,
        before.created * 100,
        digest.hexdigest(),
    )


def snapshot_windows_git(path: Path) -> WindowsGitSnapshot:
    """Capture native object identity and the SHA-256 of an actual retained Git image.

    Parameters
    ----------
    path : Path
        Explicit absolute executable selected by the operator's Git trust policy.

    Returns
    -------
    tuple[int, int, int, int, int, int, int, str]
        Volume, file identity, native attributes, links, size, write/creation times
        in nanoseconds since the Windows epoch, and exact image SHA-256.

    Raises
    ------
    OSError, ValueError, RuntimeError
        If no-reparse object ownership, single-link policy or exact identity fails.
    """
    with WindowsDirectory(path.parent) as parent, parent.open_file(path.name) as image:
        return _snapshot(image)


def run_windows_git(
    path: Path,
    arguments: tuple[str, ...],
    *,
    expected_snapshot: WindowsGitSnapshot,
    environment: dict[str, str],
    cwd: Path,
    timeout_seconds: int,
    output_limit: int,
) -> subprocess.CompletedProcess[bytes]:
    """Run the exact previously captured image while retaining its real native resources.

    Parameters
    ----------
    path : Path
        Explicit selected executable, without ambient search.
    arguments : tuple[str, ...]
        Literal Git arguments, guarded by the semantic Git runner.
    expected_snapshot : tuple[int, int, int, int, int, int, int, str]
        Exact native snapshot from the same runner's initial provenance capture.
    environment : dict[str, str]
        Complete deterministic credential-free Git environment.
    cwd : Path
        Explicit Git working directory.
    timeout_seconds : int
        Positive complete-operation deadline.
    output_limit : int
        Positive aggregate raw-stream byte ceiling.

    Returns
    -------
    subprocess.CompletedProcess[bytes]
        Actual exit status and bounded streams after observed owned-process settlement.

    Raises
    ------
    OSError, ValueError, RuntimeError, TimeoutError
        If image binding, native execution, bounds or completed cleanup fail.
    """
    with WindowsDirectory(path.parent) as parent, parent.open_file(path.name) as image:
        if _snapshot(image) != expected_snapshot:
            raise RuntimeError("trusted Git executable was replaced after provenance capture")
        result = run_windows_process(
            path,
            arguments,
            image_handle=image.handle,
            cwd=cwd,
            environment=environment,
            timeout_seconds=timeout_seconds,
            output_limit=output_limit,
        )
        if _snapshot(image) != expected_snapshot:
            raise RuntimeError("trusted Git executable changed during execution")
        return subprocess.CompletedProcess(
            [str(path), *arguments], result[0], result[1], result[2]
        )
