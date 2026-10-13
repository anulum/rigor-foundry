# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real Linux no-follow descriptor tests
"""Exercise protected path opening against real files and hostile entries."""

from __future__ import annotations

import errno
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from rigor_foundry.tier0_builtin.linux_openat2_v2 import (
    MAX_EXISTING_CONTENT_BYTES,
    open_absolute_directory_nofollow_v2,
    open_child_directory_nofollow_v2,
    open_child_file_nofollow_v2,
)


def test_real_descriptor_walk_and_regular_file(tmp_path: Path) -> None:
    """Absolute root, child directory and regular file retain their inodes."""
    child = tmp_path / "child"
    child.mkdir()
    target = child / "data"
    target.write_bytes(b"measured\n")
    root_fd = open_absolute_directory_nofollow_v2(str(tmp_path))
    try:
        assert stat.S_ISDIR(os.fstat(root_fd).st_mode)
        child_fd = open_child_directory_nofollow_v2(root_fd, "child")
        try:
            assert (os.fstat(child_fd).st_dev, os.fstat(child_fd).st_ino) == (
                child.stat().st_dev,
                child.stat().st_ino,
            )
            same_mount_fd = open_child_directory_nofollow_v2(root_fd, "child", no_xdev=True)
            os.close(same_mount_fd)
            file_fd = open_child_file_nofollow_v2(child_fd, "data")
            try:
                assert os.read(file_fd, 32) == b"measured\n"
                assert os.fstat(file_fd).st_ino == target.stat().st_ino
            finally:
                os.close(file_fd)
            same_mount_file_fd = open_child_file_nofollow_v2(child_fd, "data", no_xdev=True)
            os.close(same_mount_file_fd)
        finally:
            os.close(child_fd)
    finally:
        os.close(root_fd)


def test_no_xdev_refuses_real_proc_mount() -> None:
    """A child mount is rejected even when its name has no symlink."""
    root_fd = open_absolute_directory_nofollow_v2("/")
    try:
        assert os.stat("/proc").st_dev != os.fstat(root_fd).st_dev
        with pytest.raises(OSError) as crossing:
            open_child_directory_nofollow_v2(root_fd, "proc", no_xdev=True)
        assert crossing.value.errno == errno.EXDEV
    finally:
        os.close(root_fd)


def test_symlinks_and_parent_escape_refuse(tmp_path: Path) -> None:
    """Neither an absolute ancestor nor a child symlink is traversed."""
    real = tmp_path / "real"
    real.mkdir()
    (real / "data").write_bytes(b"secret")
    linked = tmp_path / "link"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(OSError, match="link"):
        open_absolute_directory_nofollow_v2(str(linked))
    root_fd = open_absolute_directory_nofollow_v2(str(tmp_path))
    try:
        with pytest.raises(OSError) as directory_error:
            open_child_directory_nofollow_v2(root_fd, "link")
        assert directory_error.value.errno in {errno.ELOOP, errno.ENOTDIR}
        (tmp_path / "file-link").symlink_to(real / "data")
        with pytest.raises(OSError) as file_error:
            open_child_file_nofollow_v2(root_fd, "file-link")
        assert file_error.value.errno == errno.ELOOP
        with pytest.raises(ValueError, match="component"):
            open_child_directory_nofollow_v2(root_fd, "../real")
    finally:
        os.close(root_fd)


@pytest.mark.parametrize("component", ["", ".", "..", "a/b", "a\x00b", "a\nb", "\ud800"])
def test_malformed_components_refuse_before_syscall(tmp_path: Path, component: str) -> None:
    """Unsafe components never reach either directory or file resolution."""
    root_fd = open_absolute_directory_nofollow_v2(str(tmp_path))
    try:
        with pytest.raises(ValueError, match="component"):
            open_child_directory_nofollow_v2(root_fd, component)
        with pytest.raises(ValueError, match="component"):
            open_child_file_nofollow_v2(root_fd, component)
    finally:
        os.close(root_fd)


def test_fifo_directory_and_oversized_target_refuse_without_blocking(tmp_path: Path) -> None:
    """The file opener refuses special nodes and oversized pre-state inputs."""
    root_fd = open_absolute_directory_nofollow_v2(str(tmp_path))
    try:
        os.mkfifo(tmp_path / "pipe")
        with pytest.raises(PermissionError, match="not regular"):
            open_child_file_nofollow_v2(root_fd, "pipe")
        (tmp_path / "folder").mkdir()
        with pytest.raises(PermissionError, match="not regular"):
            open_child_file_nofollow_v2(root_fd, "folder")
        oversized = tmp_path / "large"
        with oversized.open("wb") as stream:
            stream.truncate(MAX_EXISTING_CONTENT_BYTES + 1)
        with pytest.raises(PermissionError, match="64 MiB"):
            open_child_file_nofollow_v2(root_fd, "large")
    finally:
        os.close(root_fd)


def test_public_absolute_path_and_descriptor_validation(tmp_path: Path) -> None:
    """Reject public path inputs and document unreachable defensive invariants.

    Public wrappers fix flags and validate paths before low-level descent, so
    malformed flags and NUL at the internal guard are unreachable through those
    wrappers. They remain measured residuals; no private calls supply coverage.
    Linux cannot supply a non-Linux kernel sysname, so no fake sysname is used.
    Foreign-OS execution remains unverified on this host. The real Linux32
    personality test below covers the architecture refusal publicly.
    """
    with pytest.raises(ValueError, match="canonical absolute"):
        open_absolute_directory_nofollow_v2("relative")
    with pytest.raises(ValueError, match="canonical absolute"):
        open_absolute_directory_nofollow_v2(str(tmp_path) + "/../other")
    with pytest.raises(OSError) as missing:
        open_absolute_directory_nofollow_v2(str(tmp_path / "missing"))
    assert missing.value.errno == errno.ENOENT
    with pytest.raises(ValueError, match="descriptor is malformed"):
        open_child_directory_nofollow_v2(-101, "child")


def test_real_linux32_personality_refuses_public_open(tmp_path: Path) -> None:
    """A real kernel Linux32 uname personality is refused before public descent.

    setarch changes the actual process personality; platform.machine remains
    unpatched. This proves the guard on kernel-reported machine identity and
    does not claim execution on physically different processor hardware.
    """
    child = """
import platform
import sys
from rigor_foundry.tier0_builtin.linux_openat2_v2 import open_absolute_directory_nofollow_v2
assert platform.system() == 'Linux'
assert platform.machine() != 'x86_64', platform.machine()
try:
    open_absolute_directory_nofollow_v2(sys.argv[1])
except OSError as exc:
    assert 'unavailable on this architecture' in str(exc), str(exc)
else:
    raise AssertionError('unsupported reported architecture was admitted')
"""
    source = Path(__file__).resolve().parents[1] / "src"
    completed = subprocess.run(
        ["setarch", "linux32", sys.executable, "-c", child, str(tmp_path)],
        env={**os.environ, "PYTHONPATH": str(source)},
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
