# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — second-output memory file channel tests
"""Verify the inherited memory file channel with a real child process writing to ``/dev/fd/N``.

These tests need a Linux CPython built with the memory file seal constants (``fcntl.F_SEAL_*``),
such as a distribution or python.org build. uv's standalone builds lack the constants, so the
real-channel tests fail there with ``channel-unavailable``; they are not skipped. Only the
absence of ``os.memfd_create``, a platform without memory files, skips this module.
"""

from __future__ import annotations

import mmap
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest

from rigor_foundry.sarif_import_channel import SecondOutputChannel
from rigor_foundry.sarif_import_document import MAX_SARIF_BYTES, SarifImportRefused

ROOT = Path(__file__).resolve().parents[1]
SARIF = ROOT / "tests/fixtures/sarif_import/semgrep-1.186.0-producer-repository.sarif"
pytestmark = pytest.mark.skipif(
    not hasattr(os, "memfd_create"), reason="anonymous memory files are Linux-only"
)


def _child_writes(channel: SecondOutputChannel, payload: Path) -> int:
    """Let a real child process copy ``payload`` to the channel's ``/dev/fd/N`` path."""
    code = "import shutil, sys; shutil.copyfile(sys.argv[1], sys.argv[2])"
    return subprocess.run(
        [sys.executable, "-c", code, str(payload), channel.path],
        pass_fds=(channel.descriptor,),
        check=False,
    ).returncode


def test_a_child_writes_the_second_output_that_the_host_reads_whole() -> None:
    """The real SARIF a child writes through ``/dev/fd/N`` is read back byte for byte."""
    with SecondOutputChannel() as channel:
        assert channel.limit == MAX_SARIF_BYTES
        assert not os.get_inheritable(channel.descriptor)
        assert channel.path == f"/dev/fd/{channel.descriptor}"
        assert _child_writes(channel, SARIF) == 0
        assert channel.read() == SARIF.read_bytes()
        assert channel.read() == SARIF.read_bytes()
    with pytest.raises(ValueError, match="channel is closed"):
        _ = channel.descriptor
    channel.close()


def test_an_output_past_the_limit_is_refused_and_one_at_it_is_kept(tmp_path: Path) -> None:
    """A second output one byte over its limit is refused whole; at the limit it is kept.

    Parameters
    ----------
    tmp_path : Path
        Owned payload allocation.
    """
    size = len(SARIF.read_bytes())
    with SecondOutputChannel(limit=size) as channel:
        assert _child_writes(channel, SARIF) == 0
        assert channel.read() == SARIF.read_bytes()
    larger = tmp_path / "larger.sarif"
    larger.write_bytes(SARIF.read_bytes() + b" ")
    with SecondOutputChannel(limit=size) as channel:
        assert _child_writes(channel, larger) == 0
        with pytest.raises(SarifImportRefused) as refused:
            channel.read()
        assert refused.value.reason == "too-large"


def test_the_read_seals_the_output_against_any_later_write() -> None:
    """After the read, the memory file can no longer be written, grown, shrunk or unsealed."""
    import fcntl

    every = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    with SecondOutputChannel() as channel:
        assert _child_writes(channel, SARIF) == 0
        assert channel.read() == SARIF.read_bytes()
        assert fcntl.fcntl(channel.descriptor, fcntl.F_GET_SEALS) & every == every
        with pytest.raises(PermissionError):
            os.pwrite(channel.descriptor, b"x", 0)
        with pytest.raises(PermissionError):
            os.ftruncate(channel.descriptor, 1)
        with pytest.raises(PermissionError):
            fcntl.fcntl(channel.descriptor, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE)
        assert channel.read() == SARIF.read_bytes()


def test_an_output_with_a_writable_mapping_cannot_be_sealed_or_read() -> None:
    """A live shared writable mapping makes the write seal fail, so nothing is read."""
    with SecondOutputChannel() as channel:
        assert _child_writes(channel, SARIF) == 0
        with (
            mmap.mmap(
                channel.descriptor, len(SARIF.read_bytes()), mmap.MAP_SHARED, mmap.PROT_WRITE
            ),
            pytest.raises(ValueError, match="cannot be sealed against writes"),
        ):
            channel.read()


def test_a_read_that_ends_before_the_sealed_size_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A positional read that ends early is refused, never returned short.

    Parameters
    ----------
    monkeypatch : pytest.MonkeyPatch
        Makes the positional read end early.
    """
    with SecondOutputChannel() as channel:
        assert _child_writes(channel, SARIF) == 0
        monkeypatch.setattr(os, "pread", lambda descriptor, length, offset: b"")
        with pytest.raises(ValueError, match="ended before its sealed size"):
            channel.read()


def test_a_platform_without_memory_files_has_no_channel(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without ``memfd_create`` the channel is refused before any file exists, on any interpreter.

    A stand-in control module with every seal name makes the memory file check the one that
    refuses, also on an interpreter built without the seal constants.

    Parameters
    ----------
    monkeypatch : pytest.MonkeyPatch
        Installs complete seal names and removes ``os.memfd_create`` for this test.
    """
    control = types.ModuleType("fcntl")
    for value, name in enumerate(
        (
            "F_ADD_SEALS",
            "F_GET_SEALS",
            "F_SEAL_WRITE",
            "F_SEAL_GROW",
            "F_SEAL_SHRINK",
            "F_SEAL_SEAL",
        ),
        start=1,
    ):
        setattr(control, name, value)
    monkeypatch.setitem(sys.modules, "fcntl", control)
    monkeypatch.delattr(os, "memfd_create")
    with pytest.raises(SarifImportRefused, match="no sealable anonymous memory files") as refused:
        SecondOutputChannel()
    assert refused.value.reason == "channel-unavailable"
