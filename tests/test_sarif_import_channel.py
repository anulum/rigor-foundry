# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — second-output memory file channel tests
"""Verify the inherited memory file channel with a real child process writing to ``/dev/fd/N``."""

from __future__ import annotations

import os
import subprocess
import sys
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


def test_an_output_that_shrinks_while_read_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """A read that ends before the size the file reported is refused, never returned short.

    Parameters
    ----------
    monkeypatch : pytest.MonkeyPatch
        Makes the positional read end early, as a concurrent truncation would.
    """
    with SecondOutputChannel() as channel:
        assert _child_writes(channel, SARIF) == 0
        monkeypatch.setattr(os, "pread", lambda descriptor, length, offset: b"")
        with pytest.raises(ValueError, match="changed while it was read"):
            channel.read()


def test_a_platform_without_memory_files_has_no_channel(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without ``memfd_create`` the channel cannot exist.

    Parameters
    ----------
    monkeypatch : pytest.MonkeyPatch
        Removes ``os.memfd_create`` for this test.
    """
    monkeypatch.delattr(os, "memfd_create")
    with pytest.raises(RuntimeError, match="needs anonymous memory files"):
        SecondOutputChannel()
