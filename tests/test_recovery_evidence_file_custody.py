# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — bounded public recovery evidence file custody
"""Reject special files through public reads without waiting for a FIFO writer."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from rigor_foundry.recovery_evidence_store_v2 import RecoveryEvidenceStoreV2

_CHILD = """
import sys
from pathlib import Path
from rigor_foundry.recovery_evidence_store_v2 import RecoveryEvidenceStoreV2
store = RecoveryEvidenceStoreV2(Path(sys.argv[1]), 4, 8192)
try:
    if sys.argv[2] == 'scan':
        store.scan()
    else:
        store.read('a' * 64)
except PermissionError as exc:
    assert 'custody' in str(exc), exc
else:
    raise AssertionError('special file accepted as evidence')
"""


@pytest.mark.parametrize("operation", ["scan", "read"])
def test_fifo_refuses_without_waiting_for_writer(tmp_path: Path, operation: str) -> None:
    """A genuine writerless FIFO must refuse promptly and retain its inode."""
    directory = tmp_path / "evidence"
    directory.mkdir(mode=0o700)
    fifo = directory / ("a" * 64 + ".json")
    os.mkfifo(fifo, 0o600)
    before = fifo.stat()
    completed = subprocess.run(
        [sys.executable, "-c", _CHILD, str(directory), operation],
        capture_output=True,
        text=True,
        check=False,
        timeout=3,
    )
    assert completed.returncode == 0, completed.stderr
    after = fifo.stat()
    assert (before.st_dev, before.st_ino, before.st_mode) == (
        after.st_dev,
        after.st_ino,
        after.st_mode,
    )


def test_digest_named_directory_refuses(tmp_path: Path) -> None:
    """A regular directory cannot stand in for an immutable evidence object."""
    directory = tmp_path / "evidence"
    directory.mkdir(mode=0o700)
    (directory / ("a" * 64 + ".json")).mkdir(mode=0o700)
    with pytest.raises(PermissionError, match="custody"):
        RecoveryEvidenceStoreV2(directory, 4, 8192).scan()
