# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — verified OSV-Scanner installer tests
"""Verify the installed result and immutable release pins used by CI."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from tools.install_osv_scanner import (
    OSV_SCANNER_BINARY_DIGEST,
    OSV_SCANNER_BINARY_NAME,
    OSV_SCANNER_CHECKSUM_DIGEST,
    OSV_SCANNER_VERSION,
    main,
    verify_release_payloads,
)


def test_active_environment_contains_verified_osv_scanner_release() -> None:
    """The workflow-installed executable is exact-versioned and not group-writable."""
    executable = Path(sys.prefix) / "bin" / "osv-scanner"
    completed = subprocess.run(  # nosec B603
        [str(executable), "--version"],
        check=True,
        capture_output=True,
        shell=False,
        text=True,
        timeout=10,
    )
    metadata = executable.stat(follow_symlinks=False)
    assert completed.stdout.splitlines()[0] == f"osv-scanner version: {OSV_SCANNER_VERSION}"
    assert stat.S_ISREG(metadata.st_mode)
    assert metadata.st_uid in {0, os.getuid()}
    assert stat.S_IMODE(metadata.st_mode) & (stat.S_IWGRP | stat.S_IWOTH) == 0
    assert len(OSV_SCANNER_CHECKSUM_DIGEST) == 64
    assert len(OSV_SCANNER_BINARY_DIGEST) == 64
    assert hashlib.sha256(executable.read_bytes()).hexdigest() == OSV_SCANNER_BINARY_DIGEST
    assert OSV_SCANNER_BINARY_NAME == "osv-scanner_linux_amd64"


def test_installer_cli_help_and_digest_failures_are_fail_closed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The installer documents its destination and rejects unpinned bytes."""
    with pytest.raises(SystemExit) as exit_info:
        main(["--help"])
    assert exit_info.value.code == 0
    assert "--destination" in capsys.readouterr().out

    with pytest.raises(ValueError, match="checksum document digest"):
        verify_release_payloads(b"untrusted checksums", b"untrusted binary")
