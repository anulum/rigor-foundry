# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — verified Buildx installer tests
"""Verify the installed Buildx identity and immutable release pins."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from tools.install_buildx import (
    BUILDKIT_IMAGE,
    BUILDX_BINARY_DIGEST,
    BUILDX_CHECKSUM_DIGEST,
    BUILDX_VERSION,
    main,
    verify_buildx_payloads,
)


def test_active_environment_contains_verified_buildx_release() -> None:
    """The workflow executable is exact-versioned and not group-writable."""
    executable = Path(sys.prefix) / "bin" / "docker-buildx"
    completed = subprocess.run(  # nosec B603
        [str(executable), "version"],
        check=True,
        capture_output=True,
        shell=False,
        text=True,
        timeout=10,
    )
    metadata = executable.stat(follow_symlinks=False)
    assert f"v{BUILDX_VERSION}" in completed.stdout
    assert stat.S_ISREG(metadata.st_mode)
    assert metadata.st_uid in {0, os.getuid()}
    assert stat.S_IMODE(metadata.st_mode) & (stat.S_IWGRP | stat.S_IWOTH) == 0
    assert len(BUILDX_CHECKSUM_DIGEST) == 64
    assert len(BUILDX_BINARY_DIGEST) == 64
    assert BUILDKIT_IMAGE.startswith("moby/buildkit@sha256:")


def test_buildx_installer_cli_and_digest_failure_are_fail_closed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The public installer documents its destination and rejects unpinned bytes."""
    with pytest.raises(SystemExit) as exit_info:
        main(["--help"])
    assert exit_info.value.code == 0
    assert "--destination" in capsys.readouterr().out
    with pytest.raises(ValueError, match="checksum document digest"):
        verify_buildx_payloads(b"untrusted checksums", b"untrusted executable")
