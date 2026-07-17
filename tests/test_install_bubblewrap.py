# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — verified Bubblewrap installer tests
"""Verify the installed executable and immutable Ubuntu package pins."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from tools.install_bubblewrap import (
    BUBBLEWRAP_EXECUTABLE_DIGEST,
    BUBBLEWRAP_PACKAGE_DIGEST,
    BUBBLEWRAP_VERSION,
    main,
    verify_bubblewrap_package,
)


def test_active_host_contains_pinned_bubblewrap_executable() -> None:
    """The real installed package and executable match the CI provenance policy."""
    executable = Path("/usr/bin/bwrap")
    assert hashlib.sha256(executable.read_bytes()).hexdigest() == BUBBLEWRAP_EXECUTABLE_DIGEST
    completed = subprocess.run(  # nosec B603
        ["dpkg-query", "--showformat=${Version}", "--show", "bubblewrap"],
        check=True,
        capture_output=True,
        shell=False,
        text=True,
        timeout=10,
    )
    assert completed.stdout == BUBBLEWRAP_VERSION
    assert len(BUBBLEWRAP_PACKAGE_DIGEST) == 64


def test_bubblewrap_installer_cli_and_size_failure_are_fail_closed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The public installer documents its destination and rejects altered bytes."""
    with pytest.raises(SystemExit) as exit_info:
        main(["--help"])
    assert exit_info.value.code == 0
    assert "--destination" in capsys.readouterr().out
    with pytest.raises(ValueError, match="package size"):
        verify_bubblewrap_package(b"untrusted package")
