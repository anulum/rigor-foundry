# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — SARIF schema pin command tests
"""Verify the schema pin command through its real module entry point."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from tools.sarif_schema_pin import SARIF_SCHEMA_SHA256, SARIF_SCHEMA_URL

ROOT = Path(__file__).resolve().parents[1]


def _pin(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Run the real pin command from the repository checkout."""
    return subprocess.run(
        [sys.executable, "-m", "tools.sarif_schema_pin", *arguments],
        cwd=ROOT,
        env=dict(os.environ),
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def test_the_command_prints_exactly_the_pinned_url_and_digest() -> None:
    """Each field prints one line holding the tracked pin value, for shell substitution."""
    url = _pin("url")
    digest = _pin("sha256")
    assert (url.returncode, url.stdout) == (0, SARIF_SCHEMA_URL + "\n")
    assert (digest.returncode, digest.stdout) == (0, SARIF_SCHEMA_SHA256 + "\n")
    assert SARIF_SCHEMA_URL.startswith("https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/")
    assert len(SARIF_SCHEMA_SHA256) == 64 and int(SARIF_SCHEMA_SHA256, 16) >= 0


def test_an_unknown_field_is_refused() -> None:
    """The command refuses a field that the pin does not define."""
    refused = _pin("md5")
    assert refused.returncode == 2
    assert "invalid choice: 'md5'" in refused.stderr
