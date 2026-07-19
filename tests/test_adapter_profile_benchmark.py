# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — built-in adapter profile benchmark tests
"""Exercise the real benchmark entry point and its bounded input contract."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_profile_benchmark_executes_all_real_tools() -> None:
    """One bounded iteration reports complete OSV, Semgrep, and Trivy measurements."""
    script = Path(__file__).parents[1] / "benchmarks" / "adapter_profiles.py"
    completed = subprocess.run(  # nosec B603
        (sys.executable, str(script), "--iterations", "1"),
        check=True,
        capture_output=True,
        text=True,
    )
    result = json.loads(completed.stdout)

    assert result["schema_version"] == "1.0"
    assert result["iterations_per_profile"] == 1
    profiles = result["profiles"]
    assert isinstance(profiles, dict)
    assert set(profiles) == {
        "osv-lockfile-offline-json-v1",
        "semgrep-local-json-v1",
        "trivy-repository-json-v1",
    }
    for evidence in profiles.values():
        assert isinstance(evidence, dict)
        assert evidence["tool_version"]
        assert 0 < evidence["minimum_ms"] <= evidence["maximum_ms"]


def test_profile_benchmark_cli_and_iteration_bounds() -> None:
    """The public script emits JSON help and rejects unsafe repetition counts."""
    script = Path(__file__).parents[1] / "benchmarks" / "adapter_profiles.py"
    completed = subprocess.run(  # nosec B603
        (sys.executable, str(script), "--help"),
        check=True,
        capture_output=True,
        text=True,
    )
    assert "--iterations" in completed.stdout
    rejected = subprocess.run(  # nosec B603
        (sys.executable, str(script), "--iterations", "0"),
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode != 0
    assert "iterations must be between 1 and 20" in rejected.stderr
