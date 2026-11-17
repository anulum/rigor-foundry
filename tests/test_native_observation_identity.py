# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Native observation identity qualification
"""Bind actual observation schedules at both public producer and consumer boundaries."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest
from test_run_native_tests import NATIVE_OWNER, execute_native, native_repository
from test_run_native_tests import completed_native as completed_native

from tools.native_coverage import native_coverage_inputs
from tools.test_shard_evidence import digest, read_record
from tools.test_shard_schedule import COLD_STRATEGY, WARM_STRATEGY


@pytest.mark.parametrize("case", ["strategy", "timings"])
def test_ordinary_consumer_refuses_changed_observation_cohort(
    completed_native: Path, tmp_path: Path, case: str
) -> None:
    """Refuse invalid copies whose updated digest agrees with a different cohort.

    Parameters
    ----------
    completed_native : Path
        Genuine successful ordinary local producer, kept unchanged.
    tmp_path : Path
        Owned known-invalid artifact copy; no raw arcs are altered.
    case : str
        Change the algorithm/cohort or only its advisory duration snapshot.
    """
    directory = tmp_path / "native"
    artifact = shutil.copytree(
        completed_native / ".rigor-native-coverage", directory / sys.platform
    )
    record = read_record(artifact / "receipt.json")
    observed = read_record(artifact / "observations.json")
    assert observed["strategy"] == record["identity"]["strategy"] == WARM_STRATEGY
    before = digest(artifact / ".coverage")
    if case == "strategy":
        observed["strategy"] = COLD_STRATEGY
        observed["timings"] = {}
    else:
        observed["timings"] = {NATIVE_OWNER: 12345.0}
    (artifact / "observations.json").write_text(json.dumps(observed))
    record["artifacts"]["observations.json"] = digest(artifact / "observations.json")
    (artifact / "receipt.json").write_text(json.dumps(record))
    with pytest.raises(ValueError):
        native_coverage_inputs(
            completed_native,
            directory,
            record["identity"],
            platforms=(sys.platform,),
            expected_venue="local",
        )
    assert digest(artifact / ".coverage") == before


@pytest.mark.parametrize("case", ["strategy", "timings"])
def test_actual_native_cli_refuses_observation_change_before_publication(
    completed_native: Path, tmp_path: Path, case: str
) -> None:
    """Reject real successful pytest output changed by its finalisation hook.

    Parameters
    ----------
    completed_native : Path
        Genuine unchanged successful baseline on this same actual host.
    tmp_path : Path
        Genuine ordinary-only Git fixture and unchanged production package.
    case : str
        Change the emitted algorithm/cohort or duration snapshot after observation.
    """
    root = native_repository(tmp_path / "repository")
    (root / "conftest.py").write_text(
        "import json\nfrom pathlib import Path\n"
        "def pytest_sessionfinish(session):\n"
        "    path = Path('.rigor-native-coverage/observations.json')\n"
        "    record = json.loads(path.read_text())\n"
        + (
            "    record['strategy'] = 'item-round-robin-v1'\n    record['timings'] = {}\n"
            if case == "strategy"
            else "    record['timings'] = {'tests/test_windows_job_observation.py': 12345.0}\n"
        )
        + "    path.write_text(json.dumps(record))\n"
    )
    result = execute_native(root)
    observed = read_record(root / ".rigor-native-coverage/observations.json")
    assert observed["exitstatus"] == 0 and len(observed["selected"]) == 6
    baseline = read_record(completed_native / ".rigor-native-coverage/observations.json")
    assert observed["collected"] == baseline["collected"]
    assert observed["phases"] == baseline["phases"]
    assert observed["subtests"] == baseline["subtests"]
    assert result.returncode == 1
    assert result.stderr == "Native test evidence is incomplete\n"
    assert not (root / ".rigor-native-coverage/receipt.json").exists()
