# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — ordinary native coverage ownership contract
"""Refuse falsely attributed primary receipts before accessing raw coverage data."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest
from test_run_native_tests import completed_native as completed_native

from tools.native_coverage import native_coverage_inputs
from tools.test_shard_evidence import read_record


def test_ordinary_union_refuses_primary_role_before_database_access(
    completed_native: Path, tmp_path: Path
) -> None:
    """Reject a falsely relabelled copy without opening or salvaging its database.

    Parameters
    ----------
    completed_native : Path
        Actual successful ordinary local producer, kept unchanged.
    tmp_path : Path
        Owned known-invalid copy; it never represents primary execution.
    """
    directory = tmp_path / "native"
    artifact = shutil.copytree(
        completed_native / ".rigor-native-coverage", directory / sys.platform
    )
    record = read_record(artifact / "receipt.json")
    record["role"] = "primary"
    (artifact / "receipt.json").write_text(json.dumps(record))
    (artifact / ".coverage").unlink()
    with pytest.raises(ValueError):
        native_coverage_inputs(
            completed_native,
            directory,
            record["identity"],
            platforms=(sys.platform,),
            expected_venue="local",
        )
    assert not (artifact / ".coverage").exists()
