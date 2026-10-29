# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Terminal test shard launcher
"""Publish a successful shard only after the actual pytest process terminates."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from tools.test_shard_evidence import (
    read_record,
    require,
    source_identity,
    validate_artifacts,
    validate_observations,
)

SHARD_DIRECTORY = Path(".rigor-test-shard")


def pytest_command(index: int, count: int) -> list[str]:
    """Construct the complete fixed invocation without inherited selection flags.

    Parameters
    ----------
    index : int
        Zero-based partition index.
    count : int
        Complete partition count.

    Returns
    -------
    list[str]
        Exact subprocess arguments recorded by producer and union consumer.
    """
    return [
        sys.executable,
        "-m",
        "pytest",
        "tests",
        "-q",
        "-ra",
        "--tb=short",
        "-p",
        "tools.pytest_test_shards",
        "--test-shard-index",
        str(index),
        "--test-shard-count",
        str(count),
        "--test-shard-observations",
        str(SHARD_DIRECTORY / "observations.json"),
        "--junitxml",
        str(SHARD_DIRECTORY / "junit.xml"),
        "--cov=rigor_foundry",
        "--cov-branch",
        "--cov-report=",
        "--cov-fail-under=0",
    ]


def run_shard(index: int, count: int) -> int:
    """Run a full selected partition and finalise immutable successful evidence.

    Parameters
    ----------
    index : int
        Zero-based partition index.
    count : int
        Complete partition count.

    Returns
    -------
    int
        Actual nonzero pytest status, or zero after all evidence is validated.
    """
    require(type(index) is int and type(count) is int and 0 <= index < count)
    root = Path.cwd()
    identity = source_identity(root, dict(os.environ))
    SHARD_DIRECTORY.mkdir()
    command = pytest_command(index, count)
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("COVERAGE_", "COV_CORE_")) and name != "PYTEST_ADDOPTS"
    }
    environment["COVERAGE_FILE"] = str((root / SHARD_DIRECTORY / ".coverage").resolve())
    result = subprocess.run(command, env=environment, check=False)
    if result.returncode != 0:
        return result.returncode
    require(source_identity(root, dict(os.environ)) == identity)
    observations = read_record(SHARD_DIRECTORY / "observations.json")
    validate_observations(observations, index, count)
    artifacts = validate_artifacts(SHARD_DIRECTORY, len(observations["selected"]))
    temporary = SHARD_DIRECTORY / "receipt.pending"
    temporary.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "identity": identity,
                "command": command,
                "artifacts": artifacts,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    temporary.rename(SHARD_DIRECTORY / "receipt.json")
    return 0


def main() -> int:
    """Run the explicit partition launcher; errors remain failing process exits.

    Returns
    -------
    int
        Complete evidence success or actual pytest refusal.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=int, required=True)
    parser.add_argument("--count", type=int, required=True)
    args = parser.parse_args()
    return run_shard(args.index, args.count)


if __name__ == "__main__":
    raise SystemExit(main())
