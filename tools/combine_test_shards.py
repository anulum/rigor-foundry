# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Complete interpreter coverage union
"""Combine only a complete same-attempt partition set with unchanged thresholds."""

from __future__ import annotations

import argparse
import os
import warnings
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import coverage

from tools.run_test_shard import pytest_command
from tools.test_shard_evidence import digest, require, source_identity, validate_receipt


@contextmanager
def _reporting_coverage() -> Iterator[coverage.Coverage]:
    """Close each report's mapped in-memory data without reusing a closed report."""
    measured = coverage.Coverage(config_file="pyproject.toml", data_file=".coverage")
    try:
        measured.load()
        yield measured
    finally:
        measured.get_data().close(force=True)


def combine_shards(directory: Path, count: int) -> None:
    """Validate every partition before combining its real retained branch data.

    Parameters
    ----------
    directory : Path
        Downloaded artifact root containing exactly shard-0 through shard-N.
    count : int
        Required partition count shared by every producer.

    Raises
    ------
    ValueError
        Any partition, actual coverage input or original coverage threshold fails.
    """
    require(type(count) is int and count > 0 and not directory.is_symlink())
    require(not Path(".coverage").exists() and not Path("coverage.xml").exists())
    expected = {f"shard-{index}" for index in range(count)}
    require({path.name for path in directory.iterdir()} == expected)
    identity = source_identity(Path.cwd(), dict(os.environ))
    collected: list[str] | None = None
    inputs: list[str] = []
    for index in range(count):
        shard = directory / f"shard-{index}"
        require(shard.is_dir() and not shard.is_symlink())
        actual = validate_receipt(shard, identity, index, count, pytest_command(index, count))
        if collected is None:
            collected = actual
        require(actual == collected)
        inputs.append(str((shard / ".coverage").resolve()))
    measured = coverage.Coverage(config_file="pyproject.toml", data_file=".coverage")
    hashes = [digest(Path(path)) for path in inputs]
    try:
        with warnings.catch_warnings(record=True) as emitted:
            warnings.simplefilter("always")
            measured.combine(data_paths=inputs, strict=True, keep=True)
        require(not emitted)
        require([digest(Path(path)) for path in inputs] == hashes)
        measured.save()
    finally:
        measured.get_data().close(force=True)
    with _reporting_coverage() as report:
        require(report.report() >= 98)
    with _reporting_coverage() as report:
        require(report.report(include=["*/native_dispatch.py"]) == 100)
    with _reporting_coverage() as report:
        report.xml_report(outfile="coverage.xml")
    require(source_identity(Path.cwd(), dict(os.environ)) == identity)


def main() -> int:
    """Run the complete-union gate for the current interpreter and run attempt.

    Returns
    -------
    int
        Zero only after complete validation and both original coverage gates.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--count", type=int, required=True)
    args = parser.parse_args()
    combine_shards(args.directory, args.count)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
