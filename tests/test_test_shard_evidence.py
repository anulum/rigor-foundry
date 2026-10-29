# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Retained test shard artifact validation
"""Mutate real completed artifacts and reject incomplete terminal evidence."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from xml.parsers import expat

import coverage
import pytest
from test_run_test_shard import execute_shard, shard_environment, shard_repository

from tools.run_test_shard import pytest_command
from tools.test_shard_evidence import (
    MAX_ARTIFACT_BYTES,
    artifact_bytes,
    read_record,
    source_identity,
    validate_artifacts,
    validate_observations,
    validate_receipt,
)


@pytest.fixture(scope="module")
def successful_shard(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Retain one actual successful process and its complete original artifacts.

    Parameters
    ----------
    tmp_path_factory : pytest.TempPathFactory
        Module-scoped independent repository allocator.

    Returns
    -------
    Path
        Original repository, held unchanged while copies are mutated.
    """
    root = shard_repository(tmp_path_factory.mktemp("completed-shard"))
    result = execute_shard(root, count=1)
    assert result.returncode == 0, result.stdout + result.stderr
    return root


def test_real_receipt_and_source_identity_bind_config_and_runtime(
    successful_shard: Path, tmp_path: Path
) -> None:
    """Validate original evidence and detect real configuration/source changes.

    Parameters
    ----------
    successful_shard : Path
        Immutable successful original repository.
    tmp_path : Path
        Independent source mutation repository.
    """
    root = successful_shard
    identity = source_identity(root, shard_environment(root))
    collection = validate_receipt(root / ".rigor-test-shard", identity, 0, 1, pytest_command(0, 1))
    assert len(collection) == 4
    copy = shard_repository(tmp_path)
    original = source_identity(copy, shard_environment(copy))
    assert original == identity
    for relative in (
        "pyproject.toml",
        "tests/test_dispatch.py",
        "src/rigor_foundry/native_dispatch.py",
    ):
        path = copy / relative
        before = path.read_bytes()
        path.write_bytes(before + b"\n# changed actual source\n")
        assert source_identity(copy, shard_environment(copy)) != original
        path.write_bytes(before)
    for relative in ("conftest.py", ".github/workflows/ci.yml", "requirements/test.txt"):
        path = copy / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# newly present configuration\n")
    assert source_identity(copy, shard_environment(copy)) != original
    with pytest.raises(ValueError):
        source_identity(copy, {})


@pytest.mark.parametrize("case", ["absent", "linked", "oversize", "list", "duplicate", "invalid"])
def test_bounded_records_refuse_ambiguous_or_nonregular_artifacts(
    tmp_path: Path, case: str
) -> None:
    """Use actual filesystem and JSON failures before any evidence is trusted.

    Parameters
    ----------
    tmp_path : Path
        Independent artifact directory.
    case : str
        Actual filesystem or encoding defect.
    """
    path = tmp_path / "record.json"
    if case == "linked":
        target = tmp_path / "original"
        target.write_text("{}")
        path.symlink_to(target)
    elif case == "oversize":
        with path.open("wb") as output:
            output.truncate(MAX_ARTIFACT_BYTES + 1)
    elif case != "absent":
        path.write_text({"list": "[]", "duplicate": '{"index":0,"index":1}', "invalid": "["}[case])
    with pytest.raises(ValueError):
        read_record(path)
    if case in {"linked", "oversize", "absent"}:
        with pytest.raises(ValueError):
            artifact_bytes(path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("extra", 1),
        ("schema_version", 1),
        ("strategy", "unknown-v1"),
        ("timings", []),
        ("timings", {"tests/test_dispatch.py": 1}),
        ("index", True),
        ("index", 1),
        ("count", True),
        ("count", 4),
        ("exitstatus", True),
        ("exitstatus", 1),
        ("collected", []),
        ("collected", "case"),
        ("collected", [None]),
        ("collected", [""]),
        ("collected", ["same", "same"]),
        ("selected", []),
        ("phases", []),
        ("phases", {}),
    ],
)
def test_real_observations_refuse_wrong_identity_collection_or_phase_set(
    successful_shard: Path, field: str, value: Any
) -> None:
    """Alter one actual successful record field without fabricating a producer.

    Parameters
    ----------
    successful_shard : Path
        Immutable original successful process evidence.
    field : str
        Contract field to alter.
    value : Any
        Invalid replacement.
    """
    observed = read_record(successful_shard / ".rigor-test-shard/observations.json")
    observed[field] = value
    with pytest.raises(ValueError):
        validate_observations(observed, 0, 1)


@pytest.mark.parametrize(
    "phases",
    [
        None,
        [],
        [["setup", "passed"]],
        [["call", "passed"], ["setup", "passed"], ["teardown", "passed"]],
        [["setup", "passed"], ["call", "failed"], ["teardown", "passed"]],
    ],
)
def test_missing_reordered_and_failing_real_phase_observations_refuse(
    successful_shard: Path, phases: Any
) -> None:
    """A real completed item's terminal accounting cannot be erased or reordered.

    Parameters
    ----------
    successful_shard : Path
        Immutable real successful process evidence.
    phases : Any
        Actual record mutation for one selected item.
    """
    observed = read_record(successful_shard / ".rigor-test-shard/observations.json")
    observed["phases"][observed["selected"][0]] = phases
    with pytest.raises(ValueError):
        validate_observations(observed, 0, 1)


@pytest.mark.parametrize(
    "case",
    [
        "root",
        "suites",
        "empty-suites",
        "tag",
        "count",
        "errors",
        "failures",
        "cases",
        "hidden-error",
        "hidden-failure",
        "malformed",
        "doctype",
        "raw-corrupt",
        "raw-absent",
    ],
)
def test_actual_junit_and_raw_database_must_be_readable_and_complete(
    successful_shard: Path, tmp_path: Path, case: str
) -> None:
    """Retained real artifacts must parse; matching metadata cannot replace data.

    Parameters
    ----------
    successful_shard : Path
        Original completed process evidence.
    tmp_path : Path
        Independent altered artifact directory.
    case : str
        Actual JUnit or database corruption.
    """
    directory = shutil.copytree(successful_shard / ".rigor-test-shard", tmp_path / "shard")
    junit = directory / "junit.xml"
    document = ET.fromstring(junit.read_bytes())
    suite = next(iter(document))
    if case == "root":
        document.tag = "other"
    elif case == "suites":
        ET.SubElement(document, "testsuite")
    elif case == "empty-suites":
        document.remove(suite)
    elif case == "tag":
        suite.tag = "other"
    elif case in {"count", "errors", "failures"}:
        suite.set({"count": "tests"}.get(case, case), "1")
    elif case == "cases":
        suite.remove(next(iter(suite)))
    elif case.startswith("hidden-"):
        ET.SubElement(next(iter(suite)), case.removeprefix("hidden-"))
    if case == "malformed":
        junit.write_text("<")
    elif case == "doctype":
        junit.write_bytes(b'<!DOCTYPE testsuites SYSTEM "unused-junit-definition"><testsuites/>')
    else:
        junit.write_bytes(ET.tostring(document))
    if case == "raw-corrupt":
        (directory / ".coverage").write_bytes(b"not a coverage database")
    elif case == "raw-absent":
        (directory / ".coverage").unlink()
    with pytest.raises((ValueError, expat.ExpatError, coverage.exceptions.DataError)):
        validate_artifacts(directory, 4)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("extra", True),
        ("schema_version", True),
        ("schema_version", 1),
        ("identity", {}),
        ("command", ["true"]),
        ("artifacts", {}),
    ],
)
def test_receipt_cannot_replace_actual_run_identity_command_or_artifact_hashes(
    successful_shard: Path, tmp_path: Path, field: str, value: Any
) -> None:
    """A producer receipt is accepted only with its original complete artifacts.

    Parameters
    ----------
    successful_shard : Path
        Immutable successful process evidence.
    tmp_path : Path
        Altered artifact directory.
    field : str
        Actual receipt field to replace.
    value : Any
        Invalid receipt replacement.
    """
    directory = shutil.copytree(successful_shard / ".rigor-test-shard", tmp_path / "shard")
    receipt = read_record(directory / "receipt.json")
    receipt[field] = value
    (directory / "receipt.json").write_text(json.dumps(receipt))
    identity = source_identity(successful_shard, shard_environment(successful_shard))
    with pytest.raises(ValueError):
        validate_receipt(directory, identity, 0, 1, pytest_command(0, 1))
    with pytest.raises(ValueError):
        validate_receipt(directory, {}, 0, 1, pytest_command(0, 1))


@pytest.mark.parametrize("case", ["line-only", "unrelated-source"])
def test_real_runtime_coverage_requires_branch_observations_for_the_package(
    successful_shard: Path, tmp_path: Path, case: str
) -> None:
    """Collect real replacement data and refuse lines-only or unrelated execution.

    Parameters
    ----------
    successful_shard : Path
        Original completed producer artifacts and executable source.
    tmp_path : Path
        Independent actual runtime measurement location.
    case : str
        Genuine incompatible measurement mode or source owner.
    """
    directory = shutil.copytree(successful_shard / ".rigor-test-shard", tmp_path / "shard")
    (directory / ".coverage").unlink()
    path = successful_shard / "src/rigor_foundry/native_dispatch.py"
    if case == "unrelated-source":
        target = tmp_path / "unrelated.py"
        shutil.copyfile(path, target)
        path = target
    config = tmp_path / "measurement.rc"
    config.write_text("[run]\nbranch = " + ("False" if case == "line-only" else "True") + "\n")
    driver = tmp_path / "measure_runtime.py"
    driver.write_text(
        "import runpy, sys\nnamespace = runpy.run_path(sys.argv[1])\n"
        'assert namespace["dispatch"]("validate") == "valid"\n'
    )
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.startswith(("COVERAGE_", "COV_CORE_"))
    }
    measured = subprocess.run(
        [
            sys.executable,
            "-m",
            "coverage",
            "run",
            "--rcfile",
            str(config),
            "--data-file",
            str(directory / ".coverage"),
            str(driver),
            str(path),
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert measured.returncode == 0, measured.stdout + measured.stderr
    with pytest.raises(ValueError):
        validate_artifacts(directory, 4)
