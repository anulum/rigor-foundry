# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Complete test shard evidence
"""Validate real terminal pytest observations and their retained raw artifacts."""

from __future__ import annotations

import hashlib
import json
import platform
from pathlib import Path
from typing import Any
from xml.parsers import expat

import coverage

from tools.test_shard_schedule import WARM_STRATEGY, partition, read_timings

MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
IDENTITY_FIELDS = {
    "repository",
    "run_id",
    "run_attempt",
    "head",
    "python",
    "source",
    "config",
    "schedule",
    "strategy",
}
OBSERVATION_FIELDS = {
    "schema_version",
    "strategy",
    "index",
    "count",
    "collected",
    "selected",
    "phases",
    "exitstatus",
    "timings",
}
ARTIFACT_NAMES = ("observations.json", "junit.xml", ".coverage")


def require(condition: bool) -> None:
    """Refuse incomplete evidence with a source-free message.

    Parameters
    ----------
    condition : bool
        Actual contract predicate.

    Raises
    ------
    ValueError
        The complete evidence contract is not satisfied.
    """
    if not condition:
        raise ValueError("incomplete test shard evidence")


def artifact_bytes(path: Path) -> bytes:
    """Read one bounded regular artifact without accepting symbolic links.

    Parameters
    ----------
    path : Path
        Retained actual file.

    Returns
    -------
    bytes
        Complete file content.
    """
    require(not path.is_symlink() and path.is_file())
    require(path.stat().st_size <= MAX_ARTIFACT_BYTES)
    return path.read_bytes()


def digest(path: Path) -> str:
    """Hash the entire bounded artifact.

    Parameters
    ----------
    path : Path
        Regular artifact to bind.

    Returns
    -------
    str
        SHA-256 of complete bytes.
    """
    return hashlib.sha256(artifact_bytes(path)).hexdigest()


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject ambiguous JSON objects in receipts and observations."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def read_record(path: Path) -> dict[str, Any]:
    """Read an unambiguous bounded JSON object.

    Parameters
    ----------
    path : Path
        Receipt or provisional observations.

    Returns
    -------
    dict[str, Any]
        Actual object whose fields still require contract validation.
    """
    record: Any = json.loads(artifact_bytes(path), object_pairs_hook=_unique_fields)
    require(isinstance(record, dict))
    return dict(record)


def source_identity(root: Path, environment: dict[str, str]) -> dict[str, str]:
    """Bind full interpreter, run attempt, configuration and actual source bytes.

    Parameters
    ----------
    root : Path
        Actual checked-out repository.
    environment : dict[str, str]
        Explicit GitHub run identity, also supplied by real local qualification.

    Returns
    -------
    dict[str, str]
        Same-attempt identity with deterministic path/content source digest.
    """
    files = [root / "pyproject.toml"]
    files.extend(root.glob("conftest.py"))
    for directory in ("src", "tools", "tests"):
        files.extend((root / directory).rglob("*.py"))
    files.extend((root / ".github/workflows").glob("*.yml"))
    files.extend((root / "requirements").glob("*.txt"))
    source = hashlib.sha256()
    for path in sorted(files):
        source.update(path.relative_to(root).as_posix().encode() + b"\0")
        source.update(bytes.fromhex(digest(path)))
    for name in (
        "pytest_test_shards",
        "test_shard_evidence",
        "run_test_shard",
        "combine_test_shards",
        "test_shard_schedule",
    ):
        source.update(name.encode() + b"\0")
        source.update(bytes.fromhex(digest(Path(__file__).with_name(name + ".py"))))
    strategy = environment.get("RIGOR_TEST_SHARD_STRATEGY", WARM_STRATEGY)
    result = {
        "strategy": strategy,
        "repository": environment.get("GITHUB_REPOSITORY", ""),
        "run_id": environment.get("GITHUB_RUN_ID", ""),
        "run_attempt": environment.get("GITHUB_RUN_ATTEMPT", ""),
        "head": environment.get("GITHUB_SHA", ""),
        "python": platform.python_version(),
        "source": source.hexdigest(),
        "config": digest(root / "pyproject.toml"),
        "schedule": json.dumps(
            read_timings(root, strategy), sort_keys=True, separators=(",", ":")
        ),
    }
    require(all(result.values()))
    return result


def validate_observations(record: dict[str, Any], index: int, count: int) -> list[str]:
    """Require exact ordered collection, selection and successful terminal phases.

    Parameters
    ----------
    record : dict[str, Any]
        Real provisional pytest observations.
    index : int
        Required zero-based partition index.
    count : int
        Required number of partitions.

    Returns
    -------
    list[str]
        Complete ordered collection, identical across all partitions.
    """
    require(set(record) == OBSERVATION_FIELDS)
    require(type(record["schema_version"]) is int and record["schema_version"] == 2)
    require(type(record["index"]) is int and record["index"] == index)
    require(type(record["count"]) is int and record["count"] == count)
    require(type(record["exitstatus"]) is int and record["exitstatus"] == 0)
    collected = record["collected"]
    require(isinstance(collected, list) and bool(collected))
    require(all(isinstance(item, str) and bool(item) for item in collected))
    require(len(set(collected)) == len(collected))
    selected = partition(collected, count, record["timings"], record["strategy"])[index]
    require(bool(selected) and record["selected"] == selected)
    phases = record["phases"]
    require(isinstance(phases, dict) and set(phases) == set(selected))
    for item in selected:
        actual = phases[item]
        require(isinstance(actual, list))
        normal = [["setup", "passed"], ["call", "passed"], ["teardown", "passed"]]
        skipped_call = [["setup", "passed"], ["call", "skipped"], ["teardown", "passed"]]
        skipped_setup = [["setup", "skipped"], ["teardown", "passed"]]
        require(actual in (normal, skipped_call, skipped_setup))
    return list(collected)


def validate_junit(raw: bytes, selected_count: int) -> None:
    """Count actual JUnit events without accepting document types or failures.

    Parameters
    ----------
    raw : bytes
        Complete bounded actual JUnit XML artifact.
    selected_count : int
        Expected number of completed selected cases.

    Raises
    ------
    ValueError
        The document does not describe one complete successful pytest suite.
    expat.ExpatError
        The artifact is not well-formed XML.
    """
    parser = expat.ParserCreate()
    depth = 0
    cases = 0
    suites: list[dict[str, str]] = []

    def _start(tag: str, attributes: dict[str, str]) -> None:
        """Count structural suite/case events and reject actual error elements."""
        nonlocal depth, cases
        if depth == 0:
            require(tag == "testsuites")
        elif depth == 1:
            require(tag == "testsuite" and not suites)
            suites.append(attributes)
        require(tag not in {"failure", "error"})
        cases += int(tag == "testcase")
        depth += 1

    def _end(_tag: str) -> None:
        """Track actual nesting; Expat itself enforces matching element names."""
        nonlocal depth
        depth -= 1

    def _doctype(_name: str, _system: str | None, _public: str | None, _internal: bool) -> None:
        """Refuse document types before any declared entity is processed."""
        raise ValueError("JUnit document types are not accepted")

    parser.StartElementHandler = _start
    parser.EndElementHandler = _end
    parser.StartDoctypeDeclHandler = _doctype
    parser.Parse(raw, True)
    require(len(suites) == 1)
    suite = suites[0]
    require(int(suite["tests"]) == selected_count and cases == selected_count)
    require(int(suite["errors"]) == 0 and int(suite["failures"]) == 0)


def validate_artifacts(directory: Path, selected_count: int) -> dict[str, str]:
    """Parse actual JUnit and usable branch data before binding their hashes.

    Parameters
    ----------
    directory : Path
        Isolated single-partition artifact directory.
    selected_count : int
        Number of actual completed cases.

    Returns
    -------
    dict[str, str]
        Exact three artifact hashes, including the complete raw database.
    """
    hashes = {name: digest(directory / name) for name in ARTIFACT_NAMES}
    validate_junit(artifact_bytes(directory / "junit.xml"), selected_count)
    data = coverage.CoverageData(basename=str(directory / ".coverage"))
    data.read()
    require(data.has_arcs())
    require(any(data.arcs(name) for name in data.measured_files() if "/rigor_foundry/" in name))
    return hashes


def validate_receipt(
    directory: Path, identity: dict[str, str], index: int, count: int, command: list[str]
) -> list[str]:
    """Validate a completed same-attempt receipt against every actual artifact.

    Parameters
    ----------
    directory : Path
        Exact indexed artifact directory.
    identity : dict[str, str]
        Current expected source/run/interpreter identity.
    index : int
        Expected unique index.
    count : int
        Expected complete partition count.
    command : list[str]
        Exact invocation shared by this partition and its consumer.

    Returns
    -------
    list[str]
        Validated complete ordered collection.
    """
    require(set(identity) == IDENTITY_FIELDS and all(identity.values()))
    receipt = read_record(directory / "receipt.json")
    require(set(receipt) == {"schema_version", "identity", "command", "artifacts"})
    require(type(receipt["schema_version"]) is int and receipt["schema_version"] == 2)
    require(receipt["identity"] == identity and receipt["command"] == command)
    observed = read_record(directory / "observations.json")
    require(observed["strategy"] == identity["strategy"])
    require(observed["timings"] == json.loads(identity["schedule"]))
    collected = validate_observations(observed, index, count)
    require(receipt["artifacts"] == validate_artifacts(directory, len(observed["selected"])))
    return collected
