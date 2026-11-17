# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Native interpreter test evidence
"""Bind native Python observations to the same source and interpreter as Linux shards."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Literal

from tools.native_test_profiles import NATIVE_DIRECTORIES, NativeRole, native_coverage_config
from tools.native_test_profiles import PRIMARY_TEST_HASHES as PRIMARY_TEST_HASHES
from tools.native_test_profiles import PRIMARY_TEST_NAMES as PRIMARY_TEST_NAMES
from tools.native_test_profiles import native_test_files as native_test_files
from tools.ordinary_coverage import require_ordinary_coverage
from tools.test_shard_evidence import (
    ARTIFACT_NAMES,
    IDENTITY_FIELDS,
    artifact_bytes,
    read_record,
    require,
    validate_artifacts,
    validate_observations,
)

NATIVE_RECEIPT_FIELDS = {
    "schema_version",
    "kind",
    "venue",
    "role",
    "identity",
    "platform",
    "source_root",
    "package_root",
    "files",
    "command",
    "artifacts",
    "python_executable",
}


def native_pytest_command(executable: str, directory: Path, files: Sequence[str]) -> list[str]:
    """Construct the exact measured native invocation without inherited selectors.

    Parameters
    ----------
    executable : str
        Actual producer Python executable.
    directory : Path
        Owned artifact allocation.
    files : Sequence[str]
        Complete declared maintained test selection.

    Returns
    -------
    list[str]
        Literal pytest arguments. Thresholds belong to the complete platform union.
    """
    return [
        executable,
        "-m",
        "pytest",
        *files,
        "-q",
        "-ra",
        "--tb=short",
        "-p",
        "tools.pytest_native_tests",
        "--test-shard-index",
        "0",
        "--test-shard-count",
        "1",
        "--test-shard-observations",
        (directory / "observations.json").as_posix(),
        "--junitxml",
        (directory / "junit.xml").as_posix(),
        "--cov-config",
        (directory / "coverage.ini").as_posix(),
        "--cov=rigor_foundry",
        "--cov=tests",
        "--cov-context=test",
        "--cov-branch",
        "--cov-report=",
        "--cov-fail-under=0",
    ]


def validate_native_observations(
    directory: Path,
    files: Sequence[str],
    *,
    require_primary: bool,
    identity: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Reconcile real successful pytest phases, selected owners and retained branch data.

    Parameters
    ----------
    directory : Path
        Actual terminal pytest artifact directory.
    files : Sequence[str]
        Expected complete test-file selection.
    require_primary : bool
        Require the competent owner's twelve native regressions without skips.
    identity : Mapping[str, str] or None
        Expected source-bound observation strategy and timing snapshot. Producers
        and receipt consumers always supply this; standalone observation parsing
        makes no source/run identity claim.

    Returns
    -------
    dict[str, str]
        Digests of all three validated raw observations.
    """
    observed = read_record(directory / "observations.json")
    if identity is not None:
        require(observed["strategy"] == identity["strategy"])
        require(observed["timings"] == json.loads(identity["schedule"]))
    selected = validate_observations(observed, 0, 1)
    require({node.split("::", 1)[0] for node in selected} == set(files))
    if require_primary:
        # Independent replays retain their actual file-ID namespaces; the consumer
        # separately requires the exact declared CI test-file inventory.
        primary = [
            node
            for node in selected
            if Path(node.split("::", 1)[0].replace("\\", "/")).name in PRIMARY_TEST_NAMES
        ]
        require(len(primary) == 12)
        complete = [["setup", "passed"], ["call", "passed"], ["teardown", "passed"]]
        require(all(observed["phases"][node] == complete for node in primary))
        require(
            all(
                event == ["call", "passed"]
                for node in primary
                for event in observed["subtests"].get(node, [])
            )
        )
    return validate_artifacts(directory, len(selected))


def validate_native_receipt(
    directory: Path,
    identity: dict[str, str],
    native_platform: str,
    files: Sequence[str],
    *,
    expected_venue: Literal["github", "local"] = "github",
    role: NativeRole = "ordinary",
) -> dict[str, Any]:
    """Require a successful same-attempt native producer before accepting its database.

    Parameters
    ----------
    directory : Path
        Downloaded exact native-platform artifact.
    identity : dict[str, str]
        Current Linux union's actual source, interpreter and run identity.
    native_platform : str
        Required platform for this artifact slot.
    files : Sequence[str]
        Complete expected native inventory for this interpreter.
    expected_venue : {"github", "local"}, default "github"
        Required producer venue. The CI union requires the default hosted venue;
        explicit local qualification never supplies hosted acceptance.
    role : {"ordinary", "primary"}, default "ordinary"
        Required separate acceptance role; stale unannotated receipts are refused.

    Returns
    -------
    dict[str, Any]
        Validated receipt carrying the original source and installed-package roots
        needed for source-identical coverage path mapping.
    """
    require(set(identity) == IDENTITY_FIELDS and all(identity.values()))
    require(expected_venue in {"github", "local"})
    require(directory.is_dir() and not directory.is_symlink())
    record = read_record(directory / "receipt.json")
    require(set(record) == NATIVE_RECEIPT_FIELDS)
    require(type(record["schema_version"]) is int and record["schema_version"] == 2)
    require(record["role"] == role and role in NATIVE_DIRECTORIES)
    require(record["kind"] == "native-python-tests" and record["venue"] == expected_venue)
    require(record["identity"] == identity and record["platform"] == native_platform)
    require(record["files"] == list(files))
    require(
        (role == "primary" and set(files) == set(PRIMARY_TEST_HASHES))
        or (role == "ordinary" and not set(files).intersection(PRIMARY_TEST_HASHES))
    )
    require(
        role != "primary"
        or (
            expected_venue == "github"
            and native_platform == "win32"
            and identity["python"].startswith("3.12.")
        )
    )
    for field in ("source_root", "package_root", "python_executable"):
        require(isinstance(record[field], str) and bool(record[field]))
    require(
        record["command"]
        == native_pytest_command(
            record["python_executable"],
            Path(record["source_root"]) / NATIVE_DIRECTORIES[role],
            files,
        )
    )
    require(
        artifact_bytes(directory / "coverage.ini").decode("utf-8") == native_coverage_config(role)
    )
    if role == "ordinary":
        require_ordinary_coverage(directory / ".coverage")
    require(
        record["artifacts"]
        == validate_native_observations(
            directory,
            files,
            require_primary=role == "primary",
            identity=identity,
        )
    )
    require(set(record["artifacts"]) == set(ARTIFACT_NAMES))
    return record
