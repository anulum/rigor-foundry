# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Native coverage input and path qualification
"""Admit real native inputs and preserve original foreign branch data under ordinary path mapping."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import warnings
from pathlib import Path

import coverage
import pytest
from test_run_native_tests import completed_native as completed_native

from tools._repository import ROOT
from tools.native_coverage import native_coverage_inputs
from tools.test_shard_evidence import digest, read_record


def test_standalone_linux_union_preserves_original_no_native_scope(completed_native: Path) -> None:
    """Retain the original standalone utility without claiming a native-platform union.

    Parameters
    ----------
    completed_native : Path
        Actual completed source and local producer evidence.
    """
    record = read_record(completed_native / ".rigor-native-coverage/receipt.json")
    assert native_coverage_inputs(completed_native, None, record["identity"]) == ([], [], [])


def test_actual_local_profile_keeps_its_venue_and_original_paths(
    completed_native: Path, tmp_path: Path
) -> None:
    """Admit complete explicit local inputs and refuse their use as hosted evidence.

    Parameters
    ----------
    completed_native : Path
        Actual successful native producer fixture.
    tmp_path : Path
        Owned platform artifact layout.
    """
    directory = tmp_path / "native"
    artifact = shutil.copytree(
        completed_native / ".rigor-native-coverage", directory / sys.platform
    )
    record = read_record(artifact / "receipt.json")
    before = digest(artifact / ".coverage")
    inputs, packages, tests = native_coverage_inputs(
        completed_native,
        directory,
        record["identity"],
        platforms=(sys.platform,),
        expected_venue="local",
    )
    assert inputs == [str((artifact / ".coverage").resolve())]
    assert packages == [
        (completed_native / "src/rigor_foundry").as_posix(),
        record["package_root"],
    ]
    assert tests == [(completed_native / "tests").as_posix()]
    assert digest(artifact / ".coverage") == before
    with pytest.raises(ValueError):
        native_coverage_inputs(
            completed_native, directory, record["identity"], platforms=(sys.platform,)
        )


@pytest.mark.parametrize(
    "case", ["absent", "missing", "extra", "duplicate", "unsupported", "identity"]
)
def test_incomplete_or_different_platform_inputs_are_refused(
    completed_native: Path, tmp_path: Path, case: str
) -> None:
    """Refuse wrong slots and expected identity without changing genuine input receipts.

    Parameters
    ----------
    completed_native : Path
        Immutable actual completed producer.
    tmp_path : Path
        Owned artifact copy.
    case : str
        Actual layout or declared-input defect.
    """
    directory = tmp_path / "native"
    shutil.copytree(completed_native / ".rigor-native-coverage", directory / sys.platform)
    record = read_record(completed_native / ".rigor-native-coverage/receipt.json")
    platforms: tuple[str, ...] = (sys.platform,)
    identity = dict(record["identity"])
    if case == "absent":
        directory = tmp_path / "absent"
    elif case == "missing":
        platforms = ("win32", "darwin")
    elif case == "extra":
        (directory / "extra").mkdir()
    elif case == "duplicate":
        platforms = (sys.platform, sys.platform)
    elif case == "unsupported":
        platforms = ("unsupported",)
    else:
        identity["head"] = "different-head"
    with pytest.raises(ValueError):
        native_coverage_inputs(
            completed_native, directory, identity, platforms=platforms, expected_venue="local"
        )


def test_real_windows_data_maps_every_original_package_and_test_arc(
    tmp_path: Path,
) -> None:
    """Read genuine foreign data and map paths without altering any branch or context.

    This metadata-only test does not merge different interpreter executions.
    Local qualification can supply the exact retained source snapshot of an
    earlier Windows producer; hosted CI supplies the current source and artifact.

    Parameters
    ----------
    tmp_path : Path
        Owned mapped database and copied Windows artifact allocation.
    """
    value = os.environ.get("RIGOR_NATIVE_WINDOWS_EVIDENCE_DIR")
    assert value, "Actual complete Windows producer evidence must be supplied"
    source = Path(os.environ.get("RIGOR_NATIVE_WINDOWS_SOURCE_ROOT", str(ROOT)))
    original = Path(value)
    record = read_record(original / "receipt.json")
    assert record["platform"] == "win32" and record["venue"] in {"local", "github"}
    identity = record["identity"]
    environment = {
        "GITHUB_REPOSITORY": identity["repository"],
        "GITHUB_RUN_ID": identity["run_id"],
        "GITHUB_RUN_ATTEMPT": identity["run_attempt"],
        "GITHUB_SHA": identity["head"],
        "RIGOR_TEST_SHARD_STRATEGY": identity["strategy"],
    }
    actual = json.loads(
        subprocess.check_output(
            [
                sys.executable,
                "-P",
                "-c",
                "import json,os;from pathlib import Path;"
                "from tools.test_shard_evidence import source_identity;"
                "print(json.dumps(source_identity(Path.cwd(),dict(os.environ))))",
            ],
            cwd=source,
            env={
                **os.environ,
                **environment,
                "PYTHONPATH": os.pathsep.join((str(source / "src"), str(source))),
            },
            text=True,
            timeout=20,
        )
    )
    assert all(actual[name] == identity[name] for name in identity if name != "python")
    assert (
        subprocess.check_output(
            ["git", "-C", str(source), "rev-parse", "HEAD"], text=True, timeout=10
        ).strip()
        == identity["head"]
    )
    directory = tmp_path / "native"
    artifact = shutil.copytree(original, directory / "win32")
    before = digest(artifact / ".coverage")
    inputs, packages, tests = native_coverage_inputs(
        source,
        directory,
        identity,
        platforms=("win32",),
        expected_venue=record["venue"],
    )
    measured = coverage.Coverage(config_file=False, data_file=str(tmp_path / ".coverage"))
    measured.set_option(
        "paths",
        {
            "rigor_foundry": [str(source / "src/rigor_foundry"), *packages],
            "native_tests": [str(source / "tests"), *tests],
        },
    )
    raw = coverage.CoverageData(basename=str(artifact / ".coverage"))
    raw.read()
    try:
        with warnings.catch_warnings(record=True) as emitted:
            warnings.simplefilter("always")
            measured.combine(data_paths=inputs, strict=True, keep=True)
        assert not emitted
        measured.save()
        mapped = measured.get_data()
        assert raw.has_arcs() and mapped.has_arcs()
        assert raw.measured_contexts() == mapped.measured_contexts()
        expected: dict[str, set[tuple[int, int]]] = {}
        groups = {
            record["package_root"]: source / "src/rigor_foundry",
            record["source_root"] + "/src/rigor_foundry": source / "src/rigor_foundry",
            record["source_root"] + "/tests": source / "tests",
        }
        for filename in raw.measured_files():
            normalized = filename.replace("\\", "/")
            matches = [
                (prefix, target)
                for prefix, target in groups.items()
                if normalized.startswith(prefix + "/")
            ]
            assert len(matches) == 1
            prefix, target = matches[0]
            suffix = normalized.removeprefix(prefix + "/")
            local = str((target / suffix).resolve(strict=True))
            expected.setdefault(local, set()).update(raw.arcs(filename) or [])
        assert len(expected) == len(raw.measured_files())
        assert set(mapped.measured_files()) == set(expected)
        assert all(set(mapped.arcs(name) or []) == arcs for name, arcs in expected.items())
        assert digest(artifact / ".coverage") == before
    finally:
        raw.close(force=True)
        measured.get_data().close(force=True)
