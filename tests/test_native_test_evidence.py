# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Native producer artifact qualification
"""Validate actual producer artifacts and refuse altered metadata without inventing execution."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest
from test_run_native_tests import NATIVE_OWNER
from test_run_native_tests import completed_native as completed_native

from tools._repository import ROOT
from tools.native_test_evidence import (
    PRIMARY_TEST_HASHES,
    PRIMARY_TEST_NAMES,
    native_pytest_command,
    native_test_files,
    validate_native_observations,
    validate_native_receipt,
)
from tools.native_test_profiles import DARWIN_TEST_FILES
from tools.test_shard_evidence import (
    ARTIFACT_NAMES,
    digest,
    read_record,
    source_identity,
    validate_observations,
)


@pytest.mark.parametrize(
    ("native_platform", "python_version", "hosted", "primary"),
    [
        ("win32", "3.12.13", True, True),
        ("win32", "3.12.13", False, False),
        ("win32", "3.12.13", True, False),
        ("win32", "3.11.15", True, False),
        ("win32", "3.13.14", True, False),
        ("linux", "3.12.13", True, False),
        ("darwin", "3.12.13", True, False),
    ],
)
def test_actual_native_inventory_preserves_primary_platform_and_interpreter_boundary(
    native_platform: str, python_version: str, hosted: bool, primary: bool
) -> None:
    """Inspect maintained file identities without executing reserved native controls.

    Parameters
    ----------
    native_platform : str
        Declared producer platform metadata.
    python_version : str
        Supported pinned interpreter metadata.
    hosted : bool
        Declared hosted inventory admission.
    primary : bool
        Whether that exact profile admits the two unchanged primary-owned files.
        Every ordinary darwin profile also holds the named macOS test module.
    """
    actual = native_test_files(
        ROOT,
        native_platform,
        python_version,
        hosted=hosted,
        role="primary" if primary else "ordinary",
    )
    complete = sorted(
        path.relative_to(ROOT).as_posix() for path in ROOT.glob("tests/test_windows_*.py")
    )
    darwin = list(DARWIN_TEST_FILES) if native_platform == "darwin" else []
    expected = (
        sorted(PRIMARY_TEST_HASHES)
        if primary
        else sorted([name for name in complete if name not in PRIMARY_TEST_HASHES] + darwin)
    )
    assert actual == expected


def test_empty_or_unsupported_native_inventory_is_refused(tmp_path: Path) -> None:
    """Refuse an absent native profile or unsupported platform input.

    Parameters
    ----------
    tmp_path : Path
        Actual empty directory.
    """
    with pytest.raises(ValueError):
        native_test_files(tmp_path, "linux", "3.12.13", hosted=False)
    with pytest.raises(ValueError):
        native_test_files(ROOT, "unsupported", "3.12.13", hosted=False)


def test_hosted_primary_profile_refuses_an_actual_local_source_subset(
    completed_native: Path,
) -> None:
    """Refuse a real ordinary-only checkout before reading absent reserved-owner files.

    Parameters
    ----------
    completed_native : Path
        Genuine complete package fixture with one ordinary maintained test file
        and actual successful local producer evidence.
    """
    with pytest.raises(ValueError):
        native_test_files(completed_native, "win32", "3.12.13", hosted=True, role="primary")


def test_local_receipt_requires_explicit_local_admission(completed_native: Path) -> None:
    """Accept real local execution only in local mode and retain strict hosted rejection.

    Parameters
    ----------
    completed_native : Path
        Actual successful producer fixture from the owning launcher tests.
    """
    directory = completed_native / ".rigor-native-coverage"
    record = read_record(directory / "receipt.json")
    assert record["command"] == native_pytest_command(
        record["python_executable"], directory, [NATIVE_OWNER]
    )
    assert (
        validate_native_receipt(
            directory,
            record["identity"],
            record["platform"],
            [NATIVE_OWNER],
            expected_venue="local",
        )
        == record
    )
    with pytest.raises(ValueError):
        validate_native_receipt(directory, record["identity"], record["platform"], [NATIVE_OWNER])
    assert validate_native_observations(directory, [NATIVE_OWNER], require_primary=False) == {
        name: digest(directory / name) for name in ARTIFACT_NAMES
    }
    with pytest.raises(ValueError):
        validate_native_observations(directory, [], require_primary=False)
    with pytest.raises(ValueError):
        validate_native_observations(directory, [NATIVE_OWNER], require_primary=True)
    with pytest.raises(ValueError):
        validate_native_receipt(directory, {}, record["platform"], [NATIVE_OWNER])


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("extra", True),
        ("schema_version", True),
        ("schema_version", 1),
        ("role", "primary"),
        ("role", "unknown"),
        ("kind", "different-evidence"),
        ("venue", "different-venue"),
        ("identity", {}),
        ("platform", "different-platform"),
        ("files", []),
        ("source_root", None),
        ("source_root", ""),
        ("package_root", 0),
        ("python_executable", ""),
        ("command", []),
        ("artifacts", {}),
    ],
)
def test_changed_receipt_cannot_substitute_identity_command_or_raw_artifacts(
    completed_native: Path, tmp_path: Path, field: str, value: Any
) -> None:
    """Reject known-invalid copies while retaining every original raw producer byte.

    Parameters
    ----------
    completed_native : Path
        Unchanged real terminal producer artifacts.
    tmp_path : Path
        Owned mutation directory.
    field : str
        Receipt field to alter.
    value : Any
        Invalid JSON metadata value; never accepted as an execution.
    """
    original = completed_native / ".rigor-native-coverage"
    directory = shutil.copytree(original, tmp_path / "artifacts")
    record = read_record(original / "receipt.json")
    changed = {**record, field: value}
    (directory / "receipt.json").write_text(json.dumps(changed))
    with pytest.raises(ValueError):
        validate_native_receipt(
            directory,
            record["identity"],
            record["platform"],
            [NATIVE_OWNER],
            expected_venue="local",
        )


@pytest.fixture(scope="module")
def actual_primary_artifacts() -> Path:
    """Require existing independent native observations without launching primary controls.

    Returns
    -------
    Path
        Complete genuine primary/native artifact directory supplied by the
        competent producer. CI must download it before these metadata tests.
    """
    value = os.environ.get("RIGOR_NATIVE_PRIMARY_EVIDENCE_DIR")
    assert value, (
        "Actual primary/native observations must be supplied before metadata qualification"
    )
    directory = Path(value)
    assert all((directory / name).is_file() for name in ARTIFACT_NAMES)
    return directory


def test_actual_primary_observations_have_all_required_successful_calls(
    actual_primary_artifacts: Path,
) -> None:
    """Parse existing real independent events; this test performs no primary execution.

    Parameters
    ----------
    actual_primary_artifacts : Path
        Genuine unchanged producer observations, JUnit and branch database.
    """
    consumer = source_identity(ROOT, dict(os.environ))
    # Only hosted Windows Python 3.12 produces the primary profile, while every
    # interpreter shard consumes it. The run, source, configuration and schedule
    # must equal this consumer's; the producer interpreter is the receipt's, and
    # the primary inventory admits only 3.12.
    receipt = read_record(actual_primary_artifacts / "receipt.json")
    identity = {**consumer, "python": receipt["identity"]["python"]}
    expected = native_test_files(ROOT, "win32", identity["python"], hosted=True, role="primary")
    assert (
        validate_native_receipt(
            actual_primary_artifacts, identity, "win32", expected, role="primary"
        )["role"]
        == "primary"
    )
    observed = read_record(actual_primary_artifacts / "observations.json")
    selected = validate_observations(observed, 0, 1)
    files = sorted({node.split("::", 1)[0] for node in selected})
    assert PRIMARY_TEST_NAMES.issubset({Path(name.replace("\\", "/")).name for name in files})
    assert validate_native_observations(actual_primary_artifacts, files, require_primary=True) == {
        name: digest(actual_primary_artifacts / name) for name in ARTIFACT_NAMES
    }


@pytest.mark.parametrize("case", ["parent", "subtest"])
def test_primary_admission_refuses_missing_actual_parent_or_subtest_success(
    actual_primary_artifacts: Path, tmp_path: Path, case: str
) -> None:
    """Reject altered metadata copies without changing or replaying the competent originals.

    Parameters
    ----------
    actual_primary_artifacts : Path
        Immutable independent real native observations.
    tmp_path : Path
        Owned copy for known-invalid metadata.
    case : str
        Change a required actual parent call or one of its actual subtest calls.
    """
    directory = shutil.copytree(actual_primary_artifacts, tmp_path / "artifacts")
    observed = read_record(directory / "observations.json")
    selected = validate_observations(observed, 0, 1)
    files = sorted({node.split("::", 1)[0] for node in selected})
    node = next(
        item
        for item in selected
        if Path(item.split("::", 1)[0].replace("\\", "/")).name in PRIMARY_TEST_NAMES
        and observed["subtests"].get(item)
    )
    if case == "parent":
        observed["phases"][node][1] = ["call", "skipped"]
    else:
        observed["subtests"][node][0] = ["call", "skipped"]
    (directory / "observations.json").write_text(json.dumps(observed))
    with pytest.raises(ValueError):
        validate_native_observations(directory, files, require_primary=True)
