# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Actual complete interpreter coverage union
"""Combine real shard processes and refuse incomplete or mixed artifact sets."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import coverage
import pytest
from test_run_test_shard import execute_shard, shard_environment, shard_repository

from tools.combine_test_shards import combine_shards, main
from tools.test_shard_evidence import digest, read_record


@pytest.fixture(scope="module")
def complete_union(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Retain all four actual successful partition processes on identical sources.

    Parameters
    ----------
    tmp_path_factory : pytest.TempPathFactory
        Independent module-scoped repository allocator.

    Returns
    -------
    Path
        Original repository and uncombined complete raw artifacts.
    """
    root = shard_repository(tmp_path_factory.mktemp("complete-shard-union"))
    directory = root / "test-shards"
    directory.mkdir()
    for index in range(4):
        result = execute_shard(root, index)
        assert result.returncode == 0, result.stdout + result.stderr
        (root / ".rigor-test-shard").rename(directory / f"shard-{index}")
    return root


def test_actual_complete_union_keeps_every_input_and_exports_exact_xml(
    complete_union: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Actual branch data from all indexed processes satisfies both thresholds.

    Parameters
    ----------
    complete_union : Path
        Original completed four-partition repository.
    tmp_path : Path
        Independent union execution directory.
    monkeypatch : pytest.MonkeyPatch
        Set real working directory and explicit run environment only.
    """
    root = shutil.copytree(complete_union, tmp_path / "repository")
    monkeypatch.chdir(root)
    for name, value in shard_environment(root).items():
        monkeypatch.setenv(name, value)
    directory = root / "test-shards"
    before = {
        str(path.relative_to(directory)): digest(path)
        for path in directory.rglob("*")
        if path.is_file()
    }
    monkeypatch.setattr(
        sys, "argv", ["combine-test-shards", "--directory", str(directory), "--count", "4"]
    )
    assert main() == 0
    assert (root / "coverage.xml").is_file()
    measured = coverage.Coverage(config_file="pyproject.toml", data_file=".coverage")
    measured.load()
    assert measured.report() == 100
    assert measured.report(include=["*/native_dispatch.py"]) == 100
    assert {
        str(path.relative_to(directory)): digest(path)
        for path in directory.rglob("*")
        if path.is_file()
    } == before


@pytest.mark.parametrize(
    "case",
    [
        "missing",
        "extra",
        "linked-root",
        "linked-shard",
        "non-directory",
        "attempt",
        "head",
        "collection",
        "corrupt",
        "existing-data",
        "existing-xml",
        "zero-count",
        "boolean-count",
    ],
)
def test_real_complete_union_refuses_missing_mixed_or_corrupt_inputs(
    complete_union: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    """Alter retained real producer inputs; never fabricate successful raw data.

    Parameters
    ----------
    complete_union : Path
        Immutable original complete process evidence.
    tmp_path : Path
        Independent altered repository.
    monkeypatch : pytest.MonkeyPatch
        Set actual working directory and explicit run environment only.
    case : str
        Actual missing, mixed or corrupted union input.
    """
    root = shutil.copytree(complete_union, tmp_path / "repository")
    directory = root / "test-shards"
    shard = directory / "shard-0"
    count = 4
    if case == "missing":
        shutil.rmtree(shard)
    elif case == "extra":
        (directory / "unrelated").mkdir()
    elif case == "linked-root":
        link = root / "linked-inputs"
        link.symlink_to(directory, target_is_directory=True)
        directory = link
    elif case == "linked-shard":
        saved = root / "retained-shard"
        shard.rename(saved)
        shard.symlink_to(saved, target_is_directory=True)
    elif case == "non-directory":
        shutil.rmtree(shard)
        shard.write_text("not an indexed directory")
    elif case in {"attempt", "head"}:
        receipt = read_record(shard / "receipt.json")
        receipt["identity"]["run_attempt" if case == "attempt" else "head"] = "different"
        (shard / "receipt.json").write_text(json.dumps(receipt))
    elif case == "collection":
        observed = read_record(shard / "observations.json")
        observed["collected"][-1] += "-different-unselected-item"
        (shard / "observations.json").write_text(json.dumps(observed))
        receipt = read_record(shard / "receipt.json")
        receipt["artifacts"]["observations.json"] = digest(shard / "observations.json")
        (shard / "receipt.json").write_text(json.dumps(receipt))
    elif case == "corrupt":
        (shard / ".coverage").write_bytes(b"corrupt real retained input")
    elif case in {"existing-data", "existing-xml"}:
        (root / (".coverage" if case == "existing-data" else "coverage.xml")).write_text(
            "unrelated output"
        )
    elif case == "zero-count":
        count = 0
    else:
        count = True
    monkeypatch.chdir(root)
    for name, value in shard_environment(root).items():
        monkeypatch.setenv(name, value)
    with pytest.raises((ValueError, coverage.exceptions.DataError)):
        combine_shards(directory, count)


def test_actual_partial_runtime_data_refuses_both_original_thresholds(
    complete_union: Path, tmp_path: Path
) -> None:
    """Real partial native data fails 98% and the distinct exact native gate.

    Parameters
    ----------
    complete_union : Path
        Actual completed partitions with differing runtime branch observations.
    tmp_path : Path
        Independent raw report directory.
    """
    root = shutil.copytree(complete_union, tmp_path / "repository")
    raw = root / "test-shards/shard-0/.coverage"
    environment = {**shard_environment(root), "COVERAGE_FILE": str(raw)}
    for arguments in (["--fail-under=98"], ["--include=*/native_dispatch.py", "--fail-under=100"]):
        result = subprocess.run(
            [sys.executable, "-m", "coverage", "report", *arguments],
            cwd=root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 2, result.stdout + result.stderr
        assert "Coverage failure" in result.stdout


def test_actual_union_module_entrypoint_requires_complete_attempt(
    complete_union: Path, tmp_path: Path
) -> None:
    """Run the actual external module and reject a later-attempt replay.

    Parameters
    ----------
    complete_union : Path
        Retained complete real successful producer processes.
    tmp_path : Path
        Independent actual union process directory.
    """
    root = shutil.copytree(complete_union, tmp_path / "repository")
    command = [
        sys.executable,
        "-m",
        "tools.combine_test_shards",
        "--directory",
        "test-shards",
        "--count",
        "4",
    ]
    original = shard_environment(root)
    wrong = subprocess.run(
        command,
        cwd=root,
        env=original | {"GITHUB_RUN_ATTEMPT": "3"},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert wrong.returncode != 0
    assert not (root / "coverage.xml").exists()
    valid = subprocess.run(
        command, cwd=root, env=original, capture_output=True, text=True, timeout=30
    )
    assert valid.returncode == 0, valid.stdout + valid.stderr
    assert (root / "coverage.xml").is_file()
