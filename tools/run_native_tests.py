# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Native Python coverage producer
"""Publish source-bound native test data only after real terminal pytest success."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path

import rigor_foundry
from tools.native_test_evidence import (
    native_pytest_command,
    native_test_files,
    validate_native_observations,
)
from tools.native_test_profiles import NATIVE_DIRECTORIES, NativeRole, native_coverage_config
from tools.ordinary_coverage import require_ordinary_coverage
from tools.test_shard_evidence import digest, require, source_identity

NATIVE_DIRECTORY = Path(".rigor-native-coverage")


def native_source_identity(
    root: Path, identity_environment: Mapping[str, str] | None = None
) -> tuple[str, dict[str, str], dict[str, str]]:
    """Read actual Git HEAD and preserve the difference between hosted and local evidence.

    Parameters
    ----------
    root : Path
        Genuine repository checkout containing the executed sources.
    identity_environment : Mapping[str, str] or None
        Caller-supplied run metadata, or the actual process environment. This is
        parsed metadata, not proof that a local caller ran on a hosted runner.

    Returns
    -------
    tuple[str, dict[str, str], dict[str, str]]
        Venue, actual complete identity, and the fixed identity environment used
        again after pytest. Local UUIDs never claim to be hosted Actions runs.
    """
    git = shutil.which("git")
    if git is None:
        raise ValueError("Git is unavailable")
    head = subprocess.run(
        [str(Path(git).resolve()), "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    environment = dict(os.environ if identity_environment is None else identity_environment)
    hosted = environment.get("GITHUB_ACTIONS") == "true"
    if hosted:
        require(environment.get("RUNNER_ENVIRONMENT") == "github-hosted")
        require(environment.get("GITHUB_SHA") == head)
        venue = "github"
    else:
        venue = "local"
        environment.update(
            {
                "GITHUB_REPOSITORY": root.name,
                "GITHUB_SHA": head,
                "GITHUB_RUN_ID": "local-" + uuid.uuid4().hex,
                "GITHUB_RUN_ATTEMPT": "1",
            }
        )
    return venue, source_identity(root, environment), environment


def native_package_root(root: Path) -> Path:
    """Verify every actual imported package source against this checkout.

    Parameters
    ----------
    root : Path
        Current source checkout.

    Returns
    -------
    Path
        Actual imported package directory, with complete matching Python inventory
        and bytes. Installed wheels and source imports retain their real paths.
    """
    source = root / "src" / "rigor_foundry"
    package_file = rigor_foundry.__file__
    require(package_file is not None)
    imported = Path(package_file).resolve().parent
    expected = {path.relative_to(source).as_posix(): digest(path) for path in source.rglob("*.py")}
    actual = {
        path.relative_to(imported).as_posix(): digest(path) for path in imported.rglob("*.py")
    }
    require(bool(expected) and actual == expected)
    return imported


def run_native_tests(files: Sequence[str] | None = None, *, role: NativeRole = "ordinary") -> int:
    """Run the declared native profile and retain an honest complete producer receipt.

    Parameters
    ----------
    files : Sequence[str] or None
        Optional single-file/local developer selection. Hosted producers always
        execute their complete discovered profile and reject selection overrides.
    role : {"ordinary", "primary"}, default "ordinary"
        Required acceptance role with separate inventory, output and receipt.

    Returns
    -------
    int
        Actual failing pytest status, or zero after source and artifact validation.
        An outer CI job or local supervisor owns the complete process lifetime.
    """
    root = Path.cwd().resolve()
    venue, identity, identity_environment = native_source_identity(root)
    hosted = venue == "github"
    require(not hosted or files is None)
    require(role != "primary" or files is None)
    allowed = native_test_files(
        root, sys.platform, platform.python_version(), hosted=hosted, role=role
    )
    selected = list(files) if files is not None else allowed
    require(set(selected).issubset(allowed))
    require(bool(selected) and len(selected) == len(set(selected)))
    require(
        all(
            Path(name).as_posix() == name
            and name.startswith("tests/")
            and (root / name).resolve(strict=True).is_relative_to(root)
            and (root / name).is_file()
            and not (root / name).is_symlink()
            for name in selected
        )
    )
    package_root = native_package_root(root)
    output = root / NATIVE_DIRECTORIES[role]
    output.mkdir()
    (output / "coverage.ini").write_bytes(native_coverage_config(role).encode("utf-8"))
    command = native_pytest_command(sys.executable, output, selected)
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("COVERAGE_", "COV_CORE_")) and key != "PYTEST_ADDOPTS"
    }
    environment["COVERAGE_FILE"] = str(output / ".coverage")
    with (
        (output / "pytest.stdout").open("x", encoding="utf-8") as stdout,
        (output / "pytest.stderr").open("x", encoding="utf-8") as stderr,
    ):
        result = subprocess.run(
            command, env=environment, stdout=stdout, stderr=stderr, check=False
        )
    if result.returncode != 0:
        return result.returncode
    require(source_identity(root, identity_environment) == identity)
    require(native_package_root(root) == package_root)
    if role == "ordinary":
        require_ordinary_coverage(output / ".coverage")
    artifacts = validate_native_observations(
        output, selected, require_primary=role == "primary", identity=identity
    )
    record = {
        "schema_version": 2,
        "role": role,
        "kind": "native-python-tests",
        "venue": venue,
        "identity": identity,
        "platform": sys.platform,
        "source_root": root.as_posix(),
        "package_root": package_root.as_posix(),
        "files": selected,
        "command": command,
        "artifacts": artifacts,
        "python_executable": sys.executable,
    }
    pending = output / "receipt.pending"
    pending.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
    pending.rename(output / "receipt.json")
    return 0


def main() -> int:
    """Run native evidence production with source-free CLI refusal text.

    Returns
    -------
    int
        Successful publication, actual pytest failure, or fixed contract refusal.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-file", action="append", dest="files")
    parser.add_argument("--role", choices=("ordinary", "primary"), default="ordinary")
    arguments = parser.parse_args()
    try:
        return run_native_tests(arguments.files, role=arguments.role)
    except (OSError, ValueError, subprocess.SubprocessError):
        print("Native test evidence is incomplete", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
