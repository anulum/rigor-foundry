# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Native coverage input admission
"""Validate complete declared platform inputs before supplying raw branch data to a union."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import Literal

from tools.native_test_evidence import (
    native_test_files,
    validate_native_receipt,
)
from tools.test_shard_evidence import require


def native_coverage_inputs(
    root: Path,
    directory: Path | None,
    identity: dict[str, str],
    *,
    platforms: Sequence[str] = ("win32", "darwin"),
    expected_venue: Literal["github", "local"] = "github",
) -> tuple[list[str], list[str], list[str]]:
    """Admit exact same-source/interpreter/attempt native inputs and original path roots.

    Parameters
    ----------
    root : Path
        Actual source checkout represented by the caller's complete identity.
    directory : Path or None
        Artifact root containing exactly one directory per required platform.
        None retains the standalone Linux-only shard utility's original scope.
    identity : dict[str, str]
        Complete expected source, interpreter and run-attempt identity.
    platforms : Sequence[str], default ("win32", "darwin")
        Required complete platform slots. Explicit local qualification can name
        its actual platform; CI uses both default native platforms.
    expected_venue : {"github", "local"}, default "github"
        Require hosted CI evidence by default. Explicit local admission preserves
        the actual local venue and does not qualify a hosted platform union.

    Raises
    ------
    ValueError
        A receipt is stale, has a different role or contains primary-owned data.
        Primary acceptance remains separately required.

    Returns
    -------
    tuple[list[str], list[str], list[str]]
        Raw database paths, original package roots and original maintained-test
        roots. Coverage's ordinary path mapping combines identical sources;
        raw databases, event identities and arcs remain unchanged.
    """
    require(
        bool(platforms)
        and len(set(platforms)) == len(platforms)
        and all(name in {"win32", "darwin", "linux"} for name in platforms)
    )
    inputs: list[str] = []
    packages: list[str] = []
    tests: list[str] = []
    if directory is None:
        return inputs, packages, tests
    require(directory.is_dir() and not directory.is_symlink())
    require({path.name for path in directory.iterdir()} == set(platforms))
    for native_platform in platforms:
        artifact = directory / native_platform
        files = native_test_files(
            root, native_platform, identity["python"], hosted=expected_venue == "github"
        )
        record = validate_native_receipt(
            artifact, identity, native_platform, files, expected_venue=expected_venue
        )
        source = PurePosixPath(record["source_root"])
        inputs.append(str((artifact / ".coverage").resolve()))
        packages.extend([(source / "src/rigor_foundry").as_posix(), record["package_root"]])
        tests.append((source / "tests").as_posix())
    return inputs, packages, tests
