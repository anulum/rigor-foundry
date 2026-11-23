# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Separate native test profiles
"""Keep reserved primary acceptance separate from ordinary native test production."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

NativeRole = Literal["ordinary", "primary"]
PRIMARY_TEST_HASHES = {
    "tests/test_windows_bootstrap_hostile.py": "4e3bc4bed2f7f20523ecb7c6de51c20ce159a417824fb95f1375e9a1616b7035",
    "tests/test_windows_hostile_controls.py": "1cf28c9e2e7940d31d8d657ecb94e20b7be80fc661bc898a08bcbd4a2edbb147",
}
PRIMARY_TEST_NAMES = {Path(name).name for name in PRIMARY_TEST_HASHES}
NATIVE_DIRECTORIES = {
    "ordinary": Path(".rigor-native-coverage"),
    "primary": Path(".rigor-native-primary"),
}


def native_test_files(
    root: Path,
    native_platform: str,
    python_version: str,
    *,
    hosted: bool,
    role: NativeRole = "ordinary",
) -> list[str]:
    """Select a complete role without importing reserved test modules.

    Parameters
    ----------
    root : Path
        Actual source checkout.
    native_platform : str
        Producer platform or required consumer slot.
    python_version : str
        Complete producer interpreter version.
    hosted : bool
        Whether the producer has the admitted hosted venue.
    role : {"ordinary", "primary"}, default "ordinary"
        Separate acceptance role. Primary requires hosted Windows Python 3.12.

    Returns
    -------
    list[str]
        Complete sorted ordinary inventory or exactly the two pinned primary owners.

    Raises
    ------
    ValueError
        The role, platform, inventory or primary admission is incomplete.
    """
    if native_platform not in {"win32", "darwin", "linux"} or role not in NATIVE_DIRECTORIES:
        raise ValueError("unsupported native test profile")
    files = sorted(
        path.relative_to(root).as_posix() for path in root.glob("tests/test_windows_*.py")
    )
    if role == "ordinary":
        ordinary = [name for name in files if name not in PRIMARY_TEST_HASHES]
        if not ordinary:
            raise ValueError("ordinary native test inventory is empty")
        return ordinary
    if not (hosted and native_platform == "win32" and python_version.startswith("3.12.")):
        raise ValueError("primary native profile requires hosted Windows Python 3.12")
    if not set(PRIMARY_TEST_HASHES).issubset(files):
        raise ValueError("primary native inventory is incomplete")
    for name, expected in PRIMARY_TEST_HASHES.items():
        path = root / name
        if path.is_symlink():
            raise ValueError("primary native source is linked")
        with path.open("rb") as source:
            actual = hashlib.file_digest(source, "sha256").hexdigest()
        if actual != expected:
            raise ValueError("primary native source identity differs")
    return sorted(PRIMARY_TEST_HASHES)


def native_coverage_config(role: NativeRole) -> str:
    """Configure subprocess branch collection for one separately attributed role.

    Parameters
    ----------
    role : {"ordinary", "primary"}
        Ordinary collection omits only the separately required primary test owners.
        Every product and constructor-owned test remains measured.

    Returns
    -------
    str
        Exact configuration retained alongside the raw producer artifacts.
    """
    config = "[run]\nbranch = True\ncore = ctrace\npatch = subprocess\n"
    if role == "ordinary":
        config += "omit =\n" + "".join(
            "    */" + name + "\n" for name in sorted(PRIMARY_TEST_HASHES)
        )
    return config
