# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — consumer Action output guard
"""Reject consumer Action outputs that could overwrite adopter content."""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

_GIT = "/usr/bin/git"


def _git(root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    """Run one bounded, non-shell Git query against ``root``."""
    return subprocess.run(  # nosec B603
        [_GIT, "-C", str(root), *arguments],
        check=False,
        capture_output=True,
        shell=False,
        text=True,
        timeout=10,
    )


def consumer_output_errors(
    repository_root: Path,
    outputs: tuple[Path, ...],
    *,
    working_directory: Path | None = None,
) -> list[str]:
    """Return overwrite-policy failures for explicit Action output paths.

    Parameters
    ----------
    repository_root:
        Exact adopter Git worktree root.
    outputs:
        Explicit report paths supplied to the consumer Action.
    working_directory:
        Base for relative output paths. The process working directory is used
        when omitted, matching the CLI path contract.
    """
    errors: list[str] = []
    try:
        root = repository_root.resolve(strict=True)
    except OSError:
        return ["repository root is unavailable"]
    if not root.is_dir():
        return ["repository root is not a directory"]
    top_level = _git(root, "rev-parse", "--show-toplevel")
    if top_level.returncode != 0:
        return ["repository root is not a Git worktree"]
    try:
        discovered_root = Path(top_level.stdout.strip()).resolve(strict=True)
    except OSError:
        return ["Git worktree root is unavailable"]
    if discovered_root != root:
        return ["repository root must equal the Git worktree root"]

    base = Path.cwd() if working_directory is None else working_directory
    normalized: set[Path] = set()
    for output in outputs:
        candidate = output if output.is_absolute() else base / output
        if not candidate.name:
            errors.append(f"output path has no filename: {output}")
            continue
        try:
            parent = candidate.parent.resolve(strict=True)
        except OSError:
            errors.append(f"output parent is unavailable: {output}")
            continue
        if not parent.is_dir():
            errors.append(f"output parent is not a directory: {output}")
            continue
        target = parent / candidate.name
        if target in normalized:
            errors.append(f"output paths must be distinct: {output}")
            continue
        normalized.add(target)
        if os.path.lexists(target):
            errors.append(f"output path already exists: {output}")
            continue
        try:
            relative = target.relative_to(root).as_posix()
        except ValueError:
            continue
        tracked = _git(root, "ls-files", "--error-unmatch", "--", relative)
        if tracked.returncode == 0:
            errors.append(f"output path is tracked by Git: {output}")
            continue
        if tracked.returncode != 1:
            errors.append(f"tracked-path query failed: {output}")
            continue
        ignored = _git(root, "check-ignore", "--quiet", "--", relative)
        if ignored.returncode == 1:
            errors.append(f"in-repository output path must be ignored: {output}")
        elif ignored.returncode != 0:
            errors.append(f"ignore-policy query failed: {output}")
    return errors


def main(argv: list[str] | None = None) -> int:
    """Validate consumer Action output arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--output", required=True, action="append", type=Path)
    arguments = parser.parse_args(argv)
    errors = consumer_output_errors(
        arguments.repository_root,
        tuple(arguments.output),
    )
    if errors:
        print("Consumer output guard failed:")
        for error in errors:
            print(f"- {error}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
