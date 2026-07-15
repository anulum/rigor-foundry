# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Repository validation primitives
"""Shared, fail-closed primitives for repository validation tools."""

from __future__ import annotations

import subprocess
from pathlib import Path

from rigor_foundry.git_provenance import GitRunner

ROOT = Path(__file__).resolve().parents[1]


class RepositoryError(RuntimeError):
    """Report an inability to establish repository state."""


def run(*argv: str, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    """Run one bounded repository command without a shell.

    Parameters
    ----------
    *argv:
        Command and arguments to execute.
    cwd:
        Working directory for the child process.

    Returns
    -------
    subprocess.CompletedProcess[str]
        Captured process result. Callers decide which exit codes are valid.
    """
    if argv and argv[0] == "git":
        completed = GitRunner().run(cwd, *argv[1:], check=False)
        return subprocess.CompletedProcess(
            args=completed.args,
            returncode=completed.returncode,
            stdout=completed.stdout.decode("utf-8"),
            stderr=completed.stderr.decode("utf-8"),
        )
    return subprocess.run(  # nosec B603
        argv,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )


def visible_files(root: Path = ROOT) -> tuple[Path, ...]:
    """Return Git-visible files, including untracked files on an unborn branch.

    Parameters
    ----------
    root:
        Git worktree to inspect.

    Returns
    -------
    tuple[pathlib.Path, ...]
        Sorted repository-relative paths not excluded by Git.

    Raises
    ------
    RepositoryError
        If Git cannot establish the visible worktree inventory.
    """
    result = run(
        "git",
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
        cwd=root,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or "Git inventory failed"
        raise RepositoryError(detail)
    paths = (
        Path(value)
        for value in result.stdout.split("\0")
        if value and ((root / value).exists() or (root / value).is_symlink())
    )
    return tuple(sorted(paths, key=lambda path: path.as_posix()))


def read_text(path: Path, root: Path = ROOT) -> str | None:
    """Read a visible text file, returning ``None`` for binary content.

    Parameters
    ----------
    path:
        Repository-relative path.
    root:
        Repository root containing ``path``.

    Returns
    -------
    str | None
        UTF-8 text, or ``None`` when the file is binary or not UTF-8.
    """
    data = (root / path).read_bytes()
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None
