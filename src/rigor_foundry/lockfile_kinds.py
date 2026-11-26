# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — lockfile kind detection
"""Name the kind of a tracked lockfile from its exact file name, and Yarn's from its text.

Every kind except Yarn has a file name of its own. Yarn 1 and Yarn 2+ both write
``yarn.lock``: Yarn 1 opens it with the ``# yarn lockfile v1`` header comment, and Yarn 2+
writes a top-level ``__metadata:`` block. A ``yarn.lock`` that shows neither form, or both,
is refused rather than guessed.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Final

from .lockfile_model import LockfileKind, LockfileRefusal

YARN_LOCK: Final = "yarn.lock"
_KINDS_BY_NAME: Final[dict[str, LockfileKind]] = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "pnpm-lock.yaml": "pnpm",
    "Cargo.lock": "cargo",
    "go.sum": "go",
    "poetry.lock": "poetry",
    "Pipfile.lock": "pipenv",
}
_YARN_V1_HEADER: Final = "# yarn lockfile v1"
_YARN_BERRY_METADATA: Final = "__metadata:"


def is_lockfile_path(path: str) -> bool:
    """Return whether a repository-relative path names a lockfile the rules read.

    Parameters
    ----------
    path : str
        A repository-relative POSIX path.

    Returns
    -------
    bool
        Whether its file name is exactly one of the lockfile names.
    """
    name = PurePosixPath(path).name
    return name == YARN_LOCK or name in _KINDS_BY_NAME


def _yarn_kind(text: str) -> LockfileKind:
    """Return Yarn's lockfile kind from its text, or refuse an ambiguous file."""
    lines = text.splitlines()
    leading: list[str] = []
    for line in lines:
        if line and not line.startswith("#"):
            break
        leading.append(line)
    v1 = _YARN_V1_HEADER in leading
    berry = _YARN_BERRY_METADATA in lines
    if v1 == berry:
        raise LockfileRefusal("ambiguous-yarn-lock")
    return "yarn-v1" if v1 else "yarn-berry"


def lockfile_kind(path: str, text: str) -> LockfileKind:
    """Return the kind of one lockfile.

    Parameters
    ----------
    path : str
        A repository-relative POSIX path that ``is_lockfile_path`` accepts.
    text : str
        The file text; only ``yarn.lock`` needs it.

    Returns
    -------
    LockfileKind
        The kind.

    Raises
    ------
    ValueError
        If the path does not name a lockfile.
    LockfileRefusal
        If a ``yarn.lock`` shows neither Yarn form, or both.
    """
    name = PurePosixPath(path).name
    if name == YARN_LOCK:
        return _yarn_kind(text)
    kind = _KINDS_BY_NAME.get(name)
    if kind is None:
        raise ValueError(f"not a lockfile path: {path}")
    return kind
