# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Ordinary coverage ownership admission
"""Check database owner metadata before any ordinary consumer reads branch data."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from tools.native_test_profiles import PRIMARY_TEST_NAMES, NativeRole


def require_ordinary_coverage(path: Path) -> None:
    """Reject reserved owners or contexts without loading, clipping or rewriting arcs.

    Parameters
    ----------
    path : Path
        Terminal coverage database belonging to an ordinary producer.

    Raises
    ------
    ValueError
        The database is linked, missing, malformed or names primary acceptance.
    """
    if path.is_symlink() or not path.is_file():
        raise ValueError("ordinary coverage database is unavailable")
    try:
        with closing(
            sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
        ) as db:
            names = db.execute("SELECT path FROM file UNION ALL SELECT context FROM context")
            for (name,) in names:
                owner = name.split("::", 1)[0].replace("\\", "/").rsplit("/", 1)[-1]
                if owner in PRIMARY_TEST_NAMES:
                    raise ValueError("primary-owned data cannot supply ordinary coverage")
    except sqlite3.Error as error:
        raise ValueError("ordinary coverage database is malformed") from error


def require_role_coverage(role: NativeRole, path: Path) -> None:
    """Apply one native role's coverage admission before its receipt is written.

    Parameters
    ----------
    role : {"ordinary", "primary"}
        Acceptance role of the producer that wrote the database.
    path : Path
        Terminal coverage database of that producer.

    Raises
    ------
    ValueError
        An ordinary database is linked, missing, malformed or names primary acceptance.

    Notes
    -----
    A primary producer is admitted by its required successful calls, which the
    observation validation checks; its database is never an ordinary input.
    """
    if role == "ordinary":
        require_ordinary_coverage(path)
