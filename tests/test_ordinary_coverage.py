# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Ordinary coverage owner metadata tests
"""Admit actual ordinary producer data and refuse invalid copies before branch reads."""

from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path

import pytest
from test_run_native_tests import completed_native as completed_native

from tools.native_test_profiles import PRIMARY_TEST_NAMES
from tools.ordinary_coverage import require_ordinary_coverage, require_role_coverage
from tools.test_shard_evidence import digest


def test_actual_ordinary_database_is_admitted_without_byte_changes(completed_native: Path) -> None:
    """Keep every original owner, context and raw byte after read-only admission.

    Parameters
    ----------
    completed_native : Path
        Successful actual ordinary CLI producer.
    """
    path = completed_native / ".rigor-native-coverage/.coverage"
    before = digest(path)
    require_ordinary_coverage(path)
    assert digest(path) == before


@pytest.mark.parametrize("metadata", ["file", "context"])
def test_reserved_owner_metadata_is_refused_without_reading_or_clipping_arcs(
    completed_native: Path, tmp_path: Path, metadata: str
) -> None:
    """Reject known-invalid ordinary copies; no primary execution or arcs are created.

    Parameters
    ----------
    completed_native : Path
        Immutable actual ordinary producer data.
    tmp_path : Path
        Allocation for a deliberately invalid metadata copy.
    metadata : str
        Relabel an existing file or context to the reserved owner namespace.
    """
    original = completed_native / ".rigor-native-coverage/.coverage"
    path = tmp_path / ".coverage"
    shutil.copyfile(original, path)
    primary = sorted(PRIMARY_TEST_NAMES)[0]
    with sqlite3.connect(path) as db:
        if metadata == "file":
            db.execute(
                "UPDATE file SET path = ? WHERE id = (SELECT min(id) FROM file)",
                ("C:\\source\\tests\\" + primary,),
            )
        else:
            db.execute(
                "UPDATE context SET context = ? WHERE id = (SELECT min(id) FROM context)",
                ("tests/" + primary + "::invalid_copy|run",),
            )
    before = digest(path)
    with pytest.raises(ValueError, match="primary-owned data"):
        require_ordinary_coverage(path)
    assert digest(path) == before


@pytest.mark.parametrize("case", ["missing", "linked", "malformed"])
def test_unavailable_or_malformed_database_cannot_become_an_ordinary_input(
    completed_native: Path, tmp_path: Path, case: str
) -> None:
    """Refuse actual invalid filesystem inputs with fixed source-free diagnostics.

    Parameters
    ----------
    completed_native : Path
        Actual ordinary data; only its path is used for the linked-input case.
    tmp_path : Path
        Independent invalid input allocation.
    case : str
        Missing path, actual symbolic link or non-database content.
    """
    path = tmp_path / ".coverage"
    if case == "linked":
        path.symlink_to(completed_native / ".rigor-native-coverage/.coverage")
    elif case == "malformed":
        path.write_bytes(b"not a coverage database")
    with pytest.raises(ValueError, match="ordinary coverage database"):
        require_ordinary_coverage(path)


def test_role_admission_reads_only_ordinary_databases(
    completed_native: Path, tmp_path: Path
) -> None:
    """Admit a real ordinary database, refuse a missing one, and never read for primary.

    Parameters
    ----------
    completed_native : Path
        Actual ordinary producer output with its terminal coverage database.
    tmp_path : Path
        Allocation that holds no database at all.
    """
    require_role_coverage("ordinary", completed_native / ".rigor-native-coverage/.coverage")
    absent = tmp_path / ".coverage"
    require_role_coverage("primary", absent)
    with pytest.raises(ValueError, match="ordinary coverage database is unavailable"):
        require_role_coverage("ordinary", absent)
