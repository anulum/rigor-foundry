# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — interrupted project registry recovery CLI tests
"""Exercise explicit recovery authority and content-free operator output."""

from __future__ import annotations

from pathlib import Path

import pytest
from test_project_registry_cutover import REGISTRY_PATH, filesystem, plan
from test_project_registry_models import registry
from test_project_registry_recovery import run_crash_worker

from tools.recover_project_registry_cutover import main


def arguments(tmp_path: Path, crash_ordinal: int = 1) -> tuple[list[str], Path]:
    """Create one interrupted initial transaction and its exact CLI arguments."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    run_crash_worker(root, transactions, plan(candidate), crash_ordinal)
    return (
        [
            str(root),
            REGISTRY_PATH,
            str(transactions),
            candidate.generation_id,
            candidate.registry_sha256,
        ],
        root,
    )


@pytest.mark.parametrize(
    ("crash_ordinal", "fixed_result", "registry_exists"),
    [
        (1, "ROLLED_BACK", False),
        (3, "COMMITTED", True),
    ],
)
def test_recovery_cli_requires_explicit_apply_and_emits_fixed_result(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    crash_ordinal: int,
    fixed_result: str,
    registry_exists: bool,
) -> None:
    """Omitting apply cannot mutate; applying reveals no transaction content."""
    argv, root = arguments(tmp_path, crash_ordinal)
    assert main(argv) == 2
    assert capsys.readouterr().out == "project-registry-recovery: APPLY_REQUIRED\n"

    assert main([*argv, "--apply"]) == 0
    assert capsys.readouterr().out == f"project-registry-recovery: {fixed_result}\n"
    assert (root / REGISTRY_PATH).exists() is registry_exists


def test_recovery_cli_redacts_invalid_identity(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A private-looking invalid identity never appears in fixed failure output."""
    argv, _ = arguments(tmp_path)
    private_marker = "PRIVATE-RECOVERY-MARKER"
    argv[-2] = private_marker
    assert main([*argv, "--apply"]) == 1
    output = capsys.readouterr().out
    assert output == "project-registry-recovery: FAIL\n"
    assert private_marker not in output
