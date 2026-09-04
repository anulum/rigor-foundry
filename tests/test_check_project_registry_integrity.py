# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project registry integrity CLI tests
"""Exercise fixed-output registry validation through real consumer files."""

from __future__ import annotations

from pathlib import Path

import pytest
from test_project_registry_cutover import REGISTRY_PATH, filesystem, plan
from test_project_registry_models import registry

from rigor_foundry.project_registry_cutover import apply_project_registry_cutover
from tools.check_project_registry_integrity import main


def test_integrity_cli_accepts_exact_registry_and_consumers(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A committed all-consumer state returns the single fixed pass line."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    apply_project_registry_cutover(root, REGISTRY_PATH, transactions, plan(candidate))

    assert main([str(root), REGISTRY_PATH]) == 0
    assert capsys.readouterr().out == "project-registry-integrity: PASS\n"


def test_integrity_cli_redacts_private_consumer_details(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A changed consumer reports failure without disclosing its identity."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    cutover = plan(candidate)
    apply_project_registry_cutover(root, REGISTRY_PATH, transactions, cutover)
    private_identity = cutover.updates[0].consumer_id
    target = root / cutover.updates[0].output.target_path
    target.write_text(f'{{"private":"{private_identity}"}}', encoding="utf-8")
    target.chmod(0o600)

    assert main([str(root), REGISTRY_PATH]) == 1
    output = capsys.readouterr().out
    assert output == "project-registry-integrity: FAIL\n"
    assert private_identity not in output


def test_integrity_cli_fails_when_registry_is_absent(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An unactivated monorepo cannot be mistaken for a valid registry state."""
    root = tmp_path / "monorepo"
    root.mkdir()
    (root / "agentic-shared/memory/projects/registry").mkdir(parents=True)

    assert main([str(root), REGISTRY_PATH]) == 1
    assert capsys.readouterr().out == "project-registry-integrity: FAIL\n"
