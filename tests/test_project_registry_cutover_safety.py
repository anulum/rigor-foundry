# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project registry cutover path-safety tests
"""Exercise root, ancestry and existing-target safety through the public cutover API."""

from __future__ import annotations

from pathlib import Path

import pytest
from test_project_registry_cutover import REGISTRY_PATH, filesystem, plan
from test_project_registry_models import registry

from rigor_foundry.project_registry_cutover import (
    ProjectRegistryCutoverInvalid,
    apply_project_registry_cutover,
)


def test_cutover_rejects_unsafe_roots_parents_and_files(tmp_path: Path) -> None:
    """Cutover refuses unavailable roots, symlink parents and permissive targets."""
    candidate = registry()
    root, transactions = filesystem(tmp_path, candidate)
    cutover = plan(candidate)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="monorepo root is unavailable"):
        apply_project_registry_cutover(tmp_path / "missing", REGISTRY_PATH, transactions, cutover)

    transactions.chmod(0o755)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="safe owned directory"):
        apply_project_registry_cutover(root, REGISTRY_PATH, transactions, cutover)
    transactions.chmod(0o700)

    with pytest.raises(ProjectRegistryCutoverInvalid, match="parent is unavailable"):
        apply_project_registry_cutover(root, "missing/registry.json", transactions, cutover)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="registry path is invalid"):
        apply_project_registry_cutover(root, "../registry.json", transactions, cutover)

    target = root / cutover.updates[0].output.target_path
    target.write_text("{}", encoding="utf-8")
    target.chmod(0o644)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="owner-only file"):
        apply_project_registry_cutover(root, REGISTRY_PATH, transactions, cutover)


def test_cutover_rejects_final_symlinks_inside_and_outside_root(tmp_path: Path) -> None:
    """A final registry symlink can neither escape nor alias another owned file."""
    candidate = registry()

    outside_scenario = tmp_path / "outside"
    outside_scenario.mkdir()
    root, transactions = filesystem(outside_scenario, candidate)
    registry_target = root / REGISTRY_PATH
    outside = tmp_path / "outside-registry.json"
    outside.write_text("{}", encoding="utf-8")
    outside.chmod(0o600)
    registry_target.symlink_to(outside)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="escapes the monorepo"):
        apply_project_registry_cutover(root, REGISTRY_PATH, transactions, plan(candidate))

    inside_scenario = tmp_path / "inside"
    inside_scenario.mkdir()
    root, transactions = filesystem(inside_scenario, candidate)
    registry_target = root / REGISTRY_PATH
    inside = root / "owned-alias-target.json"
    inside.write_text("{}", encoding="utf-8")
    inside.chmod(0o600)
    registry_target.symlink_to(inside)
    with pytest.raises(ProjectRegistryCutoverInvalid, match="cannot be read safely"):
        apply_project_registry_cutover(root, REGISTRY_PATH, transactions, plan(candidate))
