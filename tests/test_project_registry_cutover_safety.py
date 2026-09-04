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
