# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Local-only data-boundary guard tests
"""Verify runtime dependency and network-client drift is rejected."""

from __future__ import annotations

from pathlib import Path

from tools.check_data_boundary import data_boundary_errors


def _repository(path: Path, *, dependencies: str, source: str) -> Path:
    """Write the minimal surfaces consumed by the data-boundary guard."""
    package = path / "src" / "rigor_foundry"
    package.mkdir(parents=True)
    (path / "pyproject.toml").write_text(
        f'[project]\nname = "sample"\ndependencies = {dependencies}\n',
        encoding="utf-8",
    )
    subsystem = package / "subsystem"
    subsystem.mkdir()
    (subsystem / "core.py").write_text(source, encoding="utf-8")
    return path


def test_data_boundary_accepts_approved_local_runtime_dependency(tmp_path: Path) -> None:
    """The pinned cryptographic verifier does not permit network-capable drift."""
    root = _repository(
        tmp_path / "repository",
        dependencies='["cryptography>=49,<50"]',
        source="from pathlib import Path\n\ndef read(path: Path) -> str:\n    return path.read_text()\n",
    )
    assert data_boundary_errors(root) == []


def test_data_boundary_rejects_dependencies_and_network_clients(tmp_path: Path) -> None:
    """Both packaging drift and direct network imports are explicit failures."""
    root = _repository(
        tmp_path / "repository",
        dependencies='["requests>=2"]',
        source="import socket\nfrom urllib import request\n",
    )
    assert data_boundary_errors(root) == [
        "project.dependencies must equal the approved local-only runtime dependency set",
        "network-capable import 'socket' in local-only core: src/rigor_foundry/subsystem/core.py",
        "network-capable import 'urllib' in local-only core: src/rigor_foundry/subsystem/core.py",
    ]
