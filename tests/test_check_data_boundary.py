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

import pytest

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
    """Declared cryptography and YAML parsing do not permit network-capable drift."""
    root = _repository(
        tmp_path / "repository",
        dependencies='["cryptography>=50,<51", "PyYAML>=6.0.3,<7"]',
        source="from pathlib import Path\n\ndef read(path: Path) -> str:\n    return path.read_text()\n",
    )
    assert data_boundary_errors(root) == []


@pytest.mark.parametrize(
    "dependencies",
    [
        '["cryptography>=50,<51"]',
        '["cryptography>=50,<51", "PyYAML>=5,<7"]',
        '["cryptography>=50,<51", "PyYAML>=6.0.3,<7", "requests>=2"]',
    ],
)
def test_yaml_enrollment_keeps_the_runtime_dependency_set_exact(
    tmp_path: Path, dependencies: str
) -> None:
    """Missing, weakened or extra runtime declarations still fail the real guard."""
    root = _repository(tmp_path / "repository", dependencies=dependencies, source="VALUE = 1\n")
    assert data_boundary_errors(root) == [
        "project.dependencies must equal the approved local-only runtime dependency set"
    ]


def test_approved_yaml_runtime_does_not_authorise_network_imports(tmp_path: Path) -> None:
    """The exact declared parser dependency leaves direct network refusal intact."""
    root = _repository(
        tmp_path / "repository",
        dependencies='["cryptography>=50,<51", "PyYAML>=6.0.3,<7"]',
        source="import requests\n",
    )
    assert data_boundary_errors(root) == [
        "network-capable import 'requests' in local-only core: src/rigor_foundry/subsystem/core.py"
    ]


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
