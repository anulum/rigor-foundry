# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Local-only data-boundary guard
"""Reject undeclared runtime dependencies and network clients in the core package."""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

from tools._repository import ROOT, redacted_guard_exit_code

_NETWORK_MODULES = frozenset(
    {
        "aiohttp",
        "ftplib",
        "http",
        "httpx",
        "requests",
        "smtplib",
        "socket",
        "telnetlib",
        "urllib",
        "websockets",
    }
)
_ALLOWED_RUNTIME_DEPENDENCIES = ("cryptography>=49,<50",)


def _imported_network_modules(path: Path) -> tuple[str, ...]:
    """Return network-capable top-level imports in one Python module."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        names: tuple[str, ...] = ()
        if isinstance(node, ast.Import):
            names = tuple(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            names = (node.module,)
        modules.update(
            name.split(".", maxsplit=1)[0]
            for name in names
            if name.split(".", maxsplit=1)[0] in _NETWORK_MODULES
        )
    return tuple(sorted(modules))


def data_boundary_errors(root: Path = ROOT) -> list[str]:
    """Return violations of the fixed-dependency, local-only core contract."""
    errors: list[str] = []
    with (root / "pyproject.toml").open("rb") as stream:
        configuration = tomllib.load(stream)
    project = configuration.get("project")
    dependencies = project.get("dependencies") if isinstance(project, dict) else None
    if dependencies != list(_ALLOWED_RUNTIME_DEPENDENCIES):
        errors.append(
            "project.dependencies must equal the approved local-only runtime dependency set"
        )

    package = root / "src" / "rigor_foundry"
    for path in sorted(package.rglob("*.py")):
        for module in _imported_network_modules(path):
            relative = path.relative_to(root).as_posix()
            errors.append(f"network-capable import {module!r} in local-only core: {relative}")
    return errors


def main() -> int:
    """Validate the local-only core data boundary and return a process exit code."""
    errors = data_boundary_errors()
    return redacted_guard_exit_code("Data-boundary guard", errors)


if __name__ == "__main__":
    raise SystemExit(main())
