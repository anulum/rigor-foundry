# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — complete implementation observation tests
"""Observe real package/interpreter inputs without reducing them to one module."""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from rigor_foundry.context_owner_implementation import observe_owner_implementation
from rigor_foundry.policy_read_budget import PolicyReadBudget1


def implementation_budget(**changes: int) -> PolicyReadBudget1:
    """Supply explicit ceilings that include the actual interpreter and full package."""
    limits = {
        "max_document_bytes": 8 * 1024**2,
        "max_source_bytes": 8 * 1024**2,
        "max_total_source_bytes": 64 * 1024**2,
        "max_sources": 4096,
        "max_rules": 16384,
        "max_references": 65536,
        "max_depth": 32,
    }
    return PolicyReadBudget1.build(**{**limits, **changes})


def package(root: Path) -> Path:
    """Create a real package with Python code, nested code and non-code runtime data."""
    root.mkdir()
    (root / "__init__.py").write_text("VALUE = 1\n")
    (root / "data.json").write_text('{"enabled":true}')
    (root / "nested").mkdir()
    (root / "nested" / "module.py").write_text("NAME = 'module'\n")
    (root / "__pycache__").mkdir()
    (root / "__pycache__" / "cache.pyc").write_bytes(b"generated")
    return root


def test_entire_package_and_actual_interpreter_have_stable_identities(tmp_path: Path) -> None:
    """Changing nested code or runtime data changes content, while cache bytes stay excluded."""
    root = package(tmp_path / "package")
    first = observe_owner_implementation(root, budget=implementation_budget())
    assert observe_owner_implementation(root, budget=implementation_budget()) == first
    assert len(first.snapshot_digest) == 64
    (root / "__pycache__" / "cache.pyc").write_bytes(b"different-cache")
    assert observe_owner_implementation(root, budget=implementation_budget()) == first
    (root / "data.json").write_text('{"enabled":false}')
    changed_data = observe_owner_implementation(root, budget=implementation_budget())
    assert changed_data.implementation_digest != first.implementation_digest
    (root / "nested" / "module.py").write_text("NAME = 'changed'\n")
    assert (
        observe_owner_implementation(root, budget=implementation_budget()).implementation_digest
        != changed_data.implementation_digest
    )
    with pytest.raises(ValueError, match="changed while"):
        replace(first, closing_identity="0" * 64)
    with pytest.raises(ValueError):
        replace(first, implementation_digest="bad")
    object.__setattr__(first, "closing_identity", "0" * 64)
    with pytest.raises(ValueError):
        _ = first.snapshot_digest


@pytest.mark.parametrize(
    "case",
    [
        "symlink-file",
        "symlink-directory",
        "fifo",
        "not-package",
        "source-budget",
        "reference-budget",
        "byte-budget",
    ],
)
def test_unsupported_or_incomplete_package_observation_refuses(tmp_path: Path, case: str) -> None:
    """Real unsupported inputs and exhausted ceilings refuse a complete observation."""
    root = package(tmp_path / "package")
    limits = implementation_budget()
    if case == "symlink-file":
        (root / "alias.py").symlink_to(root / "__init__.py")
    elif case == "symlink-directory":
        (root / "alias").symlink_to(root / "nested", target_is_directory=True)
    elif case == "fifo":
        os.mkfifo(root / "input")
    elif case == "not-package":
        (root / "__init__.py").unlink()
    elif case == "source-budget":
        limits = implementation_budget(max_sources=1)
    elif case == "reference-budget":
        limits = implementation_budget(max_references=1)
    else:
        limits = implementation_budget(max_source_bytes=1)
    with pytest.raises(ValueError):
        observe_owner_implementation(root, budget=limits)
    with pytest.raises(ValueError, match="budget is required"):
        observe_owner_implementation(root, budget=cast(PolicyReadBudget1, {}))
