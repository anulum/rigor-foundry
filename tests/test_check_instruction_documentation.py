# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native documentation gate file contracts
"""Exercise documented and undocumented real source files through the gate."""

import runpy
from pathlib import Path

import pytest

from tools.check_instruction_documentation import PATHS, main, undocumented_definitions


def test_actual_instruction_cohort_has_native_documentation() -> None:
    """The production/test/gate cohort documents every current definition."""
    root = Path(__file__).resolve().parents[1]
    assert not undocumented_definitions(tuple(root / path for path in PATHS))


def test_gate_rejects_private_nested_and_test_definitions(tmp_path: Path) -> None:
    """Actual source mutation cannot hide undocumented private or nested contracts."""
    root = Path(__file__).resolve().parents[1]
    source = root / "tests/test_instruction_dispatch.py"
    candidate = tmp_path / source.name
    candidate.write_text(
        source.read_text()
        + "\ndef _undocumented():\n    async def test_nested():\n        pass\n",
        encoding="utf-8",
    )
    assert len(undocumented_definitions((candidate,))) == 2


def test_missing_source_fails_closed(tmp_path: Path) -> None:
    """A missing required source is an error, not an empty documentation result."""
    with pytest.raises(FileNotFoundError):
        undocumented_definitions((tmp_path / "absent.py",))


def test_gate_command_and_invalid_checkout_return_status(tmp_path: Path) -> None:
    """CLI succeeds on maintained sources and fails on a real altered checkout."""
    root = Path(__file__).resolve().parents[1]
    with pytest.raises(SystemExit) as completed:
        runpy.run_path(str(root / "tools/check_instruction_documentation.py"), run_name="__main__")
    assert completed.value.code == 0
    for relative in PATHS:
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((root / relative).read_bytes())
    changed = tmp_path / PATHS[0]
    changed.write_text(changed.read_text() + "\ndef _undocumented():\n    pass\n")
    assert main(tmp_path) == 1
