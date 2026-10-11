# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Resource-bounded preflight tests
"""Verify local preflight never embeds the exhaustive test suite."""

import sys
import time
from pathlib import Path

import pytest

from tools.preflight import PreflightStep, preflight_commands, run_preflight_steps


def test_local_preflight_never_embeds_the_exhaustive_test_suite() -> None:
    """Full tests remain an explicit remote or owner-authorised operation."""
    for fast in (False, True):
        steps = preflight_commands(fast=fast)
        rendered = "\n".join(" ".join(step.argv) for step in steps)
        assert sys.executable in rendered
        assert "pytest" not in rendered
        assert all(step.timeout_seconds > 0 for step in steps)


def test_fast_preflight_omits_distribution_and_documentation_builds() -> None:
    """The pre-push path remains bounded without weakening static gates."""
    rendered = "\n".join(" ".join(step.argv) for step in preflight_commands(fast=True))
    assert "mkdocs" not in rendered
    assert " build " not in rendered
    assert "tools.check_descriptive_production_naming" in rendered
    assert "tools.audit" in rendered


def test_preflight_terminates_a_command_that_exceeds_its_budget(tmp_path: Path) -> None:
    """A stalled gate cannot hang the bounded local preflight indefinitely."""
    step = PreflightStep(
        (sys.executable, "-c", "import time; time.sleep(10)"),
        timeout_seconds=1,
    )
    started = time.monotonic()
    assert run_preflight_steps((step,), tmp_path) == 124
    assert time.monotonic() - started < 5


@pytest.mark.parametrize("invalid_root", ["src", "tools", "tests", "fuzz", "benchmarks", None])
def test_typing_preflight_checks_every_maintained_python_root(
    tmp_path: Path, invalid_root: str | None
) -> None:
    """The real compiler refuses a type defect in each root and accepts valid input.

    Parameters
    ----------
    tmp_path : Path
        Temporary directory containing all five maintained Python roots.
    invalid_root : str or None
        Maintained root containing a type error, or None for valid input.
    """
    for number, root in enumerate(("src", "tools", "tests", "fuzz", "benchmarks")):
        directory = tmp_path / root
        directory.mkdir()
        value = '"wrong type"' if root == invalid_root else "1"
        (directory / f"typed_owner_{number}.py").write_text(
            f'"""Declare one value checked by the real typing gate."""\nvalue: int = {value}\n',
            encoding="utf-8",
        )
    typing_step = next(step for step in preflight_commands(fast=True) if "mypy" in step.argv)
    assert run_preflight_steps((typing_step,), tmp_path) == (0 if invalid_root is None else 1)
