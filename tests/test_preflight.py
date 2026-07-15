# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Resource-bounded preflight tests
"""Verify local preflight never embeds the exhaustive test suite."""

import sys
import time
from pathlib import Path

from tools.preflight import PreflightStep, _run, preflight_commands


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
    assert "tools.audit" in rendered


def test_preflight_terminates_a_command_that_exceeds_its_budget(tmp_path: Path) -> None:
    """A stalled gate cannot hang the bounded local preflight indefinitely."""
    step = PreflightStep(
        (sys.executable, "-c", "import time; time.sleep(10)"),
        timeout_seconds=1,
    )
    started = time.monotonic()
    assert _run(step, tmp_path) == 124
    assert time.monotonic() - started < 5
