# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Isolated Semgrep environment guard tests
"""Exercise the isolated Semgrep guard against the actual locks and interpreter."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys

import pytest

from tools._repository import ROOT
from tools.check_semgrep_isolation import (
    canonical_name,
    isolation_errors,
    locked_names,
    main,
    semgrep_only_names,
)

VIRTUAL = "the audited interpreter must be a base installation, not a virtual one"
IMPORTABLE = "the audited interpreter can import Semgrep"


def test_lock_pins_use_canonical_distribution_names() -> None:
    """Pins and installed names compare after the standard name normalisation."""
    assert canonical_name("Ruamel.Yaml__Clib") == "ruamel-yaml-clib"
    text = "a-b==1.0 \\\n    --hash=sha256:00\nC_D.e==2.0\n    # via f==3.0\n"
    assert locked_names(text) == {"a-b", "c-d-e"}


def test_semgrep_only_names_leave_out_every_audited_pin() -> None:
    """Only distributions that no audited lock pins belong to the isolated set."""
    names = semgrep_only_names()
    assert {"semgrep", "mcp", "opentelemetry-api", "wcmatch"} <= names
    assert "requests" not in names
    assert "bandit" not in names


def test_base_interpreter_without_semgrep_is_accepted() -> None:
    """A base install with only audited distributions and no Semgrep module passes."""
    assert (
        isolation_errors(
            prefix="/base",
            base_prefix="/base",
            installed=["bandit", "Requests", "pip-audit"],
            find_spec=lambda name: None,
        )
        == []
    )


def test_each_isolation_breach_is_reported() -> None:
    """A virtual environment, an importable module and isolated installs each fail."""
    assert isolation_errors(
        prefix="/base/rigor-semgrep-venv",
        base_prefix="/base",
        installed=["Semgrep", "MCP", "requests"],
        find_spec=lambda name: object() if name == "semgrep" else None,
    ) == [
        VIRTUAL,
        IMPORTABLE,
        "the audited interpreter contains Semgrep-only distributions: mcp, semgrep",
    ]


def test_running_interpreter_defaults_and_public_entry_point(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The defaults read this interpreter, and the guard reports the same outcome.

    Parameters
    ----------
    capsys : pytest.CaptureFixture[str]
        Captures the redacted in-process guard status line.
    """
    errors = isolation_errors()
    assert (VIRTUAL in errors) == (sys.prefix != sys.base_prefix)
    assert (IMPORTABLE in errors) == (importlib.util.find_spec("semgrep") is not None)
    expected = 1 if errors else 0
    status = (
        "Semgrep isolation guard failed; finding details are redacted from process output.\n"
        if errors
        else "Semgrep isolation guard passed\n"
    )
    assert main() == expected
    assert capsys.readouterr().out == status
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    result = subprocess.run(
        [sys.executable, "-B", "-m", "tools.check_semgrep_isolation"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == expected, result.stderr
    assert result.stdout == status
