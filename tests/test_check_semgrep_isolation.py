# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Isolated Semgrep environment guard tests
"""Exercise the isolated Semgrep guard against the actual locks and interpreter."""

from __future__ import annotations

import datetime
import importlib.util
import os
import re
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


_ADVISORY_ROW = re.compile(
    r"  \| (GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}) \| ([a-z0-9-]+) \| ([0-9.]+) \| ([0-9.]+) \| "
    r"([0-9]{4}-[0-9]{2}-[0-9]{2}) \|"
)


def _recorded_advisories(text: str) -> list[tuple[str, ...]]:
    """Return every advisory row of the record, refusing any table line that is malformed."""
    lines = [line for line in text.splitlines() if line.startswith("  | GHSA")]
    rows = [_ADVISORY_ROW.fullmatch(line) for line in lines]
    malformed = [line for line, row in zip(lines, rows, strict=True) if row is None]
    assert not malformed, f"malformed Semgrep advisory rows: {malformed}"
    return [row.groups() for row in rows if row is not None]


def test_every_recorded_semgrep_advisory_is_still_pinned_and_still_in_review() -> None:
    """The documented Semgrep-only advisories match the isolated lock and none is past review.

    The list is the named record of what the isolated lock leaves outside the dependency
    audit. A malformed row, a row whose package the lock no longer pins at its version, a
    Semgrep version that is no longer the lock's, or a review-by date in the past, fails
    until the record is reviewed.
    """
    rows = _recorded_advisories((ROOT / "docs/security.md").read_text(encoding="utf-8"))
    assert rows
    advisories = [row[0] for row in rows]
    assert len(advisories) == len(set(advisories))
    lock = (ROOT / "requirements/semgrep.txt").read_text(encoding="utf-8")
    pins = dict(re.findall(r"^([a-z0-9-]+)==([^ \\\n]+)", lock, re.MULTILINE))
    today = datetime.datetime.now(datetime.UTC).date()
    for advisory, package, version, semgrep, review_by in rows:
        assert pins.get(package) == version, advisory
        assert pins.get("semgrep") == semgrep, advisory
        assert datetime.date.fromisoformat(review_by) >= today, advisory


@pytest.mark.parametrize(
    "line",
    [
        "  | GHSA-53pm-wgxf-c6qf | Wcmatch | 9.9.9 | 1.184.0 | 2026-12-24 |",
        "  | GHSA-53pm-wgxf-c6qf | wcmatch | 8.5.2 | 1.184.0 |",
        "  | GHSA-53pm-wgxf | wcmatch | 8.5.2 | 1.184.0 | 2026-12-24 |",
        "  | GHSA-53pm-wgxf-c6qf | wcmatch | 8.5.2 | 1.184.0 | 24.12.2026 |",
    ],
)
def test_a_malformed_advisory_row_is_refused_not_skipped(line: str) -> None:
    """Any table line that starts like an advisory but does not match is refused.

    Parameters
    ----------
    line : str
        A malformed record line next to one well-formed row.
    """
    valid = "  | GHSA-qx49-fqc8-xw99 | mcp | 1.29.0 | 1.184.0 | 2026-12-24 |"
    assert len(_recorded_advisories(valid)) == 1
    with pytest.raises(AssertionError, match="malformed Semgrep advisory rows"):
        _recorded_advisories(f"{valid}\n{line}\n")
