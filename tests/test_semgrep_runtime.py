# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Actual Semgrep process-profile acceptance
"""Exercise the maintained shell entry point with the installed native scanner."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tools._repository import ROOT


@pytest.mark.parametrize(
    ("source", "rules"),
    [
        ("value = 1\n", set()),
        ("eval('1 + 1')\n", {"rigor-foundry-no-eval"}),
        (
            "import subprocess\nsubprocess.run('true', shell=True)\n",
            {"rigor-foundry-no-shell-true"},
        ),
    ],
)
def test_profile_preserves_actual_clean_and_findings_exit_status(
    tmp_path: Path, source: str, rules: set[str]
) -> None:
    """Run both repository rules through the real maintained scanner entry point.

    Parameters
    ----------
    tmp_path : Path
        Genuine source input outside the product checkout.
    source : str
        Safe Python or an actual violation of a repository rule.
    rules : set[str]
        Expected scanner findings; a nonempty set requires exit status one.
    """
    path = tmp_path / "input.py"
    path.write_text(source, encoding="utf-8")
    result = subprocess.run(
        [
            "bash",
            str(ROOT / "tools/run_semgrep.sh"),
            "scan",
            "--error",
            "--jobs",
            "1",
            "--json",
            "--config",
            str(ROOT / ".semgrep.yml"),
            str(path),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == (1 if rules else 0), result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["errors"] == []
    assert report["paths"]["scanned"] == [str(path)]
    assert {finding["check_id"].rsplit(".", 1)[-1] for finding in report["results"]} == rules


def test_profile_refuses_an_actual_missing_scanner(tmp_path: Path) -> None:
    """Refuse an empty executable search path before invoking a scanner.

    Parameters
    ----------
    tmp_path : Path
        Actual empty directory supplied as the executable search path.
    """
    bash = shutil.which("bash")
    assert bash is not None
    result = subprocess.run(
        [bash, str(ROOT / "tools/run_semgrep.sh"), "--version"],
        env={**os.environ, "PATH": str(tmp_path)},
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 127
    assert "locked Semgrep console entry point is not on PATH" in result.stderr
