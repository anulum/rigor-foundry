# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — discovery source validation
"""Exercise the real discovery command, including its process entry point."""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path

import pytest
from discovery_source_support import arguments, cli, limits, snapshot

from rigor_foundry.discovery_source_cli import main


def test_cli_process_replay(tmp_path: Path) -> None:
    """Run two actual CLI processes and compare complete deterministic stdout."""
    snapshot(tmp_path)
    budget = limits(tmp_path)
    first, second = cli(tmp_path, budget), cli(tmp_path, budget)
    assert first.returncode == second.returncode == 0
    assert first.stderr == second.stderr == ""
    assert first.stdout == second.stdout
    assert json.loads(first.stdout)["promotable"] is False


def test_cli_callable_and_module_entry(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Execute the public command and its main-module dispatch with real inputs."""
    snapshot(tmp_path)
    argv = arguments(tmp_path, limits(tmp_path))
    assert main(argv) == 0
    direct = capsys.readouterr()
    monkeypatch.setattr(sys, "argv", ["discovery-source", *argv])
    with (
        pytest.warns(RuntimeWarning, match="found in sys.modules"),
        pytest.raises(SystemExit) as exit_info,
    ):
        runpy.run_module("rigor_foundry.discovery_source_cli", run_name="__main__")
    assert exit_info.value.code == 0
    assert capsys.readouterr().out == direct.out


@pytest.mark.parametrize(
    "extra",
    [
        ["--secret-token", "PRIVATE-CANARY"],
        ["--max-sources", "PRIVATE-CANARY"],
        ["--root", "/missing/PRIVATE-CANARY"],
        ["--manifest", "PRIVATE-CANARY.txt"],
    ],
)
def test_cli_redacted_refusal(
    tmp_path: Path, extra: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    """Exercise public and process refusals without leaking arbitrary arguments."""
    snapshot(tmp_path)
    budget = limits(tmp_path)
    argv = [*arguments(tmp_path, budget), *extra]
    code = main(argv)
    output = capsys.readouterr()
    process = cli(tmp_path, budget, extra)
    assert code == process.returncode
    assert code in (1, 2)
    assert output.out == process.stdout == ""
    assert output.err == process.stderr
    assert "PRIVATE-CANARY" not in output.err


def test_cli_requires_explicit_inputs(capsys: pytest.CaptureFixture[str]) -> None:
    """Refuse absent root, manifest and budgets with no implicit environment."""
    assert main([]) == 2
    assert capsys.readouterr().err == "discovery-error:invalid-input\n"
