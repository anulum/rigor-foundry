# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — read-only activation proposal command tests
"""Exercise private files and the real proposal-check process without live writes."""

from __future__ import annotations

import json
import runpy
import subprocess
import sys
from pathlib import Path

import pytest
from test_project_memory_activation_plan import profiled_proposal, proposal

import tools.check_project_memory_activation_plan as command
from rigor_foundry.project_registry_models import PROJECT_REGISTRY_MAX_CONSUMERS
from tools.check_project_memory_activation_plan import main


def inputs(root: Path, *, profiled: bool = False) -> list[str]:
    p = profiled_proposal() if profiled else proposal()
    entries = (
        ("previous.json", p.previous.to_bytes()),
        ("candidate.json", p.cutover.candidate.to_bytes()),
        ("memory.json", p.memory.to_bytes()),
        ("bootstrap.json", p.bootstrap),
        ("index.md", p.index),
    )
    args = []
    for name, payload in entries:
        path = root / name
        path.write_bytes(payload)
        path.chmod(0o600)
        args.append(str(path))
    for kind, outputs in (
        ("previous", p.prior_outputs),
        ("candidate", tuple(u.output for u in p.cutover.updates)),
    ):
        for output in outputs:
            path = root / f"{kind}-{output.consumer_id}.json"
            path.write_bytes(output.to_bytes())
            path.chmod(0o600)
            args.extend((f"--{kind}-output", str(path)))
    return args


@pytest.mark.parametrize("profiled", [False, True])
def test_process_checks_proposal_without_changing_any_input(
    tmp_path: Path, profiled: bool
) -> None:
    args = inputs(tmp_path, profiled=profiled)
    if profiled:
        args.extend(("--schema-version", "project-memory-activation-plan-binding.v2"))
    before = {
        p.name: (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns)
        for p in tmp_path.iterdir()
    }
    script = Path(__file__).resolve().parents[1] / "tools/check_project_memory_activation_plan.py"
    result = subprocess.run(
        [sys.executable, str(script), *args],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout == "project-memory-activation-plan: VALIDATED_NOT_AUTHORISED\n"
    assert result.stderr == ""
    after = {
        p.name: (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns)
        for p in tmp_path.iterdir()
    }
    assert before == after


@pytest.mark.parametrize(
    "case", ["public-mode", "symlink", "malformed", "missing", "missing-consumer"]
)
def test_rejected_private_input_is_redacted(
    tmp_path: Path, case: str, capsys: pytest.CaptureFixture[str]
) -> None:
    args = inputs(tmp_path)
    target = Path(args[3])
    if case == "public-mode":
        target.chmod(0o644)
    elif case == "symlink":
        saved = tmp_path / "saved.json"
        target.rename(saved)
        target.symlink_to(saved)
    elif case == "malformed":
        target.write_bytes(b"private-value-FORGED-LINE")
    elif case == "missing":
        target.unlink()
    else:
        args = args[:-2]
    assert main(args) == 1
    assert capsys.readouterr().out == "project-memory-activation-plan: FAIL\n"


@pytest.mark.parametrize("case", ["implicit-version", "profile-tamper"])
def test_profiled_process_refuses_unselected_or_altered_binding(tmp_path: Path, case: str) -> None:
    args = inputs(tmp_path, profiled=True)
    if case == "profile-tamper":
        target = Path(args[2])
        data = json.loads(target.read_bytes())
        data["deployment_profile"]["profile_id"] = "private-canary-not-for-output"
        target.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")))
        args.extend(("--schema-version", "project-memory-activation-plan-binding.v2"))
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    script = Path(__file__).resolve().parents[1] / "tools/check_project_memory_activation_plan.py"
    result = subprocess.run(
        [sys.executable, str(script), *args],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 1
    assert result.stdout == "project-memory-activation-plan: FAIL\n"
    assert result.stderr == ""
    assert before == {p.name: p.read_bytes() for p in tmp_path.iterdir()}


def test_cli_refuses_oversized_consumer_set_before_reading_files(
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = ["absent"] * 5 + ["--previous-output", "absent"] * (PROJECT_REGISTRY_MAX_CONSUMERS + 1)
    assert main(args) == 1
    assert capsys.readouterr().out == "project-memory-activation-plan: FAIL\n"


def test_cli_cannot_apply_a_proposal(tmp_path: Path) -> None:
    args = inputs(tmp_path)
    with pytest.raises(SystemExit) as error:
        main([*args, "--apply"])
    assert error.value.code == 2


def test_aggregate_byte_budget_applies_across_all_real_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = inputs(tmp_path)
    total = sum(path.stat().st_size for path in tmp_path.iterdir())
    monkeypatch.setattr(command, "PROJECT_REGISTRY_MAX_TRANSACTION_BYTES", total)
    assert main(args) == 0
    monkeypatch.setattr(command, "PROJECT_REGISTRY_MAX_TRANSACTION_BYTES", total - 1)
    assert main(args) == 1


def test_script_entrypoint_returns_proposal_only_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    args = inputs(tmp_path)
    script = Path(__file__).resolve().parents[1] / "tools/check_project_memory_activation_plan.py"
    monkeypatch.setattr(sys, "argv", [str(script), *args])
    with pytest.raises(SystemExit) as error:
        runpy.run_path(str(script), run_name="__main__")
    assert error.value.code == 0
    assert capsys.readouterr().out == "project-memory-activation-plan: VALIDATED_NOT_AUTHORISED\n"
