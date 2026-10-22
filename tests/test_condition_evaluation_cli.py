# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — condition-evaluation command tests
"""Exercise real bounded input files and the installed module command."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from rigor_foundry.condition_evaluation_cli import (
    CONDITION_EVALUATION_SCHEMA_VERSION,
    CONDITION_OBSERVATIONS_SCHEMA_VERSION,
    MAX_CONDITION_DOCUMENT_BYTES,
    main,
)
from rigor_foundry.condition_language import ConditionExpression
from rigor_foundry.models import canonical_digest


def _documents(
    directory: Path,
    facts: dict[str, object],
) -> tuple[Path, Path, dict[str, object], ConditionExpression]:
    """Write actual condition and operand documents for the public CLI."""
    expression = ConditionExpression.build("eq", reference="flag", value=True)
    expression_path = directory / "expression.json"
    observations_path = directory / "observations.json"
    observations: dict[str, object] = {
        "schema_version": CONDITION_OBSERVATIONS_SCHEMA_VERSION,
        "facts": facts,
    }
    expression_path.write_text(json.dumps(expression.to_dict()), encoding="utf-8")
    observations_path.write_text(json.dumps(observations), encoding="utf-8")
    return expression_path, observations_path, observations, expression


@pytest.mark.parametrize(
    ("facts", "result", "exit_code"),
    [
        ({"flag": {"state": "known", "value": True}}, "true", 0),
        ({"flag": {"state": "known", "value": False}}, "false", 1),
        ({"flag": {"state": "absent", "value": None}}, "false", 1),
        ({"flag": {"state": "unknown", "value": None}}, "unknown", 3),
        ({}, "unknown", 3),
    ],
)
def test_public_command_preserves_result_and_exit_state(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    facts: dict[str, object],
    result: str,
    exit_code: int,
) -> None:
    """False and unknown remain distinct nonzero results, with exact input identities."""
    expression_path, observations_path, observations, expression = _documents(tmp_path, facts)
    assert main(
        ["--expression", str(expression_path), "--observations", str(observations_path)]
    ) == (exit_code)
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {
        "schema_version": CONDITION_EVALUATION_SCHEMA_VERSION,
        "evaluation_kind": "supplied-observations",
        "expression_digest": expression.expression_digest,
        "observations_digest": canonical_digest(observations),
        "result": result,
        "guard_admissible": False,
    }


@pytest.mark.parametrize("value", [0.5, [True, 1, None], None])
def test_json_numeric_arrays_and_null_remain_supported(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], value: object
) -> None:
    """The CLI decoder accepts finite JSON values rather than a no-float registry subset."""
    expression_path, observations_path, _, _ = _documents(
        tmp_path, {"flag": {"state": "known", "value": value}}
    )
    assert (
        main(["--expression", str(expression_path), "--observations", str(observations_path)]) == 1
    )
    assert json.loads(capsys.readouterr().out)["result"] == "false"


@pytest.mark.parametrize(
    "payload",
    [
        b"not-json",
        b"\xff",
        b'{"schema_version":"wrong","facts":{}}',
        b'{"schema_version":"rigor.condition-observations.v1","facts":[]}',
        b'{"schema_version":"rigor.condition-observations.v1","facts":{},"extra":1}',
        b'{"schema_version":"rigor.condition-observations.v1","facts":{"flag":{"state":"known","value":NaN}}}',
        b'{"schema_version":"rigor.condition-observations.v1","facts":{"flag":{"state":"known","value":1e999}}}',
        b'{"schema_version":"rigor.condition-observations.v1","facts":{"flag":{"state":"known","value":false,"value":true}}}',
        b'{"schema_version":"rigor.condition-observations.v1","facts":{"flag":{"state":"absent","value":false}}}',
        b"[" * 1500 + b"]" * 1500,
    ],
)
def test_malformed_operand_files_refuse_without_raw_diagnostics(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], payload: bytes
) -> None:
    """Bad encodings, shapes, duplicates and numeric domains have caller-safe failures."""
    expression_path, observations_path, _, _ = _documents(tmp_path, {})
    observations_path.write_bytes(payload)
    assert (
        main(["--expression", str(expression_path), "--observations", str(observations_path)]) == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "condition evaluation error: CE001 invalid input\n"


def test_a_stale_expression_digest_refuses(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The command validates the existing expression's complete digest before evaluation."""
    expression_path, observations_path, _, expression = _documents(tmp_path, {})
    damaged = expression.to_dict()
    damaged["expression_digest"] = "0" * 64
    expression_path.write_text(json.dumps(damaged), encoding="utf-8")
    assert (
        main(["--expression", str(expression_path), "--observations", str(observations_path)]) == 2
    )
    assert capsys.readouterr().err == "condition evaluation error: CE001 invalid input\n"


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "directory", "missing"])
def test_only_explicit_single_link_regular_inputs_are_read(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], kind: str
) -> None:
    """Alias, nonregular and missing paths cannot bypass the actual safe file reader."""
    expression_path, observations_path, _, _ = _documents(tmp_path, {})
    selected = tmp_path / "sensitive-marker"
    if kind == "symlink":
        selected.symlink_to(expression_path)
    elif kind == "hardlink":
        os.link(expression_path, selected)
    elif kind == "directory":
        selected.mkdir()
    assert main(["--expression", str(selected), "--observations", str(observations_path)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "condition evaluation error: CE001 invalid input\n"
    assert "sensitive-marker" not in captured.err


def test_file_byte_budget_has_an_actual_accept_and_refuse_boundary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A real exactly-sized document is accepted and one extra byte is refused."""
    expression_path, observations_path, _, _ = _documents(tmp_path, {})
    original = expression_path.read_bytes()
    expression_path.write_bytes(original + b" " * (MAX_CONDITION_DOCUMENT_BYTES - len(original)))
    assert (
        main(["--expression", str(expression_path), "--observations", str(observations_path)]) == 3
    )
    assert json.loads(capsys.readouterr().out)["result"] == "unknown"
    expression_path.write_bytes(expression_path.read_bytes() + b" ")
    assert (
        main(["--expression", str(expression_path), "--observations", str(observations_path)]) == 2
    )
    assert capsys.readouterr().err == "condition evaluation error: CE001 invalid input\n"


def test_invalid_arguments_do_not_echo_caller_contents(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Parser errors are authored rather than interpolated from unknown option values."""
    assert main(["--sensitive-marker", "do-not-echo-this"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "condition evaluation error: CE001 invalid input\n"


@pytest.mark.parametrize(
    ("facts", "result", "exit_code"),
    [
        ({"flag": {"state": "known", "value": True}}, "true", 0),
        ({"flag": {"state": "known", "value": False}}, "false", 1),
        ({}, "unknown", 3),
    ],
)
def test_actual_module_entrypoint_evaluates_supplied_files(
    tmp_path: Path, facts: dict[str, object], result: str, exit_code: int
) -> None:
    """Real interpreter argv and module execution reach the same production evaluator."""
    expression_path, observations_path, _, _ = _documents(tmp_path, facts)
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "rigor_foundry.condition_evaluation_cli",
            "--expression",
            str(expression_path),
            "--observations",
            str(observations_path),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert completed.returncode == exit_code
    assert completed.stderr == ""
    output = json.loads(completed.stdout)
    assert output["result"] == result
    assert output["guard_admissible"] is False


def test_actual_module_help_is_available_without_input_files(tmp_path: Path) -> None:
    """The installed command exposes its complete explicit operand options."""
    completed = subprocess.run(
        [sys.executable, "-m", "rigor_foundry.condition_evaluation_cli", "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0
    assert "--expression" in completed.stdout and "--observations" in completed.stdout
    assert completed.stderr == ""


def _process_read_bytes() -> int:
    """Read Linux process byte accounting without replacing the production reader."""
    fields = Path("/proc/self/io").read_text(encoding="ascii").splitlines()
    return int(next(line.partition(":")[2] for line in fields if line.startswith("rchar:")))


@pytest.mark.parametrize("document", ["expression", "observations"])
def test_oversized_input_refuses_before_reading_its_contents(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], document: str
) -> None:
    """Actual public CLI read work stays small for an already oversized regular file."""
    expression_path, observations_path, _, _ = _documents(
        tmp_path, {"flag": {"state": "known", "value": True}}
    )
    selected = expression_path if document == "expression" else observations_path
    original = selected.read_bytes()
    selected.write_bytes(original + b" " * (1024 * 1024 + 1 - len(original)))
    before = _process_read_bytes()
    result = main(["--expression", str(expression_path), "--observations", str(observations_path)])
    read_bytes = _process_read_bytes() - before
    assert result == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "condition evaluation error: CE001 invalid input\n"
    assert read_bytes < 4096, read_bytes
