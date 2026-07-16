# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — trusted executable runner tests
"""Exercise descriptor-pinned execution and bounded process-tree handling."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

import rigor_foundry.sandbox_provenance as sandbox_module
import rigor_foundry.trusted_executable as trusted_module
from rigor_foundry.trusted_executable import (
    TrustedExecutable,
    open_trusted_executable,
    run_trusted_command,
    snapshot_executable,
)

_TEST_ENVIRONMENT = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}


def _write_executable(path: Path, body: str) -> Path:
    """Write one executable test tool."""
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


def _open_fixture_executable(path: Path) -> TrustedExecutable:
    """Open one current-user executable under production trust constraints."""
    return open_trusted_executable(
        path,
        required_owner_uid=os.getuid(),
        forbidden_mode_bits=0o6022,
        require_single_link=True,
    )


@pytest.mark.parametrize(
    ("program", "message"),
    [
        ("raise SystemExit(3)", "returned failure"),
        ("import sys; print('warning', file=sys.stderr)", "wrote to stderr"),
        ("import os; os.write(1, b'\\xff')", "was not UTF-8"),
        ("print('x' * 9000)", "exceeded output limit"),
        ("import sys; print('x' * 9000, file=sys.stderr)", "exceeded output limit"),
    ],
)
def test_metadata_command_rejects_process_failures_and_unbounded_output(
    tmp_path: Path,
    program: str,
    message: str,
) -> None:
    """Metadata subprocesses have strict exit, encoding, stderr, and output bounds."""
    executable = _write_executable(
        tmp_path / "metadata-command",
        f"#!/usr/bin/python3\n{program}\n",
    )
    with (
        _open_fixture_executable(executable) as handle,
        pytest.raises(RuntimeError, match=message),
    ):
        sandbox_module._metadata_command(handle)


def test_trusted_command_normalises_spawn_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OS-level spawn failures expose no host-dependent subprocess detail."""
    executable = _write_executable(tmp_path / "command", "#!/bin/sh\nexit 0\n")

    def fail_spawn(*_args: object, **_kwargs: object) -> None:
        raise OSError("unavailable")

    monkeypatch.setattr(trusted_module.subprocess, "Popen", fail_spawn)
    with (
        _open_fixture_executable(executable) as handle,
        pytest.raises(RuntimeError, match="metadata query failed"),
    ):
        run_trusted_command(
            handle,
            (),
            environment=_TEST_ENVIRONMENT,
            timeout_seconds=1,
            output_limit=128,
        )


def test_trusted_command_kills_tree_when_pipes_close_before_timeout(tmp_path: Path) -> None:
    """A pipe-closing leader cannot outlive the command deadline with child processes."""
    child_pid_path = tmp_path / "child.pid"
    executable = _write_executable(
        tmp_path / "pipe-closer",
        "#!/bin/sh\n"
        "/bin/sleep 30 &\n"
        f"printf '%s\\n' \"$!\" > '{child_pid_path}'\n"
        "exec 1>&- 2>&-\n"
        "/bin/sleep 30\n",
    )
    started = time.monotonic()
    with (
        _open_fixture_executable(executable) as handle,
        pytest.raises(RuntimeError, match="timed out"),
    ):
        run_trusted_command(
            handle,
            (),
            environment=_TEST_ENVIRONMENT,
            timeout_seconds=1,
            output_limit=128,
        )
    assert time.monotonic() - started < 2.5
    child_pid = int(child_pid_path.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 1
    while Path(f"/proc/{child_pid}").exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not Path(f"/proc/{child_pid}").exists()


def test_trusted_command_applies_deadline_after_both_pipes_close(tmp_path: Path) -> None:
    """A live leader with closed pipes is waited for only until the same deadline."""
    executable = _write_executable(
        tmp_path / "pipe-closer",
        "#!/bin/sh\nexec 1>&- 2>&-\n/bin/sleep 30\n",
    )
    with (
        _open_fixture_executable(executable) as handle,
        pytest.raises(RuntimeError, match="timed out"),
    ):
        run_trusted_command(
            handle,
            (),
            environment=_TEST_ENVIRONMENT,
            timeout_seconds=1,
            output_limit=128,
        )


def test_trusted_command_kills_unbounded_producer_at_streaming_limit(tmp_path: Path) -> None:
    """Aggregate output is bounded while the producer is still running."""
    executable = _write_executable(
        tmp_path / "producer",
        "#!/bin/sh\nwhile :; do printf '0123456789abcdef'; done\n",
    )
    with (
        _open_fixture_executable(executable) as handle,
        pytest.raises(RuntimeError, match="exceeded output limit"),
    ):
        run_trusted_command(
            handle,
            (),
            environment=_TEST_ENVIRONMENT,
            timeout_seconds=2,
            output_limit=127,
        )


def test_trusted_command_executes_open_descriptor_after_path_replacement(tmp_path: Path) -> None:
    """Pinned execution runs inspected bytes even after an atomic path replacement."""
    executable = _write_executable(
        tmp_path / "command",
        "#!/bin/sh\nprintf 'original\\n'\n",
    )
    with _open_fixture_executable(executable) as handle:
        replacement = _write_executable(
            tmp_path / "replacement",
            "#!/bin/sh\nprintf 'replacement\\n'\n",
        )
        replacement.replace(executable)
        completed = run_trusted_command(
            handle,
            (),
            environment=_TEST_ENVIRONMENT,
            timeout_seconds=1,
            output_limit=128,
        )
        assert completed.stdout == b"original\n"
        assert completed.stderr == b""
        assert completed.returncode == 0
        replacement_snapshot = snapshot_executable(
            executable,
            required_owner_uid=os.getuid(),
            forbidden_mode_bits=0o6022,
            require_single_link=True,
        )
        assert replacement_snapshot.digest != handle.snapshot.digest
    with pytest.raises(RuntimeError, match="descriptor is closed"):
        _ = handle.execution_path


def test_trusted_command_rejects_non_positive_bounds(tmp_path: Path) -> None:
    """Timeout and output bounds cannot silently disable resource controls."""
    executable = _write_executable(tmp_path / "command", "#!/bin/sh\nexit 0\n")
    with _open_fixture_executable(executable) as handle:
        for timeout, limit in ((0, 1), (1, 0)):
            with pytest.raises(ValueError, match="bounds must be positive"):
                run_trusted_command(
                    handle,
                    (),
                    environment=_TEST_ENVIRONMENT,
                    timeout_seconds=timeout,
                    output_limit=limit,
                )


def test_trusted_executable_rejects_unsupported_components_and_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing platform primitives and descriptor execution fail closed."""
    executable = _write_executable(tmp_path / "command", "#!/bin/sh\nexit 0\n")
    with pytest.raises(RuntimeError, match="absolute file path"):
        _open_fixture_executable(Path("relative-command"))

    monkeypatch.setattr(trusted_module.os, "supports_dir_fd", set())
    with pytest.raises(RuntimeError, match="component-safe"):
        _open_fixture_executable(executable)
    monkeypatch.undo()

    handle = _open_fixture_executable(executable)
    monkeypatch.setattr(trusted_module.Path, "is_dir", lambda _path: False)
    with pytest.raises(RuntimeError, match="descriptor-pinned"):
        _ = handle.execution_path
    handle.close()
    handle.close()
