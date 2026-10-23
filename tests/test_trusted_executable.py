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


def test_trusted_command_normalises_real_spawn_failures(tmp_path: Path) -> None:
    """A missing shebang interpreter exposes no host-dependent spawn detail."""
    executable = _write_executable(
        tmp_path / "command",
        "#!/rigor-foundry-missing-interpreter\n",
    )
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


def test_trusted_executable_rejects_relative_paths(tmp_path: Path) -> None:
    """The public opener accepts only absolute component-safe paths."""
    _write_executable(tmp_path / "command", "#!/bin/sh\nexit 0\n")
    with pytest.raises(RuntimeError, match="absolute file path"):
        _open_fixture_executable(Path("relative-command"))


def test_trusted_command_combines_both_streams_under_one_limit(tmp_path: Path) -> None:
    """The ceiling counts stdout and stderr together and permits exact equality."""
    executable = _write_executable(
        tmp_path / "both-streams", "#!/bin/sh\nprintf 'abcd'\nprintf 'efgh' >&2\n"
    )
    with _open_fixture_executable(executable) as handle:
        result = run_trusted_command(
            handle,
            (),
            environment=_TEST_ENVIRONMENT,
            timeout_seconds=1,
            output_limit=8,
            cwd=tmp_path,
        )
        assert (result.stdout, result.stderr, result.returncode) == (b"abcd", b"efgh", 0)
        with pytest.raises(RuntimeError, match="exceeded output limit"):
            run_trusted_command(
                handle,
                (),
                environment=_TEST_ENVIRONMENT,
                timeout_seconds=1,
                output_limit=7,
                cwd=tmp_path,
            )


@pytest.mark.parametrize("kind", ("directory", "fifo"))
def test_trusted_executable_refuses_nonregular_sources_without_blocking(
    tmp_path: Path, kind: str
) -> None:
    """A FIFO is opened nonblocking before the actual descriptor type check."""
    path = tmp_path / "not-an-executable"
    if kind == "directory":
        path.mkdir()
    else:
        os.mkfifo(path, 0o600)
    with pytest.raises(RuntimeError, match="not a regular file"):
        _open_fixture_executable(path)


@pytest.mark.parametrize(
    ("kind", "message"),
    (
        ("missing", "unavailable"),
        ("leaf-symlink", "unavailable"),
        ("parent-symlink", "unavailable"),
        ("parent-file", "unavailable"),
        ("owner", "untrusted owner"),
        ("writable", "unsafe mode bits"),
        ("setuid", "unsafe mode bits"),
        ("hardlink", "must have one link"),
        ("nonexecutable", "not owner-executable"),
    ),
)
def test_trusted_executable_refuses_actual_unsafe_filesystem_objects(
    tmp_path: Path, kind: str, message: str
) -> None:
    """Unsafe real files and path components refuse without leaking descriptors."""
    path = _write_executable(tmp_path / "command", "#!/bin/sh\nexit 0\n")
    required_owner = os.getuid()
    if kind == "missing":
        path = tmp_path / "missing"
    elif kind == "leaf-symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(path)
        path = alias
    elif kind == "parent-symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(tmp_path, target_is_directory=True)
        path = alias / path.name
    elif kind == "parent-file":
        path = path / "child"
    elif kind == "owner":
        required_owner += 1
    elif kind == "writable":
        path.chmod(0o775)
    elif kind == "setuid":
        path.chmod(0o4755)
    elif kind == "hardlink":
        os.link(path, tmp_path / "second-link")
    else:
        path.chmod(0o644)
    descriptors = set(Path("/proc/self/fd").iterdir())
    with pytest.raises(RuntimeError, match=message):
        open_trusted_executable(
            path,
            required_owner_uid=required_owner,
            forbidden_mode_bits=0o6022,
            require_single_link=True,
        )
    assert set(Path("/proc/self/fd").iterdir()) == descriptors


def test_trusted_command_reaps_a_producer_ignoring_termination(tmp_path: Path) -> None:
    """A real SIGTERM-resistant producer is killed and reaped after output refusal."""
    pid_path = tmp_path / "producer.pid"
    executable = _write_executable(
        tmp_path / "producer",
        "#!/bin/sh\ntrap '' TERM\n"
        f"printf '%s\\n' \"$$\" > '{pid_path}'\n"
        "while :; do printf '0123456789abcdef'; done\n",
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
    pid = int(pid_path.read_text(encoding="utf-8"))
    assert not Path(f"/proc/{pid}").exists()


def test_trusted_command_accepts_a_leader_that_closes_streams_before_exit(tmp_path: Path) -> None:
    """Closed output pipes do not substitute for waiting for the real exit status."""
    executable = _write_executable(
        tmp_path / "pipe-closer",
        "#!/bin/sh\nexec 1>&- 2>&-\n/bin/sleep 0.1\nexit 23\n",
    )
    handle = _open_fixture_executable(executable)
    with handle:
        result = run_trusted_command(
            handle,
            (),
            environment=_TEST_ENVIRONMENT,
            timeout_seconds=2,
            output_limit=128,
        )
    handle.close()
    assert (result.returncode, result.stdout, result.stderr) == (23, b"", b"")


@pytest.mark.parametrize("phase", ("interrupt", "spent-deadline"))
def test_actual_process_interrupt_and_spent_deadline_reap_the_closed_pipe_leader(
    tmp_path: Path, phase: str
) -> None:
    """Real interruption and elapsed time still reap a live leader after pipe EOF."""
    import json
    import signal
    import sys

    from project_registry_syscall_scheduler import SyscallStop, run_traced, write_trace

    pid_path = tmp_path / "producer.pid"
    executable = _write_executable(
        tmp_path / "closed-pipe-producer",
        f"#!/bin/sh\nprintf '%s\\n' \"$$\" > '{pid_path}'\nexec 1>&- 2>&-\nexec /bin/sleep 30\n",
    )
    changed = False

    def boundary(stop: SyscallStop) -> bool:
        """Schedule only the owned worker's actual first nonblocking leader wait."""
        nonlocal changed
        if not changed and stop.number == 61 and stop.entering:
            assert pid_path.exists()
            assert Path(f"/proc/{int(pid_path.read_text())}").exists()
            changed = True
            if phase == "interrupt":
                os.kill(stop.pid, signal.SIGINT)
            else:
                time.sleep(1.1)
        return False

    worker = """
import json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[3])
from project_registry_syscall_scheduler import arm_native_trace
from rigor_foundry.trusted_executable import open_trusted_executable,run_trusted_command
before=set(Path('/proc/self/fd').iterdir())
with open_trusted_executable(Path(sys.argv[1]),required_owner_uid=os.getuid(),forbidden_mode_bits=0o6022,require_single_link=True) as handle:
    arm_native_trace()
    try:
        run_trusted_command(handle,(),environment={'PATH':'/usr/bin:/bin'},timeout_seconds=1,output_limit=128)
    except (KeyboardInterrupt,RuntimeError) as exc:
        outcome=type(exc).__name__
    else:
        outcome='accepted'
pid=int(Path(sys.argv[2]).read_text())
print(json.dumps({'outcome':outcome,'leader_live':Path(f'/proc/{pid}').exists(),'descriptors_restored':set(Path('/proc/self/fd').iterdir())==before}))
"""
    observed = run_traced(
        [
            sys.executable,
            "-B",
            "-c",
            worker,
            str(executable),
            str(pid_path),
            str(Path(__file__).parent),
        ],
        boundary,
        timeout=20,
    )
    write_trace(tmp_path / "process-boundary-trace.json", observed)
    assert changed, "the real leader wait boundary was not reached"
    assert observed.returncode == 0, observed.stderr
    assert json.loads(observed.stdout) == {
        "outcome": "KeyboardInterrupt" if phase == "interrupt" else "TrustedCommandTimeout",
        "leader_live": False,
        "descriptors_restored": True,
    }
