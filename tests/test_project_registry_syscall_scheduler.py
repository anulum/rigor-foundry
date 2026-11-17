# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual owned scheduler process and filesystem contracts
"""Exercise public native tracing, refusal, signals and complete worker cleanup."""

from __future__ import annotations

import ctypes
import errno
import json
import os
import signal
import sys
from pathlib import Path

import pytest
from project_registry_syscall_scheduler import (
    PATH_STAT_SYSCALLS,
    SyscallStop,
    run_traced,
    write_trace,
)


def worker_command(body: str, *arguments: str) -> list[str]:
    """Build an owned real Python worker with the maintained scheduler import.

    Parameters
    ----------
    body : str
        Actual process and filesystem operations after the common imports.
    *arguments : str
        Explicit worker input paths.

    Returns
    -------
    list[str]
        Literal Python argv without shell interpretation or dependency replacement.
    """
    imports = (
        "import sys\nsys.path.insert(0, sys.argv.pop(1))\n"
        "import ctypes, errno, json, os, signal, stat, time\nfrom pathlib import Path\n"
        "from project_registry_syscall_scheduler import arm_native_trace\n"
    )
    return [sys.executable, "-B", "-c", imports + body, str(Path(__file__).parent), *arguments]


def assert_reaped(pid: int) -> None:
    """Require that the exact owned worker is neither live nor awaiting waitpid.

    Parameters
    ----------
    pid : int
        Actual process identity observed from the worker or scheduler.
    """
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_trace_admission_requires_the_actual_process_pointer_width(tmp_path: Path) -> None:
    """Refuse real 32-bit userspace even when its native kernel reports x86-64.

    Parameters
    ----------
    tmp_path : Path
        Original native admission trace for the supported 64-bit execution.
    """
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        from project_registry_syscall_scheduler import arm_native_trace

        with pytest.raises(RuntimeError, match="requires Linux x86-64"):
            arm_native_trace()
    else:
        result = run_traced(
            worker_command("arm_native_trace()\nprint('native 64-bit admission')\n"),
            lambda _stop: False,
        )
        write_trace(tmp_path / "actual-process-admission-trace.json", result)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "native 64-bit admission"
        assert_reaped(result.pid)


def test_real_file_operations_preserve_syscall_identity_and_descriptor_paths(
    tmp_path: Path,
) -> None:
    """Observe real stat, rename and invalid-descriptor results without replacing them.

    Parameters
    ----------
    tmp_path : Path
        Owned ordinary file, symlink and descriptor-relative rename allocation.
    """
    target = tmp_path / "source"
    target.write_bytes(b"preserved source bytes")
    alias = tmp_path / "alias"
    alias.symlink_to(target.name)
    body = """
root = Path(sys.argv[1])
arm_native_trace()
with (root / "source").open("rb") as stream:
    observed = os.stat(root / "source")
    linked = os.lstat(root / "alias")
    descriptor = os.fstat(stream.fileno())
    assert observed.st_ino == descriptor.st_ino
    assert stat.S_ISLNK(linked.st_mode)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.argtypes = [ctypes.c_long, ctypes.c_char_p, ctypes.c_void_p]
    libc.syscall.restype = ctypes.c_long
    # Linux x86-64 UAPI asm/stat.h: 144 bytes; st_ino is the second ulong.
    native_stat = (ctypes.c_ulong * 18)()
    for number, name, expected in [(4, "source", observed), (6, "alias", linked)]:
        assert libc.syscall(number, os.fsencode(root / name), ctypes.byref(native_stat)) == 0
        assert native_stat[1] == expected.st_ino
try:
    os.read(-1, 1)
except OSError as exc:
    assert exc.errno == errno.EBADF
else:
    raise AssertionError("invalid descriptor unexpectedly readable")
parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.rename("source", "renamed", src_dir_fd=parent, dst_dir_fd=parent)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    libc.renameat2.restype = ctypes.c_int
    assert libc.renameat2(parent, b"renamed", parent, b"final", 1) == 0
finally:
    os.close(parent)
print(json.dumps({"size": descriptor.st_size, "content": (root / "final").read_text()}))
"""
    before = len(os.listdir("/proc/self/fd"))
    result = run_traced(worker_command(body, str(tmp_path)), lambda _stop: False)
    write_trace(tmp_path / "file-operation-trace.json", result)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"size": 22, "content": "preserved source bytes"}
    assert (tmp_path / "final").read_bytes() == b"preserved source bytes"
    assert alias.is_symlink()
    assert not target.exists() and not (tmp_path / "renamed").exists()
    assert any(
        stop.entering and stop.number in PATH_STAT_SYSCALLS and stop.path == str(alias)
        for stop in result.stops
    )
    assert any(stop.number in {5, 262} and stop.path == str(target) for stop in result.stops)
    for number, pathname in [(4, target), (6, alias)]:
        assert any(
            stop.number == number
            and not stop.entering
            and stop.result == 0
            and stop.path == str(pathname)
            for stop in result.stops
        )
    assert any(
        stop.number == 264 and stop.path == str(tmp_path / "renamed") for stop in result.stops
    )
    assert any(
        stop.number == 316 and stop.path == str(tmp_path / "final") for stop in result.stops
    )
    assert any(
        stop.number == 0 and not stop.entering and stop.result == -errno.EBADF and stop.path == ""
        for stop in result.stops
    )
    assert_reaped(result.pid)
    assert len(os.listdir("/proc/self/fd")) == before


@pytest.mark.parametrize("failure", ["exit", "signal", "wrong-stop"])
def test_actual_invalid_initial_workers_are_refused_and_reaped(
    tmp_path: Path, failure: str
) -> None:
    """Keep malformed real worker startup from leaving a live process or open pipes.

    Parameters
    ----------
    tmp_path : Path
        Actual worker identity record.
    failure : str
        Terminal exit, terminal signal or incorrect first native trace stop.
    """
    pid_file = tmp_path / "worker.pid"
    bodies = {
        "exit": "raise SystemExit(7)\n",
        "signal": "os.kill(os.getpid(), signal.SIGTERM)\n",
        "wrong-stop": (
            "libc = ctypes.CDLL(None, use_errno=True)\n"
            "libc.ptrace.restype = ctypes.c_long\n"
            "assert libc.ptrace(0, 0, None, None) == 0\n"
            "os.kill(os.getpid(), signal.SIGUSR1)\n"
        ),
    }
    body = "Path(sys.argv[1]).write_text(str(os.getpid()))\n" + bodies[failure]
    before = len(os.listdir("/proc/self/fd"))
    with pytest.raises(RuntimeError, match="worker did not enter its native trace stop"):
        run_traced(worker_command(body, str(pid_file)), lambda _stop: False)
    assert_reaped(int(pid_file.read_text()))
    assert len(os.listdir("/proc/self/fd")) == before


def test_actual_terminal_signal_is_forwarded_and_the_worker_is_reaped(tmp_path: Path) -> None:
    """Forward a genuine terminal signal without changing its native exit status.

    Parameters
    ----------
    tmp_path : Path
        Original native signal trace allocation.
    """
    body = "arm_native_trace()\nos.kill(os.getpid(), signal.SIGTERM)\n"
    result = run_traced(worker_command(body), lambda _stop: False)
    write_trace(tmp_path / "terminal-signal-trace.json", result)
    assert result.returncode == -signal.SIGTERM
    assert_reaped(result.pid)


def test_requested_crash_at_actual_open_preserves_the_file_and_reaps_worker(
    tmp_path: Path,
) -> None:
    """A selected real syscall stop kills only the owned worker before the write.

    Parameters
    ----------
    tmp_path : Path
        Owned file that must retain its original bytes after the crash.
    """
    target = tmp_path / "retained"
    target.write_bytes(b"untouched")
    selected: list[SyscallStop] = []

    def crash(stop: SyscallStop) -> bool:
        """Select the actual owned worker open without changing its result."""
        if stop.entering and stop.number == 257 and stop.path == str(target):
            selected.append(stop)
            return True
        return False

    body = "arm_native_trace()\nPath(sys.argv[1]).write_text('replacement')\n"
    result = run_traced(worker_command(body, str(target)), crash)
    write_trace(tmp_path / "requested-crash-trace.json", result)
    assert len(selected) == 1
    assert result.returncode == -signal.SIGKILL
    assert target.read_bytes() == b"untouched"
    assert_reaped(result.pid)


def test_real_deadline_terminates_and_reaps_the_sleeping_worker(tmp_path: Path) -> None:
    """Enforce the public absolute deadline and complete actual process cleanup.

    Parameters
    ----------
    tmp_path : Path
        Native worker PID record written before the traced sleep.
    """
    pid_file = tmp_path / "deadline.pid"
    body = "Path(sys.argv[1]).write_text(str(os.getpid()))\narm_native_trace()\ntime.sleep(30)\n"
    before = len(os.listdir("/proc/self/fd"))
    with pytest.raises(TimeoutError, match="exceeded its absolute deadline"):
        run_traced(worker_command(body, str(pid_file)), lambda _stop: False, timeout=5)
    assert_reaped(int(pid_file.read_text()))
    assert len(os.listdir("/proc/self/fd")) == before


def test_real_kernel_refuses_repeated_trace_registration(tmp_path: Path) -> None:
    """Propagate the actual kernel EPERM when an already traced worker re-arms.

    Parameters
    ----------
    tmp_path : Path
        Original repeated-registration native trace allocation.
    """
    body = """
arm_native_trace()
try:
    arm_native_trace()
except OSError as exc:
    print(json.dumps({"errno": exc.errno}))
else:
    raise AssertionError("already traced worker unexpectedly registered again")
"""
    result = run_traced(worker_command(body), lambda _stop: False)
    write_trace(tmp_path / "repeated-registration-trace.json", result)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"errno": errno.EPERM}
    assert_reaped(result.pid)
