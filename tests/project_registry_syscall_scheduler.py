# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native registry syscall scheduling
"""Schedule real filesystem mutations at owned Linux x86-64 syscall stops."""

from __future__ import annotations

import ctypes
import json
import os
import platform
import signal
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.ptrace.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
_LIBC.ptrace.restype = ctypes.c_long


class _Registers(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_ulonglong)
        for name in [
            "r15",
            "r14",
            "r13",
            "r12",
            "rbp",
            "rbx",
            "r11",
            "r10",
            "r9",
            "r8",
            "rax",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "orig_rax",
            "rip",
            "cs",
            "eflags",
            "rsp",
            "ss",
            "fs_base",
            "gs_base",
            "ds",
            "es",
            "fs",
            "gs",
        ]
    ]


def _ptrace(request: int, pid: int, data: int = 0) -> None:
    if int(_LIBC.ptrace(request, pid, None, ctypes.c_void_p(data))) < 0:
        raise OSError(ctypes.get_errno(), "owned child ptrace failed")


def arm_native_trace() -> None:
    """Ask the actual parent to schedule this child before its public API call.

    Raises
    ------
    RuntimeError
        If this is not the explicitly supported Linux x86-64 test ABI.
    OSError
        If the kernel refuses tracing of this owned child.
    """
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("registry syscall scheduler requires Linux x86-64")
    _ptrace(0, 0)
    os.kill(os.getpid(), signal.SIGSTOP)


@dataclass(frozen=True)
class SyscallStop:
    """Actual syscall phase and its observed owned-file path.

    Attributes
    ----------
    number : int
        Linux x86-64 syscall number.
    entering : bool
        Whether the kernel has stopped before executing the syscall.
    result : int
        Signed kernel result, meaningful at exit only.
    path : str
        Observed pathname or actual descriptor link; empty for other syscalls.
    pid : int
        Actual owned child stopped by the kernel.
    """

    number: int
    entering: bool
    result: int
    path: str
    pid: int


@dataclass(frozen=True)
class TracedResult:
    """Reaped child status, bounded outputs and actual syscall observations."""

    returncode: int
    stdout: str
    stderr: str
    stops: tuple[SyscallStop, ...]
    pid: int


def write_trace(path: Path, result: TracedResult) -> None:
    """Retain actual child status, outputs and syscall stops in its fixture.

    Parameters
    ----------
    path : Path
        Exact task-owned diagnostic output path.
    result : TracedResult
        Reaped native observation; no generated syscall responses.
    """
    path.write_text(
        json.dumps(
            {
                "pid": result.pid,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "stops": [
                    {
                        "number": stop.number,
                        "entering": stop.entering,
                        "result": stop.result,
                        "path": stop.path,
                    }
                    for stop in result.stops
                ],
            },
            indent=2,
        )
        + "\n"
    )


def _descriptor_path(pid: int, descriptor: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/fd/{descriptor}")
    except FileNotFoundError:
        return ""


def _pathname(pid: int, address: int, descriptor: int) -> str:
    memory = os.open(f"/proc/{pid}/mem", os.O_RDONLY | os.O_CLOEXEC)
    try:
        raw = os.pread(memory, 4096, address)
    finally:
        os.close(memory)
    pathname = os.fsdecode(raw.split(b"\0", 1)[0])
    if pathname.startswith("/"):
        return pathname
    base = (
        os.readlink(f"/proc/{pid}/cwd")
        if ctypes.c_int(descriptor).value == -100
        else _descriptor_path(pid, descriptor)
    )
    return str(Path(base) / pathname)


def _observe(pid: int, entering: bool) -> SyscallStop:
    registers = _Registers()
    _ptrace(12, pid, ctypes.addressof(registers))
    number = int(registers.orig_rax)
    path = ""
    if number in {0, 217}:
        path = _descriptor_path(pid, int(registers.rdi))
    elif number in {257, 262}:
        path = _pathname(pid, int(registers.rsi), int(registers.rdi))
    elif number == 82:
        path = _pathname(pid, int(registers.rsi), -100)
    elif number in {264, 316}:
        path = _pathname(pid, int(registers.r10), int(registers.rdx))
    return SyscallStop(number, entering, ctypes.c_longlong(int(registers.rax)).value, path, pid)


def _wait(pid: int, deadline: float) -> int:
    while time.monotonic() < deadline:
        observed, status = os.waitpid(pid, os.WNOHANG)
        if observed:
            return status
        time.sleep(0.001)
    raise TimeoutError("owned registry process exceeded its absolute deadline")


def run_traced(
    command: Sequence[str],
    on_stop: Callable[[SyscallStop], bool],
    *,
    timeout: float = 20,
) -> TracedResult:
    """Run one owned worker with observation-only native syscall scheduling.

    Parameters
    ----------
    command : sequence of str
        Explicit worker argv; the worker must call ``arm_native_trace``.
    on_stop : callable
        Receives actual stops. Mutate owned fixture files here; returning true
        kills the exact worker at this boundary to create a genuine crash.
        Registers, memory and syscall results are never changed.
    timeout : float
        One absolute whole-worker budget in seconds, including initial stop.

    Returns
    -------
    TracedResult
        Reaped status and outputs, including every scheduled syscall phase.

    Raises
    ------
    RuntimeError
        If the worker exits before entering its expected initial trace stop.
    TimeoutError
        If the child exceeds its absolute deadline; it is killed and reaped.
    OSError
        If actual tracing, observation or wait operations fail.
    """
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True
    )
    stops: list[SyscallStop] = []
    entering = True
    try:
        status = _wait(process.pid, deadline)
        if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGSTOP:
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                process.returncode = os.waitstatus_to_exitcode(status)
            raise RuntimeError("worker did not enter its native trace stop")
        _ptrace(0x4200, process.pid, 0x100001)
        _ptrace(24, process.pid)
        while True:
            status = _wait(process.pid, deadline)
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                process.returncode = os.waitstatus_to_exitcode(status)
                break
            stop_signal = os.WSTOPSIG(status)
            if stop_signal == signal.SIGTRAP | 0x80:
                stop = _observe(process.pid, entering)
                stops.append(stop)
                if on_stop(stop):
                    os.kill(process.pid, signal.SIGKILL)
                else:
                    _ptrace(24, process.pid)
                entering = not entering
            else:
                _ptrace(24, process.pid, stop_signal)
        stdout, stderr = process.communicate(timeout=max(0.001, deadline - time.monotonic()))
        return TracedResult(process.returncode, stdout, stderr, tuple(stops), process.pid)
    finally:
        if process.returncode is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
