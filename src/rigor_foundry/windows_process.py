# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — bounded Windows process and job ownership
"""Start explicit native images in owned jobs before their first instruction."""

from __future__ import annotations

import ctypes
import subprocess
import sys
import time
from collections.abc import Callable
from ctypes import wintypes as w
from functools import partial
from pathlib import Path

from .windows_abi import windows_error, windows_last_error, windows_library


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("length", w.DWORD), ("descriptor", w.LPVOID), ("inherit", w.BOOL)]


class _StartupInfo(ctypes.Structure):
    _fields_ = [
        ("cb", w.DWORD),
        ("reserved", w.LPWSTR),
        ("desktop", w.LPWSTR),
        ("title", w.LPWSTR),
        ("x", w.DWORD),
        ("y", w.DWORD),
        ("x_size", w.DWORD),
        ("y_size", w.DWORD),
        ("x_chars", w.DWORD),
        ("y_chars", w.DWORD),
        ("fill", w.DWORD),
        ("flags", w.DWORD),
        ("show", w.WORD),
        ("reserved_bytes", w.WORD),
        ("reserved_data", w.LPVOID),
        ("stdin", w.HANDLE),
        ("stdout", w.HANDLE),
        ("stderr", w.HANDLE),
    ]


class _StartupInfoEx(ctypes.Structure):
    _fields_ = [("startup", _StartupInfo), ("attributes", w.LPVOID)]


class _ProcessInfo(ctypes.Structure):
    _fields_ = [
        ("process", w.HANDLE),
        ("thread", w.HANDLE),
        ("pid", w.DWORD),
        ("tid", w.DWORD),
    ]


class _BasicLimits(ctypes.Structure):
    _fields_ = [
        ("process_time", ctypes.c_int64),
        ("job_time", ctypes.c_int64),
        ("flags", w.DWORD),
        ("minimum_working_set", ctypes.c_size_t),
        ("maximum_working_set", ctypes.c_size_t),
        ("active_processes", w.DWORD),
        ("affinity", ctypes.c_size_t),
        ("priority", w.DWORD),
        ("scheduling", w.DWORD),
    ]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("basic", _BasicLimits),
        ("io_counters", ctypes.c_uint64 * 6),
        ("process_memory", ctypes.c_size_t),
        ("job_memory", ctypes.c_size_t),
        ("peak_process_memory", ctypes.c_size_t),
        ("peak_job_memory", ctypes.c_size_t),
    ]


class _JobAccounting(ctypes.Structure):
    _fields_ = [
        ("total_user", ctypes.c_int64),
        ("total_kernel", ctypes.c_int64),
        ("period_user", ctypes.c_int64),
        ("period_kernel", ctypes.c_int64),
        ("page_faults", w.DWORD),
        ("total_processes", w.DWORD),
        ("active_processes", w.DWORD),
        ("terminated_processes", w.DWORD),
    ]


def _library() -> ctypes.CDLL:
    """Bind exact Win32 process, job, pipe and attribute-list signatures."""
    k = windows_library("kernel32")
    k.CloseHandle.argtypes = [w.HANDLE]
    k.CloseHandle.restype = w.BOOL
    k.CreatePipe.argtypes = [
        ctypes.POINTER(w.HANDLE),
        ctypes.POINTER(w.HANDLE),
        ctypes.POINTER(_SecurityAttributes),
        w.DWORD,
    ]
    k.CreatePipe.restype = w.BOOL
    k.SetHandleInformation.argtypes = [w.HANDLE, w.DWORD, w.DWORD]
    k.SetHandleInformation.restype = w.BOOL
    k.CreateJobObjectW.argtypes = [w.LPVOID, w.LPCWSTR]
    k.CreateJobObjectW.restype = w.HANDLE
    k.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD]
    k.SetInformationJobObject.restype = w.BOOL
    k.QueryInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD, w.LPVOID]
    k.QueryInformationJobObject.restype = w.BOOL
    k.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
    k.AssignProcessToJobObject.restype = w.BOOL
    k.TerminateJobObject.argtypes = [w.HANDLE, w.UINT]
    k.TerminateJobObject.restype = w.BOOL
    k.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
    k.TerminateProcess.restype = w.BOOL
    k.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
    k.WaitForSingleObject.restype = w.DWORD
    k.GetExitCodeProcess.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
    k.GetExitCodeProcess.restype = w.BOOL
    k.QueryFullProcessImageNameW.argtypes = [
        w.HANDLE,
        w.DWORD,
        w.LPWSTR,
        ctypes.POINTER(w.DWORD),
    ]
    k.QueryFullProcessImageNameW.restype = w.BOOL
    k.GetFinalPathNameByHandleW.argtypes = [w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD]
    k.GetFinalPathNameByHandleW.restype = w.DWORD
    k.ResumeThread.argtypes = [w.HANDLE]
    k.ResumeThread.restype = w.DWORD
    k.InitializeProcThreadAttributeList.argtypes = [
        w.LPVOID,
        w.DWORD,
        w.DWORD,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    k.InitializeProcThreadAttributeList.restype = w.BOOL
    k.UpdateProcThreadAttribute.argtypes = [
        w.LPVOID,
        w.DWORD,
        ctypes.c_size_t,
        w.LPVOID,
        ctypes.c_size_t,
        w.LPVOID,
        w.LPVOID,
    ]
    k.UpdateProcThreadAttribute.restype = w.BOOL
    k.DeleteProcThreadAttributeList.argtypes = [w.LPVOID]
    k.DeleteProcThreadAttributeList.restype = None
    k.CreateProcessW.argtypes = [
        w.LPCWSTR,
        w.LPWSTR,
        w.LPVOID,
        w.LPVOID,
        w.BOOL,
        w.DWORD,
        w.LPVOID,
        w.LPCWSTR,
        ctypes.POINTER(_StartupInfoEx),
        ctypes.POINTER(_ProcessInfo),
    ]
    k.CreateProcessW.restype = w.BOOL
    k.PeekNamedPipe.argtypes = [
        w.HANDLE,
        w.LPVOID,
        w.DWORD,
        w.LPVOID,
        ctypes.POINTER(w.DWORD),
        w.LPVOID,
    ]
    k.PeekNamedPipe.restype = w.BOOL
    k.ReadFile.argtypes = [w.HANDLE, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD), w.LPVOID]
    k.ReadFile.restype = w.BOOL
    return k


def wait_windows_job_empty(job_handle: int, *, timeout_seconds: int = 2) -> None:
    """Observe genuine job membership until empty, without terminating or owning the job.

    Parameters
    ----------
    job_handle : int
        Nonzero exact Python integer representing a borrowed live native job
        handle with JOB_OBJECT_QUERY rights. Signed and unsigned pointer-width
        representations are accepted; booleans and out-of-range values are not.
        The caller must prevent closure or handle reuse throughout this call.
    timeout_seconds : int
        Positive exact integer observation budget in seconds; booleans are refused.

    Raises
    ------
    ValueError
        If the handle is null, not an exact integer or outside its native range,
        or the timeout is not a positive exact integer.
    OSError
        If the native accounting query fails.
    RuntimeError
        If actual job members remain at the observation deadline, or the host
        does not support the Windows native API.

    Notes
    -----
    A successful accounting query observed zero active members at one instant.
    The caller must prevent new admissions if it requires lasting quiescence.
    Accounting may lag process exit while process references remain open.
    This operation never assigns, terminates or closes a resource, and borrowing
    transfers no ownership. The caller retains all lifetime and cleanup duties.
    Polling uses a monotonic clock and five-millisecond sleeps; scheduling and
    native query time can extend the elapsed time beyond the budget. This
    observation RuntimeError is separate from run_windows_process's operation
    TimeoutError. KeyboardInterrupt and SystemExit propagate unchanged.
    """
    handle_bits = ctypes.sizeof(w.HANDLE) * 8
    if (
        type(job_handle) is not int
        or job_handle == 0
        or not -(1 << (handle_bits - 1)) <= job_handle < 1 << handle_bits
    ):
        raise ValueError("native job handle must be a nonzero native integer")
    if type(timeout_seconds) is not int or timeout_seconds < 1:
        raise ValueError("native job observation timeout must be a positive integer")
    kernel = _library()
    deadline = time.monotonic() + timeout_seconds
    while True:
        accounting = _JobAccounting()
        if not kernel.QueryInformationJobObject(
            job_handle, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None
        ):
            failure = windows_error()
            failure.add_note("query remaining owned job members")
            raise failure
        if accounting.active_processes == 0:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError("native job did not become empty before its deadline")
        time.sleep(0.005)


def run_windows_process(
    executable: Path,
    arguments: tuple[str, ...],
    *,
    image_handle: int,
    environment: dict[str, str],
    cwd: Path,
    timeout_seconds: int,
    output_limit: int,
) -> tuple[int, bytes, bytes]:
    """Run a caller-pinned image with literal argv, bounded pipes and an owned process tree.

    Parameters
    ----------
    executable : Path
        Explicit absolute executable whose pathname and image the caller keeps pinned.
    arguments : tuple[str, ...]
        Literal Windows CRT arguments, without command-interpreter processing.
    image_handle : int
        Borrowed noninheritable handle to the exact image, retained by the caller.
    environment : dict[str, str]
        Complete explicit environment, without ambient inheritance.
    cwd : Path
        Explicit child working directory.
    timeout_seconds : int
        Positive operation deadline for launch and pipe reads. Failure cleanup permits
        an additional two-second leader wait and two-second owned-job drain.
    output_limit : int
        Positive aggregate raw stdout/stderr byte ceiling.

    Returns
    -------
    tuple[int, bytes, bytes]
        Actual exit status and bounded raw standard streams after process settlement.

    Raises
    ------
    ValueError
        If paths, bounds, arguments or environment contain invalid values.
    TimeoutError
        If the complete operation exceeds its one deadline.
    OSError, RuntimeError
        If native launch, job ownership, output limits or settlement fail.

    Notes
    -----
    This runner does not select or hash images; the caller owns that contract.
    Suspended creation and job assignment prevent pre-assignment child execution.
    The created kernel image name must match the retained image before resumption.
    The complete owned job has a two-gibibyte committed-memory ceiling.
    Pipes are created noninheritable. Only the three child endpoints are briefly
    marked inheritable for creation with the explicit inherited-handle list.
    """
    if (
        not executable.is_absolute()
        or not cwd.is_absolute()
        or type(timeout_seconds) is not int
        or timeout_seconds < 1
        or type(output_limit) is not int
        or output_limit < 1
        or any("\0" in value for value in (str(executable), str(cwd), *arguments))
        or any(not key or "=" in key or "\0" in key + value for key, value in environment.items())
    ):
        raise ValueError("native command paths, environment, argv and bounds must be explicit")
    if len({key.casefold() for key in environment}) != len(environment):
        raise ValueError("native environment names must be distinct without case")
    k = _library()
    expected_image = ctypes.create_unicode_buffer(32768)
    image_length = k.GetFinalPathNameByHandleW(
        image_handle, expected_image, len(expected_image), 2
    )
    if not image_length or image_length >= len(expected_image):
        raise windows_error()
    handles: list[int] = []
    process = _ProcessInfo()
    attributes = None
    attributes_ready = False
    job: int | None = None
    assigned = False
    deadline = time.monotonic() + timeout_seconds

    def own(handle: int | None) -> int:
        if handle is None or handle == ctypes.c_void_p(-1).value:
            raise windows_error()
        handles.append(handle)
        return handle

    def release(handle: int) -> None:
        if not k.CloseHandle(handle):
            raise windows_error()
        handles.remove(handle)

    def pipe() -> tuple[int, int]:
        reader, writer = w.HANDLE(), w.HANDLE()
        security = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), None, False)
        if not k.CreatePipe(ctypes.byref(reader), ctypes.byref(writer), ctypes.byref(security), 0):
            raise windows_error()
        return own(reader.value), own(writer.value)

    try:
        stdin_read, stdin_write = pipe()
        stdout_read, stdout_write = pipe()
        stderr_read, stderr_write = pipe()
        release(stdin_write)
        job = own(k.CreateJobObjectW(None, None))
        limits = _ExtendedLimits()
        limits.basic.flags = 0x2000 | 0x200
        limits.job_memory = 2 * 1024**3
        if not k.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            raise windows_error()
        size = ctypes.c_size_t()
        k.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
        if not size.value:
            raise windows_error()
        attributes = ctypes.create_string_buffer(size.value)
        if not k.InitializeProcThreadAttributeList(attributes, 1, 0, ctypes.byref(size)):
            raise windows_error()
        attributes_ready = True
        inherited = (w.HANDLE * 3)(stdin_read, stdout_write, stderr_write)
        for child_handle in inherited:
            if not k.SetHandleInformation(child_handle, 1, 1):
                raise windows_error()
        if not k.UpdateProcThreadAttribute(
            attributes, 0, 0x20002, inherited, ctypes.sizeof(inherited), None, None
        ):
            raise windows_error()
        startup = _StartupInfoEx()
        startup.startup.cb = ctypes.sizeof(startup)
        startup.startup.flags = 0x100
        startup.startup.stdin = stdin_read
        startup.startup.stdout = stdout_write
        startup.startup.stderr = stderr_write
        startup.attributes = ctypes.cast(attributes, w.LPVOID)
        command = ctypes.create_unicode_buffer(
            subprocess.list2cmdline((str(executable), *arguments))
        )
        env = ctypes.create_unicode_buffer(
            "\0".join(
                f"{key}={value}"
                for key, value in sorted(environment.items(), key=lambda pair: pair[0].casefold())
            )
            + "\0\0"
        )
        if not k.CreateProcessW(
            str(executable),
            command,
            None,
            None,
            True,
            0x4 | 0x400 | 0x80000 | 0x8000000,
            env,
            str(cwd),
            ctypes.byref(startup),
            ctypes.byref(process),
        ):
            raise windows_error()
        own(process.process)
        own(process.thread)
        for child_handle in inherited:
            if not k.SetHandleInformation(child_handle, 1, 0):
                raise windows_error()
        if not k.AssignProcessToJobObject(job, process.process):
            raise windows_error()
        assigned = True
        actual_image = ctypes.create_unicode_buffer(32768)
        actual_length = w.DWORD(len(actual_image))
        if not k.QueryFullProcessImageNameW(
            process.process, 1, actual_image, ctypes.byref(actual_length)
        ):
            raise windows_error()
        if actual_image.value != expected_image.value:
            raise RuntimeError("created native image differs from the retained executable")
        if k.ResumeThread(process.thread) != 1:
            raise RuntimeError("native child did not have exactly one suspension")
        release(int(process.thread))
        process.thread = None
        for writer in (stdin_read, stdout_write, stderr_write):
            release(writer)
        buffers = [bytearray(), bytearray()]
        pipes = {stdout_read: 0, stderr_read: 1}
        done = False
        while pipes or not done:
            if time.monotonic() >= deadline:
                raise TimeoutError("native command exceeded its deadline")
            state = k.WaitForSingleObject(process.process, 0)
            if state == 0 and not done:
                done = True
                if not k.TerminateJobObject(job, 1):
                    raise windows_error()
            elif state not in (0, 258):
                raise windows_error()
            progress = False
            for reader, index in tuple(pipes.items()):
                available = w.DWORD()
                if not k.PeekNamedPipe(reader, None, 0, None, ctypes.byref(available), None):
                    if windows_last_error() == 109:
                        del pipes[reader]
                        continue
                    raise windows_error()
                if not available.value:
                    continue
                remaining = output_limit - sum(map(len, buffers))
                block = ctypes.create_string_buffer(min(8192, available.value, remaining + 1))
                read = w.DWORD()
                if not k.ReadFile(reader, block, len(block), ctypes.byref(read), None):
                    raise windows_error()
                if read.value > remaining:
                    raise RuntimeError("native command exceeded its output limit")
                buffers[index].extend(block.raw[: read.value])
                progress = True
            if not progress and (pipes or not done):
                time.sleep(min(0.01, max(0, deadline - time.monotonic())))
        code = w.DWORD()
        if not k.GetExitCodeProcess(process.process, ctypes.byref(code)):
            raise windows_error()
        return int(code.value), bytes(buffers[0]), bytes(buffers[1])
    finally:
        original_failure = sys.exception()
        cleanup_errors: list[BaseException] = []

        def cleanup_call(action: Callable[[], object], operation: str) -> bool:
            """Attempt one cleanup operation without skipping independent owned resources."""
            try:
                if action():
                    return True
                problem = windows_error()
                problem.add_note(operation)
                cleanup_errors.append(problem)
            except BaseException as exc:
                cleanup_errors.append(exc)
            return False

        job_terminated = job is None
        if job is not None:
            job_terminated = cleanup_call(
                lambda: k.TerminateJobObject(job, 1), "terminate owned job"
            )
        if process.process:
            if (not assigned or not job_terminated) and k.WaitForSingleObject(
                process.process, 0
            ) != 0:
                cleanup_call(
                    lambda: k.TerminateProcess(process.process, 1), "terminate owned leader"
                )
            try:
                state = k.WaitForSingleObject(process.process, 2000)
                if state == 0xFFFFFFFF:
                    cleanup_errors.append(windows_error())
                elif state != 0:
                    cleanup_errors.append(RuntimeError("native leader termination is unconfirmed"))
            except BaseException as exc:
                cleanup_errors.append(exc)
        for handle in (process.thread, process.process):
            if handle and cleanup_call(
                partial(k.CloseHandle, handle), "close completed process reference"
            ):
                handles.remove(int(handle))
        process.thread = None
        process.process = None
        if job is not None:
            try:
                wait_windows_job_empty(job)
            except BaseException as exc:
                cleanup_errors.append(exc)
        if attributes_ready:
            try:
                k.DeleteProcThreadAttributeList(attributes)
            except BaseException as exc:
                cleanup_errors.append(exc)
        while handles:
            remaining = handles.pop()
            cleanup_call(partial(k.CloseHandle, remaining), "release remaining owned handle")
        if cleanup_errors:
            failures = (
                cleanup_errors if original_failure is None else [original_failure, *cleanup_errors]
            )
            grouped = BaseExceptionGroup("native operation and cleanup failures", failures)
            if not isinstance(grouped, ExceptionGroup):
                raise grouped
            raise RuntimeError("native command cleanup failed") from grouped
