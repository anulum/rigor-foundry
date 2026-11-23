# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real native public job observation contracts
"""Observe actual empty and active jobs through the public borrowed-handle API."""

from __future__ import annotations

import ctypes
import subprocess
import sys
import unittest
from ctypes import wintypes as w
from pathlib import Path

from rigor_foundry.windows_abi import windows_library
from rigor_foundry.windows_process import wait_windows_job_empty


class JobObservationArgumentTests(unittest.TestCase):
    """Validate explicit observation bounds before accessing native resources."""

    def test_null_and_non_native_handles_are_refused(self) -> None:
        """Reject absent or lossy handle values before any native binding or query."""
        bits = ctypes.sizeof(w.HANDLE) * 8
        for handle in (0, False, True, None, 1.0, "1", 1 << bits, -(1 << (bits - 1)) - 1):
            with self.subTest(handle=handle):
                self.assertRaisesRegex(
                    ValueError,
                    "nonzero native integer",
                    wait_windows_job_empty,
                    handle,
                )

    def test_invalid_deadlines_are_refused(self) -> None:
        """Reject boolean and nonpositive operation deadlines at the public boundary."""
        for timeout in (True, 0, -1):
            with (
                self.subTest(timeout=timeout),
                self.assertRaisesRegex(ValueError, "positive integer"),
            ):
                wait_windows_job_empty(1, timeout_seconds=timeout)


@unittest.skipUnless(
    sys.platform == "win32", "requires real Windows jobs and native membership accounting"
)
class WindowsJobObservationTests(unittest.TestCase):
    """Keep genuine job populations, actual elapsed deadlines and exact resource cleanup."""

    def setUp(self) -> None:
        """Bind actual fixture APIs and warm up before measuring owned resources."""
        self.kernel = windows_library("kernel32")
        self.kernel.CreateJobObjectW.argtypes = [w.LPVOID, w.LPCWSTR]
        self.kernel.CreateJobObjectW.restype = w.HANDLE
        self.kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        self.kernel.AssignProcessToJobObject.restype = w.BOOL
        self.kernel.TerminateJobObject.argtypes = [w.HANDLE, w.UINT]
        self.kernel.TerminateJobObject.restype = w.BOOL
        self.kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        self.kernel.OpenProcess.restype = w.HANDLE
        self.kernel.CloseHandle.argtypes = [w.HANDLE]
        self.kernel.CloseHandle.restype = w.BOOL
        self.kernel.GetCurrentProcess.argtypes = []
        self.kernel.GetCurrentProcess.restype = w.HANDLE
        self.kernel.GetProcessHandleCount.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
        self.kernel.GetProcessHandleCount.restype = w.BOOL
        self.kernel.DuplicateHandle.argtypes = [
            w.HANDLE,
            w.HANDLE,
            w.HANDLE,
            ctypes.POINTER(w.HANDLE),
            w.DWORD,
            w.BOOL,
            w.DWORD,
        ]
        self.kernel.DuplicateHandle.restype = w.BOOL
        job = self.kernel.CreateJobObjectW(None, None)
        self.assertIsNotNone(job)
        try:
            wait_windows_job_empty(job)
        finally:
            self.assertTrue(self.kernel.CloseHandle(job))
        # Subprocess initializes process-wide Windows state on its first invocation.
        subprocess.run(
            [str(Path(sys.base_prefix) / "python.exe"), "-I", "-c", "pass"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=5,
        )
        self.before = self.handle_count()
        self.addCleanup(self.assert_handle_count)

    def handle_count(self) -> int:
        """Read the genuine current-process handle count independently."""
        count = w.DWORD()
        self.assertTrue(
            self.kernel.GetProcessHandleCount(self.kernel.GetCurrentProcess(), ctypes.byref(count))
        )
        return count.value

    def assert_handle_count(self) -> None:
        """Require exact equality after child reaping and explicit fixture cleanup."""
        self.assertEqual(self.handle_count(), self.before)

    def test_empty_job_and_actual_invalid_handle(self) -> None:
        """Return only for a genuinely empty job and propagate the real invalid-handle query error."""
        job = self.kernel.CreateJobObjectW(None, None)
        self.assertIsNotNone(job)
        try:
            wait_windows_job_empty(job)
            with self.assertRaises(OSError) as failure:
                wait_windows_job_empty(-3)
            self.assertEqual(getattr(failure.exception, "winerror", None), 6)
            self.assertIn("query remaining owned job members", failure.exception.__notes__)
        finally:
            self.assertTrue(self.kernel.CloseHandle(job))

    def test_job_without_query_rights_preserves_native_failure(self) -> None:
        """Refuse actual job accounting when a real duplicate lacks query access."""
        job = self.kernel.CreateJobObjectW(None, None)
        self.assertIsNotNone(job)
        try:
            process = self.kernel.GetCurrentProcess()
            restricted = w.HANDLE()
            self.assertTrue(
                self.kernel.DuplicateHandle(
                    process, job, process, ctypes.byref(restricted), 0x8, False, 0
                )
            )
            try:
                handle = restricted.value
                assert handle is not None
                with self.assertRaises(OSError) as failure:
                    wait_windows_job_empty(handle)
                self.assertEqual(getattr(failure.exception, "winerror", None), 5)
                self.assertIn("query remaining owned job members", failure.exception.__notes__)
            finally:
                self.assertTrue(self.kernel.CloseHandle(restricted))
        finally:
            self.assertTrue(self.kernel.CloseHandle(job))

    def test_real_active_job_deadline_then_actual_termination_and_empty_membership(self) -> None:
        """Observe the same actual live job before and after the caller requests termination."""
        job = self.kernel.CreateJobObjectW(None, None)
        self.assertIsNotNone(job)
        python = Path(sys.base_prefix) / "python.exe"
        self.assertTrue(python.is_file())
        try:
            with subprocess.Popen(
                [str(python), "-I", "-c", "import time;time.sleep(10)"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ) as child:
                process = self.kernel.OpenProcess(0x101, False, child.pid)
                self.assertIsNotNone(process)
                try:
                    self.assertTrue(self.kernel.AssignProcessToJobObject(job, process))
                finally:
                    self.assertTrue(self.kernel.CloseHandle(process))
                try:
                    with self.assertRaisesRegex(RuntimeError, "deadline"):
                        wait_windows_job_empty(job, timeout_seconds=1)
                    self.assertIsNone(child.poll())
                finally:
                    self.assertTrue(self.kernel.TerminateJobObject(job, 1))
                    child.wait(timeout=5)
                wait_windows_job_empty(job)
        finally:
            self.assertTrue(self.kernel.CloseHandle(job))


@unittest.skipIf(sys.platform == "win32", "checks the real unsupported-platform boundary")
class UnsupportedJobObservationTests(unittest.TestCase):
    """Keep native observation unavailable on an actual non-Windows host."""

    def test_observation_requires_actual_windows(self) -> None:
        """Refuse a public observation call before native effects on Linux."""
        with self.assertRaisesRegex(RuntimeError, "require Windows"):
            wait_windows_job_empty(1)
