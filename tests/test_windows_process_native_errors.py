# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — genuine native process API error propagation contracts
"""Keep genuine native API failures and independent process-resource cleanup evidence."""

from __future__ import annotations

import ctypes
import os
import signal
import sys
import tempfile
import unittest
from collections.abc import Callable
from contextlib import ExitStack
from ctypes import wintypes as w
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from rigor_foundry import windows_process
from rigor_foundry.windows_abi import windows_last_error, windows_library
from rigor_foundry.windows_handles import WindowsDirectory


class InvalidSecurityAttributes(ctypes.Structure):
    """Native SECURITY_ATTRIBUTES referencing an allocated descriptor with invalid revision."""

    _fields_ = [("length", w.DWORD), ("descriptor", w.LPVOID), ("inherit", w.BOOL)]


@unittest.skipUnless(
    sys.platform == "win32", "requires genuine Windows native process API failures"
)
class WindowsProcessNativeErrorTests(unittest.TestCase):
    """Use actual system functions with invalid inputs, never fabricated native return values."""

    def setUp(self) -> None:
        """Retain a real image and DLL, then warm up before exact handle-count measurement."""
        self.resources = ExitStack()
        self.addCleanup(self.resources.close)
        temporary = self.resources.enter_context(
            tempfile.TemporaryDirectory(prefix="rigor-native-api-error-")
        )
        self.root = Path(temporary).resolve()
        self.python = Path(sys.base_prefix) / "python.exe"
        directory = self.resources.enter_context(WindowsDirectory(self.python.parent))
        self.image = self.resources.enter_context(directory.open_file(self.python.name))
        self.kernel = windows_library("kernel32")
        self.kernel.GetCurrentProcess.argtypes = []
        self.kernel.GetCurrentProcess.restype = w.HANDLE
        self.kernel.GetProcessHandleCount.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
        self.kernel.GetProcessHandleCount.restype = w.BOOL
        self.resources.enter_context(
            patch.object(windows_process, "windows_library", side_effect=self.library)
        )
        self.assertEqual(self.run_python(), (0, b"native output", b""))
        self.before = self.handle_count()
        self.addCleanup(self.assert_handle_count)

    def library(self, name: str) -> ctypes.CDLL:
        """Return the same genuine system library, retaining its actual function ABI."""
        self.assertEqual(name, "kernel32")
        return self.kernel

    def run_python(self) -> tuple[int, bytes, bytes]:
        """Invoke the public runner with an actual pinned image and finite bounds."""
        return windows_process.run_windows_process(
            self.python,
            ("-I", "-c", "import sys;sys.stdout.write('native output');sys.stdout.flush()"),
            image_handle=self.image.handle,
            environment=dict(os.environ),
            cwd=self.root,
            timeout_seconds=10,
            output_limit=4096,
        )

    def handle_count(self) -> int:
        """Read the actual current process handle count independently of the owner."""
        count = w.DWORD()
        self.assertTrue(
            self.kernel.GetProcessHandleCount(self.kernel.GetCurrentProcess(), ctypes.byref(count))
        )
        return count.value

    def assert_handle_count(self) -> None:
        """Require equality after every operation while the pinned image remains retained."""
        self.assertEqual(self.handle_count(), self.before)

    def bind_actual_failure(
        self, name: str, index: int, invalid: object, outcomes: list[tuple[int | None, int]]
    ) -> Callable[..., int | None]:
        """Bind one actual native function and retain its untouched failure result."""
        original = getattr(self.kernel, name)

        def call_actual_api_with_invalid_argument(*args: object) -> int | None:
            """Call the real configured API with one invalid argument and preserve its result."""
            changed = list(args)
            changed[index] = invalid
            result: int | None = original(*changed)
            outcomes.append((result, windows_last_error()))
            return result

        return call_actual_api_with_invalid_argument

    def test_genuine_parameter_failures_release_all_independent_resources(self) -> None:
        """Propagate actual failures for each system API and return to the exact handle baseline."""
        invalid_descriptor = ctypes.create_string_buffer(64)
        invalid_security = InvalidSecurityAttributes(
            ctypes.sizeof(InvalidSecurityAttributes),
            ctypes.cast(invalid_descriptor, w.LPVOID),
            False,
        )
        invalid_pipe_security = ctypes.cast(
            ctypes.byref(invalid_security), cast(Any, self.kernel.CreatePipe.argtypes[2])
        )
        invalid_handle = w.HANDLE(-3)
        cases: tuple[tuple[str, int, object, type[Exception]], ...] = (
            ("CreatePipe", 2, invalid_pipe_security, OSError),
            ("CreateJobObjectW", 0, ctypes.byref(invalid_security), OSError),
            ("SetInformationJobObject", 1, 9999, OSError),
            ("InitializeProcThreadAttributeList", 2, 1, OSError),
            ("SetHandleInformation", 0, invalid_handle, OSError),
            ("UpdateProcThreadAttribute", 2, 0xFFFFFFFF, OSError),
            ("AssignProcessToJobObject", 0, invalid_handle, OSError),
            ("QueryFullProcessImageNameW", 0, invalid_handle, OSError),
            ("ResumeThread", 0, invalid_handle, RuntimeError),
            ("PeekNamedPipe", 0, invalid_handle, OSError),
            ("ReadFile", 0, invalid_handle, OSError),
            ("GetExitCodeProcess", 0, invalid_handle, OSError),
            ("QueryInformationJobObject", 0, invalid_handle, RuntimeError),
            ("TerminateJobObject", 0, invalid_handle, RuntimeError),
            ("WaitForSingleObject", 0, invalid_handle, RuntimeError),
        )
        for name, index, invalid, expected_exception in cases:
            with self.subTest(api=name):
                outcomes: list[tuple[int | None, int]] = []
                call_actual_api_with_invalid_argument = self.bind_actual_failure(
                    name, index, invalid, outcomes
                )
                with (
                    patch.object(self.kernel, name, call_actual_api_with_invalid_argument),
                    self.assertRaises(expected_exception),
                ):
                    self.run_python()
                self.assertTrue(outcomes)
                self.assertNotEqual(outcomes[-1][1], 0)
                self.assertIn(outcomes[-1][0], (None, 0, 0xFFFFFFFF))
                self.assert_handle_count()
                self.assertEqual(self.run_python(), (0, b"native output", b""))

    def test_actual_second_attribute_initialization_failure_releases_allocated_state(self) -> None:
        """Preserve the real size query and reject unsupported flags on actual list initialization."""
        original = self.kernel.InitializeProcThreadAttributeList
        outcomes: list[tuple[int, int]] = []

        def initialize_with_invalid_flags(
            attributes: object, count: int, flags: int, size: object
        ) -> int:
            """Keep the genuine first query and use a real invalid-flags initialization call."""
            if attributes is None:
                return int(original(attributes, count, flags, size))
            result = int(original(attributes, count, 1, size))
            outcomes.append((result, windows_last_error()))
            return result

        with (
            patch.object(
                self.kernel, "InitializeProcThreadAttributeList", initialize_with_invalid_flags
            ),
            self.assertRaises(OSError),
        ):
            self.run_python()
        self.assertEqual(outcomes, [(0, 87)])
        self.assert_handle_count()

    def test_actual_child_handle_reset_failure_reaps_suspended_unassigned_process(self) -> None:
        """Return a genuine invalid-handle failure after suspended creation and before job assignment."""
        original = self.kernel.SetHandleInformation
        outcomes: list[tuple[int, int]] = []

        def reset_invalid_handle(handle: object, mask: int, flags: int) -> int:
            """Set real inheritance initially and call the genuine invalid-handle reset afterwards."""
            if flags:
                return int(original(handle, mask, flags))
            result = int(original(w.HANDLE(-3), mask, flags))
            outcomes.append((result, windows_last_error()))
            return result

        with (
            patch.object(self.kernel, "SetHandleInformation", reset_invalid_handle),
            self.assertRaises(OSError),
        ):
            self.run_python()
        self.assertEqual(outcomes, [(0, 6)])
        self.assert_handle_count()

    def test_real_interrupt_during_final_wait_preserves_control_flow(self) -> None:
        """Deliver actual SIGINT after the genuine final wait and finish independent cleanup."""
        original = self.kernel.WaitForSingleObject
        waits: list[int] = []

        def wait_then_signal(handle: object, milliseconds: int) -> int:
            """Wait on the actual owned process, then interrupt only final cleanup."""
            result = int(original(handle, milliseconds))
            if milliseconds == 2000:
                waits.append(result)
                signal.raise_signal(signal.SIGINT)
            return result

        with (
            patch.object(self.kernel, "WaitForSingleObject", wait_then_signal),
            self.assertRaises(BaseExceptionGroup) as failure,
        ):
            self.run_python()
        self.assertEqual(waits, [0])
        self.assertTrue(
            any(isinstance(error, KeyboardInterrupt) for error in failure.exception.exceptions)
        )
        self.assert_handle_count()

    def test_real_interrupt_after_attribute_deletion_preserves_remaining_closes(self) -> None:
        """Delete the actual list before a real SIGINT, preserving interruption and resource cleanup."""
        original = self.kernel.DeleteProcThreadAttributeList
        deleted: list[None] = []

        def delete_then_signal(attributes: object) -> None:
            """Free actual native state before delivering the real interruption."""
            result = original(attributes)
            self.assertIsNone(result)
            deleted.append(result)
            signal.raise_signal(signal.SIGINT)

        with (
            patch.object(self.kernel, "DeleteProcThreadAttributeList", delete_then_signal),
            self.assertRaises(BaseExceptionGroup) as failure,
        ):
            self.run_python()
        self.assertEqual(deleted, [None])
        self.assertTrue(
            any(isinstance(error, KeyboardInterrupt) for error in failure.exception.exceptions)
        )
        self.assert_handle_count()

    def test_actual_unsignaled_event_wait_is_not_reported_as_process_settlement(self) -> None:
        """Preserve a genuine finite WAIT_TIMEOUT result at the final cleanup wait boundary."""
        self.kernel.CreateEventW.argtypes = [w.LPVOID, w.BOOL, w.BOOL, w.LPCWSTR]
        self.kernel.CreateEventW.restype = w.HANDLE
        event = self.kernel.CreateEventW(None, True, False, None)
        self.assertIsNotNone(event)
        original = self.kernel.WaitForSingleObject
        outcomes: list[int] = []

        def wait_on_actual_event(handle: object, milliseconds: int) -> int:
            """Keep regular leader waits and substitute an owned unsignaled event only at cleanup."""
            if milliseconds == 2000:
                result = int(original(event, milliseconds))
                outcomes.append(result)
                return result
            return int(original(handle, milliseconds))

        try:
            with (
                patch.object(self.kernel, "WaitForSingleObject", wait_on_actual_event),
                self.assertRaisesRegex(RuntimeError, "cleanup failed") as failure,
            ):
                self.run_python()
            self.assertEqual(outcomes, [258])
            grouped = failure.exception.__cause__
            self.assertIsInstance(grouped, ExceptionGroup)
            assert isinstance(grouped, ExceptionGroup)
            self.assertTrue(
                any("termination is unconfirmed" in str(error) for error in grouped.exceptions)
            )
        finally:
            self.assertTrue(self.kernel.CloseHandle(event))
        self.assert_handle_count()
