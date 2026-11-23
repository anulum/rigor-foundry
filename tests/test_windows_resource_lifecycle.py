# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native Windows cleanup failure regressions
"""Exercise real kernel cleanup failures around the public Windows resource owners.

The injected callbacks alter actual owned kernel objects, never fabricate native
return values. Native workflow qualification remains a separate required gate.
"""

from __future__ import annotations

import ctypes
import os
import signal
import sys
import tempfile
import unittest
from contextlib import ExitStack
from ctypes import wintypes as w
from pathlib import Path
from unittest.mock import patch

from rigor_foundry import windows_handles, windows_process
from rigor_foundry.windows_handles import WindowsDirectory, WindowsFile


class _FileBasicInformation(ctypes.Structure):
    """Actual FILE_BASIC_INFORMATION layout for the owned readonly-file control."""

    _fields_ = [
        ("created", ctypes.c_int64),
        ("accessed", ctypes.c_int64),
        ("written", ctypes.c_int64),
        ("changed", ctypes.c_int64),
        ("attributes", w.DWORD),
    ]


@unittest.skipUnless(sys.platform == "win32", "requires real native Windows resource APIs")
class WindowsResourceLifecycleTests(unittest.TestCase):
    """Retain independent cleanup after actual CloseHandle and file-discard failures."""

    def _exercise_protected_thread_cleanup(
        self, *, interrupt: bool, system_exit: bool = False
    ) -> None:
        """Exercise actual close protection and optional SIGINT during independent cleanup."""
        library = windows_process._library()
        library.GetThreadId.argtypes = [w.HANDLE]
        library.GetThreadId.restype = w.DWORD
        library.GetCurrentProcess.argtypes = []
        library.GetCurrentProcess.restype = w.HANDLE
        library.GetProcessHandleCount.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
        library.GetProcessHandleCount.restype = w.BOOL
        close = library.CloseHandle
        protected: int | None = None
        injected = False
        interrupt_pending = interrupt
        outcomes: list[int] = []
        subsequent_closes: list[int] = []
        fallback = ExitStack()

        def close_with_real_kernel_failure(handle: int) -> int:
            """Protect the actual primary thread for its first real close attempt only."""
            nonlocal protected, injected, interrupt_pending
            if not injected and library.GetThreadId(handle):
                self.assertTrue(library.SetHandleInformation(handle, 2, 2))
                fallback.callback(close, handle)
                fallback.callback(library.SetHandleInformation, handle, 2, 0)
                protected = handle
                injected = True
                result = int(close(handle))
                outcomes.append(result)
                return result
            if protected == handle:
                self.assertTrue(library.SetHandleInformation(handle, 2, 0))
                if interrupt_pending:
                    interrupt_pending = False
                    if system_exit:
                        sys.exit(7)
                    signal.raise_signal(signal.SIGINT)
                result = int(close(handle))
                outcomes.append(result)
                self.assertTrue(result)
                protected = None
                fallback.pop_all()
                return result
            result = int(close(handle))
            subsequent_closes.append(result)
            return result

        executable = Path(sys.executable)
        directory = Path(tempfile.mkdtemp(prefix="rigor-native-close-"))
        # Initialise the real Windows/CRT process path before measuring the failed
        # operation; first-use runtime handles must not be mistaken for a per-call leak.
        with (
            WindowsDirectory(executable.parent) as parent,
            parent.open_file(executable.name) as image,
        ):
            result = windows_process.run_windows_process(
                executable,
                ("-c", "print('native warmup')"),
                image_handle=image.handle,
                environment=dict(os.environ),
                cwd=directory,
                timeout_seconds=10,
                output_limit=4096,
            )
        self.assertEqual(result, (0, b"native warmup\r\n", b""))
        before, after = w.DWORD(), w.DWORD()
        self.assertTrue(
            library.GetProcessHandleCount(library.GetCurrentProcess(), ctypes.byref(before))
        )
        try:
            with (
                WindowsDirectory(executable.parent) as parent,
                parent.open_file(executable.name) as image,
                patch.object(library, "CloseHandle", close_with_real_kernel_failure),
                patch.object(windows_process, "_library", return_value=library),
            ):
                with self.assertRaises(BaseExceptionGroup if interrupt else OSError) as failure:
                    windows_process.run_windows_process(
                        executable,
                        ("-c", "print('actual native child')"),
                        image_handle=image.handle,
                        environment=dict(os.environ),
                        cwd=directory,
                        timeout_seconds=10,
                        output_limit=4096,
                    )
                if interrupt:
                    self.assertIsInstance(failure.exception, BaseExceptionGroup)
                    grouped = failure.exception
                    assert isinstance(grouped, BaseExceptionGroup)
                    self.assertTrue(
                        any(
                            isinstance(error, SystemExit if system_exit else KeyboardInterrupt)
                            for error in grouped.exceptions
                        )
                    )
                    self.assertTrue(
                        any(
                            isinstance(error, OSError) and getattr(error, "winerror", None) == 6
                            for error in grouped.exceptions
                        )
                    )
                else:
                    self.assertEqual(getattr(failure.exception, "winerror", None), 6)
        finally:
            fallback.close()
        self.assertEqual(outcomes, [0, 1])
        self.assertGreaterEqual(len(subsequent_closes), 4)
        self.assertTrue(all(subsequent_closes))
        self.assertTrue(
            library.GetProcessHandleCount(library.GetCurrentProcess(), ctypes.byref(after))
        )
        self.assertEqual(after.value, before.value)

    def test_protected_thread_close_still_settles_and_closes_remaining_resources(self) -> None:
        """HANDLE_FLAG_PROTECT_FROM_CLOSE causes a real failure, then finite cleanup succeeds."""
        self._exercise_protected_thread_cleanup(interrupt=False)

    def test_keyboard_interrupt_during_cleanup_retains_control_flow_and_releases_resources(
        self,
    ) -> None:
        """Actual Python SIGINT stays a BaseException while independent native cleanup completes."""
        self._exercise_protected_thread_cleanup(interrupt=True)

    def test_system_exit_during_cleanup_retains_control_flow_and_releases_resources(self) -> None:
        """Actual sys.exit remains SystemExit while independent native cleanup completes."""
        self._exercise_protected_thread_cleanup(interrupt=True, system_exit=True)

    def test_readonly_discard_failure_does_not_skip_crt_descriptor_close(self) -> None:
        """A real readonly-file discard error still releases its exact created descriptor."""
        library = windows_handles._kernel()
        original_path = WindowsDirectory.native_path
        original_discard = WindowsFile.discard
        original_close = WindowsFile.close
        opened: list[WindowsFile] = []
        descriptors: list[int] = []
        closed: list[int] = []

        def close_parent_before_binding_check(parent: WindowsDirectory, name: str) -> Path:
            """End the actual directory lifetime before its final ordinary binding query."""
            parent.close()
            return original_path(parent, name)

        def discard_readonly_file(file: WindowsFile) -> None:
            """Make this owned created file readonly, then call the unchanged native discard."""
            opened.append(file)
            descriptors.append(file.descriptor)
            data = _FileBasicInformation()
            data.attributes = 1
            self.assertTrue(
                library.SetFileInformationByHandle(
                    file.handle, 0, ctypes.byref(data), ctypes.sizeof(data)
                )
            )
            original_discard(file)

        def record_actual_close(file: WindowsFile) -> None:
            """Observe the real close without replacing its native effect or result."""
            descriptor = file.descriptor
            original_close(file)
            closed.append(descriptor)

        directory = Path(tempfile.mkdtemp(prefix="rigor-native-discard-"))
        try:
            with (
                WindowsDirectory(directory) as parent,
                patch.object(WindowsDirectory, "native_path", close_parent_before_binding_check),
                patch.object(WindowsFile, "discard", discard_readonly_file),
                patch.object(WindowsFile, "close", record_actual_close),
            ):
                with self.assertRaises(OSError) as failure:
                    parent.open_file("owned-created-input.json", create=True)
                self.assertEqual(getattr(failure.exception, "winerror", None), 5)
                self.assertIsInstance(failure.exception.__context__, ValueError)
            self.assertEqual(len(descriptors), 1)
            self.assertEqual(closed, descriptors)
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
        finally:
            for file in opened:
                original_close(file)
            # Preserve the owned fixture while restoring its ordinary writable state.
            target = directory / "owned-created-input.json"
            self.assertTrue(target.exists())
            target.chmod(0o600)
