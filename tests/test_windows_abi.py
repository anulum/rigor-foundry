# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real Windows ABI ownership contracts
"""Exercise saved native errors, real CRT ownership and unsupported-platform refusals."""

from __future__ import annotations

import ctypes
import os
import sys
import tempfile
import unittest
from ctypes import wintypes as w
from pathlib import Path

from rigor_foundry.windows_abi import (
    windows_descriptor,
    windows_error,
    windows_handle,
    windows_last_error,
    windows_library,
)


@unittest.skipUnless(sys.platform == "win32", "requires actual Windows and CRT resource APIs")
class WindowsAbiTests(unittest.TestCase):
    """Use actual kernel errors and real ownership-transferring CRT descriptors."""

    def test_saved_error_and_explicit_error_use_the_actual_windows_api(self) -> None:
        """Keep the calling thread's actual saved error and explicit DOS translation."""
        library = windows_library("kernel32")
        self.assertIsInstance(library, ctypes.CDLL)
        library.SetLastError.argtypes = [w.DWORD]
        library.SetLastError.restype = None
        library.SetLastError(87)
        self.assertEqual(windows_last_error(), 87)
        self.assertEqual(getattr(windows_error(), "winerror", None), 87)
        self.assertEqual(getattr(windows_error(5), "winerror", None), 5)

    def test_real_handle_transfers_to_writable_then_readonly_crt_descriptors(self) -> None:
        """Read and write exact binary bytes through real noninheritable CRT descriptors."""
        library = windows_library("kernel32")
        library.CreateFileW.argtypes = [
            w.LPCWSTR,
            w.DWORD,
            w.DWORD,
            ctypes.c_void_p,
            w.DWORD,
            w.DWORD,
            w.HANDLE,
        ]
        library.CreateFileW.restype = w.HANDLE
        directory = Path(tempfile.mkdtemp(prefix="rigor-native-abi-"))
        file = directory / "exact-crt-bytes.bin"
        payload = b"actual CRT ownership\x00\xff\r\n"
        handle = library.CreateFileW(str(file), 0xC0000000, 1, None, 1, 0x80, None)
        self.assertNotIn(handle, (None, -1, 0xFFFFFFFFFFFFFFFF))
        descriptor = windows_descriptor(handle, writable=True)
        with os.fdopen(descriptor, "w+b") as stream:
            self.assertEqual(windows_handle(stream.fileno()), handle)
            self.assertFalse(os.get_inheritable(stream.fileno()))
            self.assertEqual(stream.write(payload), len(payload))
            stream.flush()
            stream.seek(0)
            self.assertEqual(stream.read(), payload)
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        handle = library.CreateFileW(str(file), 0x80000000, 1, None, 3, 0x80, None)
        self.assertNotIn(handle, (None, -1, 0xFFFFFFFFFFFFFFFF))
        descriptor = windows_descriptor(handle, writable=False)
        with os.fdopen(descriptor, "rb") as stream:
            self.assertEqual(windows_handle(stream.fileno()), handle)
            self.assertFalse(os.get_inheritable(stream.fileno()))
            self.assertEqual(stream.read(), payload)
        with self.assertRaises(OSError):
            os.fstat(descriptor)


@unittest.skipIf(sys.platform == "win32", "checks the actual unsupported-platform boundary")
class UnsupportedWindowsAbiTests(unittest.TestCase):
    """Refuse Windows-only operations on the actual non-Windows host before effects."""

    def test_library_requires_windows(self) -> None:
        """Refuse system-DLL loading on the actual unsupported platform."""
        with self.assertRaisesRegex(RuntimeError, "require Windows"):
            windows_library("kernel32")

    def test_error_translation_requires_windows(self) -> None:
        """Refuse Windows error translation when no Windows API is present."""
        with self.assertRaisesRegex(RuntimeError, "require Windows"):
            windows_error()

    def test_saved_last_error_requires_windows(self) -> None:
        """Refuse a fabricated saved Windows error on the actual POSIX host."""
        with self.assertRaisesRegex(RuntimeError, "require Windows"):
            windows_last_error()

    def test_descriptor_transfer_requires_windows(self) -> None:
        """Refuse handle ownership transfer before any unsupported CRT effect."""
        with self.assertRaisesRegex(RuntimeError, "require Windows"):
            windows_descriptor(-1, writable=False)

    def test_descriptor_borrow_requires_windows(self) -> None:
        """Refuse native-handle borrowing when the native CRT is unavailable."""
        with self.assertRaisesRegex(RuntimeError, "require Windows"):
            windows_handle(-1)
