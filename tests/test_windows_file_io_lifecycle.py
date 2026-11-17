# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual native file cursor and write failure contracts
"""Exercise actual descriptor operations and cleanup through public native file APIs."""

from __future__ import annotations

import ctypes
import os
import sys
import tempfile
import unittest
from ctypes import wintypes as w
from pathlib import Path
from unittest.mock import patch

from rigor_foundry import windows_file_io
from rigor_foundry.git_inventory import StableReadError
from rigor_foundry.windows_abi import windows_library


@unittest.skipUnless(
    sys.platform == "win32", "requires actual NTFS descriptors and Windows resource accounting"
)
class WindowsFileIOFailureTests(unittest.TestCase):
    """Preserve real same-file read results and genuine CRT errors without fabricated bytes."""

    def setUp(self) -> None:
        """Allocate real inputs and warm up both public operations before counting handles."""
        temporary = tempfile.TemporaryDirectory(prefix="rigor-native-file-lifetime-")
        self.root = Path(temporary.name).resolve()
        self.payload = bytes(range(256)) * 8192
        self.source = self.root / "source.bin"
        self.source.write_bytes(self.payload)
        self.sibling = self.root / "sibling.txt"
        self.sibling.write_bytes(b"preserve")
        windows_file_io.read_regular_file(self.source, buffer_limit=0)
        windows_file_io.write_new_file(self.root / "warmup.txt", "warmup")
        self.kernel = windows_library("kernel32")
        self.kernel.GetCurrentProcess.argtypes = []
        self.kernel.GetCurrentProcess.restype = w.HANDLE
        self.kernel.GetProcessHandleCount.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
        self.kernel.GetProcessHandleCount.restype = w.BOOL
        self.before = self.handle_count()
        self.addCleanup(self.assert_handle_count)
        self.addCleanup(temporary.cleanup)

    def handle_count(self) -> int:
        """Read independent actual process resource accounting."""
        count = w.DWORD()
        self.assertTrue(
            self.kernel.GetProcessHandleCount(self.kernel.GetCurrentProcess(), ctypes.byref(count))
        )
        return count.value

    def assert_handle_count(self) -> None:
        """Require exact equality after all created descriptors and directory resources settle."""
        self.assertEqual(self.handle_count(), self.before)

    def test_actual_eof_after_cursor_move_is_refused(self) -> None:
        """Move the same real descriptor to EOF, then preserve its genuine empty read result."""
        original = os.read

        def read_at_actual_eof(descriptor: int, size: int) -> bytes:
            """Move only this owned cursor and return the actual same-file read result."""
            os.lseek(descriptor, 0, os.SEEK_END)
            return original(descriptor, size)

        with (
            patch.object(os, "read", read_at_actual_eof),
            self.assertRaises(StableReadError) as failure,
        ):
            windows_file_io.read_regular_file(self.source)
        self.assertEqual(failure.exception.reason, "changed-while-read")
        self.assertEqual(self.source.read_bytes(), self.payload)

    def test_actual_cursor_rewind_enforces_snapshot_and_explicit_byte_bounds(self) -> None:
        """Re-read real bytes from the same owned file and refuse the resulting excess byte count."""
        original = os.read
        calls: list[int] = []

        def read_with_actual_rewind(descriptor: int, size: int) -> bytes:
            """Rewind once between genuine reads without altering file bytes or native outcomes."""
            calls.append(size)
            if len(calls) == 2:
                os.lseek(descriptor, 0, os.SEEK_SET)
            return original(descriptor, size)

        for maximum in (None, len(self.payload)):
            with self.subTest(maximum=maximum):
                calls.clear()
                with (
                    patch.object(os, "read", read_with_actual_rewind),
                    self.assertRaises(StableReadError) as failure,
                ):
                    windows_file_io.read_regular_file(
                        self.source, buffer_limit=0, maximum_bytes=maximum
                    )
                self.assertEqual(
                    failure.exception.reason,
                    "limit-exceeded" if maximum is not None else "changed-while-read",
                )
                self.assertGreaterEqual(len(calls), 3)
        self.assertEqual(self.source.read_bytes(), self.payload)

    def test_actual_crt_read_error_preserves_its_cause(self) -> None:
        """Keep the real invalid-descriptor OSError after the input resources are already open."""
        original = os.read

        def read_invalid_descriptor(descriptor: int, size: int) -> bytes:
            """Use an explicitly invalid argument to the real CRT read, preserving its exception."""
            self.assertGreaterEqual(descriptor, 0)
            return original(-1, size)

        with (
            patch.object(os, "read", read_invalid_descriptor),
            self.assertRaises(StableReadError) as failure,
        ):
            windows_file_io.read_regular_file(self.source)
        self.assertEqual(failure.exception.reason, "inaccessible")
        self.assertEqual(getattr(failure.exception.__cause__, "errno", None), 9)
        self.assertEqual(self.source.read_bytes(), self.payload)

    def test_actual_crt_write_error_discards_only_created_output(self) -> None:
        """Propagate a genuine write error and discard the actual newly created resource."""
        original = os.write

        def write_invalid_descriptor(descriptor: int, payload: bytes) -> int:
            """Keep the real CRT invalid-descriptor exception rather than manufacturing a status."""
            self.assertGreaterEqual(descriptor, 0)
            return original(-1, payload)

        path = self.root / "failed.txt"
        with (
            patch.object(os, "write", write_invalid_descriptor),
            self.assertRaises(OSError) as failure,
        ):
            windows_file_io.write_new_file(path, "output")
        self.assertEqual(failure.exception.errno, 9)
        self.assertFalse(path.exists())
        self.assertEqual(self.sibling.read_bytes(), b"preserve")

    def test_actual_zero_byte_write_refuses_no_progress_and_discards_output(self) -> None:
        """Preserve a genuine same-descriptor zero-byte write result and refuse incomplete output."""
        original = os.write
        outcomes: list[int] = []

        def write_actual_empty_buffer(descriptor: int, payload: bytes) -> int:
            """Request zero bytes from the real CRT while retaining the actual created descriptor."""
            self.assertEqual(payload, b"output")
            result = original(descriptor, b"")
            outcomes.append(result)
            return result

        path = self.root / "no-progress.txt"
        with (
            patch.object(os, "write", write_actual_empty_buffer),
            self.assertRaisesRegex(OSError, "no progress"),
        ):
            windows_file_io.write_new_file(path, "output")
        self.assertEqual(outcomes, [0])
        self.assertFalse(path.exists())
        self.assertEqual(self.sibling.read_bytes(), b"preserve")


if __name__ == "__main__":
    unittest.main()
