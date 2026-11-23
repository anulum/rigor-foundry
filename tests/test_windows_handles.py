# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native file and directory resource lifetime contracts
"""Exercise actual public native resource ownership, closed-state and path contracts."""

from __future__ import annotations

import ctypes
import os
import sys
import tempfile
import unittest
from ctypes import wintypes as w
from pathlib import Path

from rigor_foundry.windows_abi import windows_library
from rigor_foundry.windows_handles import WindowsDirectory


@unittest.skipUnless(
    sys.platform == "win32", "requires actual Windows NTFS and kernel handle APIs"
)
class WindowsHandleTests(unittest.TestCase):
    """Keep real resource results and exact post-cleanup handle equality."""

    def setUp(self) -> None:
        """Warm up actual libraries before measuring only this test's resource lifetime."""
        temporary = tempfile.TemporaryDirectory(prefix="rigor-native-handles-contract-")
        self.root = Path(temporary.name).resolve()
        self.kernel = windows_library("kernel32")
        self.kernel.GetCurrentProcess.argtypes = []
        self.kernel.GetCurrentProcess.restype = w.HANDLE
        self.kernel.GetProcessHandleCount.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
        self.kernel.GetProcessHandleCount.restype = w.BOOL
        with WindowsDirectory(self.root) as directory:
            self.assertIsInstance(directory.identity, tuple)
        self.before = self.handle_count()
        self.addCleanup(self.assert_handle_count)
        self.addCleanup(temporary.cleanup)

    def handle_count(self) -> int:
        """Read the actual kernel count for the current process."""
        result = w.DWORD()
        self.assertTrue(
            self.kernel.GetProcessHandleCount(
                self.kernel.GetCurrentProcess(), ctypes.byref(result)
            )
        )
        return result.value

    def assert_handle_count(self) -> None:
        """Require exact equality after all owned file and directory handles are released."""
        self.assertEqual(self.handle_count(), self.before)

    def test_directory_close_is_idempotent_and_use_after_close_is_refused(self) -> None:
        """Close real resources twice and refuse each public use after close."""
        directory = WindowsDirectory(self.root)
        self.addCleanup(directory.close)
        directory.close()
        directory.close()
        with self.assertRaisesRegex(ValueError, "closed"):
            _ = directory.identity
        with self.assertRaisesRegex(ValueError, "closed"):
            directory.open_file("unused.txt")
        with self.assertRaisesRegex(ValueError, "closed"):
            directory.open_directory(Path("."))
        with self.assertRaisesRegex(ValueError, "closed"):
            directory.native_path("unused.txt")
        with self.assertRaisesRegex(ValueError, "closed"):
            directory.__enter__()

    def test_file_close_is_idempotent_and_context_body_error_releases_it(self) -> None:
        """Retain actual file identity, propagate an ordinary body error and close exactly once."""
        path = self.root / "input.bin"
        path.write_bytes(b"actual bytes")
        with WindowsDirectory(self.root) as directory:
            file = directory.open_file(path.name)
            self.addCleanup(file.close)
            with self.assertRaisesRegex(ValueError, "body error"), file:
                self.assertEqual(os.read(file.descriptor, 32), b"actual bytes")
                self.assertEqual(file.identity().size, 12)
                raise ValueError("body error")
            file.close()
            with self.assertRaisesRegex(ValueError, "closed"):
                _ = file.descriptor
            with self.assertRaisesRegex(ValueError, "closed"):
                file.__enter__()
        self.assertEqual(path.read_bytes(), b"actual bytes")

    def test_readonly_handle_flush_preserves_actual_os_failure(self) -> None:
        """Call the genuine native flush on a handle opened without write access."""
        path = self.root / "readonly-access.txt"
        path.write_bytes(b"preserved")
        with WindowsDirectory(self.root) as directory, directory.open_file(path.name) as file:
            with self.assertRaises(OSError) as failure:
                file.flush()
            self.assertEqual(getattr(failure.exception, "winerror", None), 5)
        self.assertEqual(path.read_bytes(), b"preserved")

    def test_discard_removes_only_its_actual_created_file(self) -> None:
        """Create, write, flush and discard one owned object while preserving a sibling."""
        sibling = self.root / "sibling.txt"
        sibling.write_bytes(b"keep")
        with (
            WindowsDirectory(self.root) as directory,
            directory.open_file("created.txt", create=True) as file,
        ):
            self.assertEqual(os.write(file.descriptor, b"new"), 3)
            file.flush()
            self.assertEqual(file.identity().size, 3)
            file.discard()
        self.assertFalse((self.root / "created.txt").exists())
        self.assertEqual(sibling.read_bytes(), b"keep")

    def test_duplicate_directory_outlives_original_owner(self) -> None:
        """Retain actual independent duplicated handles after the original chain closes."""
        path = self.root / "source.bin"
        path.write_bytes(b"data")
        directory = WindowsDirectory(self.root)
        self.addCleanup(directory.close)
        child = directory.open_directory(Path("."))
        self.addCleanup(child.close)
        self.assertEqual(directory.identity, child.identity)
        directory.close()
        with child.open_file(path.name) as file:
            self.assertEqual(os.read(file.descriptor, 4), b"data")
        self.assertEqual(child.native_path(path.name).name, path.name)

    def test_nested_directory_and_missing_child_cleanup(self) -> None:
        """Open an existing nested directory and preserve the parent after a genuine missing-child error."""
        nested = self.root / "one/two"
        nested.mkdir(parents=True)
        (nested / "content.txt").write_bytes(b"nested")
        with WindowsDirectory(self.root) as directory:
            with (
                directory.open_directory(Path("one/two")) as child,
                child.open_file("content.txt") as file,
            ):
                self.assertEqual(os.read(file.descriptor, 16), b"nested")
                self.assertEqual(child.identity[0], directory.identity[0])
            with self.assertRaises(FileNotFoundError):
                directory.open_directory(Path("one/missing"))
            with directory.open_directory(Path(".")) as duplicate:
                self.assertEqual(directory.identity, duplicate.identity)

    def test_invalid_components_are_rejected_at_public_boundaries(self) -> None:
        """Reject explicit malformed names without creating or altering any native object."""
        with WindowsDirectory(self.root) as directory:
            for name in (
                "",
                ".",
                "..",
                "trailing ",
                "trailing.",
                "bad:name",
                "bad\x01name",
                "NUL",
                "COM1.txt",
            ):
                with (
                    self.subTest(name=name),
                    self.assertRaisesRegex(ValueError, "unsupported component"),
                ):
                    directory.open_file(name, create=True)
                with (
                    self.subTest(native_name=name),
                    self.assertRaisesRegex(ValueError, "unsupported component"),
                ):
                    directory.native_path(name)
            for relative in (self.root, Path(".."), Path("one/../two"), Path("C:relative")):
                with (
                    self.subTest(relative=relative),
                    self.assertRaisesRegex(ValueError, "untraversed relative"),
                ):
                    directory.open_directory(relative)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_relative_root_is_rejected_before_native_open(self) -> None:
        """Require an explicit absolute drive root for construction."""
        with self.assertRaisesRegex(ValueError, "absolute local drive"):
            WindowsDirectory(Path("relative-directory"))
