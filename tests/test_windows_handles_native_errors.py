# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — genuine native file resource API error contracts
"""Exercise genuine file API errors through public native resource operations."""

from __future__ import annotations

import ctypes
import sys
import tempfile
import unittest
from collections.abc import Callable
from contextlib import ExitStack
from ctypes import wintypes as w
from pathlib import Path
from unittest.mock import patch

from rigor_foundry import windows_handles
from rigor_foundry.windows_abi import windows_descriptor, windows_last_error, windows_library
from rigor_foundry.windows_handles import WindowsDirectory, WindowsFile


@unittest.skipUnless(
    sys.platform == "win32", "requires genuine Windows NTFS and CRT error handling"
)
class WindowsHandleNativeErrorTests(unittest.TestCase):
    """Retain actual native errors and exact post-operation resource counts."""

    def setUp(self) -> None:
        """Initialize genuine libraries before measuring each public operation's ownership."""
        self.resources = ExitStack()
        self.addCleanup(self.resources.close)
        temporary = self.resources.enter_context(
            tempfile.TemporaryDirectory(prefix="rigor-native-file-api-error-")
        )
        self.root = Path(temporary).resolve()
        self.source = self.root / "source.txt"
        self.source.write_bytes(b"preserved")
        self.kernel = windows_library("kernel32")
        self.ntdll = windows_library("ntdll")
        self.kernel.GetCurrentProcess.argtypes = []
        self.kernel.GetCurrentProcess.restype = w.HANDLE
        self.kernel.GetProcessHandleCount.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
        self.kernel.GetProcessHandleCount.restype = w.BOOL
        self.kernel.GetLogicalDrives.argtypes = []
        self.kernel.GetLogicalDrives.restype = w.DWORD
        self.kernel.SetHandleInformation.argtypes = [w.HANDLE, w.DWORD, w.DWORD]
        self.kernel.SetHandleInformation.restype = w.BOOL
        self.resources.enter_context(
            patch.object(windows_handles, "windows_library", side_effect=self.library)
        )
        with (
            WindowsDirectory(self.root) as directory,
            directory.open_file(self.source.name) as file,
        ):
            self.assertEqual(file.identity().size, 9)
        self.before = self.handle_count()
        self.addCleanup(self.assert_handle_count)

    def library(self, name: str) -> ctypes.CDLL:
        """Supply only actual loaded system DLL instances."""
        return {"kernel32": self.kernel, "ntdll": self.ntdll}[name]

    def handle_count(self) -> int:
        """Read the current process's actual kernel handle count."""
        count = w.DWORD()
        self.assertTrue(
            self.kernel.GetProcessHandleCount(self.kernel.GetCurrentProcess(), ctypes.byref(count))
        )
        return count.value

    def assert_handle_count(self) -> None:
        """Require equality after every owned file and directory operation settles."""
        self.assertEqual(self.handle_count(), self.before)

    def bind_actual_failure(
        self, name: str, index: int, invalid: object, outcomes: list[tuple[int | None, int]]
    ) -> Callable[..., int | None]:
        """Retain an actual native function's result after giving it one explicit invalid argument."""
        original = getattr(self.kernel, name)

        def actual_failure(*args: object) -> int | None:
            """Call the genuine ABI and retain its untouched result and GetLastError."""
            changed = list(args)
            changed[index] = invalid
            result: int | None = original(*changed)
            outcomes.append((result, windows_last_error()))
            return result

        return actual_failure

    def test_actual_constructor_errors_release_every_opened_parent(self) -> None:
        """Keep genuine missing-path and invalid-handle failures at each constructor stage."""
        cases = (
            ("CreateFileW", str(self.root / "missing-root")),
            ("GetFileInformationByHandle", w.HANDLE(-3)),
            ("GetFinalPathNameByHandleW", w.HANDLE(-3)),
            ("GetVolumeInformationByHandleW", w.HANDLE(-3)),
        )
        for name, invalid in cases:
            with self.subTest(api=name):
                outcomes: list[tuple[int | None, int]] = []
                callback = self.bind_actual_failure(name, 0, invalid, outcomes)
                with patch.object(self.kernel, name, callback), self.assertRaises(OSError):
                    WindowsDirectory(self.root)
                self.assertEqual(len(outcomes), 1)
                self.assertNotEqual(outcomes[0][1], 0)
                self.assert_handle_count()

    def test_actual_unmapped_drive_is_refused_as_a_fixed_volume(self) -> None:
        """Query a genuinely unassigned local drive letter rather than fabricating a volume type."""
        available = (~int(self.kernel.GetLogicalDrives())) & ((1 << 26) - 1)
        self.assertNotEqual(available, 0)
        letter = chr(ord("A") + (available & -available).bit_length() - 1)
        with self.assertRaisesRegex(ValueError, "fixed local NTFS"):
            WindowsDirectory(Path(letter + ":\\"))

    def test_real_duplicate_failure_preserves_original_directory(self) -> None:
        """Return a genuine DuplicateHandle failure and retain the original directory resources."""
        outcomes: list[tuple[int | None, int]] = []
        with WindowsDirectory(self.root) as directory:
            callback = self.bind_actual_failure("DuplicateHandle", 1, w.HANDLE(-3), outcomes)
            with (
                patch.object(self.kernel, "DuplicateHandle", callback),
                self.assertRaises(OSError),
            ):
                directory.open_directory(Path("."))
            with directory.open_file(self.source.name) as file:
                self.assertEqual(file.identity().size, 9)
        self.assertEqual(outcomes, [(0, 6)])

    def test_real_child_path_query_failure_closes_opened_and_created_files(self) -> None:
        """Propagate actual final-path errors and discard only the newly created output."""
        with WindowsDirectory(self.root) as directory:
            for create, name in ((False, self.source.name), (True, "created.txt")):
                with self.subTest(create=create):
                    outcomes: list[tuple[int | None, int]] = []
                    callback = self.bind_actual_failure(
                        "GetFinalPathNameByHandleW", 0, w.HANDLE(-3), outcomes
                    )
                    with (
                        patch.object(self.kernel, "GetFinalPathNameByHandleW", callback),
                        self.assertRaises(OSError),
                    ):
                        directory.open_file(name, create=create)
                    self.assertEqual(outcomes, [(0, 6)])
        self.assertEqual(self.source.read_bytes(), b"preserved")
        self.assertFalse((self.root / "created.txt").exists())

    def test_real_child_directory_path_query_failure_releases_duplicated_chain(self) -> None:
        """Keep an actual native query failure after a relative directory was opened."""
        (self.root / "child").mkdir()
        outcomes: list[tuple[int | None, int]] = []
        with WindowsDirectory(self.root) as directory:
            callback = self.bind_actual_failure(
                "GetFinalPathNameByHandleW", 0, w.HANDLE(-3), outcomes
            )
            with (
                patch.object(self.kernel, "GetFinalPathNameByHandleW", callback),
                self.assertRaises(OSError),
            ):
                directory.open_directory(Path("child"))
            with directory.open_directory(Path(".")) as duplicate:
                self.assertEqual(duplicate.identity, directory.identity)
        self.assertEqual(outcomes, [(0, 6)])

    def test_real_crt_transfer_failure_closes_owned_handle_and_discards_only_new_file(
        self,
    ) -> None:
        """Use actual msvcrt invalid-handle failure while preserving the real untransferred owner."""
        failures: list[int | None] = []

        def transfer_invalid_handle(handle: int, *, writable: bool) -> int:
            """Call the actual standard-library CRT bridge with INVALID_HANDLE_VALUE."""
            self.assertNotEqual(handle, -1)
            try:
                return windows_descriptor(-1, writable=writable)
            except OSError as exc:
                failures.append(exc.errno)
                raise

        with WindowsDirectory(self.root) as directory:
            for create, name in ((False, self.source.name), (True, "created.txt")):
                with (
                    self.subTest(create=create),
                    patch.object(windows_handles, "windows_descriptor", transfer_invalid_handle),
                    self.assertRaises(OSError),
                ):
                    directory.open_file(name, create=create)
        self.assertEqual(failures, [9, 9])
        self.assertEqual(self.source.read_bytes(), b"preserved")
        self.assertFalse((self.root / "created.txt").exists())

    def test_real_protected_close_failure_still_releases_remaining_parent_handles(self) -> None:
        """Keep an actual protected-handle error, then release the retained failed resource explicitly."""
        directory = WindowsDirectory(self.root)
        self.addCleanup(directory.close)
        original = self.kernel.CloseHandle
        retained: list[object] = []
        subsequent: list[int] = []

        def close_with_real_protection(handle: object) -> int:
            """Protect the first actual handle, retain its real failed close and close later ones."""
            if not retained:
                self.assertTrue(self.kernel.SetHandleInformation(handle, 2, 2))
                retained.append(handle)
                result = int(original(handle))
                error = windows_last_error()
                self.assertEqual((result, error), (0, 6))
                return result
            result = int(original(handle))
            subsequent.append(result)
            return result

        try:
            with (
                patch.object(self.kernel, "CloseHandle", close_with_real_protection),
                self.assertRaisesRegex(RuntimeError, "handle cleanup failed"),
            ):
                directory.close()
            self.assertTrue(subsequent)
            self.assertTrue(all(subsequent))
        finally:
            self.assertEqual(len(retained), 1)
            self.assertTrue(self.kernel.SetHandleInformation(retained[0], 2, 0))
            self.assertTrue(original(retained[0]))
        self.assert_handle_count()

    def test_oversized_utf16_child_is_refused_before_native_open(self) -> None:
        """Bound a caller's actual oversized child name before NT UNICODE_STRING conversion."""
        with (
            WindowsDirectory(self.root) as directory,
            self.assertRaisesRegex(ValueError, "UTF-16 limit"),
        ):
            directory.open_file("x" * 32768, create=True)

    def test_differently_cased_file_name_is_not_treated_as_an_exact_binding(self) -> None:
        """Reject a real case-insensitive lookup whose stored name differs from the requested spelling."""
        with (
            WindowsDirectory(self.root) as directory,
            self.assertRaisesRegex(ValueError, "differs from the retained parent"),
        ):
            directory.open_file(self.source.name.upper())
        self.assertEqual(self.source.read_bytes(), b"preserved")

    def test_differently_cased_child_directory_name_preserves_parent_ownership(self) -> None:
        """Reject the actual normalized child name and keep the retained parent usable."""
        (self.root / "child").mkdir()
        with WindowsDirectory(self.root) as directory:
            with self.assertRaisesRegex(ValueError, "differs from the retained parent"):
                directory.open_directory(Path("CHILD"))
            with directory.open_file(self.source.name) as file:
                self.assertEqual(file.identity().size, 9)

    def test_actual_dos_namespace_query_is_refused_as_a_volume_guid_root(self) -> None:
        """Return a genuine successful DOS-name query and refuse its unsupported namespace."""
        original = self.kernel.GetFinalPathNameByHandleW
        outcomes: list[int] = []

        def query_actual_dos_path(handle: object, buffer: object, size: int, flags: int) -> int:
            """Keep the actual output buffer and query the documented DOS namespace instead."""
            self.assertEqual(flags, 1)
            result = int(original(handle, buffer, size, 0))
            outcomes.append(result)
            return result

        with (
            patch.object(self.kernel, "GetFinalPathNameByHandleW", query_actual_dos_path),
            self.assertRaisesRegex(ValueError, "volume GUID namespace"),
        ):
            WindowsDirectory(self.root)
        self.assertEqual(len(outcomes), 1)
        self.assertGreater(outcomes[0], 0)

    def test_actual_query_without_optional_filesystem_name_is_not_accepted_as_ntfs(self) -> None:
        """Refuse undiscovered filesystem identity when the genuine API omits its optional name output."""
        original = self.kernel.GetVolumeInformationByHandleW
        outcomes: list[int] = []

        def query_without_optional_name(*args: object) -> int:
            """Call the native API without requesting a name, preserving its actual success result."""
            changed = list(args)
            changed[6] = None
            changed[7] = 0
            result = int(original(*changed))
            outcomes.append(result)
            return result

        with (
            patch.object(
                self.kernel, "GetVolumeInformationByHandleW", query_without_optional_name
            ),
            self.assertRaisesRegex(ValueError, "fixed local NTFS"),
        ):
            WindowsDirectory(self.root)
        self.assertEqual(outcomes, [1])

    def test_actual_directory_handle_is_not_accepted_as_a_regular_file(self) -> None:
        """Reject the real native directory type through the public file identity contract."""
        handle = self.kernel.CreateFileW(str(self.root), 0x80000000, 1, None, 3, 0x02000000, None)
        self.assertIsNotNone(handle)
        self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
        with (
            WindowsFile(handle, writable=False) as file,
            self.assertRaisesRegex(ValueError, "required non-reparse disk object"),
        ):
            file.identity()


if __name__ == "__main__":
    unittest.main()
