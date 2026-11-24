# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual native security descriptor allocation contracts
"""Exercise public descriptor ownership with real Windows conversion and kernel failures."""

from __future__ import annotations

import csv
import ctypes
import os
import subprocess
import sys
import unittest
from contextlib import ExitStack
from ctypes import wintypes as w
from pathlib import Path
from unittest.mock import patch

from rigor_foundry import windows_permissions
from rigor_foundry.windows_abi import windows_last_error, windows_library


class SecurityDescriptorFormattingTests(unittest.TestCase):
    """Validate plain SID grammar before interpolation, without native API stand-ins."""

    def test_valid_sid_strings_have_one_protected_principal(self) -> None:
        """Accept documented SID strings as formatter inputs, not current-user evidence."""
        for sid in ("S-1-0", "S-1-5-18", "S-1-5-32-544"):
            self.assertEqual(
                windows_permissions.private_descriptor_sddl(sid), f"D:P(A;;FA;;;{sid})"
            )

    def test_invalid_and_oversized_sid_strings_are_refused(self) -> None:
        """Reject separators, NULs, non-ASCII digits and strings outside the SDK bound."""
        for sid in (
            "",
            "S-2-5-18",
            "S-1-5-18\n",
            "S-1-5-18\0",
            "S-1-٥-١٨",
            "S-1-5);(A;;FA;;;WD)",
            "S-1-" + "1" * 187,
        ):
            with self.subTest(sid=sid), self.assertRaisesRegex(ValueError, "invalid format"):
                windows_permissions.private_descriptor_sddl(sid)


@unittest.skipUnless(sys.platform == "win32", "requires actual Windows token and descriptor APIs")
class WindowsPermissionsTests(unittest.TestCase):
    """Keep actual native results and independent allocation/handle lifetime evidence."""

    def setUp(self) -> None:
        """Initialize the real system libraries before measuring each owned operation."""
        self.kernel = windows_library("kernel32")
        self.advapi = windows_library("advapi32")
        self.kernel.GetCurrentProcess.argtypes = []
        self.kernel.GetCurrentProcess.restype = w.HANDLE
        self.kernel.GetProcessHandleCount.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
        self.kernel.GetProcessHandleCount.restype = w.BOOL
        self.kernel.CloseHandle.argtypes = [w.HANDLE]
        self.kernel.CloseHandle.restype = w.BOOL
        self.kernel.LocalFree.argtypes = [w.LPVOID]
        self.kernel.LocalFree.restype = w.LPVOID
        self.resources = ExitStack()
        self.addCleanup(self.resources.close)
        self.resources.enter_context(
            patch.object(windows_permissions, "windows_library", side_effect=self.library)
        )
        # The native whoami image is an oracle independent of the code under test, and it
        # starts in well under a second where a PowerShell host can take longer than 15 s
        # on a loaded runner.
        whoami = Path(os.environ["SYSTEMROOT"]) / "System32/whoami.exe"
        result = subprocess.run(
            [str(whoami), "/user", "/fo", "csv", "/nh"],
            capture_output=True,
            check=True,
            timeout=15,
            encoding="utf-8",
            errors="replace",
        )
        (row,) = csv.reader(result.stdout.strip().splitlines())
        self.sid = row[1]
        self.assertRegex(self.sid, r"^S-1-[0-9-]+$")
        self.conversion = self.advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW
        self.conversion.argtypes = [
            w.LPVOID,
            w.DWORD,
            w.DWORD,
            ctypes.POINTER(w.LPWSTR),
            ctypes.POINTER(w.DWORD),
        ]
        self.conversion.restype = w.BOOL
        # First-use library/runtime state is outside the per-invocation handle baseline.
        with windows_permissions.private_security_descriptor() as descriptor:
            self.assertIsNotNone(descriptor.value)
            text = w.LPWSTR()
            length = w.DWORD()
            self.assertTrue(
                self.conversion(descriptor, 1, 4, ctypes.byref(text), ctypes.byref(length))
            )
            self.kernel.LocalFree(text)
        self.before = self.handle_count()
        self.addCleanup(self.assert_handle_count)

    def library(self, name: str) -> ctypes.CDLL:
        """Return an actual loaded DLL, retaining its genuine native ABI functions."""
        return {"kernel32": self.kernel, "advapi32": self.advapi}[name]

    def handle_count(self) -> int:
        """Read the actual process handle count through the kernel API."""
        count = w.DWORD()
        self.assertTrue(
            self.kernel.GetProcessHandleCount(self.kernel.GetCurrentProcess(), ctypes.byref(count))
        )
        return count.value

    def assert_handle_count(self) -> None:
        """Require exact equality after all descriptor/token operations have settled."""
        self.assertEqual(self.handle_count(), self.before)

    def rendered(self, sddl: str) -> str:
        """Render one DACL through the system formatter that reads the product descriptor.

        Windows writes some account SIDs as SDDL aliases, such as ``LA`` for the
        built-in Administrator, so the independently queried SID is compared in that
        rendering.
        """
        parse = self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
        parse.argtypes = [w.LPCWSTR, w.DWORD, ctypes.POINTER(w.LPVOID), ctypes.POINTER(w.DWORD)]
        parse.restype = w.BOOL
        descriptor = w.LPVOID()
        self.assertTrue(parse(sddl, 1, ctypes.byref(descriptor), None), windows_last_error())
        try:
            text = w.LPWSTR()
            length = w.DWORD()
            self.assertTrue(
                self.conversion(descriptor, 1, 4, ctypes.byref(text), ctypes.byref(length)),
                windows_last_error(),
            )
            try:
                return str(text.value)
            finally:
                self.kernel.LocalFree(text)
        finally:
            self.kernel.LocalFree(descriptor)

    def test_descriptor_matches_independent_current_user_and_is_freed_after_body_error(
        self,
    ) -> None:
        """Read the real protected DACL and release native strings on both body outcomes."""
        expected = self.rendered(f"D:P(A;;FA;;;{self.sid})")
        freed: list[int] = []
        local_free = self.kernel.LocalFree

        def free_actual_allocation(pointer: object) -> object:
            """Record only an actual successful LocalFree without changing its result."""
            result: object = local_free(pointer)
            self.assertIsNone(result)
            freed.append(1)
            return result

        with patch.object(self.kernel, "LocalFree", free_actual_allocation):
            with windows_permissions.private_security_descriptor() as descriptor:
                text = w.LPWSTR()
                length = w.DWORD()
                self.assertTrue(
                    self.conversion(descriptor, 1, 4, ctypes.byref(text), ctypes.byref(length))
                )
                try:
                    self.assertEqual(text.value, expected)
                finally:
                    self.kernel.LocalFree(text)
            with (
                self.assertRaisesRegex(ValueError, "body failure"),
                windows_permissions.private_security_descriptor(),
            ):
                raise ValueError("body failure")
        # Two token SID strings, two descriptors and the independently queried SDDL string.
        self.assertEqual(len(freed), 5)

    def test_actual_invalid_process_handle_stops_before_descriptor_creation(self) -> None:
        """Propagate the real invalid-handle error from OpenProcessToken."""
        original = self.advapi.OpenProcessToken
        outcomes: list[tuple[int, int]] = []

        def open_invalid_process(process: object, access: int, token: object) -> int:
            """Call the actual native API with an invalid process handle."""
            self.assertEqual(process, self.kernel.GetCurrentProcess())
            result = int(original(w.HANDLE(-3), access, token))
            outcomes.append((result, windows_last_error()))
            return result

        with (
            patch.object(self.advapi, "OpenProcessToken", open_invalid_process),
            self.assertRaises(OSError) as failure,
        ):
            self.resources.enter_context(windows_permissions.private_security_descriptor())
        self.assertEqual(outcomes, [(0, 6)])
        self.assertEqual(getattr(failure.exception, "winerror", None), 6)

    def test_actual_closed_token_query_still_releases_remaining_resources(self) -> None:
        """Keep the actual invalid-handle result from querying an already closed owned token."""
        original = self.advapi.GetTokenInformation
        outcomes: list[tuple[int, int]] = []

        def query_closed_token(
            token: object, information: int, data: object, size: int, length: object
        ) -> int:
            """Close the real owned token, then return the genuine native query failure."""
            self.assertTrue(self.kernel.CloseHandle(token))
            result = int(original(token, information, data, size, length))
            outcomes.append((result, windows_last_error()))
            return result

        with (
            patch.object(self.advapi, "GetTokenInformation", query_closed_token),
            self.assertRaises(OSError) as failure,
        ):
            self.resources.enter_context(windows_permissions.private_security_descriptor())
        self.assertEqual(outcomes, [(0, 6)])
        self.assertEqual(getattr(failure.exception, "winerror", None), 6)

    def test_actual_invalid_sid_conversion_releases_the_token(self) -> None:
        """Propagate the actual SID conversion error while still closing the opened token."""
        original = self.advapi.ConvertSidToStringSidW
        invalid_sid = ctypes.create_string_buffer(68)
        outcomes: list[tuple[int, int]] = []

        def convert_invalid_sid(sid: object, text: object) -> int:
            """Pass allocated invalid SID bytes to the genuine native conversion function."""
            self.assertIsNotNone(sid)
            result = int(original(invalid_sid, text))
            outcomes.append((result, windows_last_error()))
            return result

        with (
            patch.object(self.advapi, "ConvertSidToStringSidW", convert_invalid_sid),
            self.assertRaises(OSError) as failure,
        ):
            self.resources.enter_context(windows_permissions.private_security_descriptor())
        self.assertEqual(outcomes, [(0, 1337)])
        self.assertEqual(getattr(failure.exception, "winerror", None), 1337)

    def test_actual_unknown_descriptor_revision_refuses_allocation(self) -> None:
        """Keep the real descriptor converter's unknown-revision error and finite cleanup."""
        original = self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
        outcomes: list[tuple[int, int]] = []

        def convert_invalid_revision(
            sddl: str, revision: int, descriptor: object, length: object
        ) -> int:
            """Use the actual authored SDDL and native converter with an unsupported revision."""
            self.assertEqual(revision, 1)
            self.assertTrue(sddl.startswith("D:P(A;;FA;;;S-1-"))
            result = int(original(sddl, 2, descriptor, length))
            outcomes.append((result, windows_last_error()))
            return result

        with (
            patch.object(
                self.advapi,
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                convert_invalid_revision,
            ),
            self.assertRaises(OSError) as failure,
        ):
            self.resources.enter_context(windows_permissions.private_security_descriptor())
        self.assertEqual(outcomes, [(0, 1305)])
        self.assertEqual(getattr(failure.exception, "winerror", None), 1305)


@unittest.skipIf(sys.platform == "win32", "checks the actual unsupported-platform boundary")
class UnsupportedWindowsPermissionsTests(unittest.TestCase):
    """Refuse descriptor allocation before any native effect on a non-Windows host."""

    def test_descriptor_allocation_requires_actual_windows(self) -> None:
        """Exercise the public context factory on the actual unsupported platform."""
        with ExitStack() as resources, self.assertRaisesRegex(RuntimeError, "require Windows"):
            resources.enter_context(windows_permissions.private_security_descriptor())
