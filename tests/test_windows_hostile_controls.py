# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native Windows hostile-control regressions
"""Replay the reserved native hostile controls against the public Windows owners.

Every attack is performed by a real second process or a real kernel object
(mount point, DOS device, copied image). No native return value is fabricated
and no owner is patched. These tests require a fixed local NTFS temp directory
and the right to create directory mount points, which a standard user has.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from ctypes import wintypes as w
from pathlib import Path

from rigor_foundry import windows_handles
from rigor_foundry.windows_abi import windows_last_error, windows_library
from rigor_foundry.windows_handles import WindowsDirectory
from rigor_foundry.windows_permissions import _current_user_sid
from rigor_foundry.windows_process import run_windows_process

_ATTACKER = r"""
import ctypes, struct, sys
from ctypes import wintypes as w
k = ctypes.WinDLL("kernel32", use_last_error=True)
k.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID, w.DWORD, w.DWORD, w.HANDLE]
k.CreateFileW.restype = w.HANDLE
k.DeviceIoControl.argtypes = [w.HANDLE, w.DWORD, w.LPVOID, w.DWORD, w.LPVOID, w.DWORD,
                              ctypes.POINTER(w.DWORD), w.LPVOID]
k.DeviceIoControl.restype = w.BOOL
k.MoveFileExW.argtypes = [w.LPCWSTR, w.LPCWSTR, w.DWORD]
k.MoveFileExW.restype = w.BOOL
k.CloseHandle.argtypes = [w.HANDLE]
mode, path, argument = sys.argv[1], sys.argv[2], sys.argv[3]
if mode == "rename":
    ok = k.MoveFileExW(path, argument, 0)
    print("ok" if ok else ctypes.get_last_error())
    raise SystemExit
handle = k.CreateFileW(path, 0x100, 7, None, 3, 0x2200000, None)
if handle == ctypes.c_void_p(-1).value:
    print(ctypes.get_last_error())
    raise SystemExit
returned = w.DWORD()
if mode == "set":
    data = bytes.fromhex(argument)
    ok = k.DeviceIoControl(handle, 0x900A4, data, len(data), None, 0, ctypes.byref(returned), None)
else:
    data = struct.pack("<IHH", 0xA0000003, 0, 0)
    ok = k.DeviceIoControl(handle, 0x900AC, data, 8, None, 0, ctypes.byref(returned), None)
k.CloseHandle(handle)
print("ok" if ok else ctypes.get_last_error())
"""


def _attack(mode: str, path: Path, argument: str = "-") -> str:
    """Run one hostile filesystem action in an independent same-user process."""
    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-c", _ATTACKER, mode, str(path), argument],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return completed.stdout.strip() or completed.stderr.strip()


def _mount_point(target: Path) -> str:
    """Encode a real IO_REPARSE_TAG_MOUNT_POINT buffer redirecting to target."""
    substitute = ("\\??\\" + str(target)).encode("utf-16-le")
    printed = str(target).encode("utf-16-le")
    body = struct.pack("<HHHH", 0, len(substitute), len(substitute) + 2, len(printed))
    body += substitute + b"\0\0" + printed + b"\0\0"
    return (struct.pack("<IHH", 0xA0000003, len(body), 0) + body).hex()


@unittest.skipUnless(sys.platform == "win32", "requires real native Windows resource APIs")
class WindowsHostileControlTests(unittest.TestCase):
    """Native parent-exclusion, private-creation and process-launch invariants under attack."""

    def setUp(self) -> None:
        """Allocate an independent real NTFS directory and attacker target per control."""
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name).resolve()
        self.target = self.root / "attacker_target"
        (self.target / "sub").mkdir(parents=True)
        self.mounts: list[Path] = []
        self.environment = {
            "SystemRoot": os.environ["SYSTEMROOT"],
            "PATH": os.environ["SYSTEMROOT"] + "\\System32",
        }

    def tearDown(self) -> None:
        """Remove every mount point this control created, then the temporary tree."""
        for mount in reversed(self.mounts):
            _attack("delete", mount)
        self._temporary.cleanup()

    def _sddl(self, path: Path) -> str:
        """Read the actual owner and DACL of one object as SDDL."""
        advapi = windows_library("advapi32")
        kernel = windows_library("kernel32")
        advapi.GetFileSecurityW.argtypes = [
            w.LPCWSTR,
            w.DWORD,
            w.LPVOID,
            w.DWORD,
            ctypes.POINTER(w.DWORD),
        ]
        advapi.GetFileSecurityW.restype = w.BOOL
        advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
            w.LPVOID,
            w.DWORD,
            w.DWORD,
            ctypes.POINTER(w.LPWSTR),
            ctypes.POINTER(w.DWORD),
        ]
        advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = w.BOOL
        kernel.LocalFree.argtypes = [w.LPVOID]
        needed = w.DWORD()
        advapi.GetFileSecurityW(str(path), 5, None, 0, ctypes.byref(needed))
        buffer = ctypes.create_string_buffer(needed.value)
        self.assertTrue(
            advapi.GetFileSecurityW(str(path), 5, buffer, needed, ctypes.byref(needed)),
            windows_last_error(),
        )
        text = w.LPWSTR()
        self.assertTrue(
            advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                buffer, 1, 5, ctypes.byref(text), None
            ),
            windows_last_error(),
        )
        try:
            return str(text.value)
        finally:
            kernel.LocalFree(text)

    def _rendered_dacl(self, sddl: str) -> str:
        """Render one DACL through the same system formatter as the object read.

        Windows writes some account SIDs as SDDL aliases, such as ``LA`` for the
        built-in Administrator, so an expected raw SID is compared in that rendering.
        """
        advapi = windows_library("advapi32")
        kernel = windows_library("kernel32")
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            w.LPCWSTR,
            w.DWORD,
            ctypes.POINTER(w.LPVOID),
            ctypes.POINTER(w.DWORD),
        ]
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = w.BOOL
        advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
            w.LPVOID,
            w.DWORD,
            w.DWORD,
            ctypes.POINTER(w.LPWSTR),
            ctypes.POINTER(w.DWORD),
        ]
        advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = w.BOOL
        kernel.LocalFree.argtypes = [w.LPVOID]
        descriptor = w.LPVOID()
        self.assertTrue(
            advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1, ctypes.byref(descriptor), None
            ),
            windows_last_error(),
        )
        try:
            text = w.LPWSTR()
            self.assertTrue(
                advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    descriptor, 1, 4, ctypes.byref(text), None
                ),
                windows_last_error(),
            )
            try:
                return str(text.value)
            finally:
                kernel.LocalFree(text)
        finally:
            kernel.LocalFree(descriptor)

    def _mount(self, directory: Path) -> None:
        """Turn one owned empty directory into a real mount point to the attacker target."""
        self.assertEqual(_attack("set", directory, _mount_point(self.target)), "ok")
        self.mounts.append(directory)

    def test_transient_mount_point_at_relative_create_is_refused(self) -> None:
        """A mount point raced in after the pre-check cannot redirect a relative create."""
        leaf = self.root / "store"
        leaf.mkdir()
        with WindowsDirectory(leaf) as directory:
            self.assertTrue(directory.identity)  # actual pre-check passes on the clean leaf
            self._mount(leaf)
            with self.assertRaises(OSError) as refusal:
                windows_handles._open_relative(
                    directory._handles[-1], "payload.bin", directory=False, create=True
                )
            self.assertEqual(getattr(refusal.exception, "winerror", None), 1921)
        self.assertFalse((self.target / "payload.bin").exists())
        self.assertFalse((leaf / "payload.bin").exists())

    def test_persistent_mount_point_on_retained_leaf_refuses_creation(self) -> None:
        """A retained leaf that became a mount point is refused before any child effect."""
        leaf = self.root / "store"
        leaf.mkdir()
        with WindowsDirectory(leaf) as directory:
            self._mount(leaf)
            with self.assertRaises(ValueError):
                directory.open_file("payload.bin", create=True)
        self.assertFalse((self.target / "payload.bin").exists())

    def test_child_and_intermediate_mount_points_are_refused(self) -> None:
        """Mount-point children and components never resolve through to their target."""
        leaf = self.root / "store"
        (leaf / "c").mkdir(parents=True)
        self._mount(leaf / "c")
        with WindowsDirectory(leaf) as directory:
            with self.assertRaises(OSError):
                directory.open_file("c")
            with self.assertRaises(ValueError):
                directory.open_directory(Path("c"))
        with self.assertRaises(ValueError):
            WindowsDirectory(leaf / "c" / "sub")

    def test_open_directory_refuses_traversal_and_duplicates_identity(self) -> None:
        """Relative children cannot traverse; the empty path duplicates the exact object."""
        with WindowsDirectory(self.root) as directory:
            for refused in (Path(".."), Path("..") / "x", Path(self.root)):
                with self.subTest(path=str(refused)), self.assertRaises(ValueError):
                    directory.open_directory(refused)
            with directory.open_directory(Path(".")) as duplicate:
                self.assertEqual(duplicate.identity, directory.identity)

    def test_retained_directory_cannot_be_renamed_by_another_process(self) -> None:
        """Delete-sharing denial keeps the retained name bound to its object."""
        leaf = self.root / "store"
        leaf.mkdir()
        with WindowsDirectory(leaf):
            self.assertEqual(_attack("rename", leaf, str(self.root / "moved")), "32")
        self.assertTrue(leaf.is_dir())

    def test_private_creation_has_protected_single_user_dacl(self) -> None:
        """Created files carry only the current user's full-control ACE, without inheritance."""
        leaf = self.root / "store"
        leaf.mkdir()
        with (
            WindowsDirectory(leaf) as directory,
            directory.open_file("private.bin", create=True) as created,
        ):
            os.write(created.descriptor, b"p")
            created.flush()
        descriptor = self._sddl(leaf / "private.bin")
        self.assertIn(self._rendered_dacl(f"D:P(A;;FA;;;{_current_user_sid()})"), descriptor)
        self.assertEqual(descriptor.count("(A;"), 1)

    def test_script_image_is_refused_before_resume(self) -> None:
        """A .cmd image would start the command interpreter; the image check refuses it."""
        script = self.root / "probe.cmd"
        script.write_text("@echo unexpected\r\n", encoding="ascii")
        with (
            WindowsDirectory(self.root) as directory,
            directory.open_file(script.name) as image,
            self.assertRaisesRegex(RuntimeError, "differs from the retained executable"),
        ):
            run_windows_process(
                script,
                (),
                image_handle=image.handle,
                environment=self.environment,
                cwd=self.root,
                timeout_seconds=20,
                output_limit=4096,
            )

    def test_dos_device_redirect_is_refused_before_resume(self) -> None:
        """A drive alias pointing at another same-name image cannot replace the retained one."""
        kernel = windows_library("kernel32")
        kernel.DefineDosDeviceW.argtypes = [w.DWORD, w.LPCWSTR, w.LPCWSTR]
        kernel.DefineDosDeviceW.restype = w.BOOL
        trusted, other = self.root / "trusted", self.root / "other"
        trusted.mkdir()
        other.mkdir()
        system = Path(os.environ["SYSTEMROOT"]) / "System32"
        shutil.copyfile(system / "cmd.exe", trusted / "tool.exe")
        shutil.copyfile(system / "where.exe", other / "tool.exe")
        letter = next((c for c in "QRSTUVWXYZJKLMNOP" if not Path(c + ":\\").exists()), None)
        self.assertIsNotNone(letter, "the DOS-device control needs one unused drive letter")
        assert letter is not None
        self.assertTrue(kernel.DefineDosDeviceW(0, letter + ":", str(other)), windows_last_error())
        try:
            with (
                WindowsDirectory(trusted) as directory,
                directory.open_file("tool.exe") as image,
                self.assertRaisesRegex(RuntimeError, "differs from the retained executable"),
            ):
                run_windows_process(
                    Path(letter + ":\\tool.exe"),
                    ("/?",),
                    image_handle=image.handle,
                    environment=self.environment,
                    cwd=self.root,
                    timeout_seconds=20,
                    output_limit=65536,
                )
        finally:
            kernel.DefineDosDeviceW(2, letter + ":", str(other))

    def test_grandchild_does_not_outlive_the_owned_job(self) -> None:
        """A detached grandchild starts but is terminated with the owned job."""
        tool = self.root / "bin" / "tool.exe"
        tool.parent.mkdir()
        shutil.copyfile(Path(os.environ["SYSTEMROOT"]) / "System32" / "cmd.exe", tool)
        started, alive = self.root / "started.txt", self.root / "alive.txt"
        command = f"echo s>{started} & ping -n 4 127.0.0.1 >nul & echo a>{alive}"
        with WindowsDirectory(tool.parent) as directory, directory.open_file(tool.name) as image:
            code, stdout, _ = run_windows_process(
                tool,
                # The leader waits about one second so the grandchild has started before
                # the leader exits and the owned job is terminated.
                (
                    "/c",
                    "start",
                    "/b",
                    "cmd",
                    "/c",
                    command,
                    "&",
                    "ping",
                    "-n",
                    "2",
                    "127.0.0.1",
                    ">nul",
                    "&",
                    "echo",
                    "parent-done",
                ),
                image_handle=image.handle,
                environment=self.environment,
                cwd=self.root,
                timeout_seconds=30,
                output_limit=65536,
            )
        self.assertEqual(code, 0)
        self.assertIn(b"parent-done", stdout)
        time.sleep(6)
        self.assertTrue(
            started.exists(), "the grandchild never started; control is not meaningful"
        )
        self.assertFalse(alive.exists())

    def test_case_only_duplicate_environment_names_are_refused(self) -> None:
        """Windows resolves names case-insensitively; ambiguous duplicates are refused."""
        with WindowsDirectory(self.root) as directory:
            shutil.copyfile(
                Path(os.environ["SYSTEMROOT"]) / "System32" / "where.exe", self.root / "w.exe"
            )
            with (
                directory.open_file("w.exe") as image,
                self.assertRaisesRegex(ValueError, "distinct without case"),
            ):
                run_windows_process(
                    self.root / "w.exe",
                    ("/?",),
                    image_handle=image.handle,
                    environment={**self.environment, "Path": "x"},
                    cwd=self.root,
                    timeout_seconds=20,
                    output_limit=4096,
                )
