# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native Windows filesystem handle ownership
"""Retain local NTFS objects without following reparse points or replacing names."""

from __future__ import annotations

import ctypes
import os
import re
from contextlib import ExitStack
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import cast

from .windows_abi import windows_descriptor, windows_error, windows_handle, windows_library
from .windows_permissions import private_security_descriptor

_INVALID_HANDLE = ctypes.c_void_p(-1).value
_DIRECTORY_READ = 0x1000A1
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_DELETE = 0x10000
_SHARE_READ = 1
_OPEN_EXISTING = 3
_CREATE_NEW = 1
_OPEN_REPARSE_POINT = 0x200000
_BACKUP_SEMANTICS = 0x2000000
_WRITE_THROUGH = 0x80000000
_REPARSE_POINT = 0x400
_DIRECTORY = 0x10
_RESERVED = re.compile(r"^(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])$", re.I)


class _FileInformation(ctypes.Structure):
    """Native BY_HANDLE_FILE_INFORMATION layout, including NTFS file identity."""

    _fields_ = [
        ("attributes", wintypes.DWORD),
        ("created", wintypes.FILETIME),
        ("accessed", wintypes.FILETIME),
        ("written", wintypes.FILETIME),
        ("volume", wintypes.DWORD),
        ("size_high", wintypes.DWORD),
        ("size_low", wintypes.DWORD),
        ("links", wintypes.DWORD),
        ("index_high", wintypes.DWORD),
        ("index_low", wintypes.DWORD),
    ]


class _UnicodeString(ctypes.Structure):
    """Native UNICODE_STRING retaining its separately owned UTF-16 buffer."""

    _fields_ = [
        ("length", wintypes.USHORT),
        ("maximum_length", wintypes.USHORT),
        ("buffer", wintypes.LPWSTR),
    ]


class _ObjectAttributes(ctypes.Structure):
    """Object-manager lookup rooted at the actual retained directory handle."""

    _fields_ = [
        ("length", wintypes.ULONG),
        ("root", wintypes.HANDLE),
        ("name", ctypes.POINTER(_UnicodeString)),
        ("attributes", wintypes.ULONG),
        ("security", wintypes.LPVOID),
        ("quality", wintypes.LPVOID),
    ]


class _IoStatus(ctypes.Structure):
    """Pointer-sized native IO_STATUS_BLOCK layout."""

    _fields_ = [("status", wintypes.LPVOID), ("information", ctypes.c_size_t)]


def _open_relative(
    parent: int, name: str, *, directory: bool, create: bool = False, private: bool = True
) -> int:
    """Open one validated child relative to a retained object, without reparsing paths."""
    _component(name)
    buffer = ctypes.create_unicode_buffer(name)
    length = len(name.encode("utf-16-le"))
    if length > 65532:
        raise ValueError("Windows child name exceeds the native UTF-16 limit")
    string = _UnicodeString(length, length + 2, ctypes.cast(buffer, wintypes.LPWSTR))
    attributes = _ObjectAttributes(
        ctypes.sizeof(_ObjectAttributes), parent, ctypes.pointer(string), 0x1040, None, None
    )
    library = windows_library("ntdll")
    library.NtCreateFile.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.ULONG,
        ctypes.POINTER(_ObjectAttributes),
        ctypes.POINTER(_IoStatus),
        wintypes.LPVOID,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.LPVOID,
        wintypes.ULONG,
    ]
    library.NtCreateFile.restype = wintypes.LONG
    library.RtlNtStatusToDosError.argtypes = [wintypes.LONG]
    library.RtlNtStatusToDosError.restype = wintypes.ULONG
    result = wintypes.HANDLE()
    status_block = _IoStatus()
    access = _DIRECTORY_READ if directory else _GENERIC_READ | 0x100000
    options = 0x20 | _OPEN_REPARSE_POINT | (0x1 if directory else 0x40)
    if create:
        access |= _GENERIC_WRITE | _DELETE
        options |= 0x2
    with ExitStack() as resources:
        if create and private:
            attributes.security = resources.enter_context(private_security_descriptor())
        status = library.NtCreateFile(
            ctypes.byref(result),
            access,
            ctypes.byref(attributes),
            ctypes.byref(status_block),
            None,
            0x80,
            _SHARE_READ,
            2 if create else 1,
            options,
            None,
            0,
        )
    if status < 0:
        raise windows_error(int(library.RtlNtStatusToDosError(status)))
    return cast(int, result.value)


def _kernel() -> ctypes.CDLL:
    """Load the system library with pointer-sized handles and explicit signatures."""
    library = windows_library("kernel32")
    library.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    library.CreateFileW.restype = wintypes.HANDLE
    library.CloseHandle.argtypes = [wintypes.HANDLE]
    library.CloseHandle.restype = wintypes.BOOL
    library.GetCurrentProcess.argtypes = []
    library.GetCurrentProcess.restype = wintypes.HANDLE
    library.DuplicateHandle.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    library.DuplicateHandle.restype = wintypes.BOOL
    library.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_FileInformation),
    ]
    library.GetFileInformationByHandle.restype = wintypes.BOOL
    library.GetFileType.argtypes = [wintypes.HANDLE]
    library.GetFileType.restype = wintypes.DWORD
    library.GetVolumeInformationByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    library.GetVolumeInformationByHandleW.restype = wintypes.BOOL
    library.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    library.GetDriveTypeW.restype = wintypes.UINT
    library.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    library.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    library.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    library.FlushFileBuffers.restype = wintypes.BOOL
    library.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    library.SetFileInformationByHandle.restype = wintypes.BOOL
    return library


def _component(name: str) -> None:
    """Refuse Win32 aliases, streams, device names and ambiguous components."""
    if (
        not name
        or name in {".", ".."}
        or name[-1] in {" ", "."}
        or any(ord(character) < 32 or character in '<>:"/\\|?*' for character in name)
        or _RESERVED.fullmatch(name.split(".", 1)[0]) is not None
    ):
        raise ValueError("Windows path contains an ambiguous or unsupported component")


def _absolute(path: Path) -> Path:
    """Accept only explicit local drive paths, without normalising parent traversal."""
    if not path.is_absolute() or len(path.drive) != 2 or not path.drive[0].isalpha():
        raise ValueError("Windows file operations require an absolute local drive path")
    for name in path.parts[1:]:
        _component(name)
    return path


@dataclass(frozen=True)
class WindowsFileIdentity:
    """Handle-bound NTFS identity and exact raw content metadata."""

    volume: int
    file_id: int
    attributes: int
    links: int
    size: int
    written: int
    created: int


class WindowsFile:
    """Own one regular file and its noninheritable binary CRT descriptor."""

    def __init__(self, handle: int, *, writable: bool) -> None:
        """Transfer a native handle into the CRT, closing it if transfer fails."""
        self._descriptor: int | None = None
        self._kernel = _kernel()
        try:
            self._descriptor = windows_descriptor(handle, writable=writable)
        except BaseException:
            if writable:
                delete = wintypes.BOOL(True)
                self._kernel.SetFileInformationByHandle(
                    handle, 4, ctypes.byref(delete), ctypes.sizeof(delete)
                )
            self._kernel.CloseHandle(handle)
            raise

    @property
    def descriptor(self) -> int:
        """Return the owned CRT descriptor, refusing use after close."""
        if self._descriptor is None:
            raise ValueError("Windows file is closed")
        return self._descriptor

    @property
    def handle(self) -> int:
        """Return the actual native handle backing the live CRT descriptor."""
        return windows_handle(self.descriptor)

    def identity(self) -> WindowsFileIdentity:
        """Read type, file identity, links and raw size from this retained handle."""
        return _identity(self._kernel, self.handle, directory=False)

    def flush(self) -> None:
        """Flush actual file data and metadata or propagate the native failure."""
        if not self._kernel.FlushFileBuffers(self.handle):
            raise windows_error()

    def discard(self) -> None:
        """Mark only this owned created object for deletion when its handle closes."""
        delete = wintypes.BOOL(True)
        if not self._kernel.SetFileInformationByHandle(
            self.handle, 4, ctypes.byref(delete), ctypes.sizeof(delete)
        ):
            raise windows_error()

    def close(self) -> None:
        """Close the CRT descriptor exactly once; the CRT releases its native handle."""
        if self._descriptor is not None:
            descriptor, self._descriptor = self._descriptor, None
            os.close(descriptor)

    def __enter__(self) -> WindowsFile:
        """Return this live owned regular file."""
        _ = self.descriptor
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the owned descriptor on every context exit."""
        self.close()


def _identity(library: ctypes.CDLL, handle: int, *, directory: bool) -> WindowsFileIdentity:
    """Reject reparse/non-disk objects before exposing their handle-bound identity."""
    data = _FileInformation()
    if not library.GetFileInformationByHandle(handle, ctypes.byref(data)):
        raise windows_error()
    if (
        library.GetFileType(handle) != 1
        or data.attributes & _REPARSE_POINT
        or bool(data.attributes & _DIRECTORY) != directory
    ):
        raise ValueError("Windows path is not the required non-reparse disk object")
    return WindowsFileIdentity(
        volume=int(data.volume),
        file_id=(int(data.index_high) << 32) | int(data.index_low),
        attributes=int(data.attributes),
        links=int(data.links),
        size=(int(data.size_high) << 32) | int(data.size_low),
        written=(int(data.written.dwHighDateTime) << 32) | int(data.written.dwLowDateTime),
        created=(int(data.created.dwHighDateTime) << 32) | int(data.created.dwLowDateTime),
    )


class WindowsDirectory:
    """Retain every no-reparse parent component while operating on an NTFS child."""

    def __init__(self, path: Path) -> None:
        """Open an explicit fixed local NTFS path with write/delete sharing denied."""
        self.path = _absolute(path)
        self._kernel = _kernel()
        self._handles: list[int] = []
        if self._kernel.GetDriveTypeW(self.path.anchor) != 3:
            raise ValueError("Windows file operations require a fixed local NTFS volume")
        try:
            cursor = str(self.path.anchor)
            for index in range(len(self.path.parts)):
                if index:
                    cursor = cursor.rstrip("\\") + "\\" + self.path.parts[index]
                if index:
                    handle = _open_relative(
                        self._handles[-1], self.path.parts[index], directory=True
                    )
                else:
                    handle = self._kernel.CreateFileW(
                        str(cursor),
                        _DIRECTORY_READ,
                        _SHARE_READ,
                        None,
                        _OPEN_EXISTING,
                        _BACKUP_SEMANTICS | _OPEN_REPARSE_POINT,
                        None,
                    )
                    if handle == _INVALID_HANDLE:
                        raise windows_error()
                self._handles.append(int(handle))
                _identity(self._kernel, int(handle), directory=True)
                if index == 0:
                    root_buffer = ctypes.create_unicode_buffer(128)
                    length = self._kernel.GetFinalPathNameByHandleW(
                        handle, root_buffer, len(root_buffer), 1
                    )
                    if not length or length >= len(root_buffer):
                        raise windows_error()
                    if (
                        re.fullmatch(r"\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\", root_buffer.value)
                        is None
                    ):
                        raise ValueError("Windows root has no supported volume GUID namespace")
                    cursor = root_buffer.value
            self._native_path = cursor
            filesystem = ctypes.create_unicode_buffer(64)
            if not self._kernel.GetVolumeInformationByHandleW(
                self._handles[-1], None, 0, None, None, None, filesystem, len(filesystem)
            ):
                raise windows_error()
            if filesystem.value != "NTFS":
                raise ValueError("Windows file operations require a fixed local NTFS volume")
            self._identity = _identity(self._kernel, self._handles[-1], directory=True)
        except BaseException:
            self.close()
            raise

    @property
    def identity(self) -> tuple[int, int]:
        """Return this retained directory's NTFS volume and file identity."""
        self._check()
        return self._identity.volume, self._identity.file_id

    def _check(self) -> None:
        """Reject closed or changed directory resources before any child operation."""
        if not self._handles:
            raise ValueError("Windows directory is closed")
        _ = _identity(self._kernel, self._handles[-1], directory=True)

    def open_file(self, name: str, *, create: bool = False, private: bool = True) -> WindowsFile:
        """Open a single no-reparse child with write/delete sharing denied.

        Parameters
        ----------
        name : str
            One unambiguous child component, without traversal or streams.
        create : bool
            Create a new exclusive write-through file; never overwrite an existing name.
        private : bool
            For creation, atomically protect the DACL to the current process user only.

        Returns
        -------
        WindowsFile
            Caller-owned regular file retaining its exact native object.
        """
        self._check()
        _component(name)
        handle = _open_relative(
            self._handles[-1], name, directory=False, create=create, private=private
        )
        result = WindowsFile(int(handle), writable=create)
        try:
            _ = result.identity()
            name_buffer = ctypes.create_unicode_buffer(32768)
            length = self._kernel.GetFinalPathNameByHandleW(
                result.handle, name_buffer, len(name_buffer), 1
            )
            if not length or length >= len(name_buffer):
                raise windows_error()
            if name_buffer.value != str(self.native_path(name)):
                raise ValueError("Windows child differs from the retained parent and name")
            self._check()
        except BaseException:
            try:
                if create:
                    result.discard()
            finally:
                result.close()
            raise
        return result

    def native_path(self, name: str) -> Path:
        """Return a child path in the retained root's volume GUID namespace.

        Parameters
        ----------
        name : str
            One validated unambiguous child name.

        Returns
        -------
        Path
            Internal execution/open path, independent of mutable DOS drive mappings.
        """
        self._check()
        _component(name)
        return Path(self._native_path) / name

    def open_directory(self, relative: Path) -> WindowsDirectory:
        """Retain a relative child directory without resolving the original drive path again.

        Parameters
        ----------
        relative : Path
            Directory below this retained object, or ``Path('.')`` for an owned duplicate.

        Returns
        -------
        WindowsDirectory
            Independently owned duplicate parent chain and relative-opened descendants.

        Raises
        ------
        ValueError, OSError
            If the relative path, retained lifetime or child binding cannot be established.
        """
        self._check()
        if relative.is_absolute() or relative.drive or ".." in relative.parts:
            raise ValueError("Windows directory child must be an untraversed relative path")
        for component in relative.parts:
            _component(component)
        child = WindowsDirectory.__new__(WindowsDirectory)
        child.path = self.path / relative
        child._kernel = self._kernel
        child._handles = []
        child._native_path = self._native_path
        process = self._kernel.GetCurrentProcess()
        try:
            for original in self._handles:
                duplicate = wintypes.HANDLE()
                if not self._kernel.DuplicateHandle(
                    process, original, process, ctypes.byref(duplicate), 0, False, 2
                ):
                    raise windows_error()
                child._handles.append(cast(int, duplicate.value))
            for component in relative.parts:
                handle = _open_relative(child._handles[-1], component, directory=True)
                child._handles.append(handle)
                _identity(self._kernel, handle, directory=True)
                child._native_path = child._native_path.rstrip("\\") + "\\" + component
            child._identity = _identity(self._kernel, child._handles[-1], directory=True)
            buffer = ctypes.create_unicode_buffer(32768)
            length = self._kernel.GetFinalPathNameByHandleW(
                child._handles[-1], buffer, len(buffer), 1
            )
            if not length or length >= len(buffer):
                raise windows_error()
            if buffer.value.rstrip("\\") != child._native_path.rstrip("\\"):
                raise ValueError("Windows directory differs from the retained parent and name")
            return child
        except BaseException:
            child.close()
            raise

    def close(self) -> None:
        """Release every directory handle, in reverse acquisition order."""
        errors: list[OSError] = []
        while self._handles:
            if not self._kernel.CloseHandle(self._handles.pop()):
                errors.append(windows_error())
        if errors:
            raise RuntimeError("native directory handle cleanup failed") from ExceptionGroup(
                "native directory close failures", errors
            )

    def __enter__(self) -> WindowsDirectory:
        """Return this live owned directory chain."""
        self._check()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Release the complete retained parent chain on every context exit."""
        self.close()
