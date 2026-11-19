# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Windows handle-relative directory metadata
"""Read native directory identities and entries from already retained handles."""

from __future__ import annotations

import ctypes
import struct
from ctypes import wintypes
from dataclasses import dataclass
from functools import cache

from .windows_abi import windows_error, windows_last_error, windows_library

_FILE_BASIC_INFO = 0
_FILE_ID_EXTD_DIRECTORY_INFO = 19
_FILE_ID_EXTD_DIRECTORY_RESTART_INFO = 20
_ERROR_NO_MORE_FILES = 18
_BASIC_RECORD = struct.Struct("<4qI4x")
# FILE_ID_EXTD_DIR_INFO supplies next offset, name byte count and file ID.
_DIRECTORY_RECORD = struct.Struct("<I56xI8x16s")


@dataclass(frozen=True)
class WindowsDirectoryEntry:
    """An exact native name and NTFS object identifier from a directory enumeration."""

    name: str
    file_id: int


@cache
def _kernel() -> ctypes.CDLL:
    """Bind the Windows handle information API once per process."""
    kernel = windows_library("kernel32")
    kernel.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
    return kernel


def file_change_token(handle: int) -> tuple[int, int, int, int]:
    """Read creation, write and change timestamps and attributes of a retained object.

    Parameters
    ----------
    handle : int
        Borrowed Windows handle with permission to read attributes.

    Returns
    -------
    tuple[int, int, int, int]
        Native timestamps and attributes. Access time is irrelevant to stability.
    """
    buffer = ctypes.create_string_buffer(_BASIC_RECORD.size)
    if not _kernel().GetFileInformationByHandleEx(handle, _FILE_BASIC_INFO, buffer, len(buffer)):
        raise windows_error()
    created, _, written, changed, attributes = _BASIC_RECORD.unpack(buffer)
    return int(created), int(written), int(changed), int(attributes)


def list_directory_entries(
    handle: int, *, maximum_entries: int
) -> tuple[WindowsDirectoryEntry, ...]:
    """Enumerate the exact names and object identifiers of a retained NTFS directory.

    Parameters
    ----------
    handle : int
        Borrowed live directory handle with native listing access.
    maximum_entries : int
        Maximum number of children accepted across all native pages.

    Returns
    -------
    tuple[WindowsDirectoryEntry, ...]
        Native child records with the synthetic dot entries removed.

    Raises
    ------
    ValueError
        If the entry bound is negative.
    OSError
        If the native directory information query fails.
    OverflowError
        If the enumeration exceeds the accepted child count.
    """
    if maximum_entries < 0:
        raise ValueError("native directory entry limit must be nonnegative")
    query = _kernel().GetFileInformationByHandleEx
    buffer = ctypes.create_string_buffer(64 * 1024)
    information_class = _FILE_ID_EXTD_DIRECTORY_RESTART_INFO
    entries: list[WindowsDirectoryEntry] = []
    while query(handle, information_class, buffer, len(buffer)):
        information_class = _FILE_ID_EXTD_DIRECTORY_INFO
        offset = 0
        page = buffer.raw
        while True:
            following, name_bytes, file_id = _DIRECTORY_RECORD.unpack_from(page, offset)
            start = offset + _DIRECTORY_RECORD.size
            name = page[start : start + name_bytes].decode("utf-16-le", errors="surrogatepass")
            if name not in {".", ".."}:
                if len(entries) == maximum_entries:
                    raise OverflowError("native directory exceeds its entry limit")
                entries.append(WindowsDirectoryEntry(name, int.from_bytes(file_id, "little")))
            if following == 0:
                break
            offset += following
    code = windows_last_error()
    if code != _ERROR_NO_MORE_FILES:
        raise windows_error(code)
    return tuple(entries)
