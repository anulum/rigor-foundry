# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — protected native Windows output permissions
"""Allocate protected current-user security descriptors before file creation."""

from __future__ import annotations

import ctypes
import re
from collections.abc import Iterator
from contextlib import contextmanager
from ctypes import wintypes as w

from .windows_abi import windows_error, windows_library


class _SidAndAttributes(ctypes.Structure):
    """TOKEN_USER's SID_AND_ATTRIBUTES with a pointer-sized borrowed SID."""

    _fields_ = [("sid", w.LPVOID), ("attributes", w.DWORD)]


class _TokenUser(ctypes.Structure):
    """SDK SE_TOKEN_USER maximum layout with native pointer alignment."""

    # SECURITY_MAX_SID_SIZE = 8 + SID_MAX_SUB_AUTHORITIES(15) * sizeof(DWORD).
    # https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_se_token_user
    _fields_ = [("user", _SidAndAttributes), ("sid_storage", ctypes.c_ubyte * 68)]


def private_descriptor_sddl(user_sid: str) -> str:
    """Format one bounded SID into a protected, single-principal full-access DACL.

    Parameters
    ----------
    user_sid : str
        Explicit SID in the Windows SDK's ASCII string representation.

    Returns
    -------
    str
        Protected DACL containing exactly the supplied principal.

    Raises
    ------
    ValueError
        If the SID is malformed or exceeds the SDK's maximum string size.
    """
    if len(user_sid) > 186 or re.fullmatch(r"S-1-[0-9]+(?:-[0-9]+)*", user_sid) is None:
        raise ValueError("Windows user SID has an invalid format")
    return f"D:P(A;;FA;;;{user_sid})"


def _current_user_sid() -> str:
    """Copy the current process token's user SID and release token/native strings."""
    kernel = windows_library("kernel32")
    advapi = windows_library("advapi32")
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.CloseHandle.restype = w.BOOL
    kernel.LocalFree.argtypes = [w.LPVOID]
    kernel.LocalFree.restype = w.LPVOID
    advapi.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
    advapi.OpenProcessToken.restype = w.BOOL
    advapi.GetTokenInformation.argtypes = [
        w.HANDLE,
        ctypes.c_int,
        w.LPVOID,
        w.DWORD,
        ctypes.POINTER(w.DWORD),
    ]
    advapi.GetTokenInformation.restype = w.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [w.LPVOID, ctypes.POINTER(w.LPWSTR)]
    advapi.ConvertSidToStringSidW.restype = w.BOOL
    token = w.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise windows_error()
    text = w.LPWSTR()
    try:
        length = w.DWORD()
        data = _TokenUser()
        if not advapi.GetTokenInformation(
            token, 1, ctypes.byref(data), ctypes.sizeof(data), ctypes.byref(length)
        ):
            raise windows_error()
        if not advapi.ConvertSidToStringSidW(data.user.sid, ctypes.byref(text)):
            raise windows_error()
        # Successful conversion owns a null-terminated string; the SDDL boundary validates it.
        return ctypes.wstring_at(text)
    finally:
        if text:
            kernel.LocalFree(text)
        kernel.CloseHandle(token)


@contextmanager
def private_security_descriptor() -> Iterator[ctypes.c_void_p]:
    """Retain a protected current-user-only DACL for one atomic object creation.

    Yields
    ------
    ctypes.c_void_p
        Borrowed self-relative SECURITY_DESCRIPTOR, valid only inside the context.

    Raises
    ------
    OSError, RuntimeError
        If the current user, descriptor conversion or native allocation is unavailable.
        Creation must not fall back to an inherited DACL after such failure.
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
    kernel.LocalFree.argtypes = [w.LPVOID]
    kernel.LocalFree.restype = w.LPVOID
    descriptor = w.LPVOID()
    sddl = private_descriptor_sddl(_current_user_sid())
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None
    ):
        raise windows_error()
    try:
        # Successful conversion returns an owned self-relative descriptor (sddl.h).
        yield descriptor
    finally:
        kernel.LocalFree(descriptor)
