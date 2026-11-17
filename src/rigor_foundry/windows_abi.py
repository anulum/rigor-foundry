# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — platform-gated Windows ABI constructors
"""Keep platform-specific standard-library imports behind explicit Windows gates."""

from __future__ import annotations

import ctypes
import os
import sys


def windows_library(name: str) -> ctypes.CDLL:
    """Load a system DLL with the Windows calling convention and saved last-error."""
    if sys.platform == "win32":
        return ctypes.WinDLL(name, use_last_error=True)
    raise RuntimeError("native Windows libraries require Windows")


def windows_error(code: int | None = None) -> OSError:
    """Capture the current saved Windows error, or translate an explicit DOS code."""
    if sys.platform == "win32":
        return ctypes.WinError(ctypes.get_last_error() if code is None else code)
    raise RuntimeError("native Windows errors require Windows")


def windows_last_error() -> int:
    """Return the calling thread's saved Windows error immediately after a call."""
    if sys.platform == "win32":
        return ctypes.get_last_error()
    raise RuntimeError("native Windows errors require Windows")


def windows_descriptor(handle: int, *, writable: bool) -> int:
    """Transfer an owned native handle into a noninheritable binary CRT descriptor."""
    if sys.platform == "win32":
        import msvcrt

        flags = os.O_BINARY | os.O_NOINHERIT | (os.O_RDWR if writable else os.O_RDONLY)
        return msvcrt.open_osfhandle(handle, flags)
    raise RuntimeError("native Windows descriptors require Windows")


def windows_handle(descriptor: int) -> int:
    """Borrow the real native handle of a live CRT descriptor without ownership transfer."""
    if sys.platform == "win32":
        import msvcrt

        return msvcrt.get_osfhandle(descriptor)
    raise RuntimeError("native Windows descriptors require Windows")
