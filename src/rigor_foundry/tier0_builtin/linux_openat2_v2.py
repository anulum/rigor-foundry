# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — descriptor-bound Linux path opening
"""Use Linux openat2 with no-follow resolution for Tier-0 path descent.

These entrypoints require Linux descriptor flags and the x86-64 syscall ABI.
Linux personality refusals are exercised on the qualified local host; other
operating systems and physical architectures have not been qualified.
"""

from __future__ import annotations

import ctypes
import os
import platform
import stat
from typing import Final

from ..effect_journal_records_v2 import parse_effect_target_ref_v2
from .atomic_replace_refusal_v2 import PreEffectRefusalV2

_SYS_OPENAT2_X86_64: Final = 437
_RESOLVE_NO_XDEV: Final = 0x01
_RESOLVE_NO_MAGICLINKS: Final = 0x02
_RESOLVE_NO_SYMLINKS: Final = 0x04
_RESOLVE_BENEATH: Final = 0x08
_AT_FDCWD: Final = -100
MAX_EXISTING_CONTENT_BYTES: Final = 64 * 1024 * 1024


class _OpenHow(ctypes.Structure):
    """The three unsigned 64-bit fields of Linux ``struct open_how``."""

    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


def _openat2(dir_fd: int, path: str, *, flags: int, resolve: int) -> int:
    """Open one path with the kernel's resolution restrictions or fail closed."""
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise OSError("Tier-0 openat2 is unavailable on this architecture")
    if not path or "\x00" in path or type(dir_fd) is not int or dir_fd < _AT_FDCWD:
        raise ValueError("Tier-0 openat2 path or directory descriptor is malformed")
    if type(flags) is not int or flags < 0:
        raise ValueError("Tier-0 openat2 flags are malformed")
    how = _OpenHow(flags, 0, resolve)
    libc = ctypes.CDLL(None, use_errno=True)
    syscall = libc.syscall
    syscall.restype = ctypes.c_long
    result = syscall(
        ctypes.c_long(_SYS_OPENAT2_X86_64),
        ctypes.c_int(dir_fd),
        ctypes.c_char_p(path.encode("utf-8")),
        ctypes.byref(how),
        ctypes.c_size_t(ctypes.sizeof(how)),
    )
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), path)
    return int(result)


def open_absolute_directory_nofollow_v2(path: str) -> int:
    """Open a canonical absolute directory without traversing symlinks.

    Parameters
    ----------
    path : str
        Canonical absolute path accepted by the effect-target parser.

    Returns
    -------
    int
        Held O_PATH directory descriptor; the caller must close it.

    Raises
    ------
    ValueError
        If the path is malformed.
    OSError
        If Linux x86-64 openat2 is unavailable or kernel resolution refuses
        the path. No fallback follows symlinks.
    """
    parse_effect_target_ref_v2({"form": "path", "value": path})
    return _openat2(
        _AT_FDCWD,
        path,
        flags=os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC,
        resolve=_RESOLVE_NO_SYMLINKS | _RESOLVE_NO_MAGICLINKS,
    )


def open_child_directory_nofollow_v2(
    parent_fd: int, component: str, *, no_xdev: bool = False
) -> int:
    """Open one child directory, optionally refusing any mount crossing.

    Parameters
    ----------
    parent_fd : int
        Held directory descriptor used as the resolution root.
    component : str
        Single nonempty name, excluding dot, dot-dot, slashes and controls.
    no_xdev : bool, optional
        Refuse mount crossings, including bind mounts, when true.

    Returns
    -------
    int
        Held O_PATH child directory descriptor; the caller must close it.

    Raises
    ------
    ValueError
        If the component or descriptor is malformed.
    OSError
        If the architecture is unsupported or kernel resolution fails.
        Resolution is beneath the held parent and refuses all symlinks.
    """
    if (
        not component
        or component in {".", ".."}
        or "/" in component
        or any(ord(char) < 0x20 or 0xD800 <= ord(char) <= 0xDFFF for char in component)
    ):
        raise ValueError("Tier-0 path component is malformed")
    return _openat2(
        parent_fd,
        component,
        flags=os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC,
        resolve=(
            _RESOLVE_BENEATH
            | _RESOLVE_NO_SYMLINKS
            | _RESOLVE_NO_MAGICLINKS
            | (_RESOLVE_NO_XDEV if no_xdev else 0)
        ),
    )


def open_child_file_nofollow_v2(parent_fd: int, component: str, *, no_xdev: bool = False) -> int:
    """Open one bounded regular child file without links or selected mounts.

    Parameters
    ----------
    parent_fd : int
        Held directory descriptor used as the resolution root.
    component : str
        Single nonempty name, excluding dot, dot-dot, slashes and controls.
    no_xdev : bool, optional
        Refuse mount crossings, including bind mounts, when true.

    Returns
    -------
    int
        Readable held descriptor for a regular file no larger than 64 MiB.
        The caller must close it and separately revalidate before effects.

    Raises
    ------
    ValueError
        If the component or descriptor is malformed.
    OSError
        If the architecture is unsupported or kernel resolution fails.
    PreEffectRefusalV2
        For a nonregular or oversized opened inode. Its descriptor closes
        before refusal; no symlink-following fallback is attempted.
    """
    if (
        not component
        or component in {".", ".."}
        or "/" in component
        or any(ord(char) < 0x20 or 0xD800 <= ord(char) <= 0xDFFF for char in component)
    ):
        raise ValueError("Tier-0 path component is malformed")
    fd = _openat2(
        parent_fd,
        component,
        flags=os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        resolve=(
            _RESOLVE_BENEATH
            | _RESOLVE_NO_SYMLINKS
            | _RESOLVE_NO_MAGICLINKS
            | (_RESOLVE_NO_XDEV if no_xdev else 0)
        ),
    )
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise PreEffectRefusalV2("not-regular", "Tier-0 file target is not regular")
        if info.st_size > MAX_EXISTING_CONTENT_BYTES:
            raise PreEffectRefusalV2("pre-state-too-large", "Tier-0 existing file exceeds 64 MiB")
    except BaseException:
        os.close(fd)
        raise
    return fd
