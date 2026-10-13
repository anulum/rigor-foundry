# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — child-local descriptor kernel errno support
"""Install real fd-scoped kernel errno filters only inside bounded test children."""

from __future__ import annotations

import ctypes


class Compare(ctypes.Structure):
    """Match the selected syscall's descriptor argument in libseccomp."""

    _fields_ = [
        ("arg", ctypes.c_uint),
        ("op", ctypes.c_uint),
        ("datum_a", ctypes.c_uint64),
        ("datum_b", ctypes.c_uint64),
    ]


def refuse_syscall(name: str, result_errno: int, descriptor: int) -> None:
    """Install one child-local errno filter for the specified descriptor."""
    lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_rule_add_array.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.POINTER(Compare),
    ]
    lib.seccomp_rule_add_array.restype = ctypes.c_int
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_load.restype = ctypes.c_int
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.restype = None
    context = lib.seccomp_init(0x7FFF0000)
    assert context, "seccomp_init failed"
    try:
        syscall = lib.seccomp_syscall_resolve_name(name.encode("ascii"))
        assert syscall >= 0, name
        comparison = Compare(0, 4, descriptor, 0)
        result = lib.seccomp_rule_add_array(
            context,
            0x00050000 | result_errno,
            syscall,
            1,
            ctypes.byref(comparison),
        )
        assert result == 0, ("seccomp_rule_add_array", result)
        result = lib.seccomp_load(context)
        assert result == 0, ("seccomp_load", result)
    finally:
        lib.seccomp_release(context)
