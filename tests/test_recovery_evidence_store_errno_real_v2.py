# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real recovery evidence kernel failures
"""Exercise public publication failure and residue under actual syscall refusals."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_CHILD = """
import ctypes
import errno
import os
import sys
from pathlib import Path
from types import FrameType
from kernel_errno_support_v2 import refuse_syscall
from test_recovery_evidence_store_v2 import _journal_object, _object, _store
from rigor_foundry.recovery_evidence_store_v2 import RecoveryEvidenceStoreV2

case = sys.argv[1]
store = _store(Path(sys.argv[2]))
filtered_fd = -1
keeper = os.open('/dev/null', os.O_RDONLY)

def observe(frame: FrameType, event: str, arg: object) -> None:
    '''Apply a real kernel refusal at the actual publication syscall boundary.'''
    global filtered_fd
    if filtered_fd >= 0:
        return
    if (case == 'write-eio' and event == 'c_call' and arg is os.write
            and frame.f_back is not None
            and frame.f_back.f_code is RecoveryEvidenceStoreV2.publish.__code__):
        descriptor = frame.f_locals['descriptor']
        assert type(descriptor) is int
        filtered_fd = descriptor
        refuse_syscall('write', errno.EIO, descriptor)
    elif (case == 'rename-enosys' and event == 'call'
            and frame.f_code.co_name == '_rename_noreplace'
            and frame.f_back is not None
            and frame.f_back.f_code is RecoveryEvidenceStoreV2.publish.__code__):
        descriptor = frame.f_locals['parent']
        assert type(descriptor) is int
        filtered_fd = descriptor
        refuse_syscall('renameat2', errno.ENOSYS, descriptor)

sys.setprofile(observe)
try:
    try:
        store.publish(_object() if case == 'write-eio' else _journal_object())
    except OSError as exc:
        if case == 'write-eio':
            assert exc.errno == errno.EIO, exc
        else:
            # libc can translate kernel ENOSYS to EINVAL for nonzero rename flags.
            # Verify the raw syscall still receives ENOSYS from the installed filter.
            assert exc.errno in (errno.ENOSYS, errno.EINVAL), exc
            seccomp = ctypes.CDLL('libseccomp.so.2')
            resolve = seccomp.seccomp_syscall_resolve_name
            resolve.argtypes = [ctypes.c_char_p]
            resolve.restype = ctypes.c_int
            number = resolve(b'renameat2')
            assert number >= 0
            libc = ctypes.CDLL(None, use_errno=True)
            syscall = libc.syscall
            syscall.restype = ctypes.c_long
            result = syscall(ctypes.c_long(number), ctypes.c_int(filtered_fd),
                             ctypes.c_char_p(b'absent'), ctypes.c_int(filtered_fd),
                             ctypes.c_char_p(b'target'), ctypes.c_uint(1))
            assert result == -1 and ctypes.get_errno() == errno.ENOSYS
    else:
        raise AssertionError('actual kernel refusal was accepted')
finally:
    sys.setprofile(None)
assert filtered_fd >= 0
# Publication closes its descriptor after refusal; reserve that number so
# coverage and subsequent reads cannot reuse a descriptor affected by the filter.
os.dup2(keeper, filtered_fd)
if case == 'write-eio':
    entries = list(store.directory.iterdir())
    assert len(entries) == 1
    assert entries[0].stat().st_size == 0
    try:
        store.scan()
    except PermissionError as exc:
        assert 'custody' in str(exc), str(exc)
    else:
        raise AssertionError('incomplete digest object was accepted')
else:
    assert store.scan() == {}
    assert list(store.directory.iterdir()) == []
"""


def test_real_publication_write_refusal_keeps_evidence_fail_closed(tmp_path: Path) -> None:
    """Actual write EIO preserves refusal and inert residue.

    Rename ENOSYS is exercised by the baseline publication syscall test.

    These fd-scoped child-local seccomp refusals prove error handling and
    cleanup, not a failing physical device or execution on an obsolete kernel.
    The bounded child retains filtered descriptor numbers until exit.
    """
    test_directory = Path(__file__).parent
    source = test_directory.parent / "src"
    completed = subprocess.run(
        [sys.executable, "-c", _CHILD, "write-eio", str(tmp_path)],
        env={**os.environ, "PYTHONPATH": os.pathsep.join((str(source), str(test_directory)))},
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
