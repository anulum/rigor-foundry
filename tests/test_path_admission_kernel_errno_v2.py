# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real registered-root kernel errno tests
"""Keep kernel EIO and ENOMEM distinct from unavailable registry roots."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_CHILD = """
import errno
import os
import sys
from pathlib import Path
from types import FrameType
from kernel_errno_support_v2 import refuse_syscall
from rigor_foundry.tier0_builtin.linux_openat2_v2 import open_child_directory_nofollow_v2
from rigor_foundry.tier0_builtin.path_admission_v2 import (
    PinnedDirectoryV2, PinnedPathScopeV2, RegisteredRootUnavailableV2,
    canonicalize_atomic_path_v2,
)

error = getattr(errno, sys.argv[1])
mono = Path(sys.argv[2]) / 'mono'
group = mono / 'group'
group.mkdir(parents=True)
broken = group / 'other-project'
broken.mkdir()
scope = PinnedPathScopeV2(
    PinnedDirectoryV2(str(mono)), PinnedDirectoryV2(str(group)), None,
    (PinnedDirectoryV2(str(broken)),), (PinnedDirectoryV2(str(group)),),
)
filtered_fd = -1
keeper = os.open('/dev/null', os.O_RDONLY)

def observe(frame: FrameType, event: str, arg: object) -> None:
    '''Install at the actual public descent used for a registered-root lookup.'''
    global filtered_fd
    if (filtered_fd < 0 and event == 'call'
            and frame.f_code is open_child_directory_nofollow_v2.__code__
            and frame.f_back is not None
            and frame.f_back.f_code.co_name == '_current_root_identity'):
        descriptor = frame.f_locals['parent_fd']
        assert type(descriptor) is int
        filtered_fd = descriptor
        refuse_syscall('openat2', error, descriptor)

sys.setprofile(observe)
try:
    try:
        canonicalize_atomic_path_v2(str(group / 'direct.txt'), scope)
    except OSError as exc:
        assert exc.errno == error, (exc.errno, error)
        assert not isinstance(exc, RegisteredRootUnavailableV2)
    else:
        raise AssertionError('registered-root kernel failure was accepted')
finally:
    sys.setprofile(None)
assert filtered_fd >= 0
# Admission closed the failed lookup fd. Reserve that number until child exit.
os.dup2(keeper, filtered_fd)
assert not (group / 'direct.txt').exists()
"""


@pytest.mark.parametrize("error_name", ["EIO", "ENOMEM"])
def test_real_host_errors_are_not_relabelled_as_broken_roots(
    tmp_path: Path, error_name: str
) -> None:
    """Actual registered-root openat2 errors retain their original host errno.

    A child-local fd-scoped seccomp filter produces controlled kernel errors,
    avoiding physical device failure or unsafe global memory pressure. Timing
    observation leaves the public path walker and syscall results unpatched.
    """
    test_directory = Path(__file__).parent
    source = test_directory.parent / "src"
    completed = subprocess.run(
        [sys.executable, "-c", _CHILD, error_name, str(tmp_path)],
        env={**os.environ, "PYTHONPATH": os.pathsep.join((str(source), str(test_directory)))},
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
