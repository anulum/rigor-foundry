# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real OS registered-root failure tests
"""Exercise EACCES and EMFILE through public path admission in child processes."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

_CHILD = """
import errno
import os
import resource
import sys
from rigor_foundry.tier0_builtin.path_admission_v2 import (
    PinnedDirectoryV2,
    PinnedPathScopeV2,
    RegisteredRootUnavailableV2,
    canonicalize_atomic_path_v2,
)

case, mono, group, broken = sys.argv[1:]
scope = PinnedPathScopeV2(
    PinnedDirectoryV2(mono),
    PinnedDirectoryV2(group),
    None,
    (PinnedDirectoryV2(broken),),
    (PinnedDirectoryV2(group),),
)
target = os.path.join(group, "docs", "new.txt")
if case == "access":
    if os.geteuid() == 0:
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)
    try:
        canonicalize_atomic_path_v2(target, scope)
    except RegisteredRootUnavailableV2 as exc:
        assert exc.root_path == broken
        assert broken not in str(exc)
    else:
        raise AssertionError("inaccessible registered root was admitted")
else:
    used = len(os.listdir("/proc/self/fd")) - 1
    _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (used + 1, hard))
    try:
        canonicalize_atomic_path_v2(target, scope)
    except OSError as exc:
        assert exc.errno == errno.EMFILE, repr(exc)
        assert not isinstance(exc, RegisteredRootUnavailableV2)
    else:
        raise AssertionError("exhausted descriptor table was admitted")
"""


def _run_child(case: str, mono: Path, group: Path, broken: Path) -> None:
    """Run a real low-privilege or descriptor-exhausted admission process."""
    source = Path(__file__).resolve().parents[1] / "src"
    completed = subprocess.run(
        [sys.executable, "-c", _CHILD, case, str(mono), str(group), str(broken)],
        env={**os.environ, "PYTHONPATH": str(source)},
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr


def test_real_unsearchable_registered_root_reports_operator_identity() -> None:
    """No-follow descent reports real EACCES without leaking a root path."""
    with tempfile.TemporaryDirectory(prefix="rigor-admission-") as directory:
        mono = Path(directory) / "mono"
        group = mono / "group"
        (group / "docs").mkdir(parents=True)
        private = group / "private"
        broken = private / "other-project"
        broken.mkdir(parents=True)
        for path in (Path(directory), mono, group, group / "docs"):
            path.chmod(0o755)
        private.chmod(0)
        try:
            _run_child("access", mono, group, broken)
        finally:
            private.chmod(0o755)


def test_real_file_descriptor_exhaustion_keeps_host_error() -> None:
    """RLIMIT_NOFILE causes an actual EMFILE, never a broken-root label."""
    with tempfile.TemporaryDirectory(prefix="rigor-admission-") as directory:
        mono = Path(directory) / "mono"
        group = mono / "group"
        (group / "docs").mkdir(parents=True)
        broken = group / "other-project"
        broken.mkdir()
        _run_child("descriptors", mono, group, broken)
