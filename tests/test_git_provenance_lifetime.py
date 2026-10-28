# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Git executable pathname and descriptor lifetime tests
"""Schedule real file changes during public Git executable provenance capture."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
from project_registry_syscall_scheduler import SyscallStop, run_traced, write_trace


@pytest.mark.parametrize(
    ("boundary", "mutation", "message", "entry"),
    [
        ("hash-read", "none", "", "script"),
        ("hash-read", "none", "", "callable"),
        ("validate-lstat", "unlink", "Git executable path is unavailable", "script"),
        ("validate-resolve", "unlink", "Git executable path cannot be resolved", "script"),
        ("validate-resolve", "symlink", "Git executable path must not contain symlinks", "script"),
        ("snapshot-open", "fifo", "trusted Git executable is not a regular file", "script"),
        ("hash-read", "append", "trusted Git executable changed while hashing", "script"),
        ("hash-read", "replace", "trusted Git executable changed while hashing", "script"),
        ("snapshot-path", "unlink", "trusted Git executable disappeared while hashing", "script"),
    ],
)
def test_constructor_observes_actual_executable_lifetime(
    tmp_path: Path, boundary: str, mutation: str, message: str, entry: str
) -> None:
    """Reject changed files before execution and settle every retained descriptor.

    The worker calls the public constructor. The supervisor changes only owned
    fixture directory entries or bytes at real Linux x86-64 syscall stops;
    syscall results, memory, clocks and production functions remain unchanged.
    The unchanged control invokes the installed Git through the same script.
    """
    tools = tmp_path / "tools"
    tools.mkdir()
    executable = tools / "git"
    invoked = tmp_path / "invoked"
    script = f'#!/bin/sh\nprintf invoked > {shlex.quote(str(invoked))}\nexec /usr/bin/git "$@"\n'
    executable.write_text(script, encoding="utf-8")
    executable.chmod(0o755)
    alternate = tools / "alternate"
    alternate.write_text(script, encoding="utf-8")
    alternate.chmod(0o755)
    sentinel = tmp_path / "preserved.bin"
    sentinel.write_bytes(b"unrelated owner bytes")
    scheduled: list[SyscallStop] = []
    pathname_stats = 0
    read_seen = False

    def schedule(stop: SyscallStop) -> bool:
        """Change the actual fixture once at its declared operation boundary."""
        nonlocal pathname_stats, read_seen
        if stop.path != str(executable) or not stop.entering:
            return False
        if stop.number == 262:
            pathname_stats += 1
        if stop.number == 0:
            read_seen = True
        reached = (
            (boundary == "validate-lstat" and stop.number == 262 and pathname_stats == 1)
            or (boundary == "validate-resolve" and stop.number == 262 and pathname_stats == 2)
            or (boundary == "snapshot-open" and stop.number == 257)
            or (boundary == "hash-read" and stop.number == 0)
            or (boundary == "snapshot-path" and stop.number == 262 and read_seen)
        )
        if scheduled or not reached:
            return False
        scheduled.append(stop)
        if mutation == "unlink":
            executable.unlink()
        elif mutation == "symlink":
            executable.unlink()
            executable.symlink_to(alternate)
        elif mutation == "fifo":
            executable.unlink()
            os.mkfifo(executable, 0o700)
        elif mutation == "append":
            with executable.open("ab") as stream:
                stream.write(b"# changed during the descriptor read\n")
        elif mutation == "replace":
            os.replace(alternate, executable)
        return False

    worker = Path(__file__).with_name("git_provenance_lifetime_worker.py")
    if entry == "script":
        command = [sys.executable, "-B", str(worker), str(executable)]
    else:
        command = [
            sys.executable,
            "-B",
            "-c",
            "import sys; sys.path.insert(0, sys.argv[2]); "
            "from git_provenance_lifetime_worker import main; main()",
            str(executable),
            str(worker.parent),
        ]
    observed = run_traced(command, schedule, timeout=20)
    write_trace(tmp_path / "executable-lifetime-trace.json", observed)
    assert observed.returncode == 0, observed.stderr
    assert len(scheduled) == 1, "the declared real syscall boundary was not reached"
    with pytest.raises(ChildProcessError):
        os.waitpid(observed.pid, os.WNOHANG)
    outcome = json.loads(observed.stdout)
    assert outcome["descriptors_restored"] is True
    assert sentinel.read_bytes() == b"unrelated owner bytes"
    if mutation == "none":
        assert outcome["accepted"] is True
        installed = subprocess.run(
            ["/usr/bin/git", "--version"], capture_output=True, check=True, timeout=5
        )
        assert installed.stdout == f"git version {outcome['version']}\n".encode("ascii")
        assert invoked.read_text(encoding="utf-8") == "invoked"
        assert executable.read_text(encoding="utf-8") == script
    else:
        assert outcome["accepted"] is False
        assert message in outcome["error"]
        assert not invoked.exists()
