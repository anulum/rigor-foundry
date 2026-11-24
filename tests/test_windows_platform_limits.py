# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — POSIX-only guards and Windows Git limits on actual Windows
"""Call the POSIX-only opener and the Windows Git branch on an actual Windows host.

The public POSIX descriptor opener refuses a platform without no-follow directory
descriptors before opening anything. On Windows that refusal is the real
behaviour, and every POSIX opener shares its guard. The Windows Git branch of the
trusted runner is exercised with the actually installed Git: a real failing
command and a real command that outlives its limit.
"""

from __future__ import annotations

import os
import shutil
import socket
import stat
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from rigor_foundry.git_provenance import GitRunner
from rigor_foundry.stable_reads import open_directory_no_follow


def _remove_tree(path: Path, *, patience_seconds: float = 10.0) -> None:
    """Remove a test-owned tree, retrying only a transient sharing violation.

    A just-stopped native process or a file scanner can hold a handle briefly after the
    test's last use, so Windows reports error 32. Any other error, or a violation that
    lasts past ``patience_seconds``, still fails the test.
    """
    deadline = time.monotonic() + patience_seconds
    while True:
        try:
            shutil.rmtree(path)
            return
        except PermissionError as error:
            if getattr(error, "winerror", None) != 32 or time.monotonic() >= deadline:
                raise
            time.sleep(0.25)


@unittest.skipUnless(sys.platform == "win32", "requires actual Windows")
class WindowsPlatformLimitTests(unittest.TestCase):
    """Exercise refusals that only a platform without POSIX descriptors reaches."""

    def setUp(self) -> None:
        """Allocate one owned temporary directory."""
        self.root = Path(tempfile.mkdtemp(prefix="rigor-platform-limits-")).resolve()
        self.addCleanup(_remove_tree, self.root)

    def test_posix_descriptor_opener_refuses_before_opening(self) -> None:
        """The public opener names the missing capability and leaves the directory alone."""
        before = sorted(self.root.iterdir())
        with self.assertRaisesRegex(RuntimeError, "platform lacks no-follow descriptor traversal"):
            open_directory_no_follow(self.root)
        self.assertEqual(sorted(self.root.iterdir()), before)

    def test_windows_git_branch_reports_a_real_failing_command(self) -> None:
        """A real non-zero Git exit is refused when the caller requires success."""
        runner = GitRunner()
        runner.run(self.root, "init", "--initial-branch=main")
        with self.assertRaisesRegex(
            RuntimeError, r"trusted Git command failed with exit status 128"
        ):
            runner.run(self.root, "rev-parse", "--verify", "refs/heads/rigor-absent")
        unchecked = runner.run(
            self.root, "rev-parse", "--verify", "refs/heads/rigor-absent", check=False
        )
        self.assertEqual(unchecked.returncode, 128)

    def test_windows_git_branch_reports_a_real_command_beyond_its_limit(self) -> None:
        """A real Git daemon that keeps serving is stopped at the one-second limit."""
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        with self.assertRaisesRegex(
            RuntimeError, r"trusted Git command exceeded the 1-second limit"
        ) as failure:
            GitRunner().run(
                self.root,
                "daemon",
                "--listen=127.0.0.1",
                f"--port={port}",
                f"--base-path={self.root}",
                timeout_seconds=1,
            )
        self.assertIsInstance(failure.exception.__cause__, TimeoutError)


@unittest.skipUnless(sys.platform == "win32", "requires actual Windows")
class WindowsTreeRemovalTests(unittest.TestCase):
    """Prove the cleanup helper waits out only a real, ending sharing violation."""

    def setUp(self) -> None:
        """Allocate one owned directory holding one file."""
        self.root = Path(tempfile.mkdtemp(prefix="rigor-tree-removal-"))
        self.held = self.root / "held.bin"
        self.held.write_bytes(b"held")

    def tearDown(self) -> None:
        """Remove whatever a refusal case left behind."""
        if self.held.exists():
            os.chmod(self.held, stat.S_IWRITE | stat.S_IREAD)
        shutil.rmtree(self.root, ignore_errors=True)

    def test_a_sharing_violation_that_ends_is_waited_out(self) -> None:
        """An open handle without delete sharing blocks removal until it is closed."""
        handle = self.held.open("rb")
        release = threading.Timer(0.5, handle.close)
        release.start()
        try:
            _remove_tree(self.root)
        finally:
            release.cancel()
            handle.close()
        self.assertFalse(self.root.exists())

    def test_a_lasting_sharing_violation_still_fails(self) -> None:
        """A violation that outlasts the patience is raised with its own error code."""
        with self.held.open("rb"), self.assertRaises(PermissionError) as failure:
            _remove_tree(self.root, patience_seconds=0.5)
        self.assertEqual(getattr(failure.exception, "winerror", None), 32)
        self.assertTrue(self.root.exists())

    def test_another_permission_error_is_not_retried(self) -> None:
        """A read-only file's access denial is raised at once, not waited on."""
        os.chmod(self.held, stat.S_IREAD)
        started = time.monotonic()
        with self.assertRaises(PermissionError) as failure:
            _remove_tree(self.root)
        self.assertEqual(getattr(failure.exception, "winerror", None), 5)
        self.assertLess(time.monotonic() - started, 5)
