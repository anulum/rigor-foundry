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

import socket
import sys
import tempfile
import unittest
from pathlib import Path

from rigor_foundry.git_provenance import GitRunner
from rigor_foundry.stable_reads import open_directory_no_follow


@unittest.skipUnless(sys.platform == "win32", "requires actual Windows")
class WindowsPlatformLimitTests(unittest.TestCase):
    """Exercise refusals that only a platform without POSIX descriptors reaches."""

    def setUp(self) -> None:
        """Allocate one owned temporary directory."""
        temporary = tempfile.TemporaryDirectory(prefix="rigor-platform-limits-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

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
