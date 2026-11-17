# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native Git image provenance contracts
"""Exercise public native snapshots and bounded execution of the actually installed Git."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from rigor_foundry.windows_git import run_windows_git, snapshot_windows_git


@unittest.skipUnless(sys.platform == "win32", "requires actual Windows NTFS and installed Git")
class WindowsGitTests(unittest.TestCase):
    """Bind actual Git image bytes, real execution and explicit caller provenance."""

    def setUp(self) -> None:
        """Select the real installed Git and allocate only an owned temporary workdir."""
        self.git = Path(os.environ["PROGRAMFILES"]) / "Git/bin/git.exe"
        self.assertTrue(self.git.is_file())
        temporary = tempfile.TemporaryDirectory(prefix="rigor-native-git-contract-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def test_snapshot_binds_actual_git_bytes_and_native_identity(self) -> None:
        """Compare the actual retained image snapshot with independently read image bytes."""
        snapshot = snapshot_windows_git(self.git)
        self.assertGreaterEqual(snapshot[0], 0)
        self.assertGreaterEqual(snapshot[1], 0)
        self.assertEqual(snapshot[3], 1)
        self.assertEqual(snapshot[4], self.git.stat().st_size)
        self.assertGreater(snapshot[5], 0)
        self.assertGreater(snapshot[6], 0)
        self.assertEqual(snapshot[7], hashlib.sha256(self.git.read_bytes()).hexdigest())
        self.assertEqual(snapshot_windows_git(self.git), snapshot)

    def test_execution_preserves_real_git_status_and_both_output_streams(self) -> None:
        """Execute actual installed Git through the native owner and compare public results."""
        snapshot = snapshot_windows_git(self.git)
        environment = dict(os.environ)
        reference = subprocess.run(
            [str(self.git), "--version"],
            cwd=self.root,
            env=environment,
            capture_output=True,
            check=True,
            timeout=10,
        )
        result = run_windows_git(
            self.git,
            ("--version",),
            expected_snapshot=snapshot,
            environment=environment,
            cwd=self.root,
            timeout_seconds=10,
            output_limit=4096,
        )
        self.assertEqual(result.returncode, reference.returncode)
        self.assertEqual(result.stdout, reference.stdout)
        self.assertEqual(result.stderr, reference.stderr)
        self.assertTrue(result.stdout.startswith(b"git version "))

    def test_mismatched_caller_snapshot_is_refused_before_execution(self) -> None:
        """Refuse an explicitly incorrect expected digest without inventing native results."""
        snapshot = snapshot_windows_git(self.git)
        incorrect = (*snapshot[:7], "0" * 64)
        with self.assertRaisesRegex(RuntimeError, "after provenance capture"):
            run_windows_git(
                self.git,
                ("--version",),
                expected_snapshot=incorrect,
                environment=dict(os.environ),
                cwd=self.root,
                timeout_seconds=10,
                output_limit=4096,
            )

    def test_snapshot_refuses_two_real_links_to_an_owned_copy(self) -> None:
        """Check the declared single-link image contract on static owned filesystem inputs."""
        copied = self.root / "owned-git-image.exe"
        linked = self.root / "second-owned-name.exe"
        shutil.copyfile(self.git, copied)
        os.link(copied, linked)
        with self.assertRaisesRegex(RuntimeError, "exactly one hard link"):
            snapshot_windows_git(copied)
        self.assertEqual(copied.read_bytes(), self.git.read_bytes())
        self.assertEqual(linked.read_bytes(), copied.read_bytes())


if __name__ == "__main__":
    unittest.main()
