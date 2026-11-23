# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native identity changes between paired observations
"""Change real NTFS identities between the native owners' paired observations.

Each test wraps the genuine function that makes one observation so that it first
or afterwards changes the real file or image, and then asserts the exact refusal.
No product seam is added and no observation result is fabricated.
"""

from __future__ import annotations

import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rigor_foundry import windows_bootstrap, windows_git
from rigor_foundry.bootstrap import bootstrap_repository
from rigor_foundry.git_provenance import GitRunner
from rigor_foundry.windows_file_io import write_new_file_at
from rigor_foundry.windows_git import run_windows_git, snapshot_windows_git
from rigor_foundry.windows_handles import WindowsDirectory, WindowsFile, WindowsFileIdentity
from rigor_foundry.windows_process import run_windows_process


@unittest.skipUnless(sys.platform == "win32", "requires actual Windows NTFS")
class WindowsIdentityRaceTests(unittest.TestCase):
    """Refuse a native image or created file whose real identity changed in between."""

    def setUp(self) -> None:
        """Copy one real system image into an owned temporary directory."""
        temporary = tempfile.TemporaryDirectory(prefix="rigor-identity-races-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.system = Path(os.environ["SYSTEMROOT"]) / "System32"
        self.image = self.root / "tool.exe"
        shutil.copyfile(self.system / "whoami.exe", self.image)
        self.addCleanup(os.chmod, self.image, stat.S_IREAD | stat.S_IWRITE)
        self.environment = {"SystemRoot": os.environ["SYSTEMROOT"], "PATH": str(self.system)}

    def test_snapshot_refuses_an_image_whose_attributes_changed_while_hashing(self) -> None:
        """Mark the real image read-only after the snapshot's first identity read.

        Opening the image reads its identity once; the snapshot then reads it before
        and after hashing.
        """
        identity = WindowsFile.identity
        calls = 0

        def mark_read_only_after_first_read(owner: WindowsFile) -> WindowsFileIdentity:
            """Read the genuine identity, then change the real attributes after the second."""
            nonlocal calls
            calls += 1
            observed = identity(owner)
            if calls == 2:
                os.chmod(self.image, stat.S_IREAD)
            return observed

        with (
            patch.object(WindowsFile, "identity", mark_read_only_after_first_read),
            self.assertRaisesRegex(RuntimeError, "trusted Git executable changed while hashing"),
        ):
            snapshot_windows_git(self.image)
        self.assertEqual(calls, 3)

    def test_execution_refuses_an_image_whose_attributes_changed_while_running(self) -> None:
        """Mark the real image read-only after the genuine pinned process has finished."""
        expected = snapshot_windows_git(self.image)
        run = run_windows_process
        runs = 0

        def mark_read_only_after_run(
            executable: Path,
            arguments: tuple[str, ...],
            *,
            image_handle: int,
            environment: dict[str, str],
            cwd: Path,
            timeout_seconds: int,
            output_limit: int,
        ) -> tuple[int, bytes, bytes]:
            """Run the genuine pinned process, then change the real image's attributes."""
            nonlocal runs
            runs += 1
            result = run(
                executable,
                arguments,
                image_handle=image_handle,
                environment=environment,
                cwd=cwd,
                timeout_seconds=timeout_seconds,
                output_limit=output_limit,
            )
            os.chmod(self.image, stat.S_IREAD)
            return result

        with (
            patch.object(windows_git, "run_windows_process", mark_read_only_after_run),
            self.assertRaisesRegex(
                RuntimeError, "trusted Git executable changed during execution"
            ),
        ):
            run_windows_git(
                self.image,
                (),
                expected_snapshot=expected,
                environment=self.environment,
                cwd=self.root,
                timeout_seconds=20,
                output_limit=65536,
            )
        self.assertEqual(runs, 1)

    def test_ordinary_process_refuses_a_script_image_before_resume(self) -> None:
        """A retained .cmd image starts the command interpreter, which is refused."""
        script = self.root / "probe.cmd"
        script.write_text("@echo unexpected\r\n", encoding="ascii")
        with (
            WindowsDirectory(self.root) as directory,
            directory.open_file(script.name) as image,
            self.assertRaisesRegex(
                RuntimeError, "created native image differs from the retained executable"
            ),
        ):
            run_windows_process(
                script,
                (),
                image_handle=image.handle,
                environment=self.environment,
                cwd=self.root,
                timeout_seconds=20,
                output_limit=4096,
            )

    def test_bootstrap_refuses_a_created_file_that_gained_a_link(self) -> None:
        """A second real link to the created policy is found by the post-creation check."""
        repository = self.root / "repository"
        for name in ("src", "tests", ".rigor"):
            (repository / name).mkdir(parents=True)
        (repository / ".gitignore").write_text(".rigor/\n", encoding="utf-8")
        GitRunner().run(repository, "init", "--initial-branch=main")
        write = write_new_file_at
        second = repository / "policy-second-link.json"

        def link_after_policy(
            parent: WindowsDirectory, name: str, text: str, *, private: bool = True
        ) -> tuple[int, int]:
            """Create the genuine file, then add a real second link to the policy."""
            created = write(parent, name, text, private=private)
            if name == "rigor-foundry-policy.json":
                os.link(parent.path / name, second)
            return created

        with (
            patch.object(windows_bootstrap, "write_new_file_at", link_after_policy),
            self.assertRaisesRegex(RuntimeError, "created bootstrap path identity changed"),
        ):
            bootstrap_repository(
                repository,
                policy_path=Path("rigor-foundry-policy.json"),
                todo_path=Path(".rigor/TODO.md"),
                review_ledger_path=Path(".rigor/reviews.json"),
                source_roots=(Path("src"),),
                test_roots=(Path("tests"),),
            )
        self.assertEqual(os.stat(second).st_nlink, 2)
