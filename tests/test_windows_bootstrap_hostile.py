# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native Windows bootstrap created-output regressions
"""Change a just-created bootstrap output from another process and require refusal.

The real ``write_new_file_at`` runs unchanged and its real identity is returned;
only afterwards a separate same-user process adds a hard link to, or replaces,
the created file. No native result is fabricated.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

from rigor_foundry import windows_bootstrap
from rigor_foundry.bootstrap import bootstrap_repository
from rigor_foundry.git_provenance import GitRunner
from rigor_foundry.windows_file_io import write_new_file_at
from rigor_foundry.windows_handles import WindowsDirectory

_ATTACKER = r"""
import ctypes, os, sys
from ctypes import wintypes as w
k = ctypes.WinDLL("kernel32", use_last_error=True)
k.CreateHardLinkW.argtypes = [w.LPCWSTR, w.LPCWSTR, w.LPVOID]
k.CreateHardLinkW.restype = w.BOOL
import time
mode, path, outside = sys.argv[1], sys.argv[2], sys.argv[3]
# A just-written file can be briefly open by an on-access scanner; retry only sharing violations.
deadline = time.monotonic() + 5
while True:
    if mode == "link":
        ok = k.CreateHardLinkW(os.path.join(outside, "extra-link"), path, None)
        code = 0 if ok else ctypes.get_last_error()
    else:
        try:
            os.replace(path, os.path.join(outside, "moved"))
            code = 0
        except PermissionError as error:
            code = getattr(error, "winerror", 5)
    if code != 32 or time.monotonic() >= deadline:
        break
    time.sleep(0.05)
if code == 0 and mode == "replace":
    with open(path, "xb") as replacement:
        replacement.write(b"{}\n")
print("ok" if code == 0 else code)
"""


@unittest.skipUnless(sys.platform == "win32", "requires native Windows NTFS and Git")
class WindowsBootstrapCreatedOutputTests(unittest.TestCase):
    """Bind each created output to its exact native object until bootstrap returns."""

    def setUp(self) -> None:
        """Create a real Git worktree plus an unretained same-volume attacker directory."""
        temporary = tempfile.TemporaryDirectory(prefix="rigor-bootstrap-hostile-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        for name in ("src", "tests", ".rigor"):
            (self.root / name).mkdir()
        (self.root / ".gitignore").write_text(".rigor/\n", encoding="utf-8")
        GitRunner().run(self.root, "init", "--initial-branch=main")
        # Same volume, but not retained by bootstrap: rename/link targets in a retained
        # directory are refused by its sharing mode, so the attacker works from outside.
        outside = tempfile.TemporaryDirectory(prefix="rigor-bootstrap-outside-")
        self.addCleanup(outside.cleanup)
        self.outside = Path(outside.name).resolve()

    def _attack_after_first_write(self, mode: str) -> Callable[..., tuple[int, int]]:
        """Wrap the real writer; after the first real write, change that output externally."""
        real = write_new_file_at
        calls: list[str] = []

        def writer(
            parent: WindowsDirectory, name: str, text: str, *, private: bool = True
        ) -> tuple[int, int]:
            identity = real(parent, name, text, private=private)
            if not calls:
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-B",
                        "-c",
                        _ATTACKER,
                        mode,
                        str(self.root / name),
                        str(self.outside),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                self.assertEqual(completed.stdout.strip(), "ok", completed.stderr)
            calls.append(name)
            return identity

        return writer

    def _bootstrap(self) -> None:
        """Invoke the supported public bootstrap operation on the real worktree."""
        bootstrap_repository(
            self.root,
            policy_path=Path("rigor-foundry-policy.json"),
            todo_path=Path(".rigor/TODO.md"),
            review_ledger_path=Path(".rigor/reviews.json"),
            source_roots=(Path("src"),),
            test_roots=(Path("tests"),),
        )

    def test_extra_hard_link_to_created_policy_is_refused(self) -> None:
        """A second name for the created object breaks the single-link ownership contract."""
        with (
            patch.object(
                windows_bootstrap, "write_new_file_at", self._attack_after_first_write("link")
            ),
            self.assertRaisesRegex(RuntimeError, "created bootstrap path identity changed"),
        ):
            self._bootstrap()
        self.assertFalse((self.root / ".rigor/reviews.json").exists())

    def test_replaced_created_policy_is_refused(self) -> None:
        """A different object under the created name is never adopted as bootstrap output."""
        with (
            patch.object(
                windows_bootstrap, "write_new_file_at", self._attack_after_first_write("replace")
            ),
            self.assertRaisesRegex(RuntimeError, "created bootstrap path identity changed"),
        ):
            self._bootstrap()
        self.assertFalse((self.root / ".rigor/reviews.json").exists())
