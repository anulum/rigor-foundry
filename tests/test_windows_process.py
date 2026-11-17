# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — native public process execution contracts
"""Exercise explicit public command validation and actual bounded native execution."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import TypedDict

from rigor_foundry.windows_handles import WindowsDirectory
from rigor_foundry.windows_process import run_windows_process


class NativeCommandOptions(TypedDict, total=False):
    """Explicit typed public arguments used by the invalid-input cases."""

    executable: Path
    arguments: tuple[str, ...]
    image_handle: int
    environment: dict[str, str]
    cwd: Path
    timeout_seconds: int
    output_limit: int


class NativeCommandArgumentTests(unittest.TestCase):
    """Reject malformed explicit commands before opening any native resources."""

    def test_invalid_command_inputs_are_rejected(self) -> None:
        """Check each independent public argument constraint with an explicitly invalid input."""
        root = Path.cwd()
        executable = root / "unused.exe"
        cases: tuple[NativeCommandOptions, ...] = (
            {"executable": Path("relative.exe")},
            {"cwd": Path("relative-directory")},
            {"timeout_seconds": True},
            {"timeout_seconds": 0},
            {"output_limit": True},
            {"output_limit": 0},
            {"arguments": ("contains\0nul",)},
            {"environment": {"": "value"}},
            {"environment": {"invalid=name": "value"}},
            {"environment": {"name": "contains\0nul"}},
            {"environment": {"Name": "one", "NAME": "two"}},
        )
        for changes in cases:
            options: NativeCommandOptions = {
                "executable": executable,
                "arguments": (),
                "image_handle": 0,
                "environment": {},
                "cwd": root,
                "timeout_seconds": 1,
                "output_limit": 1,
            }
            options.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                run_windows_process(**options)


@unittest.skipUnless(
    sys.platform == "win32", "requires actual Windows native process and job APIs"
)
class WindowsProcessTests(unittest.TestCase):
    """Pin the actual installed Python image while exercising real child process outcomes."""

    def setUp(self) -> None:
        """Retain the actual interpreter image and a private test working directory."""
        temporary = tempfile.TemporaryDirectory(prefix="rigor-native-process-contract-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.python = Path(sys.base_prefix) / "python.exe"
        self.assertTrue(self.python.is_file())
        self.environment = dict(os.environ)
        directory = WindowsDirectory(self.python.parent)
        self.addCleanup(directory.close)
        self.image = directory.open_file(self.python.name)
        self.addCleanup(self.image.close)

    def run_python(
        self, source: str, *, timeout: int = 10, limit: int = 4096
    ) -> tuple[int, bytes, bytes]:
        """Execute actual Python code under the public pinned-image runner."""
        return run_windows_process(
            self.python,
            ("-I", "-c", source),
            image_handle=self.image.handle,
            environment=self.environment,
            cwd=self.root,
            timeout_seconds=timeout,
            output_limit=limit,
        )

    def test_actual_exit_status_and_independent_streams(self) -> None:
        """Compare actual nonzero status and raw streams with a standard subprocess reference."""
        source = "import sys;sys.stdout.buffer.write(b'out\\x00data');sys.stderr.buffer.write(b'err\\r\\n');sys.exit(7)"
        reference = subprocess.run(
            [str(self.python), "-I", "-c", source],
            cwd=self.root,
            env=self.environment,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(
            self.run_python(source), (reference.returncode, reference.stdout, reference.stderr)
        )
        self.assertEqual(reference.returncode, 7)

    def test_empty_output_and_literal_arguments(self) -> None:
        """Return empty streams and preserve literal CRT argv bytes through the same native owner."""
        self.assertEqual(self.run_python("pass"), (0, b"", b""))
        values = ("with spaces", 'contains"quote', "trailing\\", "")
        source = "import sys;sys.stdout.buffer.write(repr(sys.argv[1:]).encode('utf-8'))"
        result = run_windows_process(
            self.python,
            ("-I", "-c", source, *values),
            image_handle=self.image.handle,
            environment=self.environment,
            cwd=self.root,
            timeout_seconds=10,
            output_limit=4096,
        )
        self.assertEqual(result, (0, repr(list(values)).encode(), b""))

    def test_actual_output_bound_and_deadline(self) -> None:
        """Bound actual child output and elapsed execution without substituting clock or pipe results."""
        with self.assertRaisesRegex(RuntimeError, "output limit"):
            self.run_python("import sys;sys.stdout.buffer.write(b'x'*4096)", limit=32)
        with self.assertRaisesRegex(TimeoutError, "deadline"):
            self.run_python("import time;time.sleep(10)", timeout=1)
        self.assertEqual(self.run_python("pass"), (0, b"", b""))

    def test_missing_working_directory_preserves_actual_launch_failure(self) -> None:
        """Propagate the genuine CreateProcessW failure and release all partially prepared resources."""
        with self.assertRaises(OSError):
            run_windows_process(
                self.python,
                ("-I", "-c", "pass"),
                image_handle=self.image.handle,
                environment=self.environment,
                cwd=self.root / "missing",
                timeout_seconds=10,
                output_limit=4096,
            )
        self.assertEqual(self.run_python("pass"), (0, b"", b""))

    def test_invalid_caller_handle_preserves_actual_os_error(self) -> None:
        """Keep the genuine kernel invalid-handle result for an explicitly invalid public argument."""
        with self.assertRaises(OSError) as failure:
            run_windows_process(
                self.python,
                (),
                image_handle=-3,
                environment=self.environment,
                cwd=self.root,
                timeout_seconds=10,
                output_limit=4096,
            )
        self.assertEqual(getattr(failure.exception, "winerror", None), 6)


if __name__ == "__main__":
    unittest.main()
