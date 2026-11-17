# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Actual complete-file coverage gate contracts
"""Generate real branch databases and exercise the public coverage gate and CLI."""

from __future__ import annotations

import hashlib
import os
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import coverage

from tools.check_full_file_coverage import check_full_files, main


class FullFileCoverageTests(unittest.TestCase):
    """Distinguish full execution, branch-only gaps and statement gaps using real producers."""

    def setUp(self) -> None:
        """Allocate a private program, driver and genuine Coverage.py data destination."""
        temporary = tempfile.TemporaryDirectory(prefix="rigor-full-file-gate-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "branch_example.py"
        self.driver = self.root / "driver.py"
        self.data = self.root / "actual.sqlite"

    def produce(self, source: str, calls: str, *, branches: bool = True) -> None:
        """Execute an authored generic program in a real finite Python child, never native evidence."""
        self.source.write_text(source, encoding="utf-8")
        self.driver.write_text("from branch_example import choose\n" + calls, encoding="utf-8")
        config = self.root / "coverage.ini"
        config.write_text("[run]\nbranch = " + str(branches).lower() + "\n", encoding="utf-8")
        environment = dict(os.environ)
        environment.pop("COVERAGE_PROCESS_START", None)
        environment.pop("COVERAGE_FILE", None)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "coverage",
                "run",
                "--rcfile",
                str(config),
                "--data-file",
                str(self.data),
                str(self.driver),
            ],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.data.is_file())

    def complete_program(self) -> None:
        """Exercise both real outcomes of one ordinary branch before checking it."""
        self.produce(
            "def choose(flag):\n    if flag:\n        return 'yes'\n    return 'no'\n",
            "assert choose(True) == 'yes'\nassert choose(False) == 'no'\n",
        )

    def test_full_execution_passes_without_mutating_source_or_raw_data(self) -> None:
        """Accept complete real branch execution and preserve both measured inputs byte-for-byte."""
        self.complete_program()
        before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in [self.source, self.data]}
        check_full_files(self.data, [self.source])
        self.assertEqual({p: hashlib.sha256(p.read_bytes()).hexdigest() for p in before}, before)

    def test_statement_gap_is_refused(self) -> None:
        """Reject a genuine unexecuted return rather than accepting a high aggregate percentage."""
        self.produce(
            "def choose(flag):\n    if flag:\n        return 'yes'\n    return 'no'\n",
            "assert choose(True) == 'yes'\n",
        )
        with self.assertRaisesRegex(
            ValueError, "incomplete whole-file coverage: .*branch_example"
        ):
            check_full_files(self.data, [self.source])

    def test_branch_gap_is_refused_even_when_every_statement_executed(self) -> None:
        """Keep statement-complete execution distinct from complete control-flow coverage."""
        self.produce(
            "def choose(flag):\n    if flag:\n        flag = True\n    return True\n",
            "assert choose(True) is True\n",
        )
        measured = coverage.Coverage(data_file=str(self.data), config_file=False)
        try:
            measured.load()
            self.assertEqual(measured.analysis2(str(self.source))[3], [])
        finally:
            measured.get_data().close(force=True)
        with self.assertRaisesRegex(ValueError, "incomplete whole-file coverage"):
            check_full_files(self.data, [self.source])

    def test_source_exclusion_directive_does_not_hide_missing_execution(self) -> None:
        """Reject an actual unvisited branch even when its source asks ordinary reports to omit it."""
        self.produce(
            "def choose(flag):\n    if flag:  # " + "pragma" + ": no cover\n"
            "        return 'yes'\n    return 'no'\n",
            "assert choose(False) == 'no'\n",
        )
        with self.assertRaisesRegex(ValueError, "incomplete whole-file coverage"):
            check_full_files(self.data, [self.source])

    def test_branch_directive_does_not_hide_a_statement_complete_branch_gap(self) -> None:
        """Refuse an unvisited outcome even when a branch directive masks the ordinary report."""
        self.produce(
            "def choose(flag):\n    if flag:  # " + "pragma" + ": no branch\n"
            "        flag = True\n    return True\n",
            "assert choose(True) is True\n",
        )
        with self.assertRaisesRegex(ValueError, "incomplete whole-file coverage"):
            check_full_files(self.data, [self.source])

    def test_literal_text_does_not_hide_a_dynamic_branch(self) -> None:
        """Refuse missing outcomes masked by constant-looking comments or string literals."""
        for predicate in (
            "flag:  # while True:",
            "flag:  # if False:",
            'flag and "while True:":',
            'flag and "if True:":',
        ):
            with self.subTest(predicate=predicate):
                self.produce(
                    "def choose(flag):\n    if " + predicate + "\n"
                    "        flag = True\n    return True\n",
                    "assert choose(True) is True\n",
                )
                with self.assertRaisesRegex(ValueError, "incomplete whole-file coverage"):
                    check_full_files(self.data, [self.source])

    def test_real_constant_loop_and_fully_executed_directive_are_accepted(self) -> None:
        """Preserve structural constant-loop semantics and admit both actual branch outcomes."""
        for source in (
            "def choose(flag):\n    while True:\n        if flag:\n"
            "            break\n        return False\n    return True\n",
            "def choose(flag):\n    if flag:  # " + "pragma" + ": no branch\n"
            "        return True\n    return False\n",
        ):
            with self.subTest(source=source):
                self.produce(source, "assert choose(True)\nassert not choose(False)\n")
                check_full_files(self.data, [self.source])

    def test_line_only_database_is_refused(self) -> None:
        """Require real arcs rather than treating missing branch observations as zero obligations."""
        self.produce(
            "def choose(flag):\n    return flag\n", "assert choose(True)\n", branches=False
        )
        with self.assertRaisesRegex(ValueError, "requires actual branch data"):
            check_full_files(self.data, [self.source])

    def test_empty_or_duplicate_file_requests_are_refused(self) -> None:
        """Reject incomplete cohort arguments before opening any database."""
        self.complete_program()
        for files in ([], [self.source, self.source]):
            with self.subTest(files=files), self.assertRaisesRegex(ValueError, "distinct source"):
                check_full_files(self.data, files)

    def test_cli_accepts_complete_actual_program(self) -> None:
        """Parse real explicit data and source arguments through the public command entry point."""
        self.complete_program()
        self.assertEqual(main(["--data-file", str(self.data), str(self.source)]), 0)

    def test_script_entry_point_exits_zero_for_complete_actual_program(self) -> None:
        """Execute the same maintained script entry point with real arguments and its real database."""
        self.complete_program()
        script = Path(__file__).resolve().parents[1] / "tools/check_full_file_coverage.py"
        with (
            patch.object(
                sys, "argv", [str(script), "--data-file", str(self.data), str(self.source)]
            ),
            self.assertRaises(SystemExit) as result,
        ):
            runpy.run_path(str(script), run_name="__main__")
        self.assertEqual(result.exception.code, 0)
