# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Complete executable-file coverage gate
"""Require every named file's actual statements and branches after a validated platform union."""

from __future__ import annotations

import argparse
import json
import tempfile
from collections.abc import Sequence
from pathlib import Path

import coverage


def check_full_files(data_file: Path, files: Sequence[Path]) -> None:
    """Check whole source files without changing the retained raw branch database.

    The caller must validate the producer, source, interpreter and run identity
    before supplying its combined database. This gate ignores source and branch
    exclusion directives and text-based structural masks, and requires branch data.
    """
    paths = [path.resolve(strict=True) for path in files]
    if not paths or len(set(paths)) != len(paths):
        raise ValueError("whole-file coverage requires a nonempty set of distinct source files")
    measured = coverage.Coverage(data_file=str(data_file), config_file=False)
    try:
        measured.load()
        if not measured.get_data().has_arcs():
            raise ValueError("whole-file coverage requires actual branch data")
        measured.set_option("report:exclude_lines", [])
        measured.set_option("report:exclude_also", [])
        measured.set_option("report:partial_branches", [])
        # Coverage joins empty pattern lists into a regex that matches every line.
        measured.set_option("report:partial_branches_always", [r"(?!)"])
        with tempfile.TemporaryDirectory(prefix="rigor-whole-file-coverage-") as temporary:
            report_path = Path(temporary) / "coverage.json"
            measured.json_report(morfs=[str(path) for path in paths], outfile=str(report_path))
            report = json.loads(report_path.read_text(encoding="utf-8"))
        rows = report["files"]
        incomplete = [
            name for name, row in rows.items() if row["missing_lines"] or row["missing_branches"]
        ]
        if incomplete:
            raise ValueError("incomplete whole-file coverage: " + ", ".join(sorted(incomplete)))
    finally:
        measured.get_data().close(force=True)


def main(argv: Sequence[str] | None = None) -> int:
    """Validate an already bound coverage database against every explicit source argument."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-file", type=Path, required=True)
    parser.add_argument("files", nargs="+", type=Path)
    args = parser.parse_args(argv)
    check_full_files(args.data_file, args.files)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
