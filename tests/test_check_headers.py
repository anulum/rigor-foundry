# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — SPDX header guard tests
"""Exercise direct header validation through an unborn Git worktree."""

from __future__ import annotations

import subprocess
from pathlib import Path

from tools.check_headers import HEADER_LINES, HEADER_TITLE_PREFIX, header_errors


def test_header_guard_reads_untracked_files_on_unborn_branch(tmp_path: Path) -> None:
    """The guard covers migration state before an initial commit exists."""
    subprocess.run(
        ["git", "init", "--initial-branch=main", str(tmp_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    source = tmp_path / "module.py"
    source.write_text(
        "\n".join((*HEADER_LINES, f"{HEADER_TITLE_PREFIX}fixture module")) + "\n",
        encoding="utf-8",
    )
    assert header_errors(tmp_path) == []

    source.write_text("\n".join(HEADER_LINES) + "\n", encoding="utf-8")
    assert header_errors(tmp_path) == ["module.py: missing canonical Apache-2.0 header"]

    source.write_text("print('missing header')\n", encoding="utf-8")
    assert header_errors(tmp_path) == ["module.py: missing canonical Apache-2.0 header"]
