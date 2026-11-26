# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — lockfile integrity report and command witnesses
"""Pin ``rigor.lockfile-integrity-report.v1`` with a golden file, and drive the command."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from lockfile_repository_support import GOLDEN, build_lockfile_repository, render_report_golden

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.cli import main
from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.lockfile_report import LOCKFILE_REPORT_SCHEMA, lockfile_integrity_report


def test_the_report_of_the_fixture_repository_equals_the_golden_file(tmp_path: Path) -> None:
    """The whole report, field by field and in order, is the committed golden file.

    Regenerate it deliberately with ``python tests/lockfile_repository_support.py``.
    """
    assert render_report_golden(tmp_path / "repository") == GOLDEN.read_text(encoding="utf-8")


def test_the_golden_report_names_every_class_finding_and_refusal_and_its_digest() -> None:
    """The schema lists all six classes, nine findings and eight reasons, and binds its digest."""
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert golden["schema"] == LOCKFILE_REPORT_SCHEMA == "rigor.lockfile-integrity-report.v1"
    summary = golden["summary"]
    assert len(summary["classes"]) == 6
    assert len(summary["findings"]) == 9
    assert len(summary["refusals"]) == 8
    body = {key: value for key, value in golden.items() if key != "report_digest"}
    assert golden["report_digest"] == canonical_digest(body)
    assert [file["path"] for file in golden["files"]] == sorted(
        file["path"] for file in golden["files"]
    )


def test_files_out_of_path_order_or_repeated_are_refused(tmp_path: Path) -> None:
    """A report keeps one file per path, in path order."""
    repository = build_lockfile_repository(tmp_path / "repository")
    report = lockfile_integrity_report(load_git_inventory(repository.root))
    with pytest.raises(ValueError, match="ordered by path"):
        replace(report, files=tuple(reversed(report.files)))
    with pytest.raises(ValueError, match="unique"):
        replace(report, files=(report.files[0], report.files[0]))


def test_the_command_prints_the_text_summary_and_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Findings are observations: the text report lists them and the command exits zero."""
    repository = build_lockfile_repository(tmp_path / "repository")
    assert main(["lockfile-integrity", "--root", str(repository.root)]) == 0
    text = capsys.readouterr().out
    assert text.startswith(
        "lockfile integrity: 10 lockfiles, 4 classified, 6 refused, 77 entries\n"
    )
    assert "crates/Cargo.lock: refused (unsupported-file-kind)\n" in text
    assert "web/package-lock.json:" in text and "(floating-ref)" in text
    assert "node_modules/bundle-dependencies/node_modules/yargs" not in text
    assert text.endswith(
        f"report_digest {json.loads(GOLDEN.read_text(encoding='utf-8'))['report_digest']}\n"
    )


def test_the_command_prints_the_full_json_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--json`` prints exactly the report the golden file pins."""
    repository = build_lockfile_repository(tmp_path / "repository")
    assert main(["lockfile-integrity", "--root", str(repository.root), "--json"]) == 0
    assert capsys.readouterr().out == GOLDEN.read_text(encoding="utf-8")


def test_the_command_refuses_a_path_that_is_not_a_repository(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Outside a Git repository the shared error path reports and exits two."""
    assert main(["lockfile-integrity", "--root", str(tmp_path)]) == 2
    assert "repository audit error" in capsys.readouterr().err
