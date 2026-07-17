# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — OSCAL CLI adapter tests
"""Verify the rigor oscal command exports candidate evidence without attestation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from rigor_foundry.cli import main
from rigor_foundry.compliance_maps import NON_CERTIFICATION_NOTICE, builtin_template
from rigor_foundry.oscal_export import report_oscal
from tests.test_oscal_export import GENERATED_AT, _assessment, _lock


def _fixture(tmp_path: Path) -> tuple[Path, Path, str]:
    """Write lock and assessments JSON for the CLI and return paths + expected body."""
    lock, controls = _lock()
    assessments = tuple(_assessment(lock, control) for control in controls)
    expected = report_oscal(
        lock,
        assessments,
        builtin_template("iso-iec-27001-2022"),
        GENERATED_AT,
    )
    lock_path = tmp_path / "lock.json"
    assessments_path = tmp_path / "assessments.json"
    lock_path.write_text(json.dumps(lock.to_dict()), encoding="utf-8")
    assessments_path.write_text(
        json.dumps([item.to_dict() for item in assessments]),
        encoding="utf-8",
    )
    return lock_path, assessments_path, expected


def test_oscal_cli_stdout_matches_library_export(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLI stdout equals the library export for the same sealed inputs."""
    lock_path, assessments_path, expected = _fixture(tmp_path)
    code = main(
        [
            "oscal",
            "--lock",
            str(lock_path),
            "--assessments",
            str(assessments_path),
            "--template",
            "iso-iec-27001-2022",
            "--generated-at",
            GENERATED_AT,
        ]
    )
    assert code == 0
    captured = capsys.readouterr()
    assert captured.out == expected
    document = json.loads(captured.out)
    metadata = document["assessment-results"]["metadata"]
    assert metadata["remarks"] == NON_CERTIFICATION_NOTICE


def test_oscal_cli_exclusive_output(tmp_path: Path) -> None:
    """CLI writes exclusive output matching the library export."""
    lock_path, assessments_path, expected = _fixture(tmp_path)
    output = tmp_path / "out.oscal.json"
    code = main(
        [
            "oscal",
            "--lock",
            str(lock_path),
            "--assessments",
            str(assessments_path),
            "--template",
            "iso-iec-27001-2022",
            "--generated-at",
            GENERATED_AT,
            "--output",
            str(output),
        ]
    )
    assert code == 0
    assert output.read_text(encoding="utf-8") == expected


def test_oscal_cli_rejects_bad_assessments_shape(tmp_path: Path) -> None:
    """A non-array assessments document fails closed with exit 2."""
    lock_path, _assessments_path, _expected = _fixture(tmp_path)
    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")
    code = main(
        [
            "oscal",
            "--lock",
            str(lock_path),
            "--assessments",
            str(bad),
            "--template",
            "iso-iec-27001-2022",
            "--generated-at",
            GENERATED_AT,
        ]
    )
    assert code == 2
