# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Adopter preflight CLI tests
"""Exercise adopter prerequisites through the real CLI and Git repositories."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.cli import main
from rigor_foundry.version import __version__


def _rows(capsys: pytest.CaptureFixture[str]) -> dict[str, dict[str, object]]:
    """Read observations by their check names from the real command output."""
    out = capsys.readouterr()
    assert not out.err
    records = cast(list[dict[str, object]], json.loads(out.out)["checks"])
    return {str(record["check"]): record for record in records}


def test_doctor_admits_healthy_core_without_running_declared_tool(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Check the real installation and Git policy while leaving declared tools idle."""
    repo = GitRepository.create(tmp_path / "repository")
    repo.write_text("src/pkg/value.py", "VALUE = 2\n")
    repo.write_policy(
        native_audits=[
            {
                "name": "readiness-only",
                "command": [
                    "{python}",
                    "-c",
                    "from pathlib import Path; Path('unexpected').touch()",
                ],
                "required": False,
            }
        ]
    )
    repo.commit()
    assert main(["doctor", "--root", str(repo.root / "src")]) == 0
    checks = _rows(capsys)
    assert [checks[check]["status"] for check in ("package", "git", "policy")] == ["ready"] * 3
    assert checks["native_audits[0]"]["status"] == "ready"
    assert checks["sandbox"]["required"] is False
    assert checks["sandbox"]["status"] in {"ready", "unavailable"}
    assert not (repo.root / "unexpected").exists()
    assert not repo.git_command("status", "--porcelain").stdout


def test_doctor_reports_missing_invalid_and_explicit_policy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Use the scanner's real tracked policy selection and schema parser."""
    repo = GitRepository.create(tmp_path / "repository")
    repo.commit()
    command = ["doctor", "--root", str(repo.root)]
    assert main(command) == 1
    assert "Bootstrap" in str(_rows(capsys)["policy"]["detail"])
    path = repo.write_policy()
    repo.commit("test: create tracked policy")
    assert main([*command, "--policy", path.name]) == 0
    assert _rows(capsys)["policy"]["status"] == "ready"
    path.write_text('{"schema_version":"invalid"}\n', encoding="utf-8")
    assert main(command) == 1
    assert "schema" in str(_rows(capsys)["policy"]["detail"])


def test_doctor_retains_partial_observations_when_git_is_unusable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Distinguish a real nonrepository and unsupported executable version."""
    assert main(["doctor", "--root", str(tmp_path)]) == 1
    assert _rows(capsys)["policy"]["status"] == "not-assessed"
    repo = GitRepository.create(tmp_path / "repository")
    repo.commit()
    assert (
        main(
            [
                "doctor",
                "--root",
                str(repo.root),
                "--git-min-version",
                "999.0.0",
                "--git-max-version-exclusive",
                "1000.0.0",
            ]
        )
        == 1
    )
    checks = _rows(capsys)
    assert checks["git"]["status"] == "unavailable"
    assert checks["package"]["status"] == "ready"
    assert checks["sandbox"]["status"] == "not-assessed"


def test_doctor_checks_required_adapter_resolution_and_tracked_inputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Use actual filesystem state for missing executables and tracked inputs."""
    repo = GitRepository.create(tmp_path / "repository")
    repo.write_text("src/pkg/value.py", "VALUE = 2\n")
    repo.write_policy(
        native_audits=[
            {"name": "missing", "command": ["doctor-test-uninstalled-tool"]},
            {
                "name": "missing-config",
                "profile": "semgrep-local-json-v1",
                "configuration_path": "rules.yml",
                "target_paths": ["src"],
                "timeout_seconds": 10,
                "scope": "both",
                "working_directory": ".",
                "required": True,
            },
        ]
    )
    repo.commit()
    command = ["doctor", "--root", str(repo.root)]
    assert main(command) == 1
    checks = _rows(capsys)
    assert checks["policy"]["status"] == "ready"
    assert checks["sandbox"]["required"] is True
    assert checks["native_audits[0]"]["status"] == "unavailable"
    assert checks["native_audits[1]"]["status"] == "unavailable"
    repo.write_text("src/pkg/value.py", "VALUE = 3\n")
    assert main(command) == 1
    assert _rows(capsys)["native_audits[1]"]["status"] == "unavailable"
    repo.write_text("rules.yml", "rules: []\n")
    repo.commit("test: supply the real profile inputs")
    assert main(command) == 1
    checks = _rows(capsys)
    assert checks["native_audits[0]"]["status"] == "unavailable"
    assert not repo.git_command("status", "--porcelain").stdout


def test_doctor_detects_actual_missing_or_stale_distribution_metadata(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Read real distribution metadata files under an isolated Python search path."""
    command = ["doctor", "--root", str(tmp_path)]
    with monkeypatch.context() as search:
        search.setattr("sys.path", [str(tmp_path)])
        assert main(command) == 1
        assert "Install" in str(_rows(capsys)["package"]["detail"])
        member = tmp_path / "rigor_foundry-0.0.0.dist-info"
        member.mkdir()
        (member / "METADATA").write_text("Name: rigor-foundry\nVersion: 0.0.0\n", encoding="utf-8")
        assert main(command) == 1
        assert "Reinstall" in str(_rows(capsys)["package"]["detail"])
        (member / "METADATA").write_text(
            f"Name: rigor-foundry\nVersion: {__version__}\n", encoding="utf-8"
        )
        assert main(command) == 1
        assert "Reinstall" in str(_rows(capsys)["package"]["detail"])
