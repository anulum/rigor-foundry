# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Repository conformance audit tests
"""Exercise the production repository through its composed audit boundary."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections.abc import Collection
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from tools._repository import (
    ROOT,
    RepositoryError,
    read_text,
    redacted_guard_exit_code,
    run,
    visible_files,
)
from tools.audit import EXPECTED_ORIGIN, audit_errors
from tools.check_action_pins import action_pin_errors
from tools.check_data_boundary import data_boundary_errors
from tools.check_dependency_waivers import dependency_waiver_errors
from tools.check_headers import header_errors
from tools.check_metadata import metadata_errors


def _snapshot_visible_repository(destination: Path) -> GitRepository:
    """Copy the current Git-visible worktree into one isolated repository."""
    repository = GitRepository.create(destination)
    for relative in visible_files():
        source = ROOT / relative
        target = repository.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            target.symlink_to(source.readlink())
        elif source.is_file():
            shutil.copy2(source, target)
    repository.git_command("remote", "add", "origin", EXPECTED_ORIGIN)
    return repository


def test_repository_passes_portable_conformance_audit() -> None:
    """All required surfaces and nested guards agree on the worktree."""
    assert audit_errors() == []


def test_visible_inventory_omits_tracked_paths_deleted_during_authoring(tmp_path: Path) -> None:
    """A planned rename does not make validators dereference the removed source path."""
    repository = GitRepository.create(tmp_path / "repository")
    obsolete = repository.write_text("obsolete.txt", "old\n")
    repository.commit()
    obsolete.unlink()
    assert Path("obsolete.txt") not in visible_files(repository.root)


def test_repository_runner_executes_bounded_non_git_commands(tmp_path: Path) -> None:
    """The shared runner captures a direct process without invoking a shell."""
    completed = run(
        sys.executable,
        "-c",
        "print('bounded-command')",
        cwd=tmp_path,
    )

    assert completed.returncode == 0
    assert completed.stdout == "bounded-command\n"
    assert completed.stderr == ""


def test_visible_inventory_fails_closed_outside_git(tmp_path: Path) -> None:
    """Inventory failure is a typed repository error, not an empty result."""
    with pytest.raises(RepositoryError):
        visible_files(tmp_path)


def test_repository_text_reader_rejects_invalid_utf8(tmp_path: Path) -> None:
    """An invalid UTF-8 file is classified as non-text."""
    (tmp_path / "invalid.txt").write_bytes(b"\xff")

    assert read_text(Path("invalid.txt"), tmp_path) is None


def test_redacted_guard_exit_code_keeps_validator_exceptions_private(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An unexpected validator exception remains behind the fixed CLI boundary."""

    def raise_repository_error() -> Collection[object]:
        raise RepositoryError("credential-bearing\nFORGED-LOG-LINE.py")

    assert redacted_guard_exit_code("Repository audit", raise_repository_error) == 1
    output = capsys.readouterr()
    assert output.out == (
        "Repository audit failed; finding details are redacted from process output.\n"
    )
    assert output.err == ""


def test_repository_guard_clis_redact_adversarial_repository_details(
    tmp_path: Path,
) -> None:
    """Every CI-facing repository guard suppresses values and forged log lines."""
    repository = _snapshot_visible_repository(tmp_path / "repository")
    value = "credential-value"
    forged_line = "FORGED-LOG-LINE.py"
    adversarial_leaf = f"password={value}\n{forged_line}"
    repository.write_text(adversarial_leaf, f"password = {value}\n")
    repository.write_text(
        f"src/rigor_foundry/{adversarial_leaf}",
        f"import socket\npassword = {value}\n",
    )
    repository.write_text(
        ".github/workflows/adversarial.yml",
        f"steps:\n  - uses: supplier/{value}\n",
    )

    project = repository.root / "pyproject.toml"
    project.write_text(
        project.read_text(encoding="utf-8").replace(
            'name = "rigor-foundry"',
            f'name = "{value}"',
            1,
        ),
        encoding="utf-8",
    )
    waiver_path = repository.root / ".github" / "dependency-waivers.json"
    waiver = json.loads(waiver_path.read_text(encoding="utf-8"))
    waiver["waivers"][0]["rationale"] = ""
    waiver_path.write_text(
        json.dumps(waiver, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    assert adversarial_leaf in "\n".join(header_errors(repository.root))
    assert value in "\n".join(action_pin_errors(repository.root))
    assert value in "\n".join(metadata_errors(repository.root))
    assert adversarial_leaf in "\n".join(data_boundary_errors(repository.root))
    assert "rationale must be non-empty" in "\n".join(dependency_waiver_errors(repository.root))
    assert adversarial_leaf in "\n".join(audit_errors(repository.root))
    repository.symlink(f"broken-{adversarial_leaf}.py", "missing-target")

    guards = (
        ("tools.check_headers", "Header guard"),
        ("tools.check_action_pins", "Action pin guard"),
        ("tools.check_metadata", "Metadata guard"),
        ("tools.check_secrets", "Secret guard"),
        ("tools.check_data_boundary", "Data-boundary guard"),
        ("tools.check_dependency_waivers", "Dependency-waiver guard"),
        ("tools.audit", "Repository audit"),
    )
    for module, label in guards:
        completed = subprocess.run(
            [sys.executable, "-m", module],
            cwd=repository.root,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert completed.returncode == 1, (module, completed.stdout, completed.stderr)
        assert completed.stdout == (
            f"{label} failed; finding details are redacted from process output.\n"
        )
        assert completed.stderr == ""
        assert value not in completed.stdout
        assert forged_line not in completed.stdout
