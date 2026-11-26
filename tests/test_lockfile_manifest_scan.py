# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real-scan tests of SC011 lockfile manifest drift
"""SC011 through a real scan: one candidate per drifted lockfile, and the report's counts."""

from __future__ import annotations

import hashlib
from pathlib import Path

from lockfile_repository_support import fixture_text
from repository_audit_git_repository import GitRepository

from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.lockfile_integrity import (
    DRIFT_RULE_ID,
    assess_lockfiles,
    scan_lockfile_integrity,
)
from rigor_foundry.lockfile_report import lockfile_integrity_report

FIXTURES = Path(__file__).parent / "fixtures" / "lockfiles"


def _case(
    repository: GitRepository, directory: str, case: str, manifest: str, lockfile: str
) -> None:
    """Write one stored drift case's manifest and lockfile into ``directory``."""
    source = FIXTURES / f"manifest-{case}"
    repository.write_text(f"{directory}/{manifest}", fixture_text(source / f"{manifest}.gz"))
    repository.write_text(f"{directory}/{lockfile}", fixture_text(source / f"{lockfile}.gz"))


def test_a_drifted_lockfile_raises_one_sc011_at_its_hash_line(tmp_path: Path) -> None:
    """A real drift becomes one SC011 with the manifest's digest; a fresh lock raises none."""
    repository = GitRepository.create(tmp_path / "repository")
    _case(repository, "app", "poetry-2.5.2-legacy-drift", "pyproject.toml", "poetry.lock")
    _case(repository, "svc", "pipenv-2026.12.1-fresh", "Pipfile", "Pipfile.lock")
    repository.commit()
    inventory = load_git_inventory(repository.root)

    results = {result.path: result for result in assess_lockfiles(inventory)}
    assert results["app/poetry.lock"].manifest_check is not None
    assert results["app/poetry.lock"].manifest_check.state == "drift"
    assert results["svc/Pipfile.lock"].manifest_check is not None
    assert results["svc/Pipfile.lock"].manifest_check.state == "fresh"

    drift = [c for c in scan_lockfile_integrity(inventory) if c.rule_id == DRIFT_RULE_ID]
    assert len(drift) == 1
    lock = results["app/poetry.lock"]
    pyproject = fixture_text(FIXTURES / "manifest-poetry-2.5.2-legacy-drift" / "pyproject.toml.gz")
    assert (drift[0].path, drift[0].line, drift[0].confidence) == ("app/poetry.lock", 18, "high")
    assert drift[0].evidence == (
        f"file_sha256={lock.file_sha256}; manifest=app/pyproject.toml; "
        f"manifest_sha256={hashlib.sha256(pyproject.encode()).hexdigest()}; "
        f"recorded={lock.manifest_hash}; writer=2.5.2; accepted=F1"
    )


def test_the_evidence_names_no_writer_for_pipenv_and_an_unknown_one_for_an_unnamed_poetry(
    tmp_path: Path,
) -> None:
    """Pipfile.lock names no writer, and a Poetry header without a version is unknown."""
    repository = GitRepository.create(tmp_path / "repository")
    _case(repository, "svc", "pipenv-2025.0.4-drift", "Pipfile", "Pipfile.lock")
    source = FIXTURES / "manifest-poetry-1.8.5-legacy-drift"
    repository.write_text("app/pyproject.toml", fixture_text(source / "pyproject.toml.gz"))
    lock = fixture_text(source / "poetry.lock.gz").replace("Poetry 1.8.5 and", "Poetry and", 1)
    repository.write_text("app/poetry.lock", lock)
    repository.commit()

    evidence = {
        c.path: c.evidence
        for c in scan_lockfile_integrity(load_git_inventory(repository.root))
        if c.rule_id == DRIFT_RULE_ID
    }
    assert evidence["svc/Pipfile.lock"].endswith("writer=none; accepted=plette,canonical")
    assert evidence["app/poetry.lock"].endswith("writer=and; accepted=F1,F2,F3")
    repository.write_text("app/poetry.lock", "\n".join(lock.splitlines()[1:]) + "\n")
    repository.commit()
    unnamed = [
        c.evidence
        for c in scan_lockfile_integrity(load_git_inventory(repository.root))
        if c.rule_id == DRIFT_RULE_ID and c.path == "app/poetry.lock"
    ]
    assert unnamed[0].endswith("writer=unknown; accepted=F1,F2,F3")


def test_an_untracked_or_binary_manifest_is_uncertain_and_the_report_counts_every_state(
    tmp_path: Path,
) -> None:
    """No SC011 is raised without a readable manifest, and the summary counts each state."""
    repository = GitRepository.create(tmp_path / "repository")
    _case(repository, "app", "poetry-2.5.2-legacy-drift", "pyproject.toml", "poetry.lock")
    source = FIXTURES / "manifest-poetry-2.5.2-legacy-fresh"
    repository.write_text("lib/poetry.lock", fixture_text(source / "poetry.lock.gz"))
    repository.write_text("bin/poetry.lock", fixture_text(source / "poetry.lock.gz"))
    repository.write_bytes("bin/pyproject.toml", b"\0binary\0")
    repository.write_text("none/poetry.lock", fixture_text(source / "poetry.lock.gz"))
    repository.commit()
    repository.write_text("lib/pyproject.toml", fixture_text(source / "pyproject.toml.gz"))
    inventory = load_git_inventory(repository.root)

    states = {
        result.path: result.manifest_check.state
        for result in assess_lockfiles(inventory)
        if result.manifest_check is not None
    }
    assert states == {
        "app/poetry.lock": "drift",
        "bin/poetry.lock": "manifest-uncertain",
        "lib/poetry.lock": "manifest-uncertain",
        "none/poetry.lock": "manifest-missing",
    }
    drift = [c.path for c in scan_lockfile_integrity(inventory) if c.rule_id == DRIFT_RULE_ID]
    assert drift == ["app/poetry.lock"]
    summary = lockfile_integrity_report(inventory).summary()
    assert summary["manifest_states"] == {
        "fresh": 0,
        "drift": 1,
        "manifest-missing": 1,
        "manifest-uncertain": 2,
        "manifest-unparseable": 0,
    }
    findings = summary["findings"]
    assert isinstance(findings, dict) and findings["manifest-drift"] == 1
