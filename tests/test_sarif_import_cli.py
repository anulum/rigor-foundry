# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — import-sarif command tests through the public CLI
"""Verify ``rigor import-sarif`` end to end on real producer output and a real checkout."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.cli import main
from rigor_foundry.git_inventory import load_git_inventory
from rigor_foundry.sarif_import import import_sarif
from rigor_foundry.sarif_import_document import MAX_SARIF_BYTES
from rigor_foundry.sarif_import_report import read_import_report

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/sarif_import"
SEMGREP = FIXTURES / "semgrep-1.186.0-producer-repository.sarif"
TRIVY = FIXTURES / "trivy-0.76.2-producer-repository.sarif"


@pytest.fixture
def checkout(tmp_path: Path) -> GitRepository:
    """Commit the producer repository the real Semgrep and Trivy output describes.

    Parameters
    ----------
    tmp_path : Path
        Owned repository allocation.

    Returns
    -------
    GitRepository
        The committed checkout.
    """
    repository = GitRepository.create(tmp_path / "repository")
    manifest = json.loads((FIXTURES / "producer-repository.json").read_text(encoding="utf-8"))
    for relative, text in manifest["files"].items():
        repository.write_text(relative, text)
    repository.commit("fixture: producer repository")
    return repository


def _head(repository: GitRepository) -> str:
    """Return the checkout's exact HEAD."""
    return repository.git_command("rev-parse", "HEAD").stdout.strip()


def _arguments(repository: GitRepository, sarif: Path, producer: str, output: Path) -> list[str]:
    """Return the import arguments for one file and one new output path."""
    return [
        "import-sarif",
        "--sarif",
        str(sarif),
        "--producer",
        producer,
        "--root",
        str(repository.root),
        "--output",
        str(output),
    ]


@pytest.mark.parametrize(("sarif", "producer"), [(SEMGREP, "semgrep"), (TRIVY, "trivy")])
def test_the_command_writes_the_same_verified_report_as_the_library(
    checkout: GitRepository,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sarif: Path,
    producer: str,
) -> None:
    """The written report verifies, equals the library's, and its digest and counts are printed.

    Parameters
    ----------
    checkout : GitRepository
        The producer repository.
    tmp_path : Path
        Owned output allocation.
    capsys : pytest.CaptureFixture[str]
        Captures the printed summary.
    sarif : Path
        The real producer output.
    producer : str
        Its declared producer.
    """
    output = tmp_path / "import-report.json"
    head = _head(checkout)
    assert main([*_arguments(checkout, sarif, producer, output), "--head", head]) == 0
    expected = import_sarif(
        sarif.read_bytes(), producer, load_git_inventory(checkout.root), head=head
    )
    assert output.read_text(encoding="utf-8") == expected.to_json()
    assert read_import_report(output)["report_digest"] == expected.report_digest
    summary = json.loads(capsys.readouterr().out)
    assert summary == {
        "counts": {"imported_candidates": 1, "observations": 0, "skipped": 0},
        "provenance": "declared",
        "report_digest": expected.report_digest,
    }
    assert main([*_arguments(checkout, sarif, producer, output), "--head", head]) == 2


def test_require_all_anchored_exits_one_after_writing_a_report_with_skips(
    checkout: GitRepository, tmp_path: Path
) -> None:
    """A result outside the named checkout is skipped; strict mode exits 1 with the report written.

    Parameters
    ----------
    checkout : GitRepository
        The producer repository.
    tmp_path : Path
        Owned file allocation.
    """
    document = json.loads(SEMGREP.read_bytes())
    location = document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    location["artifactLocation"] = {"uri": "file:///elsewhere/src/app/settings.py"}
    skipped = tmp_path / "skipped.sarif"
    skipped.write_text(json.dumps(document), encoding="utf-8")
    head = _head(checkout)
    lenient, strict = tmp_path / "lenient.json", tmp_path / "strict.json"
    assert main([*_arguments(checkout, skipped, "semgrep", lenient), "--head", head]) == 0
    arguments = [*_arguments(checkout, skipped, "semgrep", strict), "--head", head]
    assert main([*arguments, "--require-all-anchored"]) == 1
    assert read_import_report(strict)["counts"] == {
        "imported_candidates": 0,
        "observations": 0,
        "skipped": 1,
    }
    named = tmp_path / "named.json"
    with_checkout = [*_arguments(checkout, skipped, "semgrep", named), "--head", head]
    assert main([*with_checkout, "--checkout-root", "/elsewhere", "--require-all-anchored"]) == 0


def test_a_refused_file_exits_two_without_writing_a_report(
    checkout: GitRepository, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A missing head and an oversize file are refused before any output is written.

    Parameters
    ----------
    checkout : GitRepository
        The producer repository.
    tmp_path : Path
        Owned file allocation.
    capsys : pytest.CaptureFixture[str]
        Captures the refusal message.
    """
    output = tmp_path / "import-report.json"
    assert main(_arguments(checkout, SEMGREP, "semgrep", output)) == 2
    assert "head-required" in capsys.readouterr().err and not output.exists()
    oversize = tmp_path / "oversize.sarif"
    oversize.write_bytes(SEMGREP.read_bytes() + b" " * MAX_SARIF_BYTES)
    head = _head(checkout)
    assert main([*_arguments(checkout, oversize, "semgrep", output), "--head", head]) == 2
    assert "too-large" in capsys.readouterr().err and not output.exists()


def test_an_undeclared_producer_is_refused_by_the_parser(
    checkout: GitRepository, tmp_path: Path
) -> None:
    """Only the declared producers are accepted command values.

    Parameters
    ----------
    checkout : GitRepository
        The producer repository.
    tmp_path : Path
        Owned output allocation.
    """
    with pytest.raises(SystemExit) as exited:
        main(_arguments(checkout, SEMGREP, "bandit", tmp_path / "report.json"))
    assert exited.value.code == 2


def test_require_all_anchored_also_refuses_an_unanchored_finding(
    checkout: GitRepository, tmp_path: Path
) -> None:
    """A finding without a physical location is observed, not anchored, so strict mode exits 1.

    Parameters
    ----------
    checkout : GitRepository
        The producer repository.
    tmp_path : Path
        Owned file allocation.
    """
    document = json.loads(SEMGREP.read_bytes())
    del document["runs"][0]["results"][0]["locations"]
    unanchored = tmp_path / "unanchored.sarif"
    unanchored.write_text(json.dumps(document), encoding="utf-8")
    head = _head(checkout)
    lenient, strict = tmp_path / "lenient.json", tmp_path / "strict.json"
    assert main([*_arguments(checkout, unanchored, "semgrep", lenient), "--head", head]) == 0
    arguments = [*_arguments(checkout, unanchored, "semgrep", strict), "--head", head]
    assert main([*arguments, "--require-all-anchored"]) == 1
    report = read_import_report(strict)
    assert report["counts"] == {"imported_candidates": 0, "observations": 1, "skipped": 0}


def test_the_git_trust_options_reach_the_inventory(
    checkout: GitRepository, tmp_path: Path
) -> None:
    """A Git version floor above the installed Git refuses the checkout before anything is written.

    Parameters
    ----------
    checkout : GitRepository
        The producer repository.
    tmp_path : Path
        Owned output allocation.
    """
    output = tmp_path / "import-report.json"
    floor = ["--git-min-version", "999.0.0", "--git-max-version-exclusive", "1000.0.0"]
    arguments = [*_arguments(checkout, SEMGREP, "semgrep", output), "--head", _head(checkout)]
    assert main([*arguments, *floor]) == 2
    assert not output.exists()
    assert main(arguments) == 0 and output.exists()
