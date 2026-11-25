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

from rigor_foundry import sarif_import_cli
from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.cli import main
from rigor_foundry.git_inventory import GitInventory, load_git_inventory
from rigor_foundry.safe_output import write_new_output
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


SEMGREP_RULES = (
    "rules:\n"
    "  - id: rigor-fixture-eval\n"
    "    languages: [python]\n"
    "    severity: ERROR\n"
    "    message: Dynamic evaluation of an expression argument.\n"
    "    pattern: eval($X)\n"
)


@pytest.fixture
def scanned(tmp_path: Path) -> GitRepository:
    """Commit a checkout with one Semgrep rule and one finding for the executed path.

    Parameters
    ----------
    tmp_path : Path
        Owned repository allocation.

    Returns
    -------
    GitRepository
        The committed checkout.
    """
    repository = GitRepository.create(tmp_path / "scanned")
    repository.write_text("security/semgrep.yml", SEMGREP_RULES)
    repository.write_text(
        "src/app/settings.py", "def run(expression):\n    return eval(expression)\n"
    )
    repository.commit()
    return repository


def _execute(repository: GitRepository, report: Path, binding: Path, *extra: str) -> list[str]:
    """Return the executed import arguments for one checkout and two new outputs."""
    return [
        "import-sarif",
        "--execute",
        "semgrep-local-sarif-import-v1",
        "--configuration",
        "security/semgrep.yml",
        "--target",
        "src",
        "--root",
        str(repository.root),
        "--output",
        str(report),
        "--binding-output",
        str(binding),
        *extra,
    ]


def test_an_executed_import_writes_a_report_and_binding_that_verify_together(
    scanned: GitRepository, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The real run's report is executed, its binding verifies, and verify-import accepts both.

    Parameters
    ----------
    scanned : GitRepository
        The checkout with one finding.
    tmp_path : Path
        Owned output allocation.
    capsys : pytest.CaptureFixture[str]
        Captures the printed summaries.
    """
    report, binding = tmp_path / "report.json", tmp_path / "binding.json"
    assert main(_execute(scanned, report, binding, "--head", _head(scanned))) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["provenance"] == "executed" and summary["counts"]["imported_candidates"] == 1
    assert (
        read_import_report(report)["profile_evidence_digest"]
        == json.loads(binding.read_text())["binding_digest"]
    )
    assert main(["verify-import", "--report", str(report), "--binding", str(binding)]) == 0
    assert json.loads(capsys.readouterr().out)["verified"] is True


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (("--sarif", "x.sarif"), "omit --sarif, --producer and --checkout-root"),
        (("--producer", "semgrep"), "omit --sarif, --producer and --checkout-root"),
        (("--checkout-root", "/elsewhere"), "omit --sarif, --producer and --checkout-root"),
        ((), "needs --head equal to the checkout's HEAD"),
        (("--head", "0" * 40), "needs --head equal to the checkout's HEAD"),
    ],
)
def test_an_executed_import_refuses_bad_options_and_writes_nothing(
    scanned: GitRepository,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    extra: tuple[str, ...],
    message: str,
) -> None:
    """A mixed declared option or a missing or wrong head exits 2 with no output written.

    Parameters
    ----------
    scanned : GitRepository
        The checkout with one finding.
    tmp_path : Path
        Owned output allocation.
    capsys : pytest.CaptureFixture[str]
        Captures the refusal.
    extra : tuple[str, ...]
        The refused options.
    message : str
        Text the refusal must contain.
    """
    report, binding = tmp_path / "report.json", tmp_path / "binding.json"
    head = () if "--head" in extra or not extra else ("--head", _head(scanned))
    assert main(_execute(scanned, report, binding, *head, *extra)) == 2
    assert message in capsys.readouterr().err
    assert not report.exists() and not binding.exists()


def test_an_untracked_configuration_or_existing_output_writes_nothing(
    scanned: GitRepository, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A configuration that is not tracked, or an output that exists, refuses the run.

    Parameters
    ----------
    scanned : GitRepository
        The checkout with one finding.
    tmp_path : Path
        Owned output allocation.
    capsys : pytest.CaptureFixture[str]
        Captures the refusals.
    """
    report, binding = tmp_path / "report.json", tmp_path / "binding.json"
    head = _head(scanned)
    arguments = _execute(scanned, report, binding, "--head", head)
    untracked = [
        part if part != "security/semgrep.yml" else "security/absent.yml" for part in arguments
    ]
    assert main(untracked) == 2 and "clean tracked regular file" in capsys.readouterr().err
    report.write_text("{}", encoding="utf-8")
    assert main(arguments) == 2 and "already exists" in capsys.readouterr().err
    assert not binding.exists()
    report.unlink()
    binding.write_text("{}", encoding="utf-8")
    assert main(arguments) == 2 and "already exists" in capsys.readouterr().err
    assert not report.exists()
    binding.unlink()
    same = [part if part != str(binding) else str(report) for part in arguments]
    assert main(same) == 2 and "two different paths" in capsys.readouterr().err
    assert not report.exists()
    missing = [part for part in arguments if part not in {"--binding-output", str(binding)}]
    assert main(missing) == 2 and "needs --configuration" in capsys.readouterr().err


def test_a_declared_import_refuses_executed_only_options(
    checkout: GitRepository, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Executed-only options need --execute, and an import needs a SARIF file or --execute.

    Parameters
    ----------
    checkout : GitRepository
        The producer repository.
    tmp_path : Path
        Owned output allocation.
    capsys : pytest.CaptureFixture[str]
        Captures the refusals.
    """
    output = tmp_path / "report.json"
    head = _head(checkout)
    declared = [*_arguments(checkout, SEMGREP, "semgrep", output), "--head", head]
    assert main([*declared, "--target", "src"]) == 2
    assert "need --execute" in capsys.readouterr().err
    assert main(["import-sarif", "--root", str(checkout.root), "--output", str(output)]) == 2
    assert "needs --sarif and --producer" in capsys.readouterr().err
    assert not output.exists()


def test_verify_import_refuses_records_that_do_not_belong_together(
    scanned: GitRepository, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A declared report, another driver version or a binding that is not JSON is refused.

    Parameters
    ----------
    scanned : GitRepository
        The checkout with one finding.
    tmp_path : Path
        Owned file allocation.
    capsys : pytest.CaptureFixture[str]
        Captures the refusals.
    """
    report, binding = tmp_path / "report.json", tmp_path / "binding.json"
    assert main(_execute(scanned, report, binding, "--head", _head(scanned))) == 0
    capsys.readouterr()
    record = json.loads(binding.read_text())
    record["driver_version"] = "9.9.9"
    record["binding_digest"] = canonical_digest(
        {key: item for key, item in record.items() if key != "binding_digest"}
    )
    other = tmp_path / "other-binding.json"
    other.write_text(json.dumps(record), encoding="utf-8")
    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    for binding_path, message in (
        (other, "does not cite this binding"),
        (broken, "binding is not JSON"),
    ):
        assert (
            main(["verify-import", "--report", str(report), "--binding", str(binding_path)]) == 2
        )
        assert message in capsys.readouterr().err


def test_a_checkout_that_moves_after_its_inventory_is_refused_and_writes_nothing(
    scanned: GitRepository,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The run must scan the content of the inventory the CLI anchors against.

    Parameters
    ----------
    scanned : GitRepository
        The checkout with one finding.
    tmp_path : Path
        Owned output allocation.
    monkeypatch : pytest.MonkeyPatch
        Moves the checkout right after the command loaded and checked its inventory.
    capsys : pytest.CaptureFixture[str]
        Captures the refusal.
    """
    checked = sarif_import_cli._require_tracked_configuration

    def moving(inventory: GitInventory, configuration: str) -> None:
        checked(inventory, configuration)
        scanned.write_text("src/app/settings.py", "def run(expression):\n    return expression\n")
        scanned.commit()

    monkeypatch.setattr(sarif_import_cli, "_require_tracked_configuration", moving)
    report, binding = tmp_path / "report.json", tmp_path / "binding.json"
    assert main(_execute(scanned, report, binding, "--head", _head(scanned))) == 2
    assert "does not match the audited tracked input" in capsys.readouterr().err
    assert not report.exists() and not binding.exists()


def test_an_executed_report_is_never_written_without_its_binding(
    scanned: GitRepository,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The binding is written first, so a failed report write leaves no unbound report.

    Parameters
    ----------
    scanned : GitRepository
        The checkout with one finding.
    tmp_path : Path
        Owned output allocation.
    monkeypatch : pytest.MonkeyPatch
        Fails the write of the report path.
    capsys : pytest.CaptureFixture[str]
        Captures the refusal.
    """
    report, binding = tmp_path / "report.json", tmp_path / "binding.json"

    def failing(path: Path, text: str) -> None:
        if path == report:
            raise OSError("the report could not be written")
        write_new_output(path, text)

    monkeypatch.setattr(sarif_import_cli, "write_new_output", failing)
    assert main(_execute(scanned, report, binding, "--head", _head(scanned))) == 2
    assert "the report could not be written" in capsys.readouterr().err
    assert binding.exists() and not report.exists()
