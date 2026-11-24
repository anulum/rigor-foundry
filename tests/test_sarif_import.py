# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — end-to-end import of real producer SARIF into a real repository
"""Verify that real Semgrep, Trivy and CodeQL output imports as declared, anchored, unjudged records."""

from __future__ import annotations

import copy
import gzip
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.git_inventory import GitInventory, load_git_inventory
from rigor_foundry.rules import RULES_BY_ID, rule_pack_digest
from rigor_foundry.sarif import report_sarif
from rigor_foundry.sarif_import import import_sarif
from rigor_foundry.sarif_import_document import SarifImportRefused
from rigor_foundry.sarif_import_producers import PRODUCERS
from rigor_foundry.sarif_import_report import verify_import_report
from rigor_foundry.scanner import scan_repository

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/sarif_import"
SEMGREP = FIXTURES / "semgrep-1.186.0-producer-repository.sarif"
TRIVY = FIXTURES / "trivy-0.76.2-producer-repository.sarif"
CODEQL = FIXTURES / "codeql-2.26.0-actions-analysis-1496041210.sarif.gz"
PRODUCER_CHECKOUT = "/tmp/rigor-sarif-import/producer-repo"
FIXED_DATE = "2026-11-24T00:00:00Z"


def _repository(root: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[GitRepository, GitInventory]:
    """Commit the scanned producer repository reproducibly and load its inventory."""
    monkeypatch.setenv("GIT_AUTHOR_DATE", FIXED_DATE)
    monkeypatch.setenv("GIT_COMMITTER_DATE", FIXED_DATE)
    repository = GitRepository.create(root)
    manifest = json.loads((FIXTURES / "producer-repository.json").read_text(encoding="utf-8"))
    for relative, text in manifest["files"].items():
        repository.write_text(relative, text)
    repository.commit("fixture: producer repository")
    return repository, load_git_inventory(repository.root)


@pytest.fixture
def scanned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> GitInventory:
    """Return the inventory of the producer repository.

    Parameters
    ----------
    tmp_path : Path
        Owned repository allocation.
    monkeypatch : pytest.MonkeyPatch
        Fixes the commit dates for this test only.

    Returns
    -------
    GitInventory
        The verified inventory the real producers' paths resolve against.
    """
    return _repository(tmp_path / "repository", monkeypatch)[1]


def _variant(path: Path, change: Any) -> bytes:
    """Return a real file's bytes with one structural change applied."""
    raw = path.read_bytes()
    document: dict[str, Any] = json.loads(gzip.decompress(raw) if path.suffix == ".gz" else raw)
    change(document)
    return json.dumps(document).encode()


@pytest.mark.parametrize(
    ("path", "producer_id", "rule_id", "line", "driver"),
    [
        (SEMGREP, "semgrep", "ext:semgrep:rigor-fixture-eval", 7, ("Semgrep OSS", "1.186.0")),
        (TRIVY, "trivy", "ext:trivy:rigor-fixture-token", 3, ("Trivy", "0.76.2")),
    ],
)
def test_real_producer_output_imports_as_one_anchored_declared_candidate(
    scanned: GitInventory,
    path: Path,
    producer_id: str,
    rule_id: str,
    line: int,
    driver: tuple[str, str],
) -> None:
    """Semgrep's and Trivy's real finding anchors to the scanned blob and stays unreviewed.

    Parameters
    ----------
    scanned : GitInventory
        The producer repository's inventory.
    path : Path
        The real producer output.
    producer_id : str
        Its declared producer.
    rule_id : str
        The imported rule id of its one finding.
    line : int
        The finding's line in ``src/app/settings.py``.
    driver : tuple[str, str]
        The driver name and version the file claims.
    """
    payload = path.read_bytes()
    report = import_sarif(payload, producer_id, scanned, head=scanned.head)
    (candidate,) = report.imported_candidates
    settings = next(item for item in scanned.files if item.path == "src/app/settings.py")
    assert (candidate.anchor.path, candidate.anchor.line_start, candidate.anchor.line_end) == (
        "src/app/settings.py",
        line,
        line,
    )
    assert (candidate.anchor.blob_oid, candidate.anchor.content_sha256) == (
        settings.scanned_blob_id,
        settings.content_digest,
    )
    assert candidate.anchor.errors(scanned) == ()
    assert (candidate.result.rule_id, candidate.state) == (rule_id, "unreviewed")
    assert (report.observations, report.skipped) == ((), ())
    assert (report.driver.name, report.driver.version) == driver
    assert (report.provenance, report.profile_evidence_digest) == ("declared", None)
    assert report.producer_declaration_digest == PRODUCERS[producer_id].declaration_digest
    assert report.sarif_sha256 == hashlib.sha256(payload).hexdigest()
    assert (report.head, report.head_tree) == (scanned.head, scanned.head_tree)
    assert (
        verify_import_report(json.loads(report.to_json()))["report_digest"] == report.report_digest
    )


def test_the_report_digest_reproduces_on_an_identical_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two checkouts of the same reproducible commit give byte-identical import reports.

    Parameters
    ----------
    tmp_path : Path
        Owned repository allocations.
    monkeypatch : pytest.MonkeyPatch
        Fixes the commit dates for this test only.
    """
    first = _repository(tmp_path / "first", monkeypatch)[1]
    second = _repository(tmp_path / "second", monkeypatch)[1]
    assert first.head == second.head
    for path, producer_id in ((SEMGREP, "semgrep"), (TRIVY, "trivy")):
        reports = [
            import_sarif(path.read_bytes(), producer_id, inventory, head=inventory.head)
            for inventory in (first, second)
        ]
        assert reports[0].to_json() == reports[1].to_json()


def test_codeql_binds_to_its_stated_revision(scanned: GitInventory) -> None:
    """The real CodeQL file names another commit and is refused; bound to this one it imports."""
    raw = gzip.decompress(CODEQL.read_bytes())
    for head in (None, scanned.head):
        with pytest.raises(SarifImportRefused) as refused:
            import_sarif(raw, "codeql", scanned, head=head)
        assert refused.value.reason == "revision-mismatch"

    def rebind(document: dict[str, Any]) -> None:
        document["runs"][0]["versionControlProvenance"][0]["revisionId"] = scanned.head

    report = import_sarif(_variant(CODEQL, rebind), "codeql", scanned)
    assert report.imported_candidates == () and report.observations == ()
    ((run_index, result_index, reason),) = [
        (item.run_index, item.result_index, item.reason) for item in report.skipped
    ]
    assert (run_index, result_index, reason) == (0, 0, "untracked-path")
    assert (report.driver.name, report.driver.version) == ("CodeQL", "2.26.0")


def test_whole_file_refusals_reach_the_import(scanned: GitInventory) -> None:
    """A missing head, an unknown producer and a SARIF 2.0 file are each refused as a whole."""
    payload = SEMGREP.read_bytes()
    for producer_id, head, reason in (
        ("semgrep", None, "head-required"),
        ("bandit", scanned.head, "unknown-producer"),
        ("trivy", scanned.head, "unsupported-schema"),
    ):
        with pytest.raises(SarifImportRefused) as refused:
            import_sarif(payload, producer_id, scanned, head=head)
        assert refused.value.reason == reason

    def version_2_0(document: dict[str, Any]) -> None:
        document["version"] = "2.0.0"

    with pytest.raises(SarifImportRefused) as refused:
        import_sarif(_variant(SEMGREP, version_2_0), "semgrep", scanned, head=scanned.head)
    assert refused.value.reason == "not-sarif-2.1.0"


def test_rigor_foundrys_own_export_of_the_same_repository_is_a_self_import(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RigorFoundry's own SARIF never returns as an external finding.

    Parameters
    ----------
    tmp_path : Path
        Owned repository allocation.
    monkeypatch : pytest.MonkeyPatch
        Fixes the commit dates for this test only.
    """
    repository, inventory = _repository(tmp_path / "repository", monkeypatch)
    repository.write_policy()
    repository.commit("fixture: policy")
    inventory = load_git_inventory(repository.root)
    own = report_sarif(scan_repository(repository.root, Path("rigor-foundry-policy.json")))
    with pytest.raises(SarifImportRefused) as refused:
        import_sarif(own.encode(), "semgrep", inventory, head=inventory.head)
    assert refused.value.reason == "self-import"


def test_importing_changes_no_rule_registry_and_no_audit_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """After imports, RULES, the rule-pack digest and an audit report's SARIF are byte-identical.

    Parameters
    ----------
    tmp_path : Path
        Owned repository allocation.
    monkeypatch : pytest.MonkeyPatch
        Fixes the commit dates for this test only.
    """
    repository, _ = _repository(tmp_path / "repository", monkeypatch)
    repository.write_policy()
    repository.commit("fixture: policy")
    inventory = load_git_inventory(repository.root)
    report = scan_repository(repository.root, Path("rigor-foundry-policy.json"))
    exported, digest, registered = report_sarif(report), rule_pack_digest(), dict(RULES_BY_ID)
    for path, producer_id in ((SEMGREP, "semgrep"), (TRIVY, "trivy")):
        imported = import_sarif(path.read_bytes(), producer_id, inventory, head=inventory.head)
        assert not {item.result.rule_id for item in imported.imported_candidates} & set(
            RULES_BY_ID
        )
    assert report_sarif(report) == exported
    assert rule_pack_digest() == digest and dict(RULES_BY_ID) == registered


def test_duplicate_and_malformed_results_are_recorded_as_skips(scanned: GitInventory) -> None:
    """A repeated finding keeps one candidate, a non-finding is observed, a non-object skipped."""

    def repeat(document: dict[str, Any]) -> None:
        results = document["runs"][0]["results"]
        results.extend(
            [copy.deepcopy(results[0]), "not a result", {**results[0], "kind": "informational"}]
        )

    report = import_sarif(_variant(SEMGREP, repeat), "semgrep", scanned, head=scanned.head)
    assert len(report.imported_candidates) == 1
    ((observed_index, observed_reason),) = [
        (item.result.result_index, item.reason) for item in report.observations
    ]
    assert (observed_index, observed_reason) == (3, "kind-informational")
    assert [(item.result_index, item.reason) for item in report.skipped] == [
        (1, "duplicate-candidate"),
        (2, "malformed-result"),
    ]


def test_an_absolute_file_uri_resolves_only_under_the_named_checkout(
    scanned: GitInventory,
) -> None:
    """The producer-side checkout path makes an absolute URI importable; without it, it is outside."""

    def absolute(document: dict[str, Any]) -> None:
        location = document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        location["artifactLocation"] = {"uri": f"file://{PRODUCER_CHECKOUT}/src/app/settings.py"}

    payload = _variant(SEMGREP, absolute)
    named = import_sarif(
        payload, "semgrep", scanned, head=scanned.head, checkout_root=PRODUCER_CHECKOUT
    )
    assert named.imported_candidates[0].anchor.path == "src/app/settings.py"
    unnamed = import_sarif(payload, "semgrep", scanned, head=scanned.head)
    assert [item.reason for item in unnamed.skipped] == ["outside-checkout-root"]


def test_candidates_are_sorted_by_id_whatever_the_result_order(scanned: GitInventory) -> None:
    """Two findings in either order give the same report, with candidates sorted by id."""
    raw = json.loads(SEMGREP.read_bytes())
    first = raw["runs"][0]["results"][0]
    second = copy.deepcopy(first)
    second["message"]["text"] = "A second finding on the token line."
    region = second["locations"][0]["physicalLocation"]["region"]
    region.update(startLine=3, endLine=3, startColumn=1, endColumn=12)
    reports = []
    for order in ([first, second], [second, first]):
        raw["runs"][0]["results"] = order
        payload = json.dumps(raw).encode()
        reports.append(import_sarif(payload, "semgrep", scanned, head=scanned.head))
    ids = [[item.candidate_id for item in report.imported_candidates] for report in reports]
    assert ids[0] == ids[1] == sorted(ids[0]) and len(ids[0]) == 2
