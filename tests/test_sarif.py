# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real-surface SARIF exporter tests
"""Verify deterministic SARIF through real Git scans and the installed-style CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

import rigor_foundry
from rigor_foundry.models import AuditReport, ReviewRecord, reviews_to_json
from rigor_foundry.rules import RULES


def _repository(path: Path) -> GitRepository:
    """Create a real repository with independent blob and tree candidates."""
    repository = GitRepository.create(path)
    repository.write_text(
        "src/pkg/core.py",
        "# SPDX-License-" + "Identifier: Apache-2.0\nVALUE = 1\n",
    )
    repository.write_text(
        "src/pkg/optional.py",
        "try:\n    import pkg.extension\nexcept Exception:\n    extension = None\n",
    )
    repository.write_text("src/pkg/wild.py", "from pkg.core import *\n")
    repository.write_text("src/pkg/über file.py", "VALUE = 2  # noqa: E501\n")
    repository.write_text(
        "tests/test_core.py",
        "import pytest\n\n@pytest.mark.skip(reason='contract')\ndef test_value() -> None:\n"
        "    assert True\n",
    )
    repository.write_policy(registries=["docs/module-size-decisions.json"])
    repository.commit()
    return repository


def _completed_review(
    report: AuditReport,
    candidate_id: str,
    decision: str,
    *,
    severity: str | None = None,
) -> ReviewRecord:
    """Return one model-parsed completed review for a real candidate."""
    value = ReviewRecord.template(report.report_digest, candidate_id).to_dict()
    value.update(
        {
            "decision": decision,
            "reviewer": "RIGOR-FOUNDRY/reviewer",
            "reviewed_at": "2026-07-17T12:00:00Z",
            "rationale": "Reproduced against the exact anchored object.",
            "evidence": ["python -m rigor_foundry scan"],
            "severity": severity,
            "owner": "team/platform" if decision == "valid" else "",
            "acceptance_gates": ["focused regression passes"] if decision == "valid" else [],
            "title": "Remove the verified broad import boundary" if decision == "valid" else "",
            "boundary_justification": (
                "Required compatibility boundary." if decision == "accepted-boundary" else ""
            ),
            "reopen_triggers": ["anchored bytes change"],
        }
    )
    return ReviewRecord.from_dict(value)


def test_public_export_preserves_candidate_and_every_review_state(tmp_path: Path) -> None:
    """Real findings retain exact anchors while reviews add, rather than replace, verdicts."""
    report = rigor_foundry.scan_repository(
        _repository(tmp_path / "repository").root,
        Path("rigor-foundry-policy.json"),
    )
    assert len(report.candidates) >= 5
    reviews = (
        _completed_review(report, report.candidates[0].candidate_id, "valid", severity="P1"),
        _completed_review(report, report.candidates[1].candidate_id, "invalid"),
        _completed_review(report, report.candidates[2].candidate_id, "accepted-boundary"),
        ReviewRecord.template(report.report_digest, report.candidates[3].candidate_id),
    )

    first = rigor_foundry.report_sarif(report, reviews)
    document = json.loads(first)
    assert first == rigor_foundry.report_sarif(report, tuple(reversed(reviews)))
    assert json.loads(json.dumps(document, allow_nan=False, sort_keys=True)) == document
    assert document["$schema"] == rigor_foundry.SARIF_SCHEMA_URI
    assert document["version"] == rigor_foundry.SARIF_VERSION == "2.1.0"
    run = document["runs"][0]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [
        rule.rule_id for rule in RULES
    ]
    assert all(
        rule["helpUri"].endswith("docs/sarif.md#identity-and-anchors")
        for rule in run["tool"]["driver"]["rules"]
    )
    assert run["properties"]["rigorFoundry/branch"] == report.branch
    results = run["results"]
    assert len(results) == len(report.candidates)
    by_id = {result["properties"]["rigorFoundry/candidateId"]: result for result in results}
    expected = {
        reviews[0].candidate_id: ("fail", "error", "valid"),
        reviews[1].candidate_id: ("notApplicable", "none", "invalid"),
        reviews[2].candidate_id: ("informational", "note", "accepted-boundary"),
        reviews[3].candidate_id: ("review", "note", "needs-evidence"),
    }
    for candidate_id, (kind, level, verdict) in expected.items():
        result = by_id[candidate_id]
        assert (result["kind"], result["level"]) == (kind, level)
        assert result["properties"]["rigorFoundry/candidateState"] == "candidate"
        assert result["properties"]["rigorFoundry/verdictState"] == verdict
        assert result["fingerprints"] == {"rigorFoundry/v1": candidate_id}
        assert "partialFingerprints" not in result
    valid_review = by_id[reviews[0].candidate_id]["properties"]["rigorFoundry/review"]
    assert valid_review["digest"] == reviews[0].review_digest
    assert valid_review["severityProvenance"] == "review-record"

    unreviewed = by_id[report.candidates[4].candidate_id]
    assert unreviewed["kind"] == "review"
    assert unreviewed["properties"]["rigorFoundry/verdictState"] == "unreviewed"
    assert any(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "src/pkg/%C3%BCber%20file.py"
        for result in results
    )
    assert all(
        result["ruleIndex"]
        == next(index for index, rule in enumerate(RULES) if rule.rule_id == result["ruleId"])
        for result in results
    )


@pytest.mark.parametrize(
    ("severity", "level"),
    (("P0", "error"), ("P1", "error"), ("P2", "warning"), ("P3", "note"), ("P4", "note")),
)
def test_review_severity_is_the_only_sarif_level_provenance(
    tmp_path: Path,
    severity: str,
    level: str,
) -> None:
    """Every public severity maps exactly while the underlying candidate remains visible."""
    report = rigor_foundry.scan_repository(
        _repository(tmp_path / "repository").root,
        Path("rigor-foundry-policy.json"),
    )
    review = _completed_review(
        report,
        report.candidates[0].candidate_id,
        "valid",
        severity=severity,
    )
    document = json.loads(rigor_foundry.report_sarif(report, (review,)))
    result = document["runs"][0]["results"][0]
    assert result["level"] == level
    assert result["properties"]["rigorFoundry/candidateState"] == "candidate"
    assert result["properties"]["rigorFoundry/review"]["severity"] == severity


def test_export_carries_repository_tree_anchor_and_rejects_bad_reviews(tmp_path: Path) -> None:
    """Repository-wide evidence survives export and invalid ledgers fail closed."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    repository.commit()
    report = rigor_foundry.scan_repository(repository.root)
    document = json.loads(rigor_foundry.report_sarif(report))
    root_result = next(
        result
        for result in document["runs"][0]["results"]
        if result["properties"]["rigorFoundry/anchor"]["kind"] == "repository-tree"
    )
    assert (
        root_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == root_result["properties"]["rigorFoundry/anchor"]["path"]
    )
    anchor = root_result["properties"]["rigorFoundry/anchor"]
    assert anchor["treeOid"] == report.head_tree
    assert anchor["trackedContentSha256"] == report.tracked_content_digest

    foreign = ReviewRecord.template("f" * 64, report.candidates[0].candidate_id)
    with pytest.raises(ValueError, match="report_digest"):
        rigor_foundry.report_sarif(report, (foreign,))
    template = ReviewRecord.template(report.report_digest, report.candidates[0].candidate_id)
    with pytest.raises(ValueError, match="duplicate candidate_id"):
        rigor_foundry.report_sarif(report, (template, template))
    incomplete = ReviewRecord.from_dict({**template.to_dict(), "decision": "valid"})
    with pytest.raises(ValueError, match="valid finding requires severity"):
        rigor_foundry.report_sarif(report, (incomplete,))
    contradictory = ReviewRecord.from_dict({**template.to_dict(), "severity": "P0"})
    with pytest.raises(ValueError, match="only a valid finding may carry severity"):
        rigor_foundry.report_sarif(report, (contradictory,))


def test_zero_result_run_retains_exact_repository_and_rule_pack_provenance(
    tmp_path: Path,
) -> None:
    """Run-level identities survive when a clean real repository has no results."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.write_text(
        "src/pkg/core.py",
        "# SPDX-License-" + "Identifier: Apache-2.0\nVALUE = 1\n",
    )
    repository.write_text(
        "tests/test_core.py",
        "from pkg.core import VALUE\n\ndef test_value() -> None:\n    assert VALUE == 1\n",
    )
    repository.write_policy()
    repository.commit()
    report = rigor_foundry.scan_repository(
        repository.root,
        Path("rigor-foundry-policy.json"),
    )
    assert report.candidates == ()

    run = json.loads(rigor_foundry.report_sarif(report))["runs"][0]
    assert run["results"] == []
    assert run["properties"] == {
        "rigorFoundry/branch": report.branch,
        "rigorFoundry/gitObjectFormat": report.git_object_format,
        "rigorFoundry/head": report.head,
        "rigorFoundry/headTree": report.head_tree,
        "rigorFoundry/ignoredInventoryDigest": report.ignored_inventory_digest,
        "rigorFoundry/policyDigest": report.policy_digest,
        "rigorFoundry/reportDigest": report.report_digest,
        "rigorFoundry/rulePackDigest": report.rule_pack_digest,
        "rigorFoundry/rulePackVersion": report.rule_pack_version,
        "rigorFoundry/trackedContentDigest": report.tracked_content_digest,
    }


def test_cli_exports_stdout_and_explicit_file_from_real_report(tmp_path: Path) -> None:
    """The public subprocess CLI verifies input models before emitting SARIF."""
    repository = _repository(tmp_path / "repository")
    report_path = repository.root / ".rigor/report.json"
    report_path.parent.mkdir()
    scan = repository.run_audit(
        "scan",
        "--root",
        ".",
        "--policy",
        "rigor-foundry-policy.json",
        "--json-out",
        str(report_path),
    )
    assert scan.returncode == 0, scan.stderr
    report = AuditReport.from_path(report_path)
    review_path = repository.root / ".rigor/reviews.json"
    review_path.write_text(
        reviews_to_json(
            (ReviewRecord.template(report.report_digest, report.candidates[0].candidate_id),)
        ),
        encoding="utf-8",
    )

    stdout = repository.run_audit(
        "sarif",
        "--report",
        str(report_path),
        "--review",
        str(review_path),
    )
    assert stdout.returncode == 0, stdout.stderr
    assert json.loads(stdout.stdout)["version"] == "2.1.0"

    output_path = repository.root / ".rigor/results.sarif"
    written = repository.run_audit(
        "sarif",
        "--report",
        str(report_path),
        "--output",
        str(output_path),
    )
    assert written.returncode == 0, written.stderr
    assert output_path.read_text(encoding="utf-8") == rigor_foundry.report_sarif(report)

    missing_parent = repository.run_audit(
        "sarif",
        "--report",
        str(report_path),
        "--output",
        str(repository.root / ".rigor/missing/results.sarif"),
    )
    assert missing_parent.returncode == 2
    assert "output parent does not exist" in missing_parent.stderr
