# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — repository audit record tests
"""Verify strict, content-addressed repository-audit records."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from repository_audit_git_repository import sample_git_provenance, sample_tree_anchor

from rigor_foundry.models import (
    AUDIT_DOMAINS,
    AuditDomainSpec,
    AuditPolicy,
    AuditReport,
    Candidate,
    ReviewRecord,
    reviews_from_path,
    reviews_to_json,
)


def candidate() -> Candidate:
    """Return one registered, content-addressed candidate."""
    return Candidate.build(
        category="architecture",
        rule_id="AR001-first-party-import-cycle",
        anchor=sample_tree_anchor("src/pkg/a.py"),
        symbol="pkg.a -> pkg.b -> pkg.a",
        evidence="pkg.a, pkg.b",
        confidence="high",
        rationale="cycle requires runtime ownership review",
        verification="import both public modules in a clean process",
    )


def report() -> AuditReport:
    """Return one deterministic exact-tree report."""
    policy = AuditPolicy(
        audit_domains=tuple(
            AuditDomainSpec(name, "not-applicable", "not present in this record test")
            for name in AUDIT_DOMAINS
        )
    )
    return AuditReport.build(
        repository_root="/tmp/repository",
        head="1" * 40,
        head_tree="2" * 40,
        git_object_format="sha1",
        branch="main",
        tracked_content_digest="3" * 64,
        dirty_paths=("src/pkg/a.py",),
        tracked_file_count=2,
        git_provenance=sample_git_provenance(),
        policy=policy,
        candidates=(candidate(),),
    )


def test_candidate_and_report_reject_content_tampering() -> None:
    """Candidate, rule-pack, policy, and report digests bind all report content."""
    current = report()
    assert AuditReport.from_dict(current.to_dict()) == current
    changed_candidate = current.to_dict()
    candidates = changed_candidate["candidates"]
    assert isinstance(candidates, list)
    first = candidates[0]
    assert isinstance(first, dict)
    first["evidence"] = "changed"
    with pytest.raises(ValueError, match="candidate identifier"):
        AuditReport.from_dict(changed_candidate)
    changed_policy = current.to_dict()
    changed_policy["policy_digest"] = "0" * 64
    with pytest.raises(ValueError, match="policy digest"):
        AuditReport.from_dict(changed_policy)

    changed_provenance = current.git_provenance.to_dict()
    changed_provenance["executable_digest"] = "6" * 64
    with pytest.raises(ValueError, match="identity digest"):
        AuditReport.from_dict(
            {
                **current.to_dict(),
                "git_provenance": changed_provenance,
            }
        )


def test_candidate_rejects_unregistered_or_wrong_category_rule() -> None:
    """A candidate cannot invent a rule or mislabel its registered category."""
    with pytest.raises(ValueError, match="unregistered"):
        Candidate.build(
            category="architecture",
            rule_id="AR999-invented",
            anchor=sample_tree_anchor("src/pkg/a.py"),
            symbol="",
            evidence="invented rule",
            confidence="high",
            rationale="invalid",
            verification="reject",
        )
    with pytest.raises(ValueError, match="does not belong"):
        Candidate.build(
            category="architecture",
            rule_id="GF001-large-responsibility-owner",
            anchor=sample_tree_anchor("src/pkg/a.py"),
            symbol="",
            evidence="wrong category",
            confidence="high",
            rationale="invalid",
            verification="reject",
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("category", "performance", "category"),
        ("confidence", "certain", "confidence"),
    ],
)
def test_candidate_parsing_rejects_unsupported_protocol_enums(
    field: str,
    value: str,
    message: str,
) -> None:
    """Candidate records reject unregistered enum values before digest acceptance."""
    encoded = candidate().to_dict()
    encoded[field] = value
    with pytest.raises(ValueError, match=message):
        Candidate.from_dict(encoded)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema_version", "9", "schema"),
        ("scanner_version", "9", "scanner"),
        ("rule_pack_version", "9", "rule-pack version"),
        ("rule_pack_digest", "0" * 64, "rule-pack digest"),
        ("git_provenance", {}, "provenance schema"),
        ("candidates", {}, "array"),
        ("report_digest", "0" * 64, "report digest"),
    ],
)
def test_report_parsing_rejects_protocol_and_integrity_drift(
    field: str,
    value: object,
    message: str,
) -> None:
    """Reports fail closed for protocol drift and a mismatched report digest."""
    encoded = report().to_dict()
    encoded[field] = value
    with pytest.raises(ValueError, match=message):
        AuditReport.from_dict(encoded)


def test_report_file_loading_rejects_missing_and_malformed_documents(tmp_path: Path) -> None:
    """Report loading rejects unavailable files and malformed JSON at its public boundary."""
    with pytest.raises(ValueError, match="cannot read audit report"):
        AuditReport.from_path(tmp_path / "missing.json")

    malformed = tmp_path / "malformed.json"
    malformed.write_text("{not-json", encoding="utf-8")
    with pytest.raises(ValueError, match="cannot read audit report"):
        AuditReport.from_path(malformed)


def test_review_documents_round_trip_and_reject_schema_drift(tmp_path: Path) -> None:
    """Review ledgers retain needs-evidence records without silently promoting them."""
    current = report()
    review = ReviewRecord.template(current.report_digest, current.candidates[0].candidate_id)
    path = tmp_path / "reviews.json"
    path.write_text(reviews_to_json((review,)), encoding="utf-8")
    assert reviews_from_path(path) == (review,)
    value = json.loads(path.read_text(encoding="utf-8"))
    assert value["schema_version"] == "1.0"
    value["schema_version"] = "older"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="schema"):
        reviews_from_path(path)


def test_review_parsing_rejects_invalid_decision_and_severity() -> None:
    """Review records admit only registered decisions and severities."""
    current = report()
    encoded = ReviewRecord.template(
        current.report_digest,
        current.candidates[0].candidate_id,
    ).to_dict()
    encoded["decision"] = "approved"
    with pytest.raises(ValueError, match="decision"):
        ReviewRecord.from_dict(encoded)

    encoded["decision"] = "needs-evidence"
    encoded["severity"] = "P9"
    with pytest.raises(ValueError, match="severity"):
        ReviewRecord.from_dict(encoded)


def test_review_file_loading_rejects_invalid_document_shapes(tmp_path: Path) -> None:
    """Review loading rejects missing, malformed, and non-array documents."""
    with pytest.raises(ValueError, match="cannot read audit reviews"):
        reviews_from_path(tmp_path / "missing.json")

    path = tmp_path / "reviews.json"
    path.write_text("{not-json", encoding="utf-8")
    with pytest.raises(ValueError, match="cannot read audit reviews"):
        reviews_from_path(path)

    path.write_text(
        json.dumps({"schema_version": "1.0", "reviews": {}}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="array"):
        reviews_from_path(path)
