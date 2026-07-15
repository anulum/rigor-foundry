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

from rigor_foundry.models import (
    AUDIT_DOMAINS,
    AdapterSpec,
    AuditDomainSpec,
    AuditPolicy,
    AuditReport,
    Candidate,
    ReviewRecord,
    canonical_digest,
    reviews_from_path,
    reviews_to_json,
)


def candidate() -> Candidate:
    """Return one registered, content-addressed candidate."""
    return Candidate.build(
        category="architecture",
        rule_id="AR001-first-party-import-cycle",
        path="src/pkg/a.py",
        line=3,
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
        branch="main",
        tracked_content_digest="3" * 64,
        dirty_paths=("src/pkg/a.py",),
        tracked_file_count=2,
        policy=policy,
        candidates=(candidate(),),
    )


def test_policy_round_trip_and_digest_are_deterministic(tmp_path: Path) -> None:
    """The full domain/adapter policy survives exact JSON round-trip."""
    adapter = AdapterSpec(
        name="real-control",
        command=("{python}", "tools/control.py"),
        timeout_seconds=12,
        scope="full",
        working_directory=".",
        required=True,
        domains=("application-security",),
    )
    policy = AuditPolicy(
        audit_domains=tuple(
            AuditDomainSpec(name, "required", f"{name} applies") for name in AUDIT_DOMAINS
        ),
        native_audits=(adapter,),
    )
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy.to_dict()), encoding="utf-8")
    loaded = AuditPolicy.from_path(path)
    assert loaded == policy
    assert canonical_digest(loaded.to_dict()) == canonical_digest(policy.to_dict())


@pytest.mark.parametrize(
    "change, message",
    [
        ({"schema_version": "9"}, "schema"),
        ({"enforcement_mode": "weaker"}, "unsupported"),
        ({"canonical_todo": "../TODO.md"}, "repository-relative"),
        ({"audit_domains": "all"}, "array"),
    ],
)
def test_policy_rejects_invalid_top_level_contracts(
    change: dict[str, object],
    message: str,
) -> None:
    """Policy parsing fails closed for version, path, mode, and shape defects."""
    value = AuditPolicy().to_dict()
    value.update(change)
    with pytest.raises(ValueError, match=message):
        AuditPolicy.from_dict(value)


def test_policy_rejects_duplicate_and_unknown_domains() -> None:
    """The domain matrix cannot contain duplicates or invented domains."""
    value = AuditPolicy().to_dict()
    decision = {
        "name": "test-authenticity",
        "applicability": "required",
        "rationale": "tests apply",
    }
    value["audit_domains"] = [decision, decision]
    with pytest.raises(ValueError, match="unique"):
        AuditPolicy.from_dict(value)
    value["audit_domains"] = [
        {"name": "unknown", "applicability": "required", "rationale": "invalid"}
    ]
    with pytest.raises(ValueError, match="unsupported"):
        AuditPolicy.from_dict(value)


def test_adapter_rejects_shell_shape_escape_and_unknown_domain() -> None:
    """Native adapters accept argv only and repository-contained work directories."""
    base: dict[str, object] = {
        "name": "control",
        "command": ["{python}", "control.py"],
        "timeout_seconds": 1,
        "scope": "both",
        "working_directory": ".",
        "required": True,
        "domains": ["application-security"],
    }
    assert AdapterSpec.from_dict(base, 0).name == "control"
    for key, value in (
        ("command", []),
        ("scope", "partial"),
        ("working_directory", "../outside"),
        ("domains", ["invented"]),
    ):
        changed = {**base, key: value}
        with pytest.raises(ValueError):
            AdapterSpec.from_dict(changed, 0)


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


def test_candidate_rejects_unregistered_or_wrong_category_rule() -> None:
    """A candidate cannot invent a rule or mislabel its registered category."""
    with pytest.raises(ValueError, match="unregistered"):
        Candidate.build(
            category="architecture",
            rule_id="AR999-invented",
            path="src/pkg/a.py",
            line=1,
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
            path="src/pkg/a.py",
            line=1,
            symbol="",
            evidence="wrong category",
            confidence="high",
            rationale="invalid",
            verification="reject",
        )


def test_review_documents_round_trip_and_reject_schema_drift(tmp_path: Path) -> None:
    """Review ledgers retain needs-evidence records without silently promoting them."""
    current = report()
    review = ReviewRecord.template(current.report_digest, current.candidates[0].candidate_id)
    path = tmp_path / "reviews.json"
    path.write_text(reviews_to_json((review,)), encoding="utf-8")
    assert reviews_from_path(path) == (review,)
    value = json.loads(path.read_text(encoding="utf-8"))
    value["schema_version"] = "older"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="schema"):
        reviews_from_path(path)
