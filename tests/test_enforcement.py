# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — conformance ratchet tests
"""Verify observe, ratchet, and zero decisions with explicit current evidence."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from rigor_foundry.adapters import AdapterResult
from rigor_foundry.enforcement import evaluate_enforcement
from rigor_foundry.models import AuditPolicy, AuditReport, Candidate, ReviewRecord


def _report() -> AuditReport:
    """Return one current report with a single governance candidate."""
    candidate = Candidate.build(
        category="governance",
        rule_id="GV004-uncontrolled-required-domain",
        path="docs/internal/audit/policy.json",
        line=1,
        symbol="application-security",
        evidence="required domain has no control",
        confidence="high",
        rationale="conformance requires evidence",
        verification="wire and run a repository-specific security control",
    )
    return AuditReport.build(
        repository_root="/tmp/repository",
        head="1" * 40,
        head_tree="2" * 40,
        branch="main",
        tracked_content_digest="3" * 64,
        dirty_paths=(),
        tracked_file_count=1,
        policy=AuditPolicy(),
        candidates=(candidate,),
    )


def _review(report: AuditReport, decision: str) -> ReviewRecord:
    """Return a completed evidence record for one supported decision."""
    base = ReviewRecord(
        report_digest=report.report_digest,
        candidate_id=report.candidates[0].candidate_id,
        decision="invalid",
        reviewer="agent/reviewer",
        reviewed_at="2026-07-15T10:00:00Z",
        rationale="reproduced against current policy",
        evidence=("audit command and source path inspected",),
        severity=None,
        owner="",
        dependencies=(),
        acceptance_gates=(),
        title="",
        boundary_justification="",
        expires_at="2026-08-15T10:00:00Z",
        reopen_triggers=("policy changes",),
    )
    if decision == "valid":
        return replace(
            base,
            decision="valid",
            severity="P1",
            owner="security-lane",
            acceptance_gates=("real security audit passes",),
            title="Add missing application security control",
        )
    if decision != "invalid":
        raise ValueError("unsupported test decision")
    return base


def test_observe_records_candidates_but_native_required_failure_blocks() -> None:
    """Observe does not verdict candidates, while execution failures remain fail-closed."""
    report = _report()
    observed = evaluate_enforcement(report, (), "observe")
    assert observed.passed
    assert observed.candidate_count == 1
    failed_adapter = AdapterResult(
        name="security",
        command=("/usr/bin/false",),
        returncode=1,
        output_digest="0" * 64,
        output_excerpt="failed",
        timed_out=False,
        required=True,
    )
    blocked = evaluate_enforcement(
        report,
        (),
        "observe",
        adapter_results=(failed_adapter,),
    )
    assert not blocked.passed
    assert "native audit security failed" in blocked.blockers[0]


def test_ratchet_requires_current_unexpired_unique_review() -> None:
    """Unreviewed, expired, and duplicate decisions cannot enter the legacy ledger."""
    report = _report()
    now = datetime(2026, 7, 16, tzinfo=UTC)
    unreviewed = evaluate_enforcement(report, (), "ratchet", now=now)
    assert not unreviewed.passed
    reviewed = evaluate_enforcement(report, (_review(report, "invalid"),), "ratchet", now=now)
    assert reviewed.passed
    expired = replace(_review(report, "invalid"), expires_at="2026-07-15T10:30:00Z")
    assert not evaluate_enforcement(report, (expired,), "ratchet", now=now).passed
    with pytest.raises(ValueError, match="multiple completed"):
        evaluate_enforcement(
            report,
            (_review(report, "invalid"), _review(report, "invalid")),
            "ratchet",
            now=now,
        )


def test_zero_rejects_verified_valid_debt_until_remediated() -> None:
    """A verified finding may remain under ratchet but cannot pass zero mode."""
    report = _report()
    now = datetime(2026, 7, 16, tzinfo=UTC)
    valid = _review(report, "valid")
    ratchet = evaluate_enforcement(report, (valid,), "ratchet", now=now)
    assert ratchet.passed
    zero = evaluate_enforcement(report, (valid,), "zero", now=now)
    assert not zero.passed
    assert zero.valid_debt_count == 1
    assert any("valid remediation debt" in blocker for blocker in zero.blockers)
    with pytest.raises(ValueError, match="UTC"):
        evaluate_enforcement(report, (), "observe", now=datetime(2026, 7, 16))
