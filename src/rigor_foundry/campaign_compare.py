# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — independent audit divergence comparison
"""Compare independent audit runs without treating majority agreement as truth."""

from __future__ import annotations

from dataclasses import dataclass

from .campaign_models import CAMPAIGN_SCHEMA_VERSION, AuditCampaign
from .campaign_store import StoredAuditRun
from .models import ReviewRecord, canonical_digest


@dataclass(frozen=True)
class AuditComparison:
    """Evidence-based convergence and diligence report for one campaign."""

    comparison_id: str
    campaign_id: str
    input_contract_digest: str
    created_by: str
    created_at: str
    expected_run_count: int
    actual_run_count: int
    run_ids: tuple[str, ...]
    agent_identities: tuple[str, ...]
    input_divergence: tuple[str, ...]
    coverage_divergence: tuple[str, ...]
    scanner_divergence: tuple[str, ...]
    adapter_divergence: tuple[str, ...]
    review_divergence: tuple[str, ...]
    priority_divergence: tuple[str, ...]
    diligence_gaps: tuple[str, ...]
    unresolved: bool
    comparison_digest: str

    def to_dict(self) -> dict[str, object]:
        """Serialise the immutable comparison record."""
        return {
            "schema_version": CAMPAIGN_SCHEMA_VERSION,
            "comparison_id": self.comparison_id,
            "campaign_id": self.campaign_id,
            "input_contract_digest": self.input_contract_digest,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "expected_run_count": self.expected_run_count,
            "actual_run_count": self.actual_run_count,
            "run_ids": list(self.run_ids),
            "agent_identities": list(self.agent_identities),
            "input_divergence": list(self.input_divergence),
            "coverage_divergence": list(self.coverage_divergence),
            "scanner_divergence": list(self.scanner_divergence),
            "adapter_divergence": list(self.adapter_divergence),
            "review_divergence": list(self.review_divergence),
            "priority_divergence": list(self.priority_divergence),
            "diligence_gaps": list(self.diligence_gaps),
            "unresolved": self.unresolved,
            "comparison_digest": self.comparison_digest,
        }


def _input_divergence(
    campaign: AuditCampaign,
    runs: tuple[StoredAuditRun, ...],
) -> tuple[str, ...]:
    """Return deviations from the immutable campaign input contract."""
    problems: list[str] = []
    for stored in runs:
        run = stored.attestation
        report = stored.report
        expected = {
            "head": campaign.head,
            "head_tree": campaign.head_tree,
            "branch": campaign.branch,
            "tracked_content_digest": campaign.tracked_content_digest,
            "dirty_paths": campaign.dirty_paths,
            "policy_digest": campaign.policy_digest,
            "rule_pack_version": campaign.rule_pack_version,
            "rule_pack_digest": campaign.rule_pack_digest,
        }
        observed = {
            "head": report.head,
            "head_tree": report.head_tree,
            "branch": report.branch,
            "tracked_content_digest": report.tracked_content_digest,
            "dirty_paths": report.dirty_paths,
            "policy_digest": report.policy_digest,
            "rule_pack_version": report.rule_pack_version,
            "rule_pack_digest": report.rule_pack_digest,
        }
        for field in expected:
            if observed[field] != expected[field]:
                problems.append(f"run {run.run_id}: {field} differs from campaign contract")
        if run.toolchain.identity_digest != campaign.toolchain.identity_digest:
            problems.append(f"run {run.run_id}: toolchain differs from campaign contract")
    return tuple(sorted(problems))


def _coverage_divergence(
    campaign: AuditCampaign,
    runs: tuple[StoredAuditRun, ...],
) -> tuple[str, ...]:
    """Return required-domain omissions and cross-run coverage differences."""
    problems: list[str] = []
    required = frozenset(campaign.required_domains)
    coverage_sets: dict[tuple[str, ...], list[str]] = {}
    for stored in runs:
        run = stored.attestation
        covered = frozenset(run.covered_domains)
        missing = sorted(required.difference(covered))
        if missing:
            problems.append(f"run {run.run_id}: omitted required domains {', '.join(missing)}")
        if run.omitted_domains:
            problems.append(
                f"run {run.run_id}: declared omitted domains {', '.join(run.omitted_domains)}"
            )
        coverage_sets.setdefault(tuple(sorted(covered)), []).append(run.run_id)
    if len(coverage_sets) > 1:
        groups = "; ".join(
            f"{','.join(run_ids)}=[{','.join(domains)}]"
            for domains, run_ids in sorted(coverage_sets.items())
        )
        problems.append(f"independent runs covered different domain sets: {groups}")
    return tuple(sorted(problems))


def _scanner_divergence(runs: tuple[StoredAuditRun, ...]) -> tuple[str, ...]:
    """Return differences in candidate reports produced from identical inputs."""
    if len(runs) < 2:
        return ()
    baseline = runs[0]
    baseline_ids = {item.candidate_id for item in baseline.report.candidates}
    problems: list[str] = []
    for stored in runs[1:]:
        observed_ids = {item.candidate_id for item in stored.report.candidates}
        if observed_ids != baseline_ids:
            problems.append(
                f"runs {baseline.attestation.run_id}/{stored.attestation.run_id}: "
                f"candidate sets differ; baseline-only={len(baseline_ids - observed_ids)}, "
                f"observed-only={len(observed_ids - baseline_ids)}"
            )
        elif stored.report.report_digest != baseline.report.report_digest:
            problems.append(
                f"runs {baseline.attestation.run_id}/{stored.attestation.run_id}: "
                "candidate sets match but report digests differ"
            )
    return tuple(sorted(problems))


def _adapter_divergence(runs: tuple[StoredAuditRun, ...]) -> tuple[str, ...]:
    """Return native-adapter result or output-evidence differences."""
    by_name: dict[str, dict[tuple[bool, int, bool, str], list[str]]] = {}
    for stored in runs:
        for evidence in stored.attestation.adapter_evidence:
            signature = (
                evidence.passed,
                evidence.returncode,
                evidence.timed_out,
                evidence.output_digest,
            )
            by_name.setdefault(evidence.name, {}).setdefault(signature, []).append(
                stored.attestation.run_id
            )
    problems: list[str] = []
    for name, signatures in sorted(by_name.items()):
        if len(signatures) > 1:
            problems.append(f"native adapter {name} produced divergent status/output evidence")
    return tuple(problems)


def _review_divergence(
    reviews: tuple[tuple[ReviewRecord, ...], ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return validity and priority differences across independent reviews."""
    by_candidate: dict[str, list[ReviewRecord]] = {}
    for review_set in reviews:
        for review in review_set:
            if review.decision != "needs-evidence":
                by_candidate.setdefault(review.candidate_id, []).append(review)
    decisions: list[str] = []
    priorities: list[str] = []
    for candidate_id, records in sorted(by_candidate.items()):
        decision_values = {record.decision for record in records}
        if len(decision_values) > 1:
            decisions.append(
                f"candidate {candidate_id}: decisions differ ({', '.join(sorted(decision_values))})"
            )
        valid_records = [record for record in records if record.decision == "valid"]
        priority_values = {
            (record.severity, record.owner, record.acceptance_gates) for record in valid_records
        }
        if len(priority_values) > 1:
            priorities.append(
                f"candidate {candidate_id}: severity, owner, or acceptance gates differ"
            )
    return tuple(decisions), tuple(priorities)


def compare_campaign(
    campaign: AuditCampaign,
    runs: tuple[StoredAuditRun, ...],
    reviews: tuple[tuple[ReviewRecord, ...], ...],
    *,
    comparison_id: str,
    created_by: str,
    created_at: str,
) -> AuditComparison:
    """Build a deterministic multi-agent convergence and diligence report."""
    input_problems = _input_divergence(campaign, runs)
    coverage_problems = _coverage_divergence(campaign, runs)
    scanner_problems = _scanner_divergence(runs)
    adapter_problems = _adapter_divergence(runs)
    review_problems, priority_problems = _review_divergence(reviews)
    diligence: list[str] = []
    if len(runs) < campaign.expected_independent_runs:
        diligence.append(
            f"expected {campaign.expected_independent_runs} independent runs, found {len(runs)}"
        )
    identities = tuple(sorted(stored.attestation.agent_identity for stored in runs))
    if len(identities) != len(set(identities)):
        diligence.append("multiple runs reuse the same agent identity")
    if any(stored.attestation.status != "complete" for stored in runs):
        diligence.append("one or more runs are incomplete")
    if not reviews:
        diligence.append("no independent review records were supplied")
    run_ids = tuple(sorted(stored.attestation.run_id for stored in runs))
    body: dict[str, object] = {
        "schema_version": CAMPAIGN_SCHEMA_VERSION,
        "comparison_id": comparison_id,
        "campaign_id": campaign.campaign_id,
        "input_contract_digest": campaign.contract_digest,
        "created_by": created_by,
        "created_at": created_at,
        "expected_run_count": campaign.expected_independent_runs,
        "actual_run_count": len(runs),
        "run_ids": list(run_ids),
        "agent_identities": list(identities),
        "input_divergence": list(input_problems),
        "coverage_divergence": list(coverage_problems),
        "scanner_divergence": list(scanner_problems),
        "adapter_divergence": list(adapter_problems),
        "review_divergence": list(review_problems),
        "priority_divergence": list(priority_problems),
        "diligence_gaps": sorted(diligence),
    }
    unresolved = any(
        (
            input_problems,
            coverage_problems,
            scanner_problems,
            adapter_problems,
            review_problems,
            priority_problems,
            diligence,
        )
    )
    return AuditComparison(
        comparison_id=comparison_id,
        campaign_id=campaign.campaign_id,
        input_contract_digest=campaign.contract_digest,
        created_by=created_by,
        created_at=created_at,
        expected_run_count=campaign.expected_independent_runs,
        actual_run_count=len(runs),
        run_ids=run_ids,
        agent_identities=identities,
        input_divergence=input_problems,
        coverage_divergence=coverage_problems,
        scanner_divergence=scanner_problems,
        adapter_divergence=adapter_problems,
        review_divergence=review_problems,
        priority_divergence=priority_problems,
        diligence_gaps=tuple(sorted(diligence)),
        unresolved=unresolved,
        comparison_digest=canonical_digest({**body, "unresolved": unresolved}),
    )
