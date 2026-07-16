# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — independent audit divergence comparison
"""Compare independent audit runs without treating majority agreement as truth."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from .campaign_identity import (
    ModelWitness,
    collapse_model_witnesses,
    promotion_identity_gaps,
)
from .campaign_inputs import campaign_input_divergence
from .campaign_models import (
    CAMPAIGN_SCHEMA_VERSION,
    AuditCampaign,
    CampaignPurpose,
)
from .campaign_store import StoredAuditRun
from .models import (
    ReviewRecord,
    canonical_digest,
    require_integer,
    require_mapping,
    require_string,
    require_string_tuple,
)

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_COMPARISON_FIELDS = frozenset(
    {
        "schema_version",
        "comparison_id",
        "campaign_id",
        "input_contract_digest",
        "created_by",
        "created_at",
        "purpose",
        "expected_run_count",
        "actual_run_count",
        "required_model_witnesses",
        "actual_model_witnesses",
        "run_ids",
        "agent_identities",
        "attestation_digests",
        "report_digests",
        "review_digests",
        "model_witnesses",
        "input_divergence",
        "coverage_divergence",
        "scanner_divergence",
        "adapter_divergence",
        "review_divergence",
        "priority_divergence",
        "diligence_gaps",
        "unresolved",
        "promotion_eligible",
        "comparison_digest",
    }
)


def _identifier(value: object, field: str) -> str:
    """Return one portable comparison identifier."""
    result = require_string(value, field)
    if _IDENTIFIER.fullmatch(result) is None:
        raise ValueError(f"{field} must be a portable identifier")
    return result


def _sorted_unique_strings(value: object, field: str) -> tuple[str, ...]:
    """Return one canonical sorted, duplicate-free string tuple."""
    items = require_string_tuple(value, field)
    if items != tuple(sorted(set(items))):
        raise ValueError(f"{field} must be sorted and contain unique values")
    return items


def _utc_timestamp(value: object, field: str) -> str:
    """Return one normalised timezone-aware UTC timestamp."""
    result = require_string(value, field)
    normalised = result[:-1] + "+00:00" if result.endswith("Z") else result
    try:
        parsed = datetime.fromisoformat(normalised)
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError(f"{field} must use UTC")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _has_unresolved_evidence(body: dict[str, object]) -> bool:
    """Return whether any divergence or diligence field is non-empty."""
    return any(
        cast(list[str], body[field])
        for field in (
            "input_divergence",
            "coverage_divergence",
            "scanner_divergence",
            "adapter_divergence",
            "review_divergence",
            "priority_divergence",
            "diligence_gaps",
        )
    )


@dataclass(frozen=True)
class AuditComparison:
    """Evidence-based convergence and diligence report for one campaign."""

    comparison_id: str
    campaign_id: str
    input_contract_digest: str
    created_by: str
    created_at: str
    purpose: CampaignPurpose
    expected_run_count: int
    actual_run_count: int
    required_model_witnesses: int
    actual_model_witnesses: int
    run_ids: tuple[str, ...]
    agent_identities: tuple[str, ...]
    attestation_digests: tuple[str, ...]
    report_digests: tuple[str, ...]
    review_digests: tuple[str, ...]
    model_witnesses: tuple[ModelWitness, ...]
    input_divergence: tuple[str, ...]
    coverage_divergence: tuple[str, ...]
    scanner_divergence: tuple[str, ...]
    adapter_divergence: tuple[str, ...]
    review_divergence: tuple[str, ...]
    priority_divergence: tuple[str, ...]
    diligence_gaps: tuple[str, ...]
    unresolved: bool
    promotion_eligible: bool
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
            "purpose": self.purpose,
            "expected_run_count": self.expected_run_count,
            "actual_run_count": self.actual_run_count,
            "required_model_witnesses": self.required_model_witnesses,
            "actual_model_witnesses": self.actual_model_witnesses,
            "run_ids": list(self.run_ids),
            "agent_identities": list(self.agent_identities),
            "attestation_digests": list(self.attestation_digests),
            "report_digests": list(self.report_digests),
            "review_digests": list(self.review_digests),
            "model_witnesses": [witness.to_dict() for witness in self.model_witnesses],
            "input_divergence": list(self.input_divergence),
            "coverage_divergence": list(self.coverage_divergence),
            "scanner_divergence": list(self.scanner_divergence),
            "adapter_divergence": list(self.adapter_divergence),
            "review_divergence": list(self.review_divergence),
            "priority_divergence": list(self.priority_divergence),
            "diligence_gaps": list(self.diligence_gaps),
            "unresolved": self.unresolved,
            "promotion_eligible": self.promotion_eligible,
            "comparison_digest": self.comparison_digest,
        }

    @classmethod
    def from_dict(cls, value: object) -> AuditComparison:
        """Parse and integrity-check one campaign comparison."""
        data = require_mapping(value, "comparison")
        if frozenset(data) != _COMPARISON_FIELDS:
            raise ValueError("audit comparison fields do not match schema")
        if data.get("schema_version") != CAMPAIGN_SCHEMA_VERSION:
            raise ValueError("unsupported audit comparison schema version")
        purpose = require_string(data.get("purpose"), "purpose")
        if purpose not in {"diagnostic", "promotion"}:
            raise ValueError("unsupported audit comparison purpose")
        raw_witnesses = data.get("model_witnesses")
        if not isinstance(raw_witnesses, list):
            raise ValueError("model_witnesses must be an array")
        witnesses = tuple(ModelWitness.from_dict(item) for item in raw_witnesses)
        witness_keys = tuple((item.model_families, item.run_ids) for item in witnesses)
        if witness_keys != tuple(sorted(set(witness_keys))):
            raise ValueError("model_witnesses must be sorted with unique correlation components")
        model_families = tuple(
            family for witness in witnesses for family in witness.model_families
        )
        if len(model_families) != len(set(model_families)):
            raise ValueError("model family appears in multiple correlation components")
        exact_models = tuple(pair for witness in witnesses for pair in witness.exact_models)
        if len(exact_models) != len(set(exact_models)):
            raise ValueError("exact model appears in multiple correlation components")
        unresolved = data.get("unresolved")
        promotion_eligible = data.get("promotion_eligible")
        if not isinstance(unresolved, bool) or not isinstance(promotion_eligible, bool):
            raise ValueError("comparison status fields must be booleans")
        body: dict[str, object] = {
            "schema_version": CAMPAIGN_SCHEMA_VERSION,
            "comparison_id": _identifier(data.get("comparison_id"), "comparison_id"),
            "campaign_id": _identifier(data.get("campaign_id"), "campaign_id"),
            "input_contract_digest": require_string(
                data.get("input_contract_digest"),
                "input_contract_digest",
            ),
            "created_by": require_string(data.get("created_by"), "created_by"),
            "created_at": _utc_timestamp(data.get("created_at"), "created_at"),
            "purpose": purpose,
            "expected_run_count": require_integer(
                data.get("expected_run_count"),
                "expected_run_count",
                minimum=1,
            ),
            "actual_run_count": require_integer(
                data.get("actual_run_count"),
                "actual_run_count",
            ),
            "required_model_witnesses": require_integer(
                data.get("required_model_witnesses"),
                "required_model_witnesses",
                minimum=1,
            ),
            "actual_model_witnesses": require_integer(
                data.get("actual_model_witnesses"),
                "actual_model_witnesses",
            ),
            "run_ids": list(_sorted_unique_strings(data.get("run_ids"), "run_ids")),
            "agent_identities": list(
                _sorted_unique_strings(data.get("agent_identities"), "agent_identities")
            ),
            "attestation_digests": list(
                _sorted_unique_strings(
                    data.get("attestation_digests"),
                    "attestation_digests",
                )
            ),
            "report_digests": list(
                _sorted_unique_strings(data.get("report_digests"), "report_digests")
            ),
            "review_digests": list(
                _sorted_unique_strings(data.get("review_digests"), "review_digests")
            ),
            "model_witnesses": [witness.to_dict() for witness in witnesses],
            "input_divergence": list(
                _sorted_unique_strings(data.get("input_divergence"), "input_divergence")
            ),
            "coverage_divergence": list(
                _sorted_unique_strings(data.get("coverage_divergence"), "coverage_divergence")
            ),
            "scanner_divergence": list(
                _sorted_unique_strings(data.get("scanner_divergence"), "scanner_divergence")
            ),
            "adapter_divergence": list(
                _sorted_unique_strings(data.get("adapter_divergence"), "adapter_divergence")
            ),
            "review_divergence": list(
                _sorted_unique_strings(data.get("review_divergence"), "review_divergence")
            ),
            "priority_divergence": list(
                _sorted_unique_strings(data.get("priority_divergence"), "priority_divergence")
            ),
            "diligence_gaps": list(
                _sorted_unique_strings(data.get("diligence_gaps"), "diligence_gaps")
            ),
            "unresolved": unresolved,
            "promotion_eligible": promotion_eligible,
        }
        if body["actual_run_count"] != len(cast(list[str], body["run_ids"])):
            raise ValueError("comparison actual run count does not match run identifiers")
        if body["actual_run_count"] != len(cast(list[str], body["attestation_digests"])):
            raise ValueError("comparison actual run count does not match attestations")
        if body["actual_model_witnesses"] != len(witnesses):
            raise ValueError("comparison witness count does not match model witnesses")
        required_witnesses = cast(int, body["required_model_witnesses"])
        expected_runs = cast(int, body["expected_run_count"])
        actual_witnesses = body["actual_model_witnesses"]
        actual_runs = body["actual_run_count"]
        if required_witnesses > expected_runs:
            raise ValueError("comparison required witnesses exceed expected runs")
        if actual_witnesses > actual_runs:
            raise ValueError("comparison model witnesses exceed actual runs")
        run_ids = cast(list[str], body["run_ids"])
        witness_run_ids = sorted(run_id for witness in witnesses for run_id in witness.run_ids)
        if witness_run_ids != run_ids or len(witness_run_ids) != len(set(witness_run_ids)):
            raise ValueError("comparison model witnesses do not partition run identifiers")
        report_digests = cast(list[str], body["report_digests"])
        if bool(report_digests) != bool(run_ids) or len(report_digests) > len(run_ids):
            raise ValueError("comparison report digests do not match actual runs")
        agent_identities = cast(list[str], body["agent_identities"])
        if bool(agent_identities) != bool(run_ids) or len(agent_identities) > len(run_ids):
            raise ValueError("comparison agent identities do not match actual runs")
        expected_unresolved = _has_unresolved_evidence(body)
        if unresolved != expected_unresolved:
            raise ValueError("comparison unresolved status does not match its evidence")
        expected_promotion = purpose == "promotion" and not expected_unresolved
        if promotion_eligible != expected_promotion:
            raise ValueError("comparison promotion eligibility does not match its evidence")
        recorded = require_string(data.get("comparison_digest"), "comparison_digest")
        if recorded != canonical_digest(body):
            raise ValueError("comparison digest does not match its content")
        return cls(
            comparison_id=cast(str, body["comparison_id"]),
            campaign_id=cast(str, body["campaign_id"]),
            input_contract_digest=cast(str, body["input_contract_digest"]),
            created_by=cast(str, body["created_by"]),
            created_at=cast(str, body["created_at"]),
            purpose=cast(CampaignPurpose, body["purpose"]),
            expected_run_count=cast(int, body["expected_run_count"]),
            actual_run_count=body["actual_run_count"],
            required_model_witnesses=cast(int, body["required_model_witnesses"]),
            actual_model_witnesses=body["actual_model_witnesses"],
            run_ids=tuple(cast(list[str], body["run_ids"])),
            agent_identities=tuple(cast(list[str], body["agent_identities"])),
            attestation_digests=tuple(cast(list[str], body["attestation_digests"])),
            report_digests=tuple(cast(list[str], body["report_digests"])),
            review_digests=tuple(cast(list[str], body["review_digests"])),
            model_witnesses=witnesses,
            input_divergence=tuple(cast(list[str], body["input_divergence"])),
            coverage_divergence=tuple(cast(list[str], body["coverage_divergence"])),
            scanner_divergence=tuple(cast(list[str], body["scanner_divergence"])),
            adapter_divergence=tuple(cast(list[str], body["adapter_divergence"])),
            review_divergence=tuple(cast(list[str], body["review_divergence"])),
            priority_divergence=tuple(cast(list[str], body["priority_divergence"])),
            diligence_gaps=tuple(cast(list[str], body["diligence_gaps"])),
            unresolved=unresolved,
            promotion_eligible=promotion_eligible,
            comparison_digest=recorded,
        )


def _input_divergence(
    campaign: AuditCampaign,
    runs: tuple[StoredAuditRun, ...],
) -> tuple[str, ...]:
    """Return deviations from the immutable campaign input contract."""
    problems: list[str] = []
    for stored in runs:
        run = stored.attestation
        report = stored.report
        for field in campaign_input_divergence(campaign, report, run.toolchain):
            problems.append(f"run {run.run_id}: {field} differs from campaign contract")
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
    """Return missing, extra, duplicate, or divergent native-adapter evidence."""
    by_name: dict[str, dict[str, list[str]]] = {}
    problems: list[str] = []
    for stored in runs:
        run_id = stored.attestation.run_id
        expected = {
            adapter.name
            for adapter in stored.report.policy.native_audits
            if adapter.scope in {"full", "both"}
        }
        observed_names = [item.name for item in stored.attestation.adapter_evidence]
        observed = set(observed_names)
        missing = sorted(expected - observed)
        extra = sorted(observed - expected)
        duplicates = sorted(name for name in observed if observed_names.count(name) > 1)
        if missing:
            problems.append(f"run {run_id}: omitted native adapters {', '.join(missing)}")
        if extra:
            problems.append(
                f"run {run_id}: reported unexpected native adapters {', '.join(extra)}"
            )
        if duplicates:
            problems.append(f"run {run_id}: duplicated native adapters {', '.join(duplicates)}")
        for evidence in stored.attestation.adapter_evidence:
            signature = canonical_digest(evidence.to_dict())
            by_name.setdefault(evidence.name, {}).setdefault(signature, []).append(
                stored.attestation.run_id
            )
    for name, signatures in sorted(by_name.items()):
        if len(signatures) > 1:
            problems.append(
                f"native adapter {name} produced divergent execution/status/output evidence"
            )
    return tuple(sorted(problems))


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
    comparison_id = _identifier(comparison_id, "comparison_id")
    created_by = require_string(created_by, "created_by")
    created_at = _utc_timestamp(created_at, "created_at")
    input_problems = _input_divergence(campaign, runs)
    coverage_problems = _coverage_divergence(campaign, runs)
    scanner_problems = _scanner_divergence(runs)
    adapter_problems = _adapter_divergence(runs)
    review_problems, priority_problems = _review_divergence(reviews)
    diligence: list[str] = []
    if len(runs) < campaign.expected_runs:
        diligence.append(f"expected {campaign.expected_runs} runs, found {len(runs)}")
    raw_identities = tuple(stored.attestation.agent_identity for stored in runs)
    identities = tuple(sorted(set(raw_identities)))
    if len(raw_identities) != len(identities):
        diligence.append("multiple runs reuse the same agent identity")
    if any(stored.attestation.status != "complete" for stored in runs):
        diligence.append("one or more runs are incomplete")
    if not reviews:
        diligence.append("no independent review records were supplied")
    witnesses = collapse_model_witnesses(
        (
            stored.attestation.run_id,
            stored.attestation.inference_identity,
        )
        for stored in runs
    )
    if campaign.purpose == "promotion":
        diligence.extend(
            promotion_identity_gaps(
                witnesses,
                campaign.required_model_witnesses,
            )
        )
    elif len(witnesses) < campaign.required_model_witnesses:
        diligence.append(
            f"expected {campaign.required_model_witnesses} model-family witnesses, "
            f"found {len(witnesses)}"
        )
    run_ids = tuple(sorted(stored.attestation.run_id for stored in runs))
    attestation_digests = tuple(sorted(stored.attestation.attestation_digest for stored in runs))
    report_digests = tuple(sorted({stored.report.report_digest for stored in runs}))
    review_digests = tuple(
        sorted({review.review_digest for review_set in reviews for review in review_set})
    )
    body: dict[str, object] = {
        "schema_version": CAMPAIGN_SCHEMA_VERSION,
        "comparison_id": comparison_id,
        "campaign_id": campaign.campaign_id,
        "input_contract_digest": campaign.contract_digest,
        "created_by": created_by,
        "created_at": created_at,
        "purpose": campaign.purpose,
        "expected_run_count": campaign.expected_runs,
        "actual_run_count": len(runs),
        "required_model_witnesses": campaign.required_model_witnesses,
        "actual_model_witnesses": len(witnesses),
        "run_ids": list(run_ids),
        "agent_identities": list(identities),
        "attestation_digests": list(attestation_digests),
        "report_digests": list(report_digests),
        "review_digests": list(review_digests),
        "model_witnesses": [witness.to_dict() for witness in witnesses],
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
    promotion_eligible = campaign.purpose == "promotion" and not unresolved
    body["unresolved"] = unresolved
    body["promotion_eligible"] = promotion_eligible
    return AuditComparison(
        comparison_id=comparison_id,
        campaign_id=campaign.campaign_id,
        input_contract_digest=campaign.contract_digest,
        created_by=created_by,
        created_at=created_at,
        purpose=campaign.purpose,
        expected_run_count=campaign.expected_runs,
        actual_run_count=len(runs),
        required_model_witnesses=campaign.required_model_witnesses,
        actual_model_witnesses=len(witnesses),
        run_ids=run_ids,
        agent_identities=identities,
        attestation_digests=attestation_digests,
        report_digests=report_digests,
        review_digests=review_digests,
        model_witnesses=witnesses,
        input_divergence=input_problems,
        coverage_divergence=coverage_problems,
        scanner_divergence=scanner_problems,
        adapter_divergence=adapter_problems,
        review_divergence=review_problems,
        priority_divergence=priority_problems,
        diligence_gaps=tuple(sorted(diligence)),
        unresolved=unresolved,
        promotion_eligible=promotion_eligible,
        comparison_digest=canonical_digest(body),
    )
