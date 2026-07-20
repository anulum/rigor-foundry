# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — CRA probation rule family
"""Emit explicit-scope CRA readiness candidates from exact offline evidence."""

from __future__ import annotations

import re
from typing import cast

from .candidate_anchor import CandidateAnchor, TrackedBlobAnchor
from .cra_inventory import RepositoryBinding
from .cra_p1_store import CraP1Store
from .cra_policy import CraPolicy
from .cra_store import CraEventState, CraRepository
from .git_inventory import GitInventory
from .ignored_inventory import IgnoredInventoryEvidence
from .internal_storage import exclusive_lock
from .models import AuditPolicy, Candidate

_PUBLIC_CONTACT = re.compile(
    r"(?i)(?<![A-Z0-9._%+-])[A-Z0-9._%+-]+@[A-Z0-9-]+(?:\.[A-Z0-9-]+)+(?![A-Z0-9_%+-])"
)


def _candidate(
    anchor: CandidateAnchor,
    *,
    rule_id: str,
    symbol: str,
    evidence: str,
    rationale: str,
    verification: str,
) -> Candidate:
    """Build one probationary CRA candidate with no compliance verdict."""
    return Candidate.build(
        category="regulatory-readiness",
        rule_id=rule_id,
        anchor=anchor,
        symbol=symbol,
        evidence=evidence,
        confidence="high",
        rationale=rationale,
        verification=verification,
    )


def _static_policy_candidates(
    inventory: GitInventory,
    policy: AuditPolicy,
    policy_anchor: CandidateAnchor,
) -> tuple[Candidate, ...]:
    """Evaluate the tracked CVD policy path and public-contact signal."""
    cra = cast(CraPolicy, policy.cra)
    path = cast(str, cra.disclosure_policy_path)
    matches = tuple(item for item in inventory.files if item.path == path)
    if len(matches) != 1 or matches[0].text is None or matches[0].content_kind != "text":
        return (
            _candidate(
                policy_anchor,
                rule_id="CR001-missing-disclosure-policy",
                symbol=cra.product_key or "",
                evidence=f"declared disclosure_policy_path={path}; tracked UTF-8 text unavailable",
                rationale=(
                    "Explicit CRA scope names a coordinated-vulnerability-disclosure policy that "
                    "is not available as one tracked text file."
                ),
                verification=(
                    "Confirm applicability, then add and independently review the declared tracked "
                    "CVD policy; this candidate is not a compliance verdict."
                ),
            ),
        )
    tracked = matches[0]
    tracked_text = cast(str, tracked.text)
    if _PUBLIC_CONTACT.search(tracked_text) is not None:
        return ()
    return (
        _candidate(
            TrackedBlobAnchor.build(tracked, line_start=1),
            rule_id="CR002-missing-security-contact",
            symbol=cra.product_key or "",
            evidence=f"tracked disclosure policy {path} has no bounded public email signal",
            rationale=(
                "The declared tracked CVD policy did not expose a syntactically bounded public "
                "contact address."
            ),
            verification=(
                "Review the complete public disclosure policy and verify a monitored public contact "
                "channel; aliases, routing, and response operation require independent evidence."
            ),
        ),
    )


def _started_stages(state: CraEventState) -> tuple[str, ...]:
    """Return reporting stages whose operational clock has an available anchor."""
    result = ["early-warning", "notification"]
    event = state.event
    if event.track == "vulnerability" and event.corrective_measure_available_at is not None:
        result.append("final-report")
    incident_final_started = event.track == "incident" and (
        any(item.stage == "notification" for item in state.receipts)
        or any(item.stage == "notification" for item in state.skips)
    )
    if incident_final_started:
        result.append("final-report")
    if event.intermediate_due_at is not None:
        result.append("intermediate")
    return tuple(result)


def _timeline_candidates(
    repository: CraRepository,
    policy_anchor: CandidateAnchor,
    product_key: str,
) -> tuple[Candidate, ...]:
    """Emit missing stage and fixed-vulnerability advisory evidence candidates."""
    candidates: list[Candidate] = []
    for event_key in repository.event_keys():
        state = repository.event_state(event_key)
        if state.event.product_key != product_key:
            continue
        covered = (
            {item.stage for item in state.drafts}
            | {item.stage for item in state.receipts}
            | {item.stage for item in state.skips}
        )
        for stage in _started_stages(state):
            if stage in covered:
                continue
            candidates.append(
                _candidate(
                    policy_anchor,
                    rule_id="CR004-untracked-reporting-timeline",
                    symbol=f"{event_key}:{stage}",
                    evidence=(
                        f"event_revision={state.event.revision_digest}; stage={stage}; "
                        "draft=false; receipt=false; skip=false"
                    ),
                    rationale=(
                        "An operational reporting-stage clock has an evidence anchor but no bound "
                        "draft, receipt, or explicit already-provided skip."
                    ),
                    verification=(
                        "Recompute the exact offline timeline and inspect operator evidence; only the "
                        "manufacturer decides applicability and performs any submission."
                    ),
                )
            )
        if state.event.track != "vulnerability" or state.event.status not in {
            "fix-available",
            "disclosed",
        }:
            continue
        advisory = repository.advisory(event_key)
        if advisory is not None and advisory.state in {"published", "justified-delay"}:
            continue
        candidates.append(
            _candidate(
                policy_anchor,
                rule_id="CR006-fixed-vuln-without-advisory",
                symbol=event_key,
                evidence=(
                    f"event_revision={state.event.revision_digest}; status={state.event.status}; "
                    f"advisory_state={None if advisory is None else advisory.state}"
                ),
                rationale=(
                    "Operator-declared fixed-vulnerability state lacks a verified advisory "
                    "publication record or justified-delay review record."
                ),
                verification=(
                    "Inspect the fixed-vulnerability and security-update evidence, then bind only "
                    "operator-confirmed publication or justified-delay records; RIGOR-FOUNDRY never "
                    "publishes automatically."
                ),
            )
        )
    return tuple(candidates)


def _state_candidates(
    inventory: GitInventory,
    policy: AuditPolicy,
    policy_anchor: CandidateAnchor,
) -> tuple[Candidate, ...]:
    """Read one atomic verified CRA state snapshot and derive dynamic signals."""
    cra = cast(CraPolicy, policy.cra)
    product_key = cast(str, cra.product_key)
    repository = CraRepository.open(inventory.root)
    with exclusive_lock(repository.lock_path):
        registration = repository.current_registration(product_key)
        candidates: list[Candidate] = []
        if registration.support_period_months < 60 and (
            registration.expected_use_months is None
            or registration.support_period_months < registration.expected_use_months
        ):
            candidates.append(
                _candidate(
                    policy_anchor,
                    rule_id="CR005-support-period-too-short",
                    symbol=registration.product_key,
                    evidence=(
                        f"registration={registration.registration_digest}; "
                        f"support_months={registration.support_period_months}; "
                        f"expected_use_months={registration.expected_use_months}; "
                        f"expected_use_evidence={registration.expected_use_evidence_ref}"
                    ),
                    rationale=(
                        "The declared support period is below 60 months and no internally consistent "
                        "shorter expected-use relation currently supports it."
                    ),
                    verification=(
                        "Verify the product's reasonably expected use time and retained evidence "
                        "against the current official act; a below-60 declaration is not by itself a "
                        "legal failure."
                    ),
                )
            )
        try:
            component_inventory = CraP1Store(repository).current_inventory(product_key)
        except ValueError as exc:
            if str(exc) != "product has no verified component inventory":
                raise
        else:
            current = RepositoryBinding.from_inventory(inventory)
            if component_inventory.tree_binding != current:
                candidates.append(
                    _candidate(
                        policy_anchor,
                        rule_id="CR003-stale-component-inventory",
                        symbol=registration.product_key,
                        evidence=(
                            f"inventory={component_inventory.inventory_digest}; "
                            f"inventory_tree={component_inventory.tree_binding.tree_oid}; "
                            f"current_tree={current.tree_oid}; "
                            f"inventory_content={component_inventory.tree_binding.tracked_content_sha256}; "
                            f"current_content={current.tracked_content_sha256}"
                        ),
                        rationale=(
                            "The newest imported component inventory is bound to a different exact "
                            "repository state."
                        ),
                        verification=(
                            "Review repository/SBOM drift and import a new externally generated SBOM "
                            "only when appropriate; RIGOR-FOUNDRY does not generate an SBOM."
                        ),
                    )
                )
        candidates.extend(_timeline_candidates(repository, policy_anchor, product_key))
        return tuple(candidates)


def scan_cra(
    inventory: GitInventory,
    policy: AuditPolicy,
    policy_anchor: CandidateAnchor,
    ignored_evidence: tuple[IgnoredInventoryEvidence, ...],
) -> tuple[Candidate, ...]:
    """Emit CRA candidates only for one explicit required applicability decision."""
    if policy.cra is None or policy.cra.applicability == "not-applicable":
        return ()
    static = _static_policy_candidates(inventory, policy, policy_anchor)
    state = tuple(
        item for item in ignored_evidence if item.evidence_id == policy.cra.state_evidence_id
    )
    if len(state) != 1 or state[0].status != "observed" or state[0].observed_kind != "directory":
        return (
            *static,
            _candidate(
                policy_anchor,
                rule_id="CR004-untracked-reporting-timeline",
                symbol=policy.cra.product_key or "",
                evidence="declared .rigor/cra state is missing or unavailable",
                rationale=(
                    "Explicit CRA scope has no readable declared offline state, so reporting-stage "
                    "evidence cannot be assessed."
                ),
                verification=(
                    "Bootstrap or recover the local ignored CRA evidence tree, then repeat the scan; "
                    "absence is unresolved evidence, not a passing result."
                ),
            ),
        )
    return (*static, *_state_candidates(inventory, policy, policy_anchor))
