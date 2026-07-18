# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — mandatory audit-domain coverage
"""Map mandatory quality domains to concrete portable and native controls."""

from __future__ import annotations

from dataclasses import dataclass

from .candidate_anchor import CandidateAnchor
from .models import AUDIT_DOMAINS, AuditPolicy, Candidate

_POLICY_PATH = "rigor-foundry-policy.json"
_PORTABLE_CONTROLS = {
    "test-authenticity": "portable:test-authenticity",
    "architecture-and-wiring": "portable:architecture-and-wiring",
    "godfile-responsibility": "portable:godfile-responsibility",
    "ownership-and-maintenance": "portable:ownership-and-maintenance",
    "application-security": "portable:application-security",
    "reliability-and-concurrency": "portable:reliability-and-concurrency",
    "supply-chain": "portable:supply-chain",
}


@dataclass(frozen=True)
class DomainCoverage:
    """Concrete evidence controls available for one declared audit domain."""

    domain: str
    applicability: str
    controls: tuple[str, ...]


def audit_domain_coverage(
    policy: AuditPolicy,
    *,
    attempted_adapters: frozenset[str] | None = None,
) -> tuple[DomainCoverage, ...]:
    """Return deterministic coverage for every declared mandatory domain.

    Parameters
    ----------
    policy:
        Repository audit policy.
    attempted_adapters:
        Optional exact adapter-name set attempted by one run. If omitted,
        configured required adapters are treated as available controls.

    Returns
    -------
    tuple[DomainCoverage, ...]
        One entry for every domain in the normative registry.

    """
    declared = {item.name: item for item in policy.audit_domains}
    coverage: list[DomainCoverage] = []
    for domain_name in AUDIT_DOMAINS:
        decision = declared.get(domain_name)
        if decision is None:
            coverage.append(DomainCoverage(domain_name, "undeclared", ()))
            continue
        controls: list[str] = []
        portable = _PORTABLE_CONTROLS.get(domain_name)
        if portable is not None and decision.applicability == "required":
            controls.append(portable)
        controls.extend(
            f"native:{adapter.name}"
            for adapter in policy.native_audits
            if adapter.required
            and domain_name in adapter.domains
            and (attempted_adapters is None or adapter.name in attempted_adapters)
        )
        coverage.append(
            DomainCoverage(
                domain=domain_name,
                applicability=decision.applicability,
                controls=tuple(sorted(controls)),
            )
        )
    return tuple(coverage)


def domain_governance_candidates(
    policy: AuditPolicy,
    policy_anchor: CandidateAnchor,
) -> tuple[Candidate, ...]:
    """Return candidates for missing applicability or evidence controls."""
    candidates: list[Candidate] = []
    for coverage in audit_domain_coverage(policy):
        if coverage.applicability == "undeclared":
            candidates.append(
                Candidate.build(
                    category="governance",
                    rule_id="GV003-undeclared-audit-domain",
                    anchor=policy_anchor,
                    symbol=coverage.domain,
                    evidence=f"mandatory audit domain is undeclared: {coverage.domain}",
                    confidence="high",
                    rationale="Repository-specific audit ownership is missing or ambiguous.",
                    verification=(
                        "Read the repository rules and risk model, then declare the domain required "
                        "or justify not-applicable with repository-specific evidence."
                    ),
                )
            )
        elif coverage.applicability == "required" and not coverage.controls:
            candidates.append(
                Candidate.build(
                    category="governance",
                    rule_id="GV004-uncontrolled-required-domain",
                    anchor=policy_anchor,
                    symbol=coverage.domain,
                    evidence=(
                        f"required domain has no active evidence control: {coverage.domain}"
                    ),
                    confidence="high",
                    rationale=(
                        "A required quality domain cannot support a repository conformance claim "
                        "without a portable rule or required native adapter."
                    ),
                    verification=(
                        "Read the domain threat/risk model, wire a real time-bounded repository audit "
                        "or justify not-applicable with repository-specific evidence; do not copy a "
                        "control name that does not exercise this codebase."
                    ),
                )
            )
    return tuple(candidates)
