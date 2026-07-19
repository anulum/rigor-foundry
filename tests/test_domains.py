# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — mandatory audit-domain coverage tests
"""Verify applicability decisions and exact portable/native control mapping."""

from __future__ import annotations

from repository_audit_git_repository import sample_tree_anchor

from rigor_foundry.domains import audit_domain_coverage, domain_governance_candidates
from rigor_foundry.models import AUDIT_DOMAINS, AdapterSpec, AuditDomainSpec, AuditPolicy


def test_missing_domain_decisions_and_controls_are_governance_candidates() -> None:
    """No repository can claim conformance while a required domain is uncovered."""
    anchor = sample_tree_anchor("rigor-foundry-policy.json")
    empty = domain_governance_candidates(AuditPolicy(), anchor)
    assert len(empty) == len(AUDIT_DOMAINS)
    assert {item.rule_id for item in empty} == {"GV003-undeclared-audit-domain"}

    decisions = tuple(
        AuditDomainSpec(name, "required", f"{name} applies") for name in AUDIT_DOMAINS
    )
    uncovered = domain_governance_candidates(
        AuditPolicy(audit_domains=decisions),
        anchor,
    )
    uncovered_names = {item.symbol for item in uncovered}
    assert "scientific-numerical-correctness" in uncovered_names
    assert "test-authenticity" not in uncovered_names
    assert "documentation-claims-ip" not in uncovered_names


def test_required_native_adapter_closes_only_its_declared_domain() -> None:
    """A native control cannot silently cover a domain it does not declare."""
    # api-abi-schema-compatibility has no portable control, so it isolates native-only closure.
    decisions = tuple(
        AuditDomainSpec(
            name,
            "required" if name == "api-abi-schema-compatibility" else "not-applicable",
            f"decision for {name}",
        )
        for name in AUDIT_DOMAINS
    )
    adapter = AdapterSpec(
        name="security-control",
        command=("{python}", "tools/security_control.py"),
        timeout_seconds=10,
        scope="full",
        working_directory=".",
        required=True,
        domains=("api-abi-schema-compatibility",),
    )
    policy = AuditPolicy(audit_domains=decisions, native_audits=(adapter,))
    configured = audit_domain_coverage(policy)
    security = next(item for item in configured if item.domain == "api-abi-schema-compatibility")
    assert security.controls == ("native:security-control",)
    not_attempted = audit_domain_coverage(policy, attempted_adapters=frozenset())
    security = next(
        item for item in not_attempted if item.domain == "api-abi-schema-compatibility"
    )
    assert security.controls == ()
    assert (
        domain_governance_candidates(
            policy,
            sample_tree_anchor("rigor-foundry-policy.json"),
        )
        == ()
    )
