# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — signed EU CRA control pack
"""Build the fixed CRA mapping payload for an externally supplied signature."""

from __future__ import annotations

from .models import Severity, canonical_digest
from .standard_pack import (
    ControlDefinition,
    EvidenceContract,
    PackSignature,
    RemediationContract,
    StandardPack,
)

CRA_PACK_ID = "eu-cra-2024-2847"
CRA_PACK_VERSION = "1.0.0"
CRA_PACK_SOURCE_URI = "urn:rigor-foundry:eu-cra-2024-2847-control-map:1.0.0"
CRA_PACK_LICENCE = "Apache-2.0 mapping metadata; official EU legal text not reproduced"


def _control(
    control_id: str,
    title: str,
    domain: str,
    severity: Severity,
    adapter: str,
    evidence_types: tuple[str, ...],
    procedure: str,
) -> ControlDefinition:
    """Build one probation-ready control with explicit evidence boundaries."""
    return ControlDefinition.build(
        control_id=f"{CRA_PACK_ID}/{control_id}",
        version="1.0.0",
        title=title,
        domain=domain,
        severity=severity,
        target_level="production",
        mode="require",
        default_applicable=True,
        condition=None,
        evidence=EvidenceContract.build(
            contract_id=f"cra-{control_id}-evidence",
            required_adapters=(adapter,),
            evidence_types=evidence_types,
            freshness_seconds=31_536_000,
            minimum_independent_reviewers=1,
        ),
        remediation=RemediationContract.build(
            dependencies=(),
            procedure_ids=(procedure,),
            acceptance_gates=("independent-evidence-review",),
            reopen_triggers=("repository-or-cra-evidence-digest-change",),
            independent_verifier_required=True,
        ),
    )


def cra_controls() -> tuple[ControlDefinition, ...]:
    """Return the fixed control set in official-provision order."""
    return (
        _control(
            "annex-I-part-I-2-a",
            "Review known exploitable vulnerabilities before release",
            "application-security",
            "P1",
            "rigor-scan",
            ("anchored-security-candidates", "independent-review"),
            "cra-known-exploitable-vulnerability-review",
        ),
        _control(
            "annex-I-part-II-1",
            "Maintain an imported component inventory",
            "supply-chain",
            "P1",
            "rigor-cra-state",
            ("component-inventory", "repository-binding"),
            "cra-component-inventory-review",
        ),
        _control(
            "annex-I-part-II-2",
            "Track vulnerability remediation and security updates",
            "application-security",
            "P1",
            "rigor-cra-state",
            ("event-revision", "security-update-reference"),
            "cra-remediation-evidence-review",
        ),
        _control(
            "annex-I-part-II-3",
            "Retain effective and regular security-test evidence",
            "test-authenticity",
            "P2",
            "rigor-scan",
            ("test-authenticity-report", "independent-review"),
            "cra-security-test-review",
        ),
        _control(
            "annex-I-part-II-4",
            "Track fixed-vulnerability advisory publication or justified delay",
            "documentation-claims-ip",
            "P1",
            "rigor-cra-state",
            ("fixed-vulnerability-advisory", "publication-or-delay-evidence"),
            "cra-fixed-vulnerability-advisory-review",
        ),
        _control(
            "annex-I-part-II-5",
            "Maintain a tracked coordinated-vulnerability-disclosure policy",
            "ownership-and-maintenance",
            "P1",
            "rigor-scan",
            ("tracked-cvd-policy", "independent-review"),
            "cra-cvd-policy-review",
        ),
        _control(
            "annex-I-part-II-6",
            "Maintain a public vulnerability contact and sharing process",
            "documentation-claims-ip",
            "P1",
            "rigor-scan",
            ("public-contact", "operational-contact-review"),
            "cra-public-contact-review",
        ),
        _control(
            "annex-I-part-II-7-8",
            "Retain operator evidence for secure and timely update distribution",
            "packaging-deployment-iac",
            "P1",
            "operator-update-distribution",
            ("update-distribution", "user-advisory-message"),
            "cra-update-distribution-review",
        ),
        _control(
            "article-14",
            "Prepare reporting timelines, drafts, and operator-bound receipts",
            "operations-and-observability",
            "P0",
            "rigor-cra-state",
            ("reporting-timeline", "draft-or-receipt"),
            "cra-article-14-evidence-review",
        ),
    )


def cra_source_digest() -> str:
    """Digest the original mapping manifest, not the external legal text bytes."""
    return canonical_digest(
        {
            "mapping_id": CRA_PACK_SOURCE_URI,
            "official_source": "https://eur-lex.europa.eu/eli/reg/2024/2847/oj",
            "official_identifier": "CELEX:32024R2847",
            "official_version": "2024-11-20",
            "control_digests": [item.control_digest for item in cra_controls()],
        }
    )


def cra_pack_payload_digest() -> str:
    """Return the exact mapping payload digest that a pack key must sign."""
    return StandardPack.payload_digest(
        pack_id=CRA_PACK_ID,
        version=CRA_PACK_VERSION,
        source_uri=CRA_PACK_SOURCE_URI,
        source_digest=cra_source_digest(),
        licence=CRA_PACK_LICENCE,
        controls=cra_controls(),
    )


def build_cra_pack(signature: PackSignature) -> StandardPack:
    """Build the fixed CRA pack after verifying signature-payload binding."""
    return StandardPack.build(
        pack_id=CRA_PACK_ID,
        version=CRA_PACK_VERSION,
        source_uri=CRA_PACK_SOURCE_URI,
        source_digest=cra_source_digest(),
        licence=CRA_PACK_LICENCE,
        signature=signature,
        controls=cra_controls(),
    )
