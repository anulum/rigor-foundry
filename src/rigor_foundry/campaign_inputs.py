# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — canonical campaign input relation
"""Compare every report and runtime input against one frozen campaign."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from .ignored_inventory import IgnoredInventoryEvidence

if TYPE_CHECKING:
    from .campaign_models import AuditCampaign, ToolchainIdentity
    from .models import AuditReport


def parse_ignored_evidence_array(value: object) -> list[dict[str, object]]:
    """Parse ignored evidence into its canonical campaign representation."""
    if not isinstance(value, list):
        raise ValueError("ignored_inventory_evidence must be an array")
    return [
        IgnoredInventoryEvidence.from_dict(item, index).to_dict()
        for index, item in enumerate(value)
    ]


def campaign_input_divergence(
    campaign: AuditCampaign,
    report: AuditReport,
    toolchain: ToolchainIdentity,
) -> tuple[str, ...]:
    """Return every report input that differs from a frozen campaign.

    The comparison covers the complete input projection represented by the
    campaign contract. Callers may reject the relation or retain the returned
    fields as unresolved divergence evidence.

    Parameters
    ----------
    campaign:
        Frozen campaign input contract.
    report:
        Candidate report presented as one campaign run.
    toolchain:
        Runtime identity recorded by the run attestation.

    Returns
    -------
    tuple[str, ...]
        Stable field names whose observed values differ from the contract.
    """
    required_domains = tuple(
        sorted(
            domain.name
            for domain in report.policy.audit_domains
            if domain.applicability == "required"
        )
    )
    observed: dict[str, object] = {
        "repository_root": str(Path(report.repository_root).resolve(strict=True)),
        "head": report.head,
        "head_tree": report.head_tree,
        "git_object_format": report.git_object_format,
        "branch": report.branch,
        "tracked_content_digest": report.tracked_content_digest,
        "dirty_paths": report.dirty_paths,
        "tracked_file_count": report.tracked_file_count,
        "policy_digest": report.policy_digest,
        "ignored_inventory_evidence": tuple(
            item.to_dict() for item in report.ignored_inventory_evidence
        ),
        "ignored_inventory_digest": report.ignored_inventory_digest,
        "rule_pack_version": report.rule_pack_version,
        "rule_pack_digest": report.rule_pack_digest,
        "scanner_version": report.scanner_version,
        "required_domains": required_domains,
        "git_provenance": report.git_provenance,
        "toolchain": toolchain,
    }
    expected: dict[str, object] = {
        "repository_root": str(Path(campaign.repository_root).resolve(strict=True)),
        "head": campaign.head,
        "head_tree": campaign.head_tree,
        "git_object_format": campaign.git_object_format,
        "branch": campaign.branch,
        "tracked_content_digest": campaign.tracked_content_digest,
        "dirty_paths": campaign.dirty_paths,
        "tracked_file_count": campaign.tracked_file_count,
        "policy_digest": campaign.policy_digest,
        "ignored_inventory_evidence": tuple(
            item.to_dict() for item in campaign.ignored_inventory_evidence
        ),
        "ignored_inventory_digest": campaign.ignored_inventory_digest,
        "rule_pack_version": campaign.rule_pack_version,
        "rule_pack_digest": campaign.rule_pack_digest,
        "scanner_version": campaign.scanner_version,
        "required_domains": campaign.required_domains,
        "git_provenance": campaign.git_provenance,
        "toolchain": campaign.toolchain,
    }
    return tuple(field for field in expected if observed[field] != expected[field])


def validate_campaign_input(
    campaign: AuditCampaign,
    report: AuditReport,
    toolchain: ToolchainIdentity,
) -> None:
    """Reject a report or runtime that differs from a campaign contract."""
    divergence = campaign_input_divergence(campaign, report, toolchain)
    if divergence:
        raise ValueError("campaign input divergence: " + ", ".join(divergence))
