# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — exact versioned protocol field contracts
"""Declare exact serialized fields shared by public protocol parsers."""

from __future__ import annotations

PROJECT_INTENT_FIELDS: frozenset[str] = frozenset(
    {
        "schema_version",
        "risk_class",
        "regulatory_classes",
        "target_maturity",
        "requirements",
        "intent_digest",
    }
)

PROJECT_PROFILE_FIELDS: frozenset[str] = frozenset(
    {
        "schema_version",
        "profile_id",
        "intent",
        "packs",
        "variables",
        "assignments",
        "applicability",
        "overlays",
        "waivers",
        "created_by",
        "created_at",
        "profile_digest",
    }
)

EVIDENCE_CONTRACT_FIELDS: frozenset[str] = frozenset(
    {
        "schema_version",
        "contract_id",
        "required_adapters",
        "evidence_types",
        "freshness_seconds",
        "minimum_independent_reviewers",
        "contract_digest",
    }
)

CONTROL_DEFINITION_FIELDS: frozenset[str] = frozenset(
    {
        "schema_version",
        "control_id",
        "version",
        "title",
        "domain",
        "severity",
        "target_level",
        "mode",
        "default_applicable",
        "condition",
        "evidence",
        "remediation",
        "control_digest",
    }
)

WORK_TASK_FIELDS: frozenset[str] = frozenset(
    {
        "schema_version",
        "task_id",
        "candidate",
        "source_report_digest",
        "source_policy_digest",
        "source_rule_pack_digest",
        "baseline_head",
        "baseline_head_tree",
        "baseline_tracked_content_digest",
        "title",
        "severity",
        "rationale",
        "production_impact",
        "suggested_owner",
        "dependencies",
        "acceptance_gates",
        "affected_surfaces",
        "prohibited_shortcuts",
        "required_verifier",
        "review_digest",
        "created_by",
        "created_at",
        "definition_digest",
    }
)
