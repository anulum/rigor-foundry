# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — rule-maturity case-manifest loader
"""Load explicit report and review references for rule calibration."""

from __future__ import annotations

import json
from pathlib import Path

from .audit_primitives import (
    require_exact_fields,
    require_integer,
    require_mapping,
    require_string,
)
from .model_primitives import require_digest, require_identifier, require_nonempty_strings
from .models import AuditReport, reviews_from_path
from .rule_maturity import (
    RuleMaturityPolicy,
    RuleMaturityReport,
    RuleReviewEvidence,
)

MATURITY_CASE_MANIFEST_SCHEMA_VERSION = "1.0"

_CASE_MANIFEST_FIELDS = frozenset({"schema_version", "policy", "cases"})
_CASE_FIELDS = frozenset(
    {
        "repository_id",
        "report",
        "review",
        "candidate_id",
        "reviewer_effort_seconds",
        "effort_evidence",
    }
)


def evaluate_rule_maturity_manifest(path: Path) -> RuleMaturityReport:
    """Build maturity decisions from explicit report/review file references.

    The manifest contains one threshold policy and an array of cases. Each
    case names a report, a review document, one candidate, a portable
    repository identity, measured reviewer effort, and retained effort-source
    references. Relative paths resolve from the manifest directory.

    Parameters
    ----------
    path:
        UTF-8 JSON case manifest owned by the invoking operator.
    """
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read rule maturity case manifest {path}") from exc
    data = require_mapping(value, "rule maturity case manifest")
    require_exact_fields(data, _CASE_MANIFEST_FIELDS, "rule maturity case manifest")
    if data.get("schema_version") != MATURITY_CASE_MANIFEST_SCHEMA_VERSION:
        raise ValueError("unsupported rule maturity case-manifest schema version")
    policy = RuleMaturityPolicy.from_dict(data.get("policy"))
    raw_cases = data.get("cases")
    if not isinstance(raw_cases, list):
        raise ValueError("rule maturity case manifest.cases must be an array")
    evidence: list[RuleReviewEvidence] = []
    for index, raw_case in enumerate(raw_cases):
        case = require_mapping(raw_case, f"rule maturity case manifest.cases[{index}]")
        require_exact_fields(
            case,
            _CASE_FIELDS,
            f"rule maturity case manifest.cases[{index}]",
        )
        report_path = _manifest_reference(
            path,
            case.get("report"),
            f"rule maturity case manifest.cases[{index}].report",
        )
        review_path = _manifest_reference(
            path,
            case.get("review"),
            f"rule maturity case manifest.cases[{index}].review",
        )
        report = AuditReport.from_path(report_path)
        candidate_id = require_digest(
            case.get("candidate_id"),
            f"rule maturity case manifest.cases[{index}].candidate_id",
        )
        matches = tuple(
            review
            for review in reviews_from_path(review_path)
            if review.candidate_id == candidate_id
        )
        if len(matches) != 1:
            raise ValueError(
                f"rule maturity case manifest.cases[{index}] must select exactly one review"
            )
        evidence.append(
            RuleReviewEvidence.build(
                report,
                matches[0],
                repository_id=require_identifier(
                    case.get("repository_id"),
                    f"rule maturity case manifest.cases[{index}].repository_id",
                ),
                reviewer_effort_seconds=require_integer(
                    case.get("reviewer_effort_seconds"),
                    f"rule maturity case manifest.cases[{index}].reviewer_effort_seconds",
                    minimum=1,
                ),
                effort_evidence=require_nonempty_strings(
                    case.get("effort_evidence"),
                    f"rule maturity case manifest.cases[{index}].effort_evidence",
                    minimum=1,
                ),
            )
        )
    return RuleMaturityReport.build(policy, tuple(evidence))


def _manifest_reference(manifest: Path, value: object, field: str) -> Path:
    """Resolve one explicit case-manifest path without guessing a location."""
    text = require_string(value, field)
    reference = Path(text)
    return reference if reference.is_absolute() else manifest.parent / reference
