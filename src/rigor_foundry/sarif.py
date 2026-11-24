# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — deterministic SARIF 2.1.0 export
"""Export audit candidates and evidence reviews without conflating their states."""

from __future__ import annotations

import json
from pathlib import PurePosixPath
from typing import cast

from .candidate_anchor import Candidate, RepositoryTreeAnchor
from .cwe_mapping import (
    CWE_INFORMATION_URI,
    CWE_ORGANIZATION,
    CWE_TAXONOMY_NAME,
    CweCatalogue,
    CweMapping,
    cwe_catalogue,
)
from .models import AuditReport, ReviewRecord
from .review import validate_reviews
from .rule_catalogue import (
    CANDIDATE_NOT_VERDICT,
    RULE_CATALOGUE_PATH,
    rule_catalogue_anchor,
    rule_guidance,
)
from .rule_guidance import RuleGuidance
from .rules import RULES
from .sarif_github_profile import (
    GITHUB_CODE_SCANNING_PROFILE,
    github_code_scanning_document,
    require_github_limits,
)
from .version import __version__

SARIF_SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"

_DOCUMENTATION_ROOT = "https://github.com/anulum/RIGOR-FOUNDRY"
CATEGORY_TAXONOMY_NAME = "RigorFoundry rule categories"
_URI_SAFE_BYTES = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/-._~")
_SEVERITY_LEVEL = {
    "P0": "error",
    "P1": "error",
    "P2": "warning",
    "P3": "note",
    "P4": "note",
}


def _artifact_uri(path: str) -> str:
    """Return one percent-encoded repository-relative artifact URI."""
    canonical = PurePosixPath(path).as_posix()
    return "".join(
        chr(byte) if byte in _URI_SAFE_BYTES else f"%{byte:02X}"
        for byte in canonical.encode("utf-8")
    )


def _rule_categories() -> tuple[str, ...]:
    """Return the rule categories in first-registry order, the category taxa order."""
    return tuple(dict.fromkeys(rule.category for rule in RULES))


def _rule_help(summary: str, guidance: RuleGuidance) -> dict[str, str]:
    """Return the plain-text and Markdown help of one rule from its fixed guidance."""
    cases = guidance.all_cases()
    text = [summary]
    markdown = [summary]
    for case in cases:
        when = f"When {case.condition}:\n" if case.condition else ""
        text.append(f"{when}Why it matters: {case.rationale}\nHow to verify: {case.verification}")
        markdown.append(
            (f"**When {case.condition}.**\n\n" if case.condition else "")
            + f"**Why it matters.** {case.rationale}\n\n**How to verify.** {case.verification}"
        )
    markdown.append(CANDIDATE_NOT_VERDICT)
    return {"text": "\n\n".join(text), "markdown": "\n\n".join(markdown)}


def _rule_descriptor(
    index: int,
    guidance: RuleGuidance,
    category_index: int,
    cwe: tuple[CweMapping, int] | None,
) -> dict[str, object]:
    """Return stable SARIF metadata for one rule-registry position.

    ``cwe`` is the rule's reviewed CWE mapping and its CWE taxon index, or ``None`` for an
    unmapped rule, which then carries no CWE relationship.
    """
    rule = RULES[index]
    relationships: list[dict[str, object]] = [
        {
            "target": {
                "id": rule.category,
                "index": category_index,
                "toolComponent": {"name": CATEGORY_TAXONOMY_NAME, "index": 0},
            },
            "kinds": ["subset"],
        }
    ]
    if cwe is not None:
        relationships.append(
            {
                "target": {
                    "id": str(cwe[0].cwe_id),
                    "index": cwe[1],
                    "toolComponent": {"name": CWE_TAXONOMY_NAME, "index": 1},
                },
                "kinds": [cwe[0].kind],
            }
        )
    return {
        "id": rule.rule_id,
        "name": rule.rule_id,
        "shortDescription": {"text": rule.summary},
        "fullDescription": {"text": " ".join(case.rationale for case in guidance.all_cases())},
        "help": _rule_help(rule.summary, guidance),
        "helpUri": (
            f"{_DOCUMENTATION_ROOT}/blob/main/{RULE_CATALOGUE_PATH}"
            f"#{rule_catalogue_anchor(rule.rule_id)}"
        ),
        "properties": {
            "category": rule.category,
            "introduced": rule.introduced,
            "tags": ["rigor-foundry", rule.category],
        },
        "relationships": relationships,
    }


def _cwe_taxonomy(catalogue: CweCatalogue) -> dict[str, object]:
    """Return the pinned CWE taxonomy, holding each reviewed mapping's CWE id once."""
    return {
        "name": CWE_TAXONOMY_NAME,
        "organization": CWE_ORGANIZATION,
        "version": catalogue.version,
        "releaseDateUtc": catalogue.release_date,
        "informationUri": CWE_INFORMATION_URI,
        "downloadUri": catalogue.download_uri,
        "isComprehensive": False,
        "taxa": [{"id": str(cwe_id)} for cwe_id in catalogue.taxa()],
    }


def _state(review: ReviewRecord | None) -> tuple[str, str, str]:
    """Map candidate/review state to SARIF kind, level, and neutral message."""
    if review is None or review.decision == "needs-evidence":
        return "review", "note", "Audit candidate requires evidence review."
    if review.decision == "valid":
        severity = cast(str, review.severity)  # Enforced by validate_reviews.
        return "fail", _SEVERITY_LEVEL[severity], review.title
    if review.decision == "invalid":
        return "notApplicable", "none", "Audit candidate was reviewed as invalid."
    return "informational", "note", "Audit candidate is an accepted boundary."


def _anchor_properties(candidate: Candidate) -> dict[str, object]:
    """Return exact machine-verifiable anchor evidence for one result."""
    anchor = candidate.anchor
    properties: dict[str, object] = {
        "schemaVersion": anchor.to_dict()["schema_version"],
        "kind": anchor.kind,
        "path": anchor.path,
        "lineStart": anchor.line_start,
        "lineEnd": anchor.line_end,
    }
    if isinstance(anchor, RepositoryTreeAnchor):
        properties["treeOid"] = anchor.tree_oid
        properties["trackedContentSha256"] = anchor.tracked_content_sha256
    else:
        properties["blobOid"] = anchor.blob_oid
        properties["contentSha256"] = anchor.content_sha256
    return properties


def _result(
    report: AuditReport,
    candidate: Candidate,
    review: ReviewRecord | None,
    rule_index: int,
) -> dict[str, object]:
    """Return one deterministic SARIF result preserving candidate and verdict state."""
    kind, level, message = _state(review)
    review_properties: dict[str, object] | None = None
    if review is not None:
        review_properties = {
            "digest": review.review_digest,
            "decision": review.decision,
            "severity": review.severity,
            "severityProvenance": "review-record" if review.severity is not None else "none",
            "reviewer": review.reviewer,
            "reviewedAt": review.reviewed_at,
        }
    properties: dict[str, object] = {
        "rigorFoundry/candidateId": candidate.candidate_id,
        "rigorFoundry/candidateState": "candidate",
        "rigorFoundry/verdictState": review.decision if review is not None else "unreviewed",
        "rigorFoundry/reportDigest": report.report_digest,
        "rigorFoundry/head": report.head,
        "rigorFoundry/headTree": report.head_tree,
        "rigorFoundry/gitObjectFormat": report.git_object_format,
        "rigorFoundry/rulePackVersion": report.rule_pack_version,
        "rigorFoundry/rulePackDigest": report.rule_pack_digest,
        "rigorFoundry/anchor": _anchor_properties(candidate),
        "rigorFoundry/confidence": candidate.confidence,
        "rigorFoundry/evidence": candidate.evidence,
        "rigorFoundry/verification": candidate.verification,
    }
    if review_properties is not None:
        properties["rigorFoundry/review"] = review_properties
    anchor = candidate.anchor
    return {
        "ruleId": candidate.rule_id,
        "ruleIndex": rule_index,
        "kind": kind,
        "level": level,
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _artifact_uri(anchor.path)},
                    "region": {
                        "startLine": anchor.line_start,
                        "endLine": anchor.line_end,
                    },
                }
            }
        ],
        "fingerprints": {"rigorFoundry/v1": candidate.candidate_id},
        "properties": properties,
    }


def _sarif_document(
    report: AuditReport,
    reviews: tuple[ReviewRecord, ...] = (),
) -> dict[str, object]:
    """Build a deterministic SARIF 2.1.0 document.

    Parameters
    ----------
    report:
        Integrity-verified repository audit report.
    reviews:
        Optional evidence decisions for candidates in ``report``.

    Returns
    -------
    dict[str, object]
        Schema-compatible SARIF document containing every audit candidate.

    Raises
    ------
    ValueError
        If reviews are duplicated, incomplete, or belong to another report.
    """
    errors = validate_reviews(report, reviews)
    if errors:
        raise ValueError("invalid SARIF reviews: " + "; ".join(errors))
    review_by_candidate = {review.candidate_id: review for review in reviews}
    rule_index = {rule.rule_id: index for index, rule in enumerate(RULES)}
    guidance = rule_guidance()
    categories = _rule_categories()
    category_index = {category: index for index, category in enumerate(categories)}
    catalogue = cwe_catalogue()
    cwe_index = {cwe_id: index for index, cwe_id in enumerate(catalogue.taxa())}
    cwe_by_rule = {
        rule_id: (mapping, cwe_index[mapping.cwe_id])
        for rule_id, mapping in catalogue.mappings.items()
    }
    results = [
        _result(
            report,
            candidate,
            review_by_candidate.get(candidate.candidate_id),
            rule_index[candidate.rule_id],
        )
        for candidate in report.candidates
    ]
    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RigorFoundry",
                        "semanticVersion": __version__,
                        "informationUri": _DOCUMENTATION_ROOT,
                        "rules": [
                            _rule_descriptor(
                                index,
                                guidance[rule.rule_id],
                                category_index[rule.category],
                                cwe_by_rule.get(rule.rule_id),
                            )
                            for index, rule in enumerate(RULES)
                        ],
                    }
                },
                "automationDetails": {"id": f"rigor-foundry/{report.report_digest}"},
                "taxonomies": [
                    {
                        "name": CATEGORY_TAXONOMY_NAME,
                        "informationUri": f"{_DOCUMENTATION_ROOT}/blob/main/{RULE_CATALOGUE_PATH}",
                        "taxa": [{"id": category, "name": category} for category in categories],
                    },
                    _cwe_taxonomy(catalogue),
                ],
                "results": results,
                "properties": {
                    "rigorFoundry/reportDigest": report.report_digest,
                    "rigorFoundry/trackedContentDigest": report.tracked_content_digest,
                    "rigorFoundry/policyDigest": report.policy_digest,
                    "rigorFoundry/ignoredInventoryDigest": report.ignored_inventory_digest,
                    "rigorFoundry/branch": report.branch,
                    "rigorFoundry/head": report.head,
                    "rigorFoundry/headTree": report.head_tree,
                    "rigorFoundry/gitObjectFormat": report.git_object_format,
                    "rigorFoundry/rulePackVersion": report.rule_pack_version,
                    "rigorFoundry/rulePackDigest": report.rule_pack_digest,
                },
            }
        ],
    }


def _render(document: dict[str, object]) -> str:
    """Render one SARIF document as deterministic, stable-key-order JSON with a newline."""
    return (
        json.dumps(document, allow_nan=False, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    )


def report_sarif(
    report: AuditReport,
    reviews: tuple[ReviewRecord, ...] = (),
    *,
    profile: str | None = None,
) -> str:
    """Render deterministic SARIF 2.1.0 JSON with a trailing newline.

    Parameters
    ----------
    report:
        Integrity-verified repository audit report.
    reviews:
        Optional evidence decisions for candidates in ``report``.
    profile:
        ``None`` for the complete canonical export, or ``"github-code-scanning"`` for the
        GitHub consumer profile that keeps only reviewed ``valid`` results.

    Returns
    -------
    str
        Human-readable, stable-key-order SARIF JSON.

    Raises
    ------
    ValueError
        If reviews are invalid, the profile is unknown, or the GitHub profile exceeds a
        documented GitHub upload limit.
    """
    document = _sarif_document(report, reviews)
    canonical = _render(document)
    if profile is None:
        return canonical
    if profile != GITHUB_CODE_SCANNING_PROFILE:
        raise ValueError(f"unknown SARIF profile: {profile}")
    profiled = github_code_scanning_document(document, canonical)
    rendered = _render(profiled)
    require_github_limits(profiled, rendered)
    return rendered
