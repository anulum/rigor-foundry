# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — provider-neutral assisted-review drafting
"""Draft needs-evidence reviews from digest-bound evidence without asserting a verdict."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .campaign_identity import InferenceIdentity
from .candidate_anchor import Candidate, CandidateAnchor, RepositoryTreeAnchor
from .model_primitives import require_digest, require_git_object, validate_unique_strings
from .models import (
    AuditReport,
    canonical_digest,
    require_integer,
    require_mapping,
    require_string,
)

ASSISTED_REVIEW_SCHEMA_VERSION = "1.0"

DRAFT_DECISION = "needs-evidence"

PROMOTION_REQUIREMENT = (
    "This is an assisted-review draft. It carries no verdict and no signature. "
    "Promoting the candidate to valid or invalid requires an independent human or "
    "signed reviewer attestation; the draft alone never establishes a decision."
)

_REDACTION_PLACEHOLDER = "[redacted-secret]"
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/-]{16,}={0,2}"),
    re.compile(
        r"(?i)(?:secret|token|password|passwd|api[_-]?key|access[_-]?key)"
        r"\s*[:=]\s*[^\s'\"]{8,}"
    ),
    re.compile(r"[0-9a-fA-F]{32,}"),
    re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
)


def redact_secrets(text: str) -> tuple[str, int]:
    """Replace secret-shaped substrings with a fixed placeholder.

    The redactor is deterministic and network-free. It is deliberately
    conservative: it errs towards removing high-entropy or assignment-shaped
    values rather than risking secret leakage into a shared draft.

    Parameters
    ----------
    text:
        Free-text draft content that may embed repository secrets.

    Returns
    -------
    tuple[str, int]
        The redacted text and the number of substitutions performed.
    """
    redacted = text
    count = 0
    for pattern in _SECRET_PATTERNS:
        redacted, substitutions = pattern.subn(_REDACTION_PLACEHOLDER, redacted)
        count += substitutions
    return redacted, count


def _anchor_evidence_digests(anchor: CandidateAnchor) -> tuple[str, ...]:
    """Return the digest-bound evidence identifiers for one candidate anchor."""
    if isinstance(anchor, RepositoryTreeAnchor):
        return (anchor.tree_oid, anchor.tracked_content_sha256)
    return (anchor.blob_oid, anchor.content_sha256)


@dataclass(frozen=True)
class ReviewDraft:
    """A non-binding needs-evidence draft bound to one report candidate.

    Parameters
    ----------
    report_digest:
        Digest of the exact report the drafted candidate belongs to.
    candidate_id:
        Identifier of the candidate the draft addresses.
    rule_id:
        Rule that produced the candidate.
    identity:
        Provider, model, and operator identity that produced the draft.
    decision:
        Always :data:`DRAFT_DECISION`; a draft never carries a verdict.
    title:
        Redacted draft title.
    rationale:
        Redacted draft rationale.
    evidence_digests:
        Digest-bound evidence identifiers the draft consumed.
    redaction_count:
        Number of secret substitutions performed on the draft content.

    """

    report_digest: str
    candidate_id: str
    rule_id: str
    identity: InferenceIdentity
    decision: str
    title: str
    rationale: str
    evidence_digests: tuple[str, ...]
    redaction_count: int
    draft_digest: str

    @classmethod
    def build(
        cls,
        *,
        report_digest: str,
        candidate_id: str,
        rule_id: str,
        identity: InferenceIdentity,
        title: str,
        rationale: str,
        evidence_digests: tuple[str, ...],
        redaction_count: int,
    ) -> ReviewDraft:
        """Build one validated, content-addressed draft from final fields."""
        digests = tuple(
            require_git_object(item, "draft.evidence_digests[]") for item in evidence_digests
        )
        validate_unique_strings(digests, "draft.evidence_digests", minimum=1)
        body: dict[str, object] = {
            "schema_version": ASSISTED_REVIEW_SCHEMA_VERSION,
            "report_digest": require_digest(report_digest, "draft.report_digest"),
            "candidate_id": require_string(candidate_id, "draft.candidate_id"),
            "rule_id": require_string(rule_id, "draft.rule_id"),
            "identity": identity.to_dict(),
            "decision": DRAFT_DECISION,
            "title": require_string(title, "draft.title"),
            "rationale": require_string(rationale, "draft.rationale"),
            "evidence_digests": list(digests),
            "redaction_count": require_integer(
                redaction_count, "draft.redaction_count", minimum=0
            ),
        }
        return cls(
            report_digest=str(body["report_digest"]),
            candidate_id=str(body["candidate_id"]),
            rule_id=str(body["rule_id"]),
            identity=identity,
            decision=DRAFT_DECISION,
            title=str(body["title"]),
            rationale=str(body["rationale"]),
            evidence_digests=digests,
            redaction_count=int(redaction_count),
            draft_digest=canonical_digest(body),
        )

    @property
    def promotion_requirement(self) -> str:
        """Return the standing requirement for promoting the candidate."""
        return PROMOTION_REQUIREMENT

    def to_dict(self) -> dict[str, object]:
        """Serialise one review draft."""
        return {
            "schema_version": ASSISTED_REVIEW_SCHEMA_VERSION,
            "report_digest": self.report_digest,
            "candidate_id": self.candidate_id,
            "rule_id": self.rule_id,
            "identity": self.identity.to_dict(),
            "decision": self.decision,
            "title": self.title,
            "rationale": self.rationale,
            "evidence_digests": list(self.evidence_digests),
            "redaction_count": self.redaction_count,
            "draft_digest": self.draft_digest,
        }

    @classmethod
    def from_dict(cls, value: object, report: AuditReport) -> ReviewDraft:
        """Parse a draft and rebind it to an exact report candidate."""
        data = require_mapping(value, "draft")
        if data.get("schema_version") != ASSISTED_REVIEW_SCHEMA_VERSION:
            raise ValueError("unsupported assisted-review schema version")
        if data.get("decision") != DRAFT_DECISION:
            raise ValueError("an assisted-review draft may only carry a needs-evidence decision")
        candidate = _require_candidate(
            report, require_string(data.get("candidate_id"), "draft.candidate_id")
        )
        draft = cls.build(
            report_digest=report.report_digest,
            candidate_id=candidate.candidate_id,
            rule_id=candidate.rule_id,
            identity=InferenceIdentity.from_dict(data.get("identity")),
            title=require_string(data.get("title"), "draft.title"),
            rationale=require_string(data.get("rationale"), "draft.rationale"),
            evidence_digests=_anchor_evidence_digests(candidate.anchor),
            redaction_count=require_integer(data.get("redaction_count"), "draft.redaction_count"),
        )
        if data.get("report_digest") != draft.report_digest:
            raise ValueError("draft report digest does not match the report")
        if data.get("rule_id") != draft.rule_id:
            raise ValueError("draft rule id does not match the candidate")
        if data.get("draft_digest") != draft.draft_digest:
            raise ValueError("draft digest does not match its content")
        return draft


def _require_candidate(report: AuditReport, candidate_id: str) -> Candidate:
    """Return the exact report candidate for one candidate identifier."""
    matches = tuple(item for item in report.candidates if item.candidate_id == candidate_id)
    if len(matches) != 1:
        raise ValueError("draft candidate is not present in the report")
    return matches[0]


def draft_assisted_review(
    report: AuditReport,
    candidate: Candidate,
    identity: InferenceIdentity,
    *,
    title: str,
    rationale: str,
) -> ReviewDraft:
    """Draft a needs-evidence review for one report candidate.

    The candidate must belong to ``report``. Draft content is redacted before it
    is stored, the decision is fixed to needs-evidence, and the provider, model,
    and operator identity is recorded. The draft never promotes the candidate.

    Parameters
    ----------
    report:
        Integrity-verified repository audit report.
    candidate:
        Candidate from ``report`` to draft a review for.
    identity:
        Provider, model, and operator identity producing the draft.
    title:
        Proposed draft title; redacted before storage.
    rationale:
        Proposed draft rationale; redacted before storage.

    Returns
    -------
    ReviewDraft
        A non-binding, digest-bound needs-evidence draft.

    Raises
    ------
    ValueError
        If the candidate is not present in the report or content is empty.
    """
    resolved = _require_candidate(report, candidate.candidate_id)
    if resolved != candidate:
        raise ValueError("draft candidate does not match the report candidate")
    redacted_title, title_count = redact_secrets(require_string(title, "draft.title"))
    redacted_rationale, rationale_count = redact_secrets(
        require_string(rationale, "draft.rationale")
    )
    return ReviewDraft.build(
        report_digest=report.report_digest,
        candidate_id=candidate.candidate_id,
        rule_id=candidate.rule_id,
        identity=identity,
        title=redacted_title,
        rationale=redacted_rationale,
        evidence_digests=_anchor_evidence_digests(candidate.anchor),
        redaction_count=title_count + rationale_count,
    )
