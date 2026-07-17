# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — reusable repository-audit records
"""Versioned records for evidence-first repository auditing."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .audit_primitives import (
    AUDIT_DOMAINS,
    POLICY_SCHEMA_VERSION,
    REVIEW_SCHEMA_VERSION,
    SCANNER_VERSION,
    SCHEMA_VERSION,
    AdapterScope,
    Category,
    Confidence,
    Decision,
    DomainApplicability,
    EnforcementMode,
    Severity,
    _integer,
    _mapping,
    _sha256,
    _string,
    _string_tuple,
    canonical_digest,
    require_integer,
    require_mapping,
    require_string,
    require_string_tuple,
)
from .candidate_anchor import (
    Candidate,
    CandidateAnchor,
    candidate_object_format_errors,
)
from .git_provenance import GitExecutableProvenance
from .ignored_inventory import (
    IgnoredInventoryEvidence,
    ignored_inventory_digest,
    parse_ignored_evidence_array,
)
from .policy_models import AdapterSpec as AdapterSpec
from .policy_models import AuditDomainSpec as AuditDomainSpec
from .policy_models import AuditPolicy as AuditPolicy
from .rules import RULE_PACK_VERSION, rule_pack_digest

__all__ = (
    "AUDIT_DOMAINS",
    "POLICY_SCHEMA_VERSION",
    "REVIEW_SCHEMA_VERSION",
    "SCANNER_VERSION",
    "SCHEMA_VERSION",
    "AdapterScope",
    "Candidate",
    "CandidateAnchor",
    "Category",
    "Confidence",
    "Decision",
    "DomainApplicability",
    "EnforcementMode",
    "Severity",
    "canonical_digest",
    "require_integer",
    "require_mapping",
    "require_string",
    "require_string_tuple",
)

_REPORT_FIELDS = frozenset(
    {
        "schema_version",
        "scanner_version",
        "rule_pack_version",
        "rule_pack_digest",
        "repository_root",
        "head",
        "head_tree",
        "git_object_format",
        "branch",
        "tracked_content_digest",
        "dirty_paths",
        "tracked_file_count",
        "git_provenance",
        "policy",
        "policy_digest",
        "ignored_inventory_evidence",
        "ignored_inventory_digest",
        "candidates",
        "report_digest",
    }
)


@dataclass(frozen=True)
class AuditReport:
    """Deterministic candidate report for one exact Git tree."""

    scanner_version: str
    repository_root: str
    head: str
    head_tree: str
    git_object_format: str
    branch: str
    tracked_content_digest: str
    dirty_paths: tuple[str, ...]
    tracked_file_count: int
    git_provenance: GitExecutableProvenance
    policy: AuditPolicy
    ignored_inventory_evidence: tuple[IgnoredInventoryEvidence, ...]
    candidates: tuple[Candidate, ...]
    rule_pack_version: str
    rule_pack_digest: str
    policy_digest: str
    ignored_inventory_digest: str
    report_digest: str

    @classmethod
    def build(
        cls,
        *,
        repository_root: str,
        head: str,
        head_tree: str,
        git_object_format: str,
        branch: str,
        tracked_content_digest: str,
        dirty_paths: tuple[str, ...],
        tracked_file_count: int,
        git_provenance: GitExecutableProvenance,
        policy: AuditPolicy,
        ignored_inventory_evidence: tuple[IgnoredInventoryEvidence, ...] = (),
        candidates: tuple[Candidate, ...],
    ) -> AuditReport:
        """Build a sorted report and compute its integrity digest."""
        if git_object_format not in {"sha1", "sha256"}:
            raise ValueError("report.git_object_format is unsupported")
        object_length = 40 if git_object_format == "sha1" else 64
        if len(head) != object_length or len(head_tree) != object_length:
            raise ValueError("report Git identities contradict git_object_format")
        anchor_errors = candidate_object_format_errors(git_object_format, candidates)
        if anchor_errors:
            raise ValueError("; ".join(anchor_errors))
        declarations = tuple(
            (item.evidence_id, item.path, item.capture) for item in policy.ignored_inventory
        )
        observations = tuple(
            (item.evidence_id, item.path, item.capture) for item in ignored_inventory_evidence
        )
        if observations != declarations:
            raise ValueError("ignored inventory evidence does not match policy declarations")
        ignored_digest = ignored_inventory_digest(ignored_inventory_evidence)
        ordered = tuple(
            sorted(
                candidates,
                key=lambda item: (
                    item.category,
                    item.path,
                    item.anchor.line_start,
                    item.anchor.line_end,
                    item.anchor.kind,
                    item.rule_id,
                    item.candidate_id,
                ),
            )
        )
        body = {
            "schema_version": SCHEMA_VERSION,
            "scanner_version": SCANNER_VERSION,
            "rule_pack_version": RULE_PACK_VERSION,
            "rule_pack_digest": rule_pack_digest(),
            "repository_root": repository_root,
            "head": head,
            "head_tree": head_tree,
            "git_object_format": git_object_format,
            "branch": branch,
            "tracked_content_digest": tracked_content_digest,
            "dirty_paths": sorted(dirty_paths),
            "tracked_file_count": tracked_file_count,
            "git_provenance": git_provenance.to_dict(),
            "policy": policy.to_dict(),
            "policy_digest": policy.policy_digest,
            "ignored_inventory_evidence": [item.to_dict() for item in ignored_inventory_evidence],
            "ignored_inventory_digest": ignored_digest,
            "candidates": [item.to_dict() for item in ordered],
        }
        return cls(
            scanner_version=SCANNER_VERSION,
            repository_root=repository_root,
            head=head,
            head_tree=head_tree,
            git_object_format=git_object_format,
            branch=branch,
            tracked_content_digest=tracked_content_digest,
            dirty_paths=tuple(sorted(dirty_paths)),
            tracked_file_count=tracked_file_count,
            git_provenance=git_provenance,
            policy=policy,
            ignored_inventory_evidence=ignored_inventory_evidence,
            candidates=ordered,
            rule_pack_version=RULE_PACK_VERSION,
            rule_pack_digest=rule_pack_digest(),
            policy_digest=policy.policy_digest,
            ignored_inventory_digest=ignored_digest,
            report_digest=_sha256(body),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the report with its integrity digest."""
        return {
            "schema_version": SCHEMA_VERSION,
            "scanner_version": self.scanner_version,
            "rule_pack_version": self.rule_pack_version,
            "rule_pack_digest": self.rule_pack_digest,
            "repository_root": self.repository_root,
            "head": self.head,
            "head_tree": self.head_tree,
            "git_object_format": self.git_object_format,
            "branch": self.branch,
            "tracked_content_digest": self.tracked_content_digest,
            "dirty_paths": list(self.dirty_paths),
            "tracked_file_count": self.tracked_file_count,
            "git_provenance": self.git_provenance.to_dict(),
            "policy": self.policy.to_dict(),
            "policy_digest": self.policy_digest,
            "ignored_inventory_evidence": [
                item.to_dict() for item in self.ignored_inventory_evidence
            ],
            "ignored_inventory_digest": self.ignored_inventory_digest,
            "candidates": [item.to_dict() for item in self.candidates],
            "report_digest": self.report_digest,
        }

    def to_json(self) -> str:
        """Render deterministic human-readable JSON."""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_dict(cls, value: object) -> AuditReport:
        """Parse a report and verify its digest and record identifiers."""
        data = _mapping(value, "report")
        if frozenset(data) != _REPORT_FIELDS:
            raise ValueError("report fields do not match the schema")
        if data.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("unsupported report schema version")
        if data.get("scanner_version") != SCANNER_VERSION:
            raise ValueError("unsupported scanner version")
        if data.get("rule_pack_version") != RULE_PACK_VERSION:
            raise ValueError("unsupported audit rule-pack version")
        if data.get("rule_pack_digest") != rule_pack_digest():
            raise ValueError("audit rule-pack digest does not match this scanner")
        raw_candidates = data.get("candidates")
        if not isinstance(raw_candidates, list):
            raise ValueError("report.candidates must be an array")
        raw_ignored = data.get("ignored_inventory_evidence")
        if not isinstance(raw_ignored, list):
            raise ValueError("report.ignored_inventory_evidence must be an array")
        report = cls.build(
            repository_root=_string(data.get("repository_root"), "report.repository_root"),
            head=_string(data.get("head"), "report.head"),
            head_tree=_string(data.get("head_tree"), "report.head_tree"),
            git_object_format=_string(
                data.get("git_object_format"),
                "report.git_object_format",
            ),
            branch=_string(data.get("branch"), "report.branch"),
            tracked_content_digest=_string(
                data.get("tracked_content_digest"),
                "report.tracked_content_digest",
            ),
            dirty_paths=_string_tuple(data.get("dirty_paths"), "report.dirty_paths"),
            tracked_file_count=_integer(
                data.get("tracked_file_count"),
                "report.tracked_file_count",
            ),
            git_provenance=GitExecutableProvenance.from_dict(data.get("git_provenance")),
            policy=AuditPolicy.from_dict(data.get("policy")),
            ignored_inventory_evidence=parse_ignored_evidence_array(raw_ignored),
            candidates=tuple(Candidate.from_dict(item) for item in raw_candidates),
        )
        recorded_digest = _string(data.get("report_digest"), "report.report_digest")
        recorded_policy_digest = _string(
            data.get("policy_digest"),
            "report.policy_digest",
        )
        recorded_ignored_digest = _string(
            data.get("ignored_inventory_digest"),
            "report.ignored_inventory_digest",
        )
        if report.policy_digest != recorded_policy_digest:
            raise ValueError("policy digest does not match report policy")
        if report.ignored_inventory_digest != recorded_ignored_digest:
            raise ValueError("ignored inventory digest does not match report evidence")
        if report.report_digest != recorded_digest:
            raise ValueError("report digest does not match report content")
        return report

    @classmethod
    def from_path(cls, path: Path) -> AuditReport:
        """Read and verify a report JSON file."""
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read audit report {path}") from exc
        return cls.from_dict(value)


@dataclass(frozen=True)
class ReviewRecord:
    """Evidence decision for one audit candidate."""

    report_digest: str
    candidate_id: str
    decision: Decision
    reviewer: str
    reviewed_at: str
    rationale: str
    evidence: tuple[str, ...]
    severity: Severity | None
    owner: str
    dependencies: tuple[str, ...]
    acceptance_gates: tuple[str, ...]
    title: str
    boundary_justification: str
    expires_at: str
    reopen_triggers: tuple[str, ...]

    @classmethod
    def template(cls, report_digest: str, candidate_id: str) -> ReviewRecord:
        """Create a deliberately non-promotable review template."""
        return cls(
            report_digest=report_digest,
            candidate_id=candidate_id,
            decision="needs-evidence",
            reviewer="",
            reviewed_at="",
            rationale="",
            evidence=(),
            severity=None,
            owner="",
            dependencies=(),
            acceptance_gates=(),
            title="",
            boundary_justification="",
            expires_at="",
            reopen_triggers=(),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one review record."""
        return {
            "report_digest": self.report_digest,
            "candidate_id": self.candidate_id,
            "decision": self.decision,
            "reviewer": self.reviewer,
            "reviewed_at": self.reviewed_at,
            "rationale": self.rationale,
            "evidence": list(self.evidence),
            "severity": self.severity,
            "owner": self.owner,
            "dependencies": list(self.dependencies),
            "acceptance_gates": list(self.acceptance_gates),
            "title": self.title,
            "boundary_justification": self.boundary_justification,
            "expires_at": self.expires_at,
            "reopen_triggers": list(self.reopen_triggers),
        }

    @property
    def review_digest(self) -> str:
        """Return the canonical identity of this complete review record."""
        return canonical_digest(self.to_dict())

    @classmethod
    def from_dict(cls, value: object) -> ReviewRecord:
        """Parse one review record without asserting promotion readiness."""
        data = _mapping(value, "review")
        decision = _string(data.get("decision"), "review.decision")
        if decision not in {"valid", "invalid", "accepted-boundary", "needs-evidence"}:
            raise ValueError("review.decision is unsupported")
        raw_severity = data.get("severity")
        severity: Severity | None
        if raw_severity is None:
            severity = None
        else:
            severity_text = _string(raw_severity, "review.severity")
            if severity_text not in {"P0", "P1", "P2", "P3", "P4"}:
                raise ValueError("review.severity is unsupported")
            severity = cast(Severity, severity_text)
        return cls(
            report_digest=_string(data.get("report_digest"), "review.report_digest"),
            candidate_id=_string(data.get("candidate_id"), "review.candidate_id"),
            decision=cast(Decision, decision),
            reviewer=_string(data.get("reviewer", ""), "review.reviewer", allow_empty=True),
            reviewed_at=_string(
                data.get("reviewed_at", ""),
                "review.reviewed_at",
                allow_empty=True,
            ),
            rationale=_string(data.get("rationale", ""), "review.rationale", allow_empty=True),
            evidence=_string_tuple(data.get("evidence", []), "review.evidence"),
            severity=severity,
            owner=_string(data.get("owner", ""), "review.owner", allow_empty=True),
            dependencies=_string_tuple(data.get("dependencies", []), "review.dependencies"),
            acceptance_gates=_string_tuple(
                data.get("acceptance_gates", []),
                "review.acceptance_gates",
            ),
            title=_string(data.get("title", ""), "review.title", allow_empty=True),
            boundary_justification=_string(
                data.get("boundary_justification", ""),
                "review.boundary_justification",
                allow_empty=True,
            ),
            expires_at=_string(
                data.get("expires_at", ""),
                "review.expires_at",
                allow_empty=True,
            ),
            reopen_triggers=_string_tuple(
                data.get("reopen_triggers", []),
                "review.reopen_triggers",
            ),
        )


def reviews_to_json(reviews: tuple[ReviewRecord, ...]) -> str:
    """Render deterministic review JSON."""
    value = {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "reviews": [review.to_dict() for review in reviews],
    }
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def reviews_from_path(path: Path) -> tuple[ReviewRecord, ...]:
    """Read review records from one UTF-8 JSON file."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read audit reviews {path}") from exc
    data = _mapping(value, "review document")
    if data.get("schema_version") != REVIEW_SCHEMA_VERSION:
        raise ValueError("unsupported review schema version")
    raw_reviews = data.get("reviews")
    if not isinstance(raw_reviews, list):
        raise ValueError("review document reviews must be an array")
    return tuple(ReviewRecord.from_dict(item) for item in raw_reviews)
