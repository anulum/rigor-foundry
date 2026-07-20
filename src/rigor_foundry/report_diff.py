# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — content-addressed audit-report differences
"""Compare exact audit reports without turning candidate drift into a verdict."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from .audit_primitives import (
    SCHEMA_VERSION,
    canonical_digest,
    require_integer,
    require_mapping,
    require_string,
    require_string_tuple,
)
from .candidate_anchor import Candidate, candidate_object_format_errors
from .git_provenance import GitExecutableProvenance
from .ignored_inventory import ignored_inventory_digest, parse_ignored_evidence_array
from .models import AuditPolicy, AuditReport

REPORT_DIFF_SCHEMA_VERSION = "1.0"

MatchBasis = Literal["automatic", "declared"]

_SHA256 = re.compile(r"[0-9a-f]{64}")
_COMPATIBILITY_FIELDS = frozenset(
    {
        "repository_change",
        "branch_change",
        "policy_change",
        "rule_pack_change",
        "scanner_change",
        "justification",
    }
)
_ANCHOR_MATCH_FIELDS = frozenset({"before_candidate_id", "after_candidate_id", "rationale"})
_ANCHOR_CHANGE_FIELDS = frozenset(
    {
        "before_candidate_id",
        "after_candidate_id",
        "semantic_digest",
        "match_basis",
        "rationale",
    }
)
_REPORT_DIFF_FIELDS = frozenset(
    {
        "schema_version",
        "before_report_digest",
        "after_report_digest",
        "compatibility",
        "retained_candidate_ids",
        "appeared_candidate_ids",
        "resolved_candidate_ids",
        "anchor_changes",
        "diff_digest",
    }
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


def _strict_bool(value: object, field: str) -> bool:
    """Return a JSON boolean without accepting integer aliases."""
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a boolean")
    return value


def _sha256(value: object, field: str) -> str:
    """Return one lowercase SHA-256 identity."""
    result = require_string(value, field)
    if _SHA256.fullmatch(result) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return result


def _string_array(value: object, field: str) -> tuple[str, ...]:
    """Parse one ordered array of non-empty strings."""
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array")
    return tuple(require_string(item, f"{field}[{index}]") for index, item in enumerate(value))


def _candidate_identity(candidate: Candidate) -> str:
    """Return the anchor-independent identity used only for relocation matching."""
    return canonical_digest(
        {
            "category": candidate.category,
            "rule_id": candidate.rule_id,
            "path": candidate.path,
            "symbol": candidate.symbol,
            "evidence": candidate.evidence,
            "confidence": candidate.confidence,
            "rationale": candidate.rationale,
            "verification": candidate.verification,
        }
    )


def _verified_report(report: AuditReport, field: str) -> None:
    """Verify the exact report envelope without requiring the current rule pack."""
    document = report.to_dict()
    body = dict(document)
    recorded_digest = body.pop("report_digest", None)
    if recorded_digest != report.report_digest or canonical_digest(body) != report.report_digest:
        raise ValueError(f"{field} report digest does not match report content")
    if report.policy_digest != report.policy.policy_digest:
        raise ValueError(f"{field} policy digest does not match report policy")
    AuditPolicy.from_dict(report.policy.to_dict())
    GitExecutableProvenance.from_dict(report.git_provenance.to_dict())
    for candidate in report.candidates:
        Candidate.from_dict(candidate.to_dict())
    candidate_ids = tuple(candidate.candidate_id for candidate in report.candidates)
    if len(candidate_ids) != len(set(candidate_ids)):
        raise ValueError(f"{field} report contains duplicate candidate identities")
    anchor_errors = candidate_object_format_errors(report.git_object_format, report.candidates)
    if anchor_errors:
        raise ValueError(f"{field} report: {'; '.join(anchor_errors)}")
    if (
        ignored_inventory_digest(report.ignored_inventory_evidence)
        != report.ignored_inventory_digest
    ):
        raise ValueError(f"{field} ignored inventory digest does not match report evidence")


def read_report_for_diff(path: Path) -> AuditReport:
    """Read one exact schema-1.3 report without requiring the current rule pack.

    The report digest, nested policy/provenance/candidate identities, ignored
    evidence, and Git object-format relationship are still verified. Only the
    normal scanner-version and current-rule-pack equality checks are relaxed so
    that an explicit compatibility declaration can represent historical input.
    """
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read audit report {path}") from exc
    data = require_mapping(value, "historical audit report")
    if frozenset(data) != _REPORT_FIELDS:
        raise ValueError("historical audit-report fields do not match the schema")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported historical audit-report schema version")
    raw_candidates = data.get("candidates")
    raw_ignored = data.get("ignored_inventory_evidence")
    if not isinstance(raw_candidates, list):
        raise ValueError("historical audit-report candidates must be an array")
    ignored = parse_ignored_evidence_array(raw_ignored)
    policy = AuditPolicy.from_dict(data.get("policy"))
    declarations = tuple(
        (item.evidence_id, item.path, item.capture) for item in policy.ignored_inventory
    )
    observations = tuple((item.evidence_id, item.path, item.capture) for item in ignored)
    if declarations != observations:
        raise ValueError("historical ignored evidence does not match policy declarations")
    object_format = require_string(data.get("git_object_format"), "report.git_object_format")
    if object_format not in {"sha1", "sha256"}:
        raise ValueError("historical report Git object format is unsupported")
    head = require_string(data.get("head"), "report.head")
    head_tree = require_string(data.get("head_tree"), "report.head_tree")
    expected_length = 40 if object_format == "sha1" else 64
    if len(head) != expected_length or len(head_tree) != expected_length:
        raise ValueError("historical report Git identities contradict object format")
    report = AuditReport(
        scanner_version=require_string(data.get("scanner_version"), "report.scanner_version"),
        repository_root=require_string(data.get("repository_root"), "report.repository_root"),
        head=head,
        head_tree=head_tree,
        git_object_format=object_format,
        branch=require_string(data.get("branch"), "report.branch"),
        tracked_content_digest=_sha256(
            data.get("tracked_content_digest"), "report.tracked_content_digest"
        ),
        dirty_paths=require_string_tuple(data.get("dirty_paths"), "report.dirty_paths"),
        tracked_file_count=require_integer(
            data.get("tracked_file_count"), "report.tracked_file_count"
        ),
        git_provenance=GitExecutableProvenance.from_dict(data.get("git_provenance")),
        policy=policy,
        ignored_inventory_evidence=ignored,
        candidates=tuple(Candidate.from_dict(item) for item in raw_candidates),
        rule_pack_version=require_string(
            data.get("rule_pack_version"), "report.rule_pack_version"
        ),
        rule_pack_digest=_sha256(data.get("rule_pack_digest"), "report.rule_pack_digest"),
        policy_digest=_sha256(data.get("policy_digest"), "report.policy_digest"),
        ignored_inventory_digest=_sha256(
            data.get("ignored_inventory_digest"), "report.ignored_inventory_digest"
        ),
        report_digest=_sha256(data.get("report_digest"), "report.report_digest"),
    )
    _verified_report(report, "historical")
    return report


@dataclass(frozen=True)
class ReportDiffCompatibility:
    """Explicit declarations for otherwise incompatible report inputs."""

    repository_change: bool = False
    branch_change: bool = False
    policy_change: bool = False
    rule_pack_change: bool = False
    scanner_change: bool = False
    justification: str = ""

    def __post_init__(self) -> None:
        """Reject malformed or unexplained declarations."""
        declarations = (
            self.repository_change,
            self.branch_change,
            self.policy_change,
            self.rule_pack_change,
            self.scanner_change,
        )
        if not all(isinstance(item, bool) for item in declarations):
            raise ValueError("report-diff compatibility declarations must be booleans")
        if any(declarations):
            require_string(self.justification, "compatibility.justification")
        elif self.justification:
            raise ValueError("compatibility justification requires a declared change")

    def to_dict(self) -> dict[str, object]:
        """Serialise the compatibility declaration."""
        return {
            "repository_change": self.repository_change,
            "branch_change": self.branch_change,
            "policy_change": self.policy_change,
            "rule_pack_change": self.rule_pack_change,
            "scanner_change": self.scanner_change,
            "justification": self.justification,
        }

    @classmethod
    def from_dict(cls, value: object) -> ReportDiffCompatibility:
        """Parse one strict compatibility declaration."""
        data = require_mapping(value, "report-diff compatibility")
        if frozenset(data) != _COMPATIBILITY_FIELDS:
            raise ValueError("report-diff compatibility fields do not match the schema")
        return cls(
            repository_change=_strict_bool(
                data.get("repository_change"), "compatibility.repository_change"
            ),
            branch_change=_strict_bool(data.get("branch_change"), "compatibility.branch_change"),
            policy_change=_strict_bool(data.get("policy_change"), "compatibility.policy_change"),
            rule_pack_change=_strict_bool(
                data.get("rule_pack_change"), "compatibility.rule_pack_change"
            ),
            scanner_change=_strict_bool(
                data.get("scanner_change"), "compatibility.scanner_change"
            ),
            justification=require_string(
                data.get("justification", ""),
                "compatibility.justification",
                allow_empty=True,
            ),
        )

    def validate_reports(self, before: AuditReport, after: AuditReport) -> None:
        """Require every declaration to match one actual parent-report difference."""
        actual = {
            "repository_change": (
                before.repository_root != after.repository_root
                or before.git_object_format != after.git_object_format
            ),
            "branch_change": before.branch != after.branch,
            "policy_change": before.policy_digest != after.policy_digest,
            "rule_pack_change": (
                before.rule_pack_version != after.rule_pack_version
                or before.rule_pack_digest != after.rule_pack_digest
            ),
            "scanner_change": before.scanner_version != after.scanner_version,
        }
        for field, changed in actual.items():
            if getattr(self, field) != changed:
                label = field.replace("_", " ")
                raise ValueError(f"{label} declaration does not match the exact reports")


@dataclass(frozen=True)
class CandidateAnchorMatch:
    """Operator-declared pairing that resolves one ambiguous anchor change."""

    before_candidate_id: str
    after_candidate_id: str
    rationale: str

    def __post_init__(self) -> None:
        """Reject malformed direct construction."""
        _sha256(self.before_candidate_id, "anchor-match.before_candidate_id")
        _sha256(self.after_candidate_id, "anchor-match.after_candidate_id")
        require_string(self.rationale, "anchor-match.rationale")

    def to_dict(self) -> dict[str, str]:
        """Serialise the declared pair."""
        return {
            "before_candidate_id": self.before_candidate_id,
            "after_candidate_id": self.after_candidate_id,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, value: object) -> CandidateAnchorMatch:
        """Parse one strict declared pair."""
        data = require_mapping(value, "candidate anchor match")
        if frozenset(data) != _ANCHOR_MATCH_FIELDS:
            raise ValueError("candidate anchor-match fields do not match the schema")
        return cls(
            before_candidate_id=_sha256(
                data.get("before_candidate_id"), "anchor-match.before_candidate_id"
            ),
            after_candidate_id=_sha256(
                data.get("after_candidate_id"), "anchor-match.after_candidate_id"
            ),
            rationale=require_string(data.get("rationale"), "anchor-match.rationale"),
        )


@dataclass(frozen=True)
class CandidateAnchorChange:
    """One candidate preserved semantically while its exact anchor changed."""

    before_candidate_id: str
    after_candidate_id: str
    semantic_digest: str
    match_basis: MatchBasis
    rationale: str

    def __post_init__(self) -> None:
        """Reject malformed automatic and operator-declared transitions."""
        _sha256(self.before_candidate_id, "anchor-change.before_candidate_id")
        _sha256(self.after_candidate_id, "anchor-change.after_candidate_id")
        _sha256(self.semantic_digest, "anchor-change.semantic_digest")
        if self.match_basis not in {"automatic", "declared"}:
            raise ValueError("anchor-change.match_basis is unsupported")
        if self.match_basis == "declared":
            require_string(self.rationale, "anchor-change.rationale")
        elif self.rationale:
            raise ValueError("automatic anchor change must not carry operator rationale")

    def to_dict(self) -> dict[str, str]:
        """Serialise the anchor transition."""
        return {
            "before_candidate_id": self.before_candidate_id,
            "after_candidate_id": self.after_candidate_id,
            "semantic_digest": self.semantic_digest,
            "match_basis": self.match_basis,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, value: object) -> CandidateAnchorChange:
        """Parse one strict recorded anchor transition."""
        data = require_mapping(value, "candidate anchor change")
        if frozenset(data) != _ANCHOR_CHANGE_FIELDS:
            raise ValueError("candidate anchor-change fields do not match the schema")
        basis = require_string(data.get("match_basis"), "anchor-change.match_basis")
        if basis not in {"automatic", "declared"}:
            raise ValueError("anchor-change.match_basis is unsupported")
        return cls(
            before_candidate_id=_sha256(
                data.get("before_candidate_id"), "anchor-change.before_candidate_id"
            ),
            after_candidate_id=_sha256(
                data.get("after_candidate_id"), "anchor-change.after_candidate_id"
            ),
            semantic_digest=_sha256(data.get("semantic_digest"), "anchor-change.semantic_digest"),
            match_basis=cast(MatchBasis, basis),
            rationale=require_string(
                data.get("rationale", ""), "anchor-change.rationale", allow_empty=True
            ),
        )


@dataclass(frozen=True)
class ReportDiff:
    """Replay-verifiable candidate transitions between two exact reports."""

    before_report_digest: str
    after_report_digest: str
    compatibility: ReportDiffCompatibility
    retained_candidate_ids: tuple[str, ...]
    appeared_candidate_ids: tuple[str, ...]
    resolved_candidate_ids: tuple[str, ...]
    anchor_changes: tuple[CandidateAnchorChange, ...]
    diff_digest: str

    @classmethod
    def build(
        cls,
        before: AuditReport,
        after: AuditReport,
        *,
        compatibility: ReportDiffCompatibility | None = None,
        anchor_matches: tuple[CandidateAnchorMatch, ...] = (),
    ) -> ReportDiff:
        """Compare exact reports and reject ambiguous candidate relocation."""
        _verified_report(before, "before")
        _verified_report(after, "after")
        declaration = compatibility or ReportDiffCompatibility()
        declaration.validate_reports(before, after)

        before_by_id = {candidate.candidate_id: candidate for candidate in before.candidates}
        after_by_id = {candidate.candidate_id: candidate for candidate in after.candidates}
        retained = set(before_by_id) & set(after_by_id)
        unmatched_before = {
            key: value for key, value in before_by_id.items() if key not in retained
        }
        unmatched_after = {key: value for key, value in after_by_id.items() if key not in retained}
        changes: list[CandidateAnchorChange] = []
        used_before: set[str] = set()
        used_after: set[str] = set()

        for match in sorted(
            anchor_matches,
            key=lambda item: (item.before_candidate_id, item.after_candidate_id),
        ):
            if match.before_candidate_id in used_before or match.after_candidate_id in used_after:
                raise ValueError("declared anchor matches must use each candidate exactly once")
            old = unmatched_before.get(match.before_candidate_id)
            new = unmatched_after.get(match.after_candidate_id)
            if old is None or new is None:
                raise ValueError("declared anchor match must name unmatched report candidates")
            semantic_digest = _candidate_identity(old)
            if semantic_digest != _candidate_identity(new):
                raise ValueError("declared anchor match changes candidate semantics")
            used_before.add(old.candidate_id)
            used_after.add(new.candidate_id)
            changes.append(
                CandidateAnchorChange(
                    before_candidate_id=old.candidate_id,
                    after_candidate_id=new.candidate_id,
                    semantic_digest=semantic_digest,
                    match_basis="declared",
                    rationale=match.rationale,
                )
            )

        before_groups: dict[str, list[Candidate]] = {}
        after_groups: dict[str, list[Candidate]] = {}
        for candidate in unmatched_before.values():
            if candidate.candidate_id not in used_before:
                before_groups.setdefault(_candidate_identity(candidate), []).append(candidate)
        for candidate in unmatched_after.values():
            if candidate.candidate_id not in used_after:
                after_groups.setdefault(_candidate_identity(candidate), []).append(candidate)

        for semantic_digest in sorted(set(before_groups) & set(after_groups)):
            old_group = sorted(before_groups[semantic_digest], key=lambda item: item.candidate_id)
            new_group = sorted(after_groups[semantic_digest], key=lambda item: item.candidate_id)
            if len(old_group) != 1 or len(new_group) != 1:
                raise ValueError("ambiguous anchor change requires explicit candidate-ID matches")
            old = old_group[0]
            new = new_group[0]
            used_before.add(old.candidate_id)
            used_after.add(new.candidate_id)
            changes.append(
                CandidateAnchorChange(
                    before_candidate_id=old.candidate_id,
                    after_candidate_id=new.candidate_id,
                    semantic_digest=semantic_digest,
                    match_basis="automatic",
                    rationale="",
                )
            )

        appeared = tuple(sorted(set(unmatched_after) - used_after))
        resolved = tuple(sorted(set(unmatched_before) - used_before))
        ordered_changes = tuple(
            sorted(changes, key=lambda item: (item.before_candidate_id, item.after_candidate_id))
        )
        body = {
            "schema_version": REPORT_DIFF_SCHEMA_VERSION,
            "before_report_digest": before.report_digest,
            "after_report_digest": after.report_digest,
            "compatibility": declaration.to_dict(),
            "retained_candidate_ids": sorted(retained),
            "appeared_candidate_ids": list(appeared),
            "resolved_candidate_ids": list(resolved),
            "anchor_changes": [item.to_dict() for item in ordered_changes],
        }
        return cls(
            before_report_digest=before.report_digest,
            after_report_digest=after.report_digest,
            compatibility=declaration,
            retained_candidate_ids=tuple(sorted(retained)),
            appeared_candidate_ids=appeared,
            resolved_candidate_ids=resolved,
            anchor_changes=ordered_changes,
            diff_digest=canonical_digest(body),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the complete content-addressed comparison."""
        return {
            "schema_version": REPORT_DIFF_SCHEMA_VERSION,
            "before_report_digest": self.before_report_digest,
            "after_report_digest": self.after_report_digest,
            "compatibility": self.compatibility.to_dict(),
            "retained_candidate_ids": list(self.retained_candidate_ids),
            "appeared_candidate_ids": list(self.appeared_candidate_ids),
            "resolved_candidate_ids": list(self.resolved_candidate_ids),
            "anchor_changes": [item.to_dict() for item in self.anchor_changes],
            "diff_digest": self.diff_digest,
        }

    def to_json(self) -> str:
        """Render deterministic human-readable JSON."""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_dict(
        cls,
        value: object,
        *,
        before_report: AuditReport,
        after_report: AuditReport,
    ) -> ReportDiff:
        """Replay a serialised comparison from its exact parent reports."""
        data = require_mapping(value, "report diff")
        if frozenset(data) != _REPORT_DIFF_FIELDS:
            raise ValueError("report-diff fields do not match the schema")
        if data.get("schema_version") != REPORT_DIFF_SCHEMA_VERSION:
            raise ValueError("unsupported report-diff schema version")
        compatibility = ReportDiffCompatibility.from_dict(data.get("compatibility"))
        raw_changes = data.get("anchor_changes")
        if not isinstance(raw_changes, list):
            raise ValueError("report-diff anchor_changes must be an array")
        recorded_changes = tuple(CandidateAnchorChange.from_dict(item) for item in raw_changes)
        declared_matches = tuple(
            CandidateAnchorMatch(
                before_candidate_id=item.before_candidate_id,
                after_candidate_id=item.after_candidate_id,
                rationale=item.rationale,
            )
            for item in recorded_changes
            if item.match_basis == "declared"
        )
        rebuilt = cls.build(
            before_report,
            after_report,
            compatibility=compatibility,
            anchor_matches=declared_matches,
        )
        _sha256(data.get("before_report_digest"), "report-diff.before_report_digest")
        _sha256(data.get("after_report_digest"), "report-diff.after_report_digest")
        _sha256(data.get("diff_digest"), "report-diff.diff_digest")
        _string_array(data.get("retained_candidate_ids"), "report-diff.retained_candidate_ids")
        _string_array(data.get("appeared_candidate_ids"), "report-diff.appeared_candidate_ids")
        _string_array(data.get("resolved_candidate_ids"), "report-diff.resolved_candidate_ids")
        if rebuilt.to_dict() != data:
            raise ValueError("report-diff content does not replay from the exact reports")
        return rebuilt

    @classmethod
    def from_path(
        cls,
        path: Path,
        *,
        before_report: AuditReport,
        after_report: AuditReport,
    ) -> ReportDiff:
        """Read and replay one report-diff JSON document."""
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read report diff {path}") from exc
        return cls.from_dict(
            value,
            before_report=before_report,
            after_report=after_report,
        )


def compare_reports(
    before: AuditReport,
    after: AuditReport,
    *,
    compatibility: ReportDiffCompatibility | None = None,
    anchor_matches: tuple[CandidateAnchorMatch, ...] = (),
) -> ReportDiff:
    """Build the evidence-only difference between two exact reports."""
    return ReportDiff.build(
        before,
        after,
        compatibility=compatibility,
        anchor_matches=anchor_matches,
    )
