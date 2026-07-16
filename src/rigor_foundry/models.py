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
from .git_provenance import GitExecutableProvenance
from .rules import RULE_PACK_VERSION, RULES_BY_ID, rule_pack_digest

__all__ = (
    "AUDIT_DOMAINS",
    "POLICY_SCHEMA_VERSION",
    "REVIEW_SCHEMA_VERSION",
    "SCANNER_VERSION",
    "SCHEMA_VERSION",
    "AdapterScope",
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


@dataclass(frozen=True)
class AuditDomainSpec:
    """Repository decision for one mandatory audit domain."""

    name: str
    applicability: DomainApplicability
    rationale: str

    def to_dict(self) -> dict[str, str]:
        """Serialise one domain decision."""
        return {
            "name": self.name,
            "applicability": self.applicability,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, value: object, index: int) -> AuditDomainSpec:
        """Parse one repository audit-domain decision."""
        data = _mapping(value, f"audit_domains[{index}]")
        name = _string(data.get("name"), f"audit_domains[{index}].name")
        if name not in AUDIT_DOMAINS:
            raise ValueError(f"audit_domains[{index}].name is unsupported")
        applicability = _string(
            data.get("applicability"),
            f"audit_domains[{index}].applicability",
        )
        if applicability not in {"required", "not-applicable"}:
            raise ValueError(f"audit_domains[{index}].applicability is unsupported")
        return cls(
            name=name,
            applicability=cast(DomainApplicability, applicability),
            rationale=_string(data.get("rationale"), f"audit_domains[{index}].rationale"),
        )


@dataclass(frozen=True)
class AdapterSpec:
    """One bounded repository-native argv audit command and its domain coverage."""

    name: str
    command: tuple[str, ...]
    timeout_seconds: int
    scope: AdapterScope
    working_directory: str
    required: bool
    domains: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Serialise one adapter specification."""
        return {
            "name": self.name,
            "command": list(self.command),
            "timeout_seconds": self.timeout_seconds,
            "scope": self.scope,
            "working_directory": self.working_directory,
            "required": self.required,
            "domains": list(self.domains),
        }

    @classmethod
    def from_dict(cls, value: object, index: int) -> AdapterSpec:
        """Parse one repository-native adapter specification."""
        data = _mapping(value, f"native_audits[{index}]")
        command = _string_tuple(data.get("command"), f"native_audits[{index}].command")
        if not command or any(not item for item in command):
            raise ValueError(f"native_audits[{index}].command must be non-empty argv")
        scope = _string(data.get("scope", "both"), f"native_audits[{index}].scope")
        if scope not in {"staged", "full", "both"}:
            raise ValueError(f"native_audits[{index}].scope is unsupported")
        required = data.get("required", True)
        if not isinstance(required, bool):
            raise ValueError(f"native_audits[{index}].required must be boolean")
        working_directory = _string(
            data.get("working_directory", "."),
            f"native_audits[{index}].working_directory",
        )
        working_path = Path(working_directory)
        if working_path.is_absolute() or ".." in working_path.parts:
            raise ValueError(
                f"native_audits[{index}].working_directory must be repository-relative"
            )
        domains = _string_tuple(data.get("domains", []), f"native_audits[{index}].domains")
        unknown_domains = sorted(set(domains).difference(AUDIT_DOMAINS))
        if unknown_domains:
            raise ValueError(
                f"native_audits[{index}].domains contains unsupported values: "
                + ", ".join(unknown_domains)
            )
        if len(domains) != len(set(domains)):
            raise ValueError(f"native_audits[{index}].domains must be unique")
        return cls(
            name=_string(data.get("name"), f"native_audits[{index}].name"),
            command=command,
            timeout_seconds=_integer(
                data.get("timeout_seconds", 300),
                f"native_audits[{index}].timeout_seconds",
                minimum=1,
            ),
            scope=cast(AdapterScope, scope),
            working_directory=working_directory,
            required=required,
            domains=domains,
        )


@dataclass(frozen=True)
class AuditPolicy:
    """Repository-local roots, thresholds, enforcement, domains, and native audits."""

    source_line_threshold: int = 1000
    test_line_threshold: int = 1000
    source_roots: tuple[str, ...] = ("src", "lib", "tools", "scripts")
    test_roots: tuple[str, ...] = ("tests", "test")
    production_packages: tuple[str, ...] = ()
    module_size_registries: tuple[str, ...] = ()
    canonical_todo: str = ".rigor/TODO.md"
    review_ledger: str = ".rigor/reviews.json"
    enforcement_mode: EnforcementMode = "observe"
    audit_domains: tuple[AuditDomainSpec, ...] = ()
    native_audits: tuple[AdapterSpec, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Serialise the policy deterministically."""
        return {
            "schema_version": POLICY_SCHEMA_VERSION,
            "source_line_threshold": self.source_line_threshold,
            "test_line_threshold": self.test_line_threshold,
            "source_roots": list(self.source_roots),
            "test_roots": list(self.test_roots),
            "production_packages": list(self.production_packages),
            "module_size_registries": list(self.module_size_registries),
            "canonical_todo": self.canonical_todo,
            "review_ledger": self.review_ledger,
            "enforcement_mode": self.enforcement_mode,
            "audit_domains": [domain.to_dict() for domain in self.audit_domains],
            "native_audits": [adapter.to_dict() for adapter in self.native_audits],
        }

    @property
    def policy_digest(self) -> str:
        """Return the canonical identity of this complete policy."""
        return canonical_digest(self.to_dict())

    @classmethod
    def from_dict(cls, value: object) -> AuditPolicy:
        """Parse and validate a policy mapping."""
        data = _mapping(value, "policy")
        if data.get("schema_version") != POLICY_SCHEMA_VERSION:
            raise ValueError("unsupported repository audit-policy schema version")
        mode = _string(data.get("enforcement_mode", "observe"), "enforcement_mode")
        if mode not in {"observe", "ratchet", "zero"}:
            raise ValueError("enforcement_mode is unsupported")
        raw_adapters = data.get("native_audits", [])
        if not isinstance(raw_adapters, list):
            raise ValueError("native_audits must be an array")
        raw_domains = data.get("audit_domains", [])
        if not isinstance(raw_domains, list):
            raise ValueError("audit_domains must be an array")
        audit_domains = tuple(
            AuditDomainSpec.from_dict(item, index) for index, item in enumerate(raw_domains)
        )
        domain_names = tuple(domain.name for domain in audit_domains)
        if len(domain_names) != len(set(domain_names)):
            raise ValueError("audit_domains names must be unique")
        canonical_todo = _string(
            data.get("canonical_todo", ".rigor/TODO.md"),
            "canonical_todo",
        )
        review_ledger = _string(
            data.get("review_ledger", ".rigor/reviews.json"),
            "review_ledger",
        )
        for field, path_text in (
            ("canonical_todo", canonical_todo),
            ("review_ledger", review_ledger),
        ):
            path = Path(path_text)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"{field} must be repository-relative")
        return cls(
            source_line_threshold=_integer(
                data.get("source_line_threshold", 1000),
                "source_line_threshold",
                minimum=1,
            ),
            test_line_threshold=_integer(
                data.get("test_line_threshold", 1000),
                "test_line_threshold",
                minimum=1,
            ),
            source_roots=_string_tuple(
                data.get("source_roots", ["src", "lib", "tools", "scripts"]),
                "source_roots",
            ),
            test_roots=_string_tuple(
                data.get("test_roots", ["tests", "test"]),
                "test_roots",
            ),
            production_packages=_string_tuple(
                data.get("production_packages", []),
                "production_packages",
            ),
            module_size_registries=_string_tuple(
                data.get("module_size_registries", []),
                "module_size_registries",
            ),
            canonical_todo=canonical_todo,
            review_ledger=review_ledger,
            enforcement_mode=cast(EnforcementMode, mode),
            audit_domains=audit_domains,
            native_audits=tuple(
                AdapterSpec.from_dict(item, index) for index, item in enumerate(raw_adapters)
            ),
        )

    @classmethod
    def from_path(cls, path: Path) -> AuditPolicy:
        """Read a policy from a UTF-8 JSON file."""
        try:
            return cls.from_json(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError) as exc:
            raise ValueError(f"cannot read audit policy {path}") from exc

    @classmethod
    def from_json(cls, text: str) -> AuditPolicy:
        """Parse a policy from already bounded, provenance-checked UTF-8 text."""
        try:
            return cls.from_dict(json.loads(text))
        except json.JSONDecodeError as exc:
            raise ValueError("cannot parse audit policy JSON") from exc


@dataclass(frozen=True)
class Candidate:
    """One static signal that requires evidence review.

    The identifier binds the category, versioned rule, repository-relative
    location, optional symbol, bounded evidence, non-verdict confidence hint,
    rationale, and concrete reviewer procedure.
    """

    candidate_id: str
    category: Category
    rule_id: str
    path: str
    line: int
    symbol: str
    evidence: str
    confidence: Confidence
    rationale: str
    verification: str

    @classmethod
    def build(
        cls,
        *,
        category: Category,
        rule_id: str,
        path: str,
        line: int,
        symbol: str,
        evidence: str,
        confidence: Confidence,
        rationale: str,
        verification: str,
    ) -> Candidate:
        """Build a candidate with a content-derived identifier."""
        fields = {
            "category": category,
            "rule_id": rule_id,
            "path": path,
            "line": line,
            "symbol": symbol,
            "evidence": evidence.strip(),
            "confidence": confidence,
            "rationale": rationale,
            "verification": verification,
        }
        definition = RULES_BY_ID.get(rule_id)
        if definition is None:
            raise ValueError(f"unregistered audit rule: {rule_id}")
        if definition.category != category:
            raise ValueError(f"audit rule {rule_id} does not belong to {category}")
        return cls(
            candidate_id=_sha256(fields),
            category=category,
            rule_id=rule_id,
            path=path,
            line=line,
            symbol=symbol,
            evidence=evidence.strip(),
            confidence=confidence,
            rationale=rationale,
            verification=verification,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the candidate."""
        return {
            "candidate_id": self.candidate_id,
            "category": self.category,
            "rule_id": self.rule_id,
            "path": self.path,
            "line": self.line,
            "symbol": self.symbol,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "verification": self.verification,
        }

    @classmethod
    def from_dict(cls, value: object) -> Candidate:
        """Parse a candidate and verify its content-derived identifier."""
        data = _mapping(value, "candidate")
        category = _string(data.get("category"), "candidate.category")
        confidence = _string(data.get("confidence"), "candidate.confidence")
        if category not in {"test-authenticity", "architecture", "godfile", "governance"}:
            raise ValueError("candidate.category is unsupported")
        if confidence not in {"low", "medium", "high"}:
            raise ValueError("candidate.confidence is unsupported")
        candidate = cls.build(
            category=cast(Category, category),
            rule_id=_string(data.get("rule_id"), "candidate.rule_id"),
            path=_string(data.get("path"), "candidate.path"),
            line=_integer(data.get("line"), "candidate.line", minimum=1),
            symbol=_string(data.get("symbol", ""), "candidate.symbol", allow_empty=True),
            evidence=_string(data.get("evidence"), "candidate.evidence"),
            confidence=cast(Confidence, confidence),
            rationale=_string(data.get("rationale"), "candidate.rationale"),
            verification=_string(data.get("verification"), "candidate.verification"),
        )
        recorded_id = _string(data.get("candidate_id"), "candidate.candidate_id")
        if candidate.candidate_id != recorded_id:
            raise ValueError("candidate identifier does not match its content")
        return candidate


@dataclass(frozen=True)
class AuditReport:
    """Deterministic candidate report for one exact Git tree."""

    scanner_version: str
    repository_root: str
    head: str
    head_tree: str
    branch: str
    tracked_content_digest: str
    dirty_paths: tuple[str, ...]
    tracked_file_count: int
    git_provenance: GitExecutableProvenance
    policy: AuditPolicy
    candidates: tuple[Candidate, ...]
    rule_pack_version: str
    rule_pack_digest: str
    policy_digest: str
    report_digest: str

    @classmethod
    def build(
        cls,
        *,
        repository_root: str,
        head: str,
        head_tree: str,
        branch: str,
        tracked_content_digest: str,
        dirty_paths: tuple[str, ...],
        tracked_file_count: int,
        git_provenance: GitExecutableProvenance,
        policy: AuditPolicy,
        candidates: tuple[Candidate, ...],
    ) -> AuditReport:
        """Build a sorted report and compute its integrity digest."""
        ordered = tuple(
            sorted(
                candidates,
                key=lambda item: (item.category, item.path, item.line, item.rule_id),
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
            "branch": branch,
            "tracked_content_digest": tracked_content_digest,
            "dirty_paths": sorted(dirty_paths),
            "tracked_file_count": tracked_file_count,
            "git_provenance": git_provenance.to_dict(),
            "policy": policy.to_dict(),
            "policy_digest": policy.policy_digest,
            "candidates": [item.to_dict() for item in ordered],
        }
        return cls(
            scanner_version=SCANNER_VERSION,
            repository_root=repository_root,
            head=head,
            head_tree=head_tree,
            branch=branch,
            tracked_content_digest=tracked_content_digest,
            dirty_paths=tuple(sorted(dirty_paths)),
            tracked_file_count=tracked_file_count,
            git_provenance=git_provenance,
            policy=policy,
            candidates=ordered,
            rule_pack_version=RULE_PACK_VERSION,
            rule_pack_digest=rule_pack_digest(),
            policy_digest=policy.policy_digest,
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
            "branch": self.branch,
            "tracked_content_digest": self.tracked_content_digest,
            "dirty_paths": list(self.dirty_paths),
            "tracked_file_count": self.tracked_file_count,
            "git_provenance": self.git_provenance.to_dict(),
            "policy": self.policy.to_dict(),
            "policy_digest": self.policy_digest,
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
        report = cls.build(
            repository_root=_string(data.get("repository_root"), "report.repository_root"),
            head=_string(data.get("head"), "report.head"),
            head_tree=_string(data.get("head_tree"), "report.head_tree"),
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
            candidates=tuple(Candidate.from_dict(item) for item in raw_candidates),
        )
        recorded_digest = _string(data.get("report_digest"), "report.report_digest")
        recorded_policy_digest = _string(
            data.get("policy_digest"),
            "report.policy_digest",
        )
        if report.policy_digest != recorded_policy_digest:
            raise ValueError("policy digest does not match report policy")
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
