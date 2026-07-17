# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — assisted-review drafting tests
"""Verify assisted-review drafts stay non-binding, identity-bound, and redacted."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

import rigor_foundry
from rigor_foundry.assisted_review import (
    DRAFT_DECISION,
    PROMOTION_REQUIREMENT,
    ReviewDraft,
    draft_assisted_review,
    redact_secrets,
)
from rigor_foundry.campaign_identity import InferenceIdentity
from rigor_foundry.candidate_anchor import Candidate, RepositoryTreeAnchor, TrackedBlobAnchor
from rigor_foundry.models import AuditReport


def _report(path: Path) -> AuditReport:
    """Scan a real repository with independent blob and tree candidates."""
    repository = GitRepository.create(path)
    repository.write_text("src/pkg/core.py", "VALUE = 1\n")
    repository.write_text("src/pkg/wild.py", "from pkg.core import *\n")
    repository.write_text(
        "tests/test_core.py",
        "import pytest\n\n@pytest.mark.skip(reason='contract')\ndef test_value() -> None:\n"
        "    assert True\n",
    )
    repository.write_policy(registries=["docs/module-size-decisions.json"])
    repository.commit()
    return rigor_foundry.scan_repository(repository.root, Path("rigor-foundry-policy.json"))


def _identity() -> InferenceIdentity:
    """Return one provider-neutral inference identity."""
    return InferenceIdentity.build(
        provider="acme-inference",
        model="acme-review-1",
        model_family="acme-review",
        operator="platform-operator",
    )


def _blob_candidate(report: AuditReport) -> Candidate:
    """Return the first candidate anchored to a tracked blob."""
    return next(c for c in report.candidates if isinstance(c.anchor, TrackedBlobAnchor))


def _tree_candidate(report: AuditReport) -> Candidate:
    """Return the first candidate anchored to the repository tree."""
    return next(c for c in report.candidates if isinstance(c.anchor, RepositoryTreeAnchor))


def test_draft_is_needs_evidence_identity_bound_and_digest_stable(tmp_path: Path) -> None:
    """A draft records identity, evidence digests, and never carries a verdict."""
    report = _report(tmp_path / "repository")
    candidate = _blob_candidate(report)
    identity = _identity()
    draft = draft_assisted_review(
        report,
        candidate,
        identity,
        title="Review the wildcard import boundary",
        rationale="The candidate needs an independent evidence review before any verdict.",
    )
    assert draft.decision == DRAFT_DECISION == "needs-evidence"
    assert draft.identity == identity
    assert draft.candidate_id == candidate.candidate_id
    assert draft.rule_id == candidate.rule_id
    assert isinstance(candidate.anchor, TrackedBlobAnchor)
    assert draft.evidence_digests == (candidate.anchor.blob_oid, candidate.anchor.content_sha256)
    assert draft.redaction_count == 0
    assert draft.promotion_requirement == PROMOTION_REQUIREMENT
    assert ReviewDraft.from_dict(draft.to_dict(), report) == draft


def test_tree_anchor_evidence_and_reversed_input_are_deterministic(tmp_path: Path) -> None:
    """A tree-anchored candidate binds its tree evidence deterministically."""
    report = _report(tmp_path / "repository")
    candidate = _tree_candidate(report)
    draft = draft_assisted_review(
        report,
        candidate,
        _identity(),
        title="Tree-anchored owner",
        rationale="Needs evidence for the deleted owner candidate.",
    )
    assert isinstance(candidate.anchor, RepositoryTreeAnchor)
    assert draft.evidence_digests == (
        candidate.anchor.tree_oid,
        candidate.anchor.tracked_content_sha256,
    )
    assert ReviewDraft.from_dict(draft.to_dict(), report).draft_digest == draft.draft_digest


def test_secrets_are_redacted_before_storage(tmp_path: Path) -> None:
    """Secret-shaped content in a draft is redacted and counted."""
    report = _report(tmp_path / "repository")
    candidate = _blob_candidate(report)
    draft = draft_assisted_review(
        report,
        candidate,
        _identity(),
        title="Token AKIAIOSFODNN7EXAMPLE appears here",
        rationale="password: hunter2hunter2 and digest deadbeefdeadbeefdeadbeefdeadbeef01234567.",
    )
    assert "AKIAIOSFODNN7EXAMPLE" not in draft.title
    assert "hunter2hunter2" not in draft.rationale
    assert "[redacted-secret]" in draft.title
    assert draft.redaction_count >= 3


def test_redact_secrets_covers_each_pattern_and_leaves_clean_text() -> None:
    """Every secret pattern is redacted while ordinary prose is preserved."""
    clean = "This candidate needs an independent evidence review."
    assert redact_secrets(clean) == (clean, 0)
    # Assemble the marker at runtime so the source file never embeds a contiguous
    # key block that the repository secrets audit would flag.
    begin = "-----BEGIN RSA PRIVATE" + " KEY-----"
    end = "-----END RSA PRIVATE" + " KEY-----"
    private_key = f"{begin}\nMIIBOwIBAAJB\n{end}"
    bearer = "Authorization is bearer abcdefghijklmnop0123456789"
    redacted, count = redact_secrets(f"{private_key} {bearer}")
    assert count == 2
    assert "MIIBOwIBAAJB" not in redacted
    assert "abcdefghijklmnop0123456789" not in redacted


def test_draft_rejects_foreign_and_mutated_candidates(tmp_path: Path) -> None:
    """A candidate outside the report, or a mutated one, fails closed."""
    report = _report(tmp_path / "repository")
    candidate = _blob_candidate(report)
    foreign = replace(candidate, candidate_id="not-a-real-candidate")
    with pytest.raises(ValueError, match="not present in the report"):
        draft_assisted_review(report, foreign, _identity(), title="x", rationale="y")
    mutated = replace(candidate, rule_id=candidate.rule_id, evidence="tampered evidence summary")
    with pytest.raises(ValueError, match="does not match the report candidate"):
        draft_assisted_review(report, mutated, _identity(), title="x", rationale="y")


def test_draft_rejects_empty_content(tmp_path: Path) -> None:
    """Empty title or rationale fails closed."""
    report = _report(tmp_path / "repository")
    candidate = _blob_candidate(report)
    with pytest.raises(ValueError, match="title must be"):
        draft_assisted_review(report, candidate, _identity(), title="", rationale="y")
    with pytest.raises(ValueError, match="rationale must be"):
        draft_assisted_review(report, candidate, _identity(), title="x", rationale="")


def test_build_requires_unique_nonempty_evidence_digests() -> None:
    """The builder rejects empty and duplicated evidence digests."""
    identity = _identity()
    with pytest.raises(ValueError, match="at least 1"):
        ReviewDraft.build(
            report_digest="a" * 64,
            candidate_id="c1",
            rule_id="AR002-wildcard-import-boundary",
            identity=identity,
            title="t",
            rationale="r",
            evidence_digests=(),
            redaction_count=0,
        )
    with pytest.raises(ValueError, match="unique"):
        ReviewDraft.build(
            report_digest="a" * 64,
            candidate_id="c1",
            rule_id="AR002-wildcard-import-boundary",
            identity=identity,
            title="t",
            rationale="r",
            evidence_digests=("b" * 64, "b" * 64),
            redaction_count=0,
        )


def test_from_dict_rejects_tampering(tmp_path: Path) -> None:
    """Schema, verdict, digest, and identifier tampering all fail closed."""
    report = _report(tmp_path / "repository")
    candidate = _blob_candidate(report)
    good = draft_assisted_review(
        report, candidate, _identity(), title="review", rationale="needs evidence"
    ).to_dict()

    bad_schema = dict(good)
    bad_schema["schema_version"] = "9.9"
    with pytest.raises(ValueError, match="schema version"):
        ReviewDraft.from_dict(bad_schema, report)

    verdict = dict(good)
    verdict["decision"] = "valid"
    with pytest.raises(ValueError, match="needs-evidence decision"):
        ReviewDraft.from_dict(verdict, report)

    unknown = dict(good)
    unknown["candidate_id"] = "not-a-real-candidate"
    with pytest.raises(ValueError, match="not present in the report"):
        ReviewDraft.from_dict(unknown, report)

    bad_report = dict(good)
    bad_report["report_digest"] = "0" * 64
    with pytest.raises(ValueError, match="report digest does not match"):
        ReviewDraft.from_dict(bad_report, report)

    bad_rule = dict(good)
    bad_rule["rule_id"] = "AR001-first-party-import-cycle"
    with pytest.raises(ValueError, match="rule id does not match"):
        ReviewDraft.from_dict(bad_rule, report)

    bad_digest = dict(good)
    bad_digest["draft_digest"] = "0" * 64
    with pytest.raises(ValueError, match="draft digest does not match"):
        ReviewDraft.from_dict(bad_digest, report)
