# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — evidence review and TODO promotion tests
"""Verify that only current evidence-backed findings reach internal work queues."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from repository_audit_git_repository import GitRepository

from rigor_foundry.models import AuditPolicy, AuditReport, Candidate, ReviewRecord
from rigor_foundry.review import (
    append_todo_entry,
    render_todo_entry,
    review_errors,
    review_templates,
    validate_reviews,
)


def _report(repository: Path) -> AuditReport:
    """Return one report containing a current architecture candidate."""
    item = Candidate.build(
        category="architecture",
        rule_id="AR003-broad-optional-import-boundary",
        path="src/pkg/optional.py",
        line=2,
        symbol="pkg.optional",
        evidence="import guarded by broad exception",
        confidence="high",
        rationale="nested import failures may be hidden",
        verification="run present, absent, and internally broken dependency cases",
    )
    return AuditReport.build(
        repository_root=str(repository),
        head="1" * 40,
        head_tree="2" * 40,
        branch="main",
        tracked_content_digest="3" * 64,
        dirty_paths=(),
        tracked_file_count=1,
        policy=AuditPolicy(),
        candidates=(item,),
    )


def _valid_review(report: AuditReport) -> ReviewRecord:
    """Return one complete verified-finding decision."""
    return ReviewRecord(
        report_digest=report.report_digest,
        candidate_id=report.candidates[0].candidate_id,
        decision="valid",
        reviewer="agent/reviewer-1",
        reviewed_at="2026-07-15T10:00:00Z",
        rationale="real import reproduction hides a nested ImportError",
        evidence=("python -I reproduce_optional_import.py -> hidden failure",),
        severity="P1",
        owner="lane/optional-import",
        dependencies=("dependency-contract",),
        acceptance_gates=("real present/absent/broken import subprocesses pass",),
        title="Narrow optional dependency exception boundary",
        boundary_justification="",
        expires_at="2026-08-15T10:00:00Z",
        reopen_triggers=("dependency version or import path changes",),
    )


def test_templates_are_non_promotable_and_valid_review_renders_bounded_todo(
    tmp_path: Path,
) -> None:
    """Review begins needs-evidence and promotion uses only reviewer-supplied gates."""
    report = _report(tmp_path)
    template = review_templates(report)
    assert len(template) == 1
    assert template[0].decision == "needs-evidence"
    assert validate_reviews(report, template) == ()
    with pytest.raises(ValueError, match="only reviewed valid"):
        render_todo_entry(report, template[0])

    review = _valid_review(report)
    assert review_errors(report, review) == ()
    entry = render_todo_entry(report, review)
    assert review.candidate_id in entry
    assert report.head in entry
    assert "real present/absent/broken import subprocesses pass" in entry
    assert "Narrow optional dependency exception boundary" in entry


def test_review_validation_requires_identity_evidence_expiry_and_valid_fields(
    tmp_path: Path,
) -> None:
    """Incomplete, stale, duplicate, and accepted-boundary decisions fail precisely."""
    report = _report(tmp_path)
    valid = _valid_review(report)
    incomplete = replace(
        valid,
        reviewer="",
        reviewed_at="local-time",
        rationale="",
        evidence=(),
        severity=None,
        owner="",
        acceptance_gates=(),
        title="",
        expires_at="",
        reopen_triggers=(),
    )
    errors = review_errors(report, incomplete)
    assert any("reviewer" in item for item in errors)
    assert any("UTC" in item for item in errors)
    assert any("evidence" in item for item in errors)
    assert any("severity" in item for item in errors)
    duplicates = validate_reviews(report, (valid, valid))
    assert any("duplicate candidate_id" in item for item in duplicates)

    boundary = replace(
        valid,
        decision="accepted-boundary",
        severity=None,
        owner="",
        title="",
        acceptance_gates=(),
        boundary_justification="",
    )
    assert any("boundary" in item for item in review_errors(report, boundary))


def test_todo_append_is_ignored_unique_locked_and_symlink_safe(tmp_path: Path) -> None:
    """Explicit apply appends once only to an existing ignored regular file."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.commit()
    todo = repository.write_text("docs/internal/work/INDEX.md", "# Active work\n")
    report = _report(repository.root)
    review = _valid_review(report)
    entry = render_todo_entry(report, review)
    relative = Path("docs/internal/work/INDEX.md")
    append_todo_entry(repository.root, relative, entry, review.candidate_id)
    assert review.candidate_id in todo.read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="already contains"):
        append_todo_entry(repository.root, relative, entry, review.candidate_id)
    with pytest.raises(ValueError, match="Git ignore"):
        append_todo_entry(
            repository.root,
            Path("public.md"),
            entry,
            review.candidate_id,
        )

    outside = repository.write_text("outside.md", "outside\n")
    link = repository.root / "docs/internal/work/LINK.md"
    link.symlink_to(outside)
    with pytest.raises(ValueError, match="symlink"):
        append_todo_entry(
            repository.root,
            Path("docs/internal/work/LINK.md"),
            entry,
            review.candidate_id,
        )


def test_review_validation_rejects_stale_identity_and_time_boundaries(tmp_path: Path) -> None:
    """Review bindings, UTC timestamps, expiry ordering, and triggers fail precisely."""
    report = _report(tmp_path)
    valid = _valid_review(report)

    stale = replace(valid, report_digest="0" * 64, candidate_id="missing-candidate")
    stale_errors = review_errors(report, stale)
    assert "review report_digest does not match the report" in stale_errors
    assert "review candidate_id is absent from the report" in stale_errors

    non_utc = replace(valid, reviewed_at="2026-07-15T12:00:00+02:00")
    assert "reviewed_at must use UTC" in review_errors(report, non_utc)

    invalid_expiry = replace(valid, expires_at="not-a-timestamp")
    assert "expires_at must be an ISO-8601 UTC timestamp" in review_errors(
        report,
        invalid_expiry,
    )

    reversed_expiry = replace(valid, expires_at=valid.reviewed_at)
    assert "expires_at must be later than reviewed_at" in review_errors(report, reversed_expiry)

    empty_trigger = replace(valid, reopen_triggers=("",))
    assert "reopen triggers must be non-empty strings" in review_errors(report, empty_trigger)

    accepted_boundary = replace(
        valid,
        decision="accepted-boundary",
        severity=None,
        owner="",
        acceptance_gates=(),
        title="",
        boundary_justification="hardware protocol fixes the register width",
    )
    assert review_errors(report, accepted_boundary) == ()

    with pytest.raises(ValueError, match="review is not promotable"):
        render_todo_entry(report, replace(valid, owner=""))

    duplicated_report = replace(
        report,
        candidates=(report.candidates[0], report.candidates[0]),
    )
    with pytest.raises(ValueError, match="exactly once"):
        render_todo_entry(duplicated_report, valid)


def test_todo_append_rejects_unsafe_targets_and_serialises_writers(tmp_path: Path) -> None:
    """Traversal, absent targets, lock contention, and missing final newlines stay safe."""
    repository = GitRepository.create(tmp_path / "repository")
    repository.commit()
    todo = repository.write_text("docs/internal/work/INDEX.md", "# Active work")
    report = _report(repository.root)
    review = _valid_review(report)
    entry = render_todo_entry(report, review)
    relative = Path("docs/internal/work/INDEX.md")

    for unsafe in (tmp_path / "outside.md", Path("../outside.md")):
        with pytest.raises(ValueError, match="repository-relative"):
            append_todo_entry(repository.root, unsafe, entry, review.candidate_id)

    with pytest.raises(ValueError, match="existing regular"):
        append_todo_entry(
            repository.root,
            Path("docs/internal/work/missing.md"),
            entry,
            review.candidate_id,
        )
    with pytest.raises(ValueError, match="existing regular"):
        append_todo_entry(
            repository.root,
            Path("docs/internal/work"),
            entry,
            review.candidate_id,
        )

    lock = todo.with_name(todo.name + ".repository-audit.lock")
    lock.write_text("held", encoding="utf-8")
    with pytest.raises(RuntimeError, match="another audit promotion"):
        append_todo_entry(repository.root, relative, entry, review.candidate_id)
    lock.unlink()

    append_todo_entry(repository.root, relative, entry, review.candidate_id)
    assert todo.read_text(encoding="utf-8").startswith("# Active work\n\n###")
