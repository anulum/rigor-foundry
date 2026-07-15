# SPDX-License-Identifier: MIT
# MIT License; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — evidence-review and TODO promotion
"""Validate candidate reviews and promote only current verified findings."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

from .git_inventory import is_git_ignored
from .models import AuditReport, Candidate, ReviewRecord


def review_templates(report: AuditReport) -> tuple[ReviewRecord, ...]:
    """Return non-promotable review templates for every report candidate.

    Parameters
    ----------
    report:
        Integrity-verified repository audit report.

    Returns
    -------
    tuple[ReviewRecord, ...]
        Records whose decisions are all ``needs-evidence``.

    """
    return tuple(
        ReviewRecord.template(report.report_digest, candidate.candidate_id)
        for candidate in report.candidates
    )


def _utc_timestamp(value: str, field: str, *, allow_empty: bool) -> datetime | None:
    """Parse one ISO-8601 UTC timestamp."""
    if not value:
        if allow_empty:
            return None
        raise ValueError(f"{field} must be an ISO-8601 UTC timestamp")
    normalised = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalised)
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError(f"{field} must use UTC")
    return parsed


def _common_review_errors(report: AuditReport, review: ReviewRecord) -> list[str]:
    """Return errors shared by every completed review decision."""
    errors: list[str] = []
    candidate_ids = {candidate.candidate_id for candidate in report.candidates}
    if review.report_digest != report.report_digest:
        errors.append("review report_digest does not match the report")
    if review.candidate_id not in candidate_ids:
        errors.append("review candidate_id is absent from the report")
    if review.decision == "needs-evidence":
        return errors
    if not review.reviewer.strip():
        errors.append("completed review requires reviewer identity")
    try:
        reviewed_at = _utc_timestamp(review.reviewed_at, "reviewed_at", allow_empty=False)
    except ValueError as exc:
        errors.append(str(exc))
        reviewed_at = None
    if not review.rationale.strip():
        errors.append("completed review requires factual rationale")
    if not review.evidence or any(not item.strip() for item in review.evidence):
        errors.append("completed review requires non-empty reproduction or source evidence")
    if not review.expires_at and not review.reopen_triggers:
        errors.append("completed review requires expires_at or at least one reopen trigger")
    if review.expires_at:
        try:
            expires_at = _utc_timestamp(review.expires_at, "expires_at", allow_empty=False)
        except ValueError as exc:
            errors.append(str(exc))
        else:
            if reviewed_at is not None and expires_at is not None and expires_at <= reviewed_at:
                errors.append("expires_at must be later than reviewed_at")
    if any(not item.strip() for item in review.reopen_triggers):
        errors.append("reopen triggers must be non-empty strings")
    return errors


def review_errors(report: AuditReport, review: ReviewRecord) -> tuple[str, ...]:
    """Return schema and evidence errors for one candidate review.

    Parameters
    ----------
    report:
        Integrity-verified candidate report.
    review:
        Evidence decision to validate.

    Returns
    -------
    tuple[str, ...]
        Empty for a complete decision or a deliberate ``needs-evidence``
        template; otherwise precise validation failures.

    """
    errors = _common_review_errors(report, review)
    if review.decision == "valid":
        if review.severity is None:
            errors.append("valid finding requires severity")
        if not review.owner.strip():
            errors.append("valid finding requires owner")
        if not review.title.strip():
            errors.append("valid finding requires a bounded remediation title")
        if not review.acceptance_gates or any(
            not item.strip() for item in review.acceptance_gates
        ):
            errors.append("valid finding requires non-empty acceptance gates")
    elif review.decision == "accepted-boundary":
        if not review.boundary_justification.strip():
            errors.append("accepted boundary requires protocol or hardware justification")
    return tuple(errors)


def validate_reviews(
    report: AuditReport,
    reviews: tuple[ReviewRecord, ...],
) -> tuple[str, ...]:
    """Return indexed errors for a complete review document."""
    errors: list[str] = []
    seen: set[str] = set()
    for index, review in enumerate(reviews):
        if review.candidate_id in seen:
            errors.append(f"reviews[{index}]: duplicate candidate_id")
        seen.add(review.candidate_id)
        errors.extend(f"reviews[{index}]: {error}" for error in review_errors(report, review))
    return tuple(errors)


def _candidate(report: AuditReport, candidate_id: str) -> Candidate:
    """Return one report candidate by exact identifier."""
    matches = tuple(
        candidate for candidate in report.candidates if candidate.candidate_id == candidate_id
    )
    if len(matches) != 1:
        raise ValueError("review candidate must occur exactly once in the report")
    return matches[0]


def _markdown_text(value: str) -> str:
    """Normalise untrusted review text for one Markdown paragraph."""
    return " ".join(value.replace("\r", " ").replace("\n", " ").split())


def render_todo_entry(report: AuditReport, review: ReviewRecord) -> str:
    """Render one verified valid finding as a bounded TODO block.

    Parameters
    ----------
    report:
        Integrity-verified candidate report.
    review:
        Completed review whose decision must be ``valid``.

    Returns
    -------
    str
        Markdown block suitable for an internal canonical task queue.

    Raises
    ------
    ValueError
        If the review is incomplete, stale, or not a valid finding.

    """
    errors = review_errors(report, review)
    if errors:
        raise ValueError("review is not promotable: " + "; ".join(errors))
    if review.decision != "valid":
        raise ValueError("only reviewed valid findings may be promoted")
    candidate = _candidate(report, review.candidate_id)
    dependencies = ", ".join(f"`{_markdown_text(item)}`" for item in review.dependencies)
    if not dependencies:
        dependencies = "none recorded"
    evidence = "; ".join(_markdown_text(item) for item in review.evidence)
    gates = "\n".join(f"  - {_markdown_text(item)}" for item in review.acceptance_gates)
    triggers = "; ".join(_markdown_text(item) for item in review.reopen_triggers)
    expiry = _markdown_text(review.expires_at) if review.expires_at else "none"
    return (
        f"\n### [{review.severity}] {_markdown_text(review.title)}\n\n"
        f"- [ ] Verified audit finding `{review.candidate_id}` from report "
        f"`{report.report_digest}` at HEAD `{report.head}`.\n"
        f"  - Rule/category: `{candidate.rule_id}` / `{candidate.category}`.\n"
        f"  - Location: `{candidate.path}:{candidate.line}`"
        f"{f' (`{_markdown_text(candidate.symbol)}`)' if candidate.symbol else ''}.\n"
        f"  - Scanner evidence: {_markdown_text(candidate.evidence)}\n"
        f"  - Reviewer: `{_markdown_text(review.reviewer)}` at "
        f"`{_markdown_text(review.reviewed_at)}`.\n"
        f"  - Validity evidence: {evidence}\n"
        f"  - Rationale: {_markdown_text(review.rationale)}\n"
        f"  - Owner: `{_markdown_text(review.owner)}`. Dependencies: {dependencies}.\n"
        f"  - Decision expiry: `{expiry}`. Reopen triggers: {triggers or 'candidate fingerprint drift'}.\n"
        "  - Acceptance gates:\n"
        f"{gates}\n"
    )


def append_todo_entry(
    repository_root: Path,
    todo_path: Path,
    entry: str,
    candidate_id: str,
) -> None:
    """Append one unique entry to an existing canonical internal TODO.

    Parameters
    ----------
    repository_root:
        Resolved Git worktree root.
    todo_path:
        Existing canonical TODO path below ``repository_root``.
    entry:
        Validated Markdown entry.
    candidate_id:
        Stable identifier used for duplicate prevention.

    Raises
    ------
    ValueError
        If the path is unsafe, absent, a symlink, or already contains the
        candidate.
    RuntimeError
        If another process holds the promotion lock.

    """
    root = repository_root.resolve(strict=True)
    if todo_path.is_absolute() or ".." in todo_path.parts:
        raise ValueError("TODO path must be repository-relative")
    if not is_git_ignored(root, todo_path):
        raise ValueError("TODO path must be covered by repository Git ignore rules")
    unresolved = root / todo_path
    cursor = root
    for part in todo_path.parts:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError("TODO path must not contain symlinks")
    absolute = unresolved.resolve(strict=False)
    try:
        absolute.relative_to(root)
    except ValueError as exc:
        raise ValueError("TODO path must remain inside the repository") from exc
    if not absolute.exists() or not absolute.is_file():
        raise ValueError("TODO path must be an existing regular non-symlink file")
    lock_path = absolute.with_name(absolute.name + ".repository-audit.lock")
    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise RuntimeError("another audit promotion holds the TODO lock") from exc
    try:
        os.close(descriptor)
        current = absolute.read_text(encoding="utf-8")
        if candidate_id in current:
            raise ValueError("TODO already contains this candidate identifier")
        with absolute.open("a", encoding="utf-8", newline="") as handle:
            if current and not current.endswith("\n"):
                handle.write("\n")
            handle.write(entry)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        lock_path.unlink(missing_ok=True)
