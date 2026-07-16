# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — cross-model campaign promotion admission
"""Require durable cross-model campaign evidence before finding promotion."""

from __future__ import annotations

from pathlib import Path

from .campaign_compare import AuditComparison, compare_campaign
from .campaign_store import (
    load_campaign,
    load_campaign_reviews,
    load_comparison_record,
    load_runs,
)
from .models import AuditReport, ReviewRecord
from .review import validate_reviews


def _validate_campaign_reviews(
    reports: dict[str, AuditReport],
    reviews: tuple[tuple[ReviewRecord, ...], ...],
) -> None:
    """Validate every durable review document against its campaign report."""
    for index, review_set in enumerate(reviews):
        digests = {review.report_digest for review in review_set}
        if len(digests) != 1:
            raise ValueError(f"review document {index} mixes report digests")
        report = reports.get(next(iter(digests)))
        if report is None:
            raise ValueError(f"review document {index} has no matching campaign report")
        errors = validate_reviews(report, review_set)
        if errors:
            raise ValueError(f"review document {index} is invalid: " + "; ".join(errors))


def validate_promotion_campaign(
    campaign_path: Path,
    comparison_path: Path,
    report: AuditReport,
    review: ReviewRecord,
) -> AuditComparison:
    """Verify exact durable cross-model evidence for one promotion.

    Parameters
    ----------
    campaign_path:
        Canonical ignored campaign manifest.
    comparison_path:
        Immutable comparison stored below that campaign.
    report:
        Exact report containing the selected candidate.
    review:
        Exact reviewed decision selected for promotion.

    Returns
    -------
    AuditComparison
        The integrity-checked promotion-eligible comparison.

    Raises
    ------
    ValueError
        If the campaign is diagnostic, unresolved, stale, incomplete, or does
        not contain the selected report and review.
    """
    campaign = load_campaign(campaign_path)
    comparison = load_comparison_record(campaign_path, comparison_path)
    if campaign.purpose != "promotion":
        raise ValueError("finding promotion requires a promotion campaign")
    if comparison.unresolved or not comparison.promotion_eligible:
        raise ValueError("campaign comparison is not eligible for promotion")
    runs = load_runs(campaign_path)
    reviews = load_campaign_reviews(campaign_path)
    reports = {stored.report.report_digest: stored.report for stored in runs}
    _validate_campaign_reviews(reports, reviews)
    reproduced = compare_campaign(
        campaign,
        runs,
        reviews,
        comparison_id=comparison.comparison_id,
        created_by=comparison.created_by,
        created_at=comparison.created_at,
    )
    if reproduced != comparison:
        raise ValueError("campaign comparison no longer matches its durable evidence")
    if report.report_digest not in comparison.report_digests:
        raise ValueError("promotion report did not participate in the campaign comparison")
    errors = validate_reviews(report, (review,))
    if errors:
        raise ValueError("promotion review validation failed: " + "; ".join(errors))
    if review.review_digest not in comparison.review_digests:
        raise ValueError("promotion review did not participate in the campaign comparison")
    return comparison
