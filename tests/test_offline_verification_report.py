# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — offline verification report tests
"""Prove deterministic result aggregation and replay rejection."""

from __future__ import annotations

from typing import cast

import pytest
from offline_verification_fixtures import EVALUATED_AT, verification_bundle

from rigor_foundry.offline_verification_models import VerificationStatus
from rigor_foundry.offline_verification_report import (
    EvidenceVerificationResult,
    OfflineVerificationReport,
)


def result(status: str) -> EvidenceVerificationResult:
    """Return one result for the fixture bundle's first entry."""
    return EvidenceVerificationResult.build(
        verification_bundle().entries[0],
        cast(VerificationStatus, status),
        f"fixture status {status}",
    )


def report(*statuses: str) -> OfflineVerificationReport:
    """Return one aggregate report with selected result states."""
    bundle = verification_bundle()
    return OfflineVerificationReport.build(
        evaluated_at=EVALUATED_AT,
        policy_digest="a" * 64,
        bundle_digest=bundle.bundle_digest,
        results=tuple(result(status) for status in statuses),
    )


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        (("verified",), "verified"),
        (("unavailable",), "unavailable"),
        (("stale", "unavailable"), "stale"),
        (("invalid", "stale", "unavailable"), "invalid"),
    ],
)
def test_aggregate_status_preserves_failure_precedence(
    statuses: tuple[str, ...],
    expected: str,
) -> None:
    """Invalid, stale, and unavailable evidence can never be upgraded."""
    aggregate = report(*statuses)
    assert aggregate.status == expected
    assert OfflineVerificationReport.from_dict(aggregate.to_dict()) == aggregate
    assert aggregate.to_json().endswith("\n")


def test_result_round_trip_and_validation_failures() -> None:
    """Per-evidence result shape, status, and digest are strict."""
    current = result("verified")
    assert EvidenceVerificationResult.from_dict(current.to_dict()) == current
    with pytest.raises(ValueError, match="unsupported"):
        result("unknown")
    for mutation, message in (
        ({**current.to_dict(), "extra": True}, "fields"),
        ({**current.to_dict(), "status": "unknown"}, "unsupported"),
        ({**current.to_dict(), "kind": "unknown"}, "kind"),
        ({**current.to_dict(), "result_digest": "0" * 64}, "digest"),
    ):
        with pytest.raises(ValueError, match=message):
            EvidenceVerificationResult.from_dict(mutation)


def test_report_parser_rejects_shape_schema_array_status_and_digest_drift() -> None:
    """Persisted aggregate state is recomputed from the exact result set."""
    aggregate = report("verified")
    for mutation, message in (
        ({**aggregate.to_dict(), "extra": True}, "fields"),
        ({**aggregate.to_dict(), "schema_version": "2.0"}, "schema"),
        ({**aggregate.to_dict(), "results": {}}, "array"),
        ({**aggregate.to_dict(), "status": "invalid"}, "status"),
        ({**aggregate.to_dict(), "report_digest": "0" * 64}, "digest"),
    ):
        with pytest.raises(ValueError, match=message):
            OfflineVerificationReport.from_dict(mutation)
