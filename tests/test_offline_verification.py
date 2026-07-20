# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — offline verification engine tests
"""Verify all evidence kinds, lifecycle states, replay, and unavailability."""

from __future__ import annotations

from offline_verification_fixtures import (
    EVALUATED_AT,
    audit_report,
    detached_signature,
    review_evidence,
    standard_pack,
    trust_policy,
    verification_bundle,
)

from rigor_foundry.offline_verification import verify_evidence_bundle
from rigor_foundry.offline_verification_models import (
    MODEL_ALIASES_SIGNATURE_DOMAIN,
    EvidenceEntry,
    VerificationBundle,
)
from rigor_foundry.offline_verification_report import OfflineVerificationReport


def verify(
    bundle: VerificationBundle | None = None,
    *,
    at: str = EVALUATED_AT,
    revoked_key: str = "",
    valid_from: str = "2026-07-01T00:00:00Z",
    valid_until: str = "2026-08-01T00:00:00Z",
) -> OfflineVerificationReport:
    """Verify a fixture bundle under one explicit lifecycle policy."""
    return verify_evidence_bundle(
        bundle or verification_bundle(),
        trust_policy(
            revoked_key=revoked_key,
            valid_from=valid_from,
            valid_until=valid_until,
        ),
        evaluated_at=at,
    )


def only(entry: EvidenceEntry) -> VerificationBundle:
    """Return one single-evidence verification bundle."""
    return VerificationBundle.build((entry,))


def test_complete_bundle_verifies_all_native_and_detached_protocols() -> None:
    """Reports, reviews, packs, and alias evidence verify without network state."""
    report = verify()
    assert report.status == "verified"
    assert tuple((item.kind, item.status) for item in report.results) == (
        ("model-aliases", "verified"),
        ("standard-pack", "verified"),
        ("audit-report", "verified"),
        ("review", "verified"),
    )
    assert OfflineVerificationReport.from_dict(report.to_dict()) == report


def test_cross_domain_and_fabricated_signature_bytes_are_invalid() -> None:
    """A valid key cannot replay another protocol or fabricated signature bytes."""
    source = audit_report()
    replayed = EvidenceEntry.available(
        "report",
        source,
        signature=detached_signature(
            "audit-report",
            source.report_digest,
            "report-key",
            signing_domain=MODEL_ALIASES_SIGNATURE_DOMAIN,
        ),
    )
    result = verify(only(replayed))
    assert result.status == "invalid"
    assert result.results[0].detail == "detached evidence signature is not valid"

    forged_pack = EvidenceEntry.available("pack", standard_pack(signature_hex="0" * 128))
    result = verify(only(forged_pack))
    assert result.status == "invalid"
    assert result.results[0].detail == "standard-pack signature is not valid"


def test_signature_cannot_move_to_a_different_artifact_identity() -> None:
    """A valid detached signature cannot verify another report digest."""
    source = audit_report()
    mismatched = detached_signature("audit-report", "a" * 64, "report-key")
    result = verify(only(EvidenceEntry.available("report", source, signature=mismatched)))
    assert result.status == "invalid"
    assert result.results[0].detail == "detached signature is bound to different evidence"


def test_revoked_expired_unknown_and_future_keys_remain_distinct() -> None:
    """Lifecycle outcomes preserve revocation severity and expiry staleness."""
    report_entry = verification_bundle().entries[2]

    revoked = verify(only(report_entry), revoked_key="report-key")
    assert revoked.status == "invalid"
    assert revoked.results[0].detail.endswith("is revoked")

    expired = verify(
        only(report_entry),
        valid_until="2026-07-20T00:00:00Z",
    )
    assert expired.status == "stale"
    assert expired.results[0].detail.endswith("is expired")

    future = verify(
        only(report_entry),
        valid_from="2026-07-21T00:00:00Z",
        valid_until="2026-08-01T00:00:00Z",
    )
    assert future.status == "invalid"
    assert future.results[0].detail.endswith("is not-yet-valid")

    source = audit_report()
    unknown = EvidenceEntry.available(
        "unknown-key-report",
        source,
        signature=detached_signature(
            "audit-report",
            source.report_digest,
            "unlisted-key",
        ),
    )
    unknown_result = verify(only(unknown))
    assert unknown_result.status == "invalid"
    assert unknown_result.results[0].detail.endswith("is unknown")


def test_key_must_have_been_active_at_signature_time() -> None:
    """Current trust cannot retroactively authorise pre-validity signatures."""
    report_entry = verification_bundle().entries[2]
    result = verify(
        only(report_entry),
        valid_from="2026-07-20T00:00:00Z",
        valid_until="2026-08-01T00:00:00Z",
    )
    assert result.status == "invalid"
    assert result.results[0].detail == ("verification key was not active when evidence was signed")


def test_future_and_expired_evidence_signatures_do_not_verify() -> None:
    """Evaluation time is explicit and preserves not-yet-effective versus stale."""
    report_entry = verification_bundle().entries[2]
    future = verify(only(report_entry), at="2026-07-18T12:00:00Z")
    assert future.status == "invalid"
    assert future.results[0].detail == "evidence signature is not yet effective"

    stale = verify(only(report_entry), at="2026-07-26T12:00:00Z")
    assert stale.status == "stale"
    assert stale.results[0].detail == "evidence signature is expired"


def test_review_binding_decision_signature_and_expiry_fail_closed() -> None:
    """A review must match its body, decision, key, time, and signature."""
    mismatched_body = EvidenceEntry.available(
        "review",
        review_evidence(assessment_body_digest="a" * 64),
    )
    result = verify(only(mismatched_body))
    assert result.status == "invalid"
    assert "different review record" in result.results[0].detail

    contradicted = EvidenceEntry.available(
        "review",
        review_evidence(decision="fail"),
    )
    result = verify(only(contradicted))
    assert result.status == "invalid"
    assert "decision contradicts" in result.results[0].detail

    forged = EvidenceEntry.available(
        "review",
        review_evidence(signature_hex="0" * 128),
    )
    result = verify(only(forged))
    assert result.status == "invalid"
    assert result.results[0].detail == "review attestation signature is not valid"

    future = verify(only(verification_bundle().entries[3]), at="2026-07-18T12:00:00Z")
    assert future.status == "invalid"
    assert future.results[0].detail == "review is not yet effective"

    stale = verify(only(verification_bundle().entries[3]), at="2026-07-26T12:00:00Z")
    assert stale.status == "stale"
    assert stale.results[0].detail == "review attestation is expired"


def test_review_key_lifecycle_applies_at_signing_and_evaluation() -> None:
    """Review keys obey the same revocation and historical-validity boundary."""
    review_entry = verification_bundle().entries[3]
    revoked = verify(only(review_entry), revoked_key="review-key")
    assert revoked.status == "invalid"
    assert revoked.results[0].detail.endswith("is revoked")

    historical = verify(
        only(review_entry),
        valid_from="2026-07-20T00:00:00Z",
        valid_until="2026-08-01T00:00:00Z",
    )
    assert historical.status == "invalid"
    assert historical.results[0].detail == (
        "verification key was not active when the review was signed"
    )


def test_pack_key_revocation_invalidates_native_signature_trust() -> None:
    """A cryptographically valid pack is invalid once its selected key is revoked."""
    pack_entry = verification_bundle().entries[1]
    revoked = verify(only(pack_entry), revoked_key="standards-key")
    assert revoked.status == "invalid"
    assert revoked.results[0].detail.endswith("is revoked")


def test_unavailable_evidence_remains_explicit_and_nonzero() -> None:
    """Missing bytes are reported, never inferred or silently ignored."""
    missing = EvidenceEntry.unavailable(
        "missing-report",
        "audit-report",
        expected_digest="a" * 64,
        reason="offline archive was not supplied",
    )
    result = verify(only(missing))
    assert result.status == "unavailable"
    assert result.results[0].artifact_digest == "a" * 64
    assert result.results[0].detail == "offline archive was not supplied"


def test_invalid_status_dominates_stale_and_unavailable_results() -> None:
    """Aggregate output cannot hide a revoked item behind partial evidence."""
    missing = EvidenceEntry.unavailable(
        "missing",
        "review",
        expected_digest="a" * 64,
        reason="not supplied",
    )
    bundle = VerificationBundle.build((verification_bundle().entries[2], missing))
    result = verify(bundle, revoked_key="report-key")
    assert result.status == "invalid"
    assert {item.status for item in result.results} == {"invalid", "unavailable"}
