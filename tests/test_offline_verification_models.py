# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — offline verification protocol-model tests
"""Prove strict bundle, signature, review, and alias evidence records."""

from __future__ import annotations

from copy import deepcopy

import pytest
from offline_verification_fixtures import (
    EXPIRES_AT,
    SIGNED_AT,
    audit_report,
    detached_signature,
    model_aliases,
    review_evidence,
    standard_pack,
    verification_bundle,
)
from signing_fixtures import sign_message

from rigor_foundry.campaign_identity import InferenceIdentity
from rigor_foundry.offline_verification_models import (
    AUDIT_REPORT_SIGNATURE_DOMAIN,
    MODEL_ALIASES_SIGNATURE_DOMAIN,
    DetachedEvidenceSignature,
    EvidenceEntry,
    ModelAliasEvidence,
    ReviewEvidence,
    VerificationBundle,
)


def test_detached_signature_round_trip_binds_kind_digest_domain_and_time() -> None:
    """A report signature preserves every signed field and derived digest."""
    report = audit_report()
    signature = detached_signature("audit-report", report.report_digest, "report-key")
    assert DetachedEvidenceSignature.from_dict(signature.to_dict()) == signature
    assert signature.signature_domain == AUDIT_REPORT_SIGNATURE_DOMAIN
    assert (
        DetachedEvidenceSignature.payload_digest(
            artifact_kind="audit-report",
            key_id="report-key",
            artifact_digest=report.report_digest,
            signed_at=SIGNED_AT,
            expires_at=EXPIRES_AT,
        )
        == signature.signed_payload_digest
    )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"artifact_kind": "review"}, "support"),
        ({"algorithm": "rsa"}, "ed25519"),
        ({"expires_at": SIGNED_AT}, "follow"),
        ({"signature_domain": MODEL_ALIASES_SIGNATURE_DOMAIN}, "wrong protocol"),
        ({"signature_hex": "0" * 126}, "lowercase hexadecimal"),
    ],
)
def test_detached_signature_builder_rejects_unsupported_protocol_shapes(
    changes: dict[str, str],
    message: str,
) -> None:
    """Kinds, algorithms, intervals, domains, and bytes fail closed."""
    report = audit_report()
    arguments = {
        "artifact_kind": "audit-report",
        "key_id": "report-key",
        "artifact_digest": report.report_digest,
        "signed_at": SIGNED_AT,
        "expires_at": EXPIRES_AT,
        "signature_domain": AUDIT_REPORT_SIGNATURE_DOMAIN,
        "signature_hex": "0" * 128,
        **changes,
    }
    with pytest.raises(ValueError, match=message):
        DetachedEvidenceSignature.build(**arguments)


def test_detached_signature_parser_rejects_shape_schema_and_derived_tampering() -> None:
    """Envelope replay fields cannot drift independently."""
    signature = detached_signature("model-aliases", model_aliases().alias_digest, "model-key")
    document = signature.to_dict()
    mutations = (
        ({**document, "extra": "x"}, "fields"),
        ({**document, "schema_version": "2.0"}, "schema"),
        ({**document, "signed_payload_digest": "0" * 64}, "signed_payload_digest"),
        ({**document, "signature_digest": "0" * 64}, "signature_digest"),
        ({**document, "envelope_digest": "0" * 64}, "envelope_digest"),
    )
    for mutation, message in mutations:
        with pytest.raises(ValueError, match=message):
            DetachedEvidenceSignature.from_dict(mutation)


def test_model_alias_evidence_round_trip_collapses_correlated_names() -> None:
    """Two declared names sharing one family remain one witness."""
    aliases = model_aliases()
    assert len(aliases.runs) == 2
    assert len(aliases.witnesses) == 1
    assert aliases.witnesses[0].run_ids == ("run-a", "run-b")
    assert ModelAliasEvidence.from_dict(aliases.to_dict()) == aliases


def test_model_alias_parser_rejects_false_witnesses_duplicates_and_shape_drift() -> None:
    """A claimed independent witness cannot survive actual alias collapse."""
    aliases = model_aliases()
    document = aliases.to_dict()
    duplicated = deepcopy(document)
    assert isinstance(duplicated["witnesses"], list)
    duplicated["witnesses"].append(duplicated["witnesses"][0])
    with pytest.raises(ValueError, match="collapsed identities"):
        ModelAliasEvidence.from_dict(duplicated)

    unsorted = deepcopy(document)
    assert isinstance(unsorted["runs"], list)
    unsorted["runs"].reverse()
    with pytest.raises(ValueError, match="sorted and canonical"):
        ModelAliasEvidence.from_dict(unsorted)

    malformed_run = deepcopy(document)
    assert isinstance(malformed_run["runs"], list)
    malformed_run["runs"][0]["extra"] = True
    with pytest.raises(ValueError, match="run fields"):
        ModelAliasEvidence.from_dict(malformed_run)

    for mutation, message in (
        ({**document, "extra": True}, "fields"),
        ({**document, "schema_version": "2.0"}, "schema"),
        ({**document, "runs": {}}, "arrays"),
        ({**document, "witnesses": {}}, "arrays"),
        ({**document, "alias_digest": "0" * 64}, "digest"),
    ):
        with pytest.raises(ValueError, match=message):
            ModelAliasEvidence.from_dict(mutation)

    identity = InferenceIdentity.build(
        provider="provider",
        model="model",
        model_family="family",
        operator="operator",
    )
    with pytest.raises(ValueError, match="duplicate run"):
        ModelAliasEvidence.build((("same", identity), ("same", identity)))


def test_review_evidence_round_trip_and_integrity_failures() -> None:
    """Review content and detached attestation retain one combined identity."""
    evidence = review_evidence()
    assert ReviewEvidence.from_dict(evidence.to_dict()) == evidence
    document = evidence.to_dict()
    for mutation, message in (
        ({**document, "extra": True}, "fields"),
        ({**document, "schema_version": "2.0"}, "schema"),
        ({**document, "evidence_digest": "0" * 64}, "digest"),
    ):
        with pytest.raises(ValueError, match=message):
            ReviewEvidence.from_dict(mutation)
    noncanonical = deepcopy(document)
    assert isinstance(noncanonical["review"], dict)
    noncanonical["review"].pop("boundary_justification")
    with pytest.raises(ValueError, match="must be canonical"):
        ReviewEvidence.from_dict(noncanonical)


def test_available_entries_round_trip_all_document_protocols() -> None:
    """Each supported document follows its native parser and signature boundary."""
    bundle = verification_bundle()
    assert VerificationBundle.from_dict(bundle.to_dict()) == bundle
    assert tuple(item.evidence_id for item in bundle.entries) == (
        "aliases",
        "pack",
        "report",
        "review",
    )
    for entry in bundle.entries:
        assert EvidenceEntry.from_dict(entry.to_dict()) == entry
        assert entry.availability == "available"
        assert entry.reason == ""


def test_entry_builder_requires_only_the_correct_signature_protocol() -> None:
    """Reports and aliases require envelopes; packs and reviews use native signatures."""
    report = audit_report()
    signature = detached_signature("audit-report", report.report_digest, "report-key")
    with pytest.raises(ValueError, match="requires"):
        EvidenceEntry.available("report", report)
    with pytest.raises(ValueError, match="native"):
        EvidenceEntry.available("pack", standard_pack(), signature=signature)


def test_unavailable_entry_is_explicit_and_cannot_smuggle_document_bytes() -> None:
    """Missing evidence retains its expected identity and a non-empty reason."""
    entry = EvidenceEntry.unavailable(
        "missing-report",
        "audit-report",
        expected_digest="a" * 64,
        reason="air-gapped archive not supplied",
    )
    assert EvidenceEntry.from_dict(entry.to_dict()) == entry
    assert entry.document is entry.signature is None
    with pytest.raises(ValueError, match="non-empty"):
        EvidenceEntry.unavailable(
            "missing-report",
            "audit-report",
            expected_digest="a" * 64,
            reason="",
        )
    smuggled = entry.to_dict()
    smuggled["document"] = audit_report().to_dict()
    with pytest.raises(ValueError, match="cannot contain"):
        EvidenceEntry.from_dict(smuggled)


def test_entry_and_bundle_parsers_reject_shape_identity_and_digest_drift() -> None:
    """Bundle membership, expected identities, and container digests are exact."""
    entry = verification_bundle().entries[0]
    for mutation, message in (
        ({**entry.to_dict(), "extra": True}, "fields"),
        ({**entry.to_dict(), "kind": "unknown"}, "unsupported"),
        ({**entry.to_dict(), "availability": "unknown"}, "unsupported"),
        ({**entry.to_dict(), "expected_digest": "0" * 64}, "expected digest"),
        ({**entry.to_dict(), "entry_digest": "0" * 64}, "entry digest"),
    ):
        with pytest.raises(ValueError, match=message):
            EvidenceEntry.from_dict(mutation)

    bundle = verification_bundle()
    with pytest.raises(ValueError, match="at least one"):
        VerificationBundle.build(())
    with pytest.raises(ValueError, match="unique"):
        VerificationBundle.build((entry, entry))
    for mutation, message in (
        ({**bundle.to_dict(), "extra": True}, "fields"),
        ({**bundle.to_dict(), "schema_version": "2.0"}, "schema"),
        ({**bundle.to_dict(), "entries": {}}, "array"),
        ({**bundle.to_dict(), "bundle_digest": "0" * 64}, "digest"),
    ):
        with pytest.raises(ValueError, match=message):
            VerificationBundle.from_dict(mutation)
    unsorted_bundle = bundle.to_dict()
    assert isinstance(unsorted_bundle["entries"], list)
    unsorted_bundle["entries"].reverse()
    with pytest.raises(ValueError, match="sorted by evidence_id"):
        VerificationBundle.from_dict(unsorted_bundle)


def test_cross_domain_signature_bytes_remain_parseable_but_not_relabelled() -> None:
    """The model permits adversarial bytes only under the one declared report domain."""
    report = audit_report()
    payload = DetachedEvidenceSignature.payload_digest(
        artifact_kind="audit-report",
        key_id="report-key",
        artifact_digest=report.report_digest,
        signed_at=SIGNED_AT,
        expires_at=EXPIRES_AT,
    )
    envelope = DetachedEvidenceSignature.build(
        artifact_kind="audit-report",
        key_id="report-key",
        artifact_digest=report.report_digest,
        signed_at=SIGNED_AT,
        expires_at=EXPIRES_AT,
        signature_domain=AUDIT_REPORT_SIGNATURE_DOMAIN,
        signature_hex=sign_message("report-key", MODEL_ALIASES_SIGNATURE_DOMAIN, payload),
    )
    assert DetachedEvidenceSignature.from_dict(envelope.to_dict()) == envelope
