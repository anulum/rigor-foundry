# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — cross-protocol signature-domain tests
"""Prove that Ed25519 signatures cannot move between protocol records."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest
from signing_fixtures import private_key, sign_message, trust_store

from rigor_foundry import (
    ED25519_SIGNATURE_MESSAGE_VERSION,
    REVIEW_ATTESTATION_SIGNATURE_DOMAIN,
    STANDARD_PACK_SIGNATURE_DOMAIN,
    ed25519_signature_message,
)
from rigor_foundry.review_attestation import (
    REVIEW_ATTESTATION_SCHEMA_VERSION,
    ReviewerAttestation,
)
from rigor_foundry.standard_pack import PACK_SIGNATURE_SCHEMA_VERSION, PackSignature
from rigor_foundry.trust import ED25519_SIGNATURE_MESSAGE_PREFIX

KEY_ID = "protocol-key"
PAYLOAD_DIGEST = "a" * 64
ASSESSMENT_BODY_DIGEST = "b" * 64
REVIEWED_AT = "2026-07-15T12:00:00Z"
EXPIRES_AT = "2026-07-17T12:00:00Z"


def review_payload_digest() -> str:
    """Return one complete reviewer-attestation payload digest."""
    return ReviewerAttestation.payload_digest(
        reviewer_id="independent-reviewer",
        algorithm="ed25519",
        key_id=KEY_ID,
        assessment_body_digest=ASSESSMENT_BODY_DIGEST,
        decision="pass",
        reviewed_at=REVIEWED_AT,
        expires_at=EXPIRES_AT,
    )


def reviewer_attestation(*, signing_domain: str) -> ReviewerAttestation:
    """Build one review record using signature bytes from the selected domain."""
    payload_digest = review_payload_digest()
    return ReviewerAttestation.build(
        reviewer_id="independent-reviewer",
        key_id=KEY_ID,
        assessment_body_digest=ASSESSMENT_BODY_DIGEST,
        decision="pass",
        reviewed_at=REVIEWED_AT,
        expires_at=EXPIRES_AT,
        signature_hex=sign_message(KEY_ID, signing_domain, payload_digest),
    )


def test_same_key_and_digest_are_cryptographically_bound_to_one_protocol() -> None:
    """A signature valid in either protocol fails under the other domain."""
    store = trust_store(KEY_ID)
    pack_signature = sign_message(
        KEY_ID,
        STANDARD_PACK_SIGNATURE_DOMAIN,
        PAYLOAD_DIGEST,
    )
    review_signature = sign_message(
        KEY_ID,
        REVIEW_ATTESTATION_SIGNATURE_DOMAIN,
        PAYLOAD_DIGEST,
    )

    assert store.verify(
        key_id=KEY_ID,
        algorithm="ed25519",
        signature_domain=STANDARD_PACK_SIGNATURE_DOMAIN,
        payload_digest=PAYLOAD_DIGEST,
        signature_hex=pack_signature,
    )
    assert not store.verify(
        key_id=KEY_ID,
        algorithm="ed25519",
        signature_domain=REVIEW_ATTESTATION_SIGNATURE_DOMAIN,
        payload_digest=PAYLOAD_DIGEST,
        signature_hex=pack_signature,
    )
    assert store.verify(
        key_id=KEY_ID,
        algorithm="ed25519",
        signature_domain=REVIEW_ATTESTATION_SIGNATURE_DOMAIN,
        payload_digest=PAYLOAD_DIGEST,
        signature_hex=review_signature,
    )
    assert not store.verify(
        key_id=KEY_ID,
        algorithm="ed25519",
        signature_domain=STANDARD_PACK_SIGNATURE_DOMAIN,
        payload_digest=PAYLOAD_DIGEST,
        signature_hex=review_signature,
    )


def test_legacy_raw_digest_signature_is_not_reinterpreted() -> None:
    """A pre-migration raw-digest signature fails every versioned domain."""
    legacy_signature = private_key(KEY_ID).sign(bytes.fromhex(PAYLOAD_DIGEST)).hex()
    store = trust_store(KEY_ID)
    for domain in (
        STANDARD_PACK_SIGNATURE_DOMAIN,
        REVIEW_ATTESTATION_SIGNATURE_DOMAIN,
    ):
        assert not store.verify(
            key_id=KEY_ID,
            algorithm="ed25519",
            signature_domain=domain,
            payload_digest=PAYLOAD_DIGEST,
            signature_hex=legacy_signature,
        )


def test_signature_message_has_one_exact_versioned_binary_encoding() -> None:
    """The public signing API emits the documented unambiguous byte sequence."""
    assert ED25519_SIGNATURE_MESSAGE_VERSION == "1.0"
    message = ed25519_signature_message(
        signature_domain=STANDARD_PACK_SIGNATURE_DOMAIN,
        payload_digest="00" * 32,
    )
    assert message == (
        b"RIGOR-FOUNDRY-ED25519\x00v1\x00\x00\x1erigor-foundry.standard-pack.v1" + (b"\x00" * 32)
    )
    assert message.startswith(ED25519_SIGNATURE_MESSAGE_PREFIX)


@pytest.mark.parametrize(
    "domain",
    (
        "",
        ".leading",
        "trailing.",
        "Uppercase",
        "contains space",
        "contains\x00nul",
        "a" * 129,
    ),
)
def test_signature_message_rejects_noncanonical_domains(domain: str) -> None:
    """Ambiguous, non-ASCII-compatible, and oversized domains fail closed."""
    with pytest.raises(ValueError):
        ed25519_signature_message(
            signature_domain=domain,
            payload_digest=PAYLOAD_DIGEST,
        )


def test_signature_message_accepts_boundary_domain_and_rejects_bad_digest() -> None:
    """The 128-byte domain ceiling is inclusive and digest validation is exact."""
    assert ed25519_signature_message(
        signature_domain="a" * 128,
        payload_digest=PAYLOAD_DIGEST,
    )
    with pytest.raises(ValueError, match="digest"):
        ed25519_signature_message(
            signature_domain=STANDARD_PACK_SIGNATURE_DOMAIN,
            payload_digest="not-a-digest",
        )


def test_pack_signature_envelope_rejects_legacy_and_cross_protocol_records() -> None:
    """Pack-signature schema and domain changes require explicit re-signing."""
    signature = PackSignature.build(
        key_id=KEY_ID,
        payload_digest=PAYLOAD_DIGEST,
        signature_hex=sign_message(
            KEY_ID,
            STANDARD_PACK_SIGNATURE_DOMAIN,
            PAYLOAD_DIGEST,
        ),
    )
    serialised = signature.to_dict()
    assert serialised["schema_version"] == PACK_SIGNATURE_SCHEMA_VERSION
    assert PackSignature.from_dict(serialised) == signature

    missing_schema = dict(serialised)
    missing_schema.pop("schema_version")
    missing_domain = dict(serialised)
    missing_domain.pop("signature_domain")
    extra_field = {**serialised, "legacy": "accepted"}
    for invalid in (missing_schema, missing_domain, extra_field):
        with pytest.raises(ValueError, match="fields"):
            PackSignature.from_dict(invalid)

    old_schema = {**serialised, "schema_version": "0.9"}
    with pytest.raises(ValueError, match="schema version"):
        PackSignature.from_dict(old_schema)
    bad_digest = {**serialised, "signature_digest": "0" * 64}
    with pytest.raises(ValueError, match="signature digest"):
        PackSignature.from_dict(bad_digest)
    replayed = {
        **serialised,
        "signature_domain": REVIEW_ATTESTATION_SIGNATURE_DOMAIN,
    }
    with pytest.raises(ValueError, match="standard-pack"):
        PackSignature.from_dict(replayed)
    with pytest.raises(ValueError, match="ed25519"):
        PackSignature.build(
            key_id=KEY_ID,
            algorithm="rsa",
            payload_digest=PAYLOAD_DIGEST,
            signature_hex=signature.signature_hex,
        )


def test_reviewer_envelope_rejects_legacy_and_cross_protocol_records() -> None:
    """Reviewer schema and domain changes never reinterpret earlier records."""
    review = reviewer_attestation(signing_domain=REVIEW_ATTESTATION_SIGNATURE_DOMAIN)
    serialised = review.to_dict()
    assert serialised["schema_version"] == REVIEW_ATTESTATION_SCHEMA_VERSION
    assert ReviewerAttestation.from_dict(serialised) == review

    missing_schema = dict(serialised)
    missing_schema.pop("schema_version")
    missing_domain = dict(serialised)
    missing_domain.pop("signature_domain")
    extra_field = {**serialised, "legacy": "accepted"}
    for invalid in (missing_schema, missing_domain, extra_field):
        with pytest.raises(ValueError, match="fields"):
            ReviewerAttestation.from_dict(invalid)

    old_schema = {**serialised, "schema_version": "1.0"}
    with pytest.raises(ValueError, match="schema version"):
        ReviewerAttestation.from_dict(old_schema)
    replayed = {**serialised, "signature_domain": STANDARD_PACK_SIGNATURE_DOMAIN}
    with pytest.raises(ValueError, match="reviewer-attestation"):
        ReviewerAttestation.from_dict(replayed)
    with pytest.raises(ValueError, match="ed25519"):
        ReviewerAttestation.build(
            reviewer_id=review.reviewer_id,
            algorithm="rsa",
            key_id=review.key_id,
            assessment_body_digest=review.assessment_body_digest,
            decision=review.decision,
            reviewed_at=review.reviewed_at,
            expires_at=review.expires_at,
            signature_hex=review.signature_hex,
        )

    invalid_domain = replace(
        review,
        signature_domain=STANDARD_PACK_SIGNATURE_DOMAIN,
    )
    assert not invalid_domain.verified_at(
        datetime(2026, 7, 16, tzinfo=UTC),
        "pass",
        ASSESSMENT_BODY_DIGEST,
        trust_store(KEY_ID),
    )


def test_pack_domain_signature_cannot_authorise_reviewer_attestation() -> None:
    """A structurally valid review record still rejects replayed pack signatures."""
    replayed = reviewer_attestation(signing_domain=STANDARD_PACK_SIGNATURE_DOMAIN)
    assert not replayed.verified_at(
        datetime(2026, 7, 16, tzinfo=UTC),
        "pass",
        ASSESSMENT_BODY_DIGEST,
        trust_store(KEY_ID),
    )


def test_reviewer_attestation_accepts_its_exact_protocol_signature() -> None:
    """The migrated reviewer record verifies through the production trust boundary."""
    review = reviewer_attestation(signing_domain=REVIEW_ATTESTATION_SIGNATURE_DOMAIN)
    assert review.verified_at(
        datetime(2026, 7, 16, tzinfo=UTC),
        "pass",
        ASSESSMENT_BODY_DIGEST,
        trust_store(KEY_ID),
    )
