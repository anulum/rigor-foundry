# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — external-source provenance tests
"""Verify exact external assertions, captures, parsing, and filesystem boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import pickle
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from rigor_foundry.source_capture import (
    MAX_SOURCE_BYTES,
    SourceCapture,
    SourceRetrievalPolicy,
    read_source_payload,
    require_media_type,
)
from rigor_foundry.source_provenance import (
    ExternalSourceClaim,
    SourceVerification,
    source_provenance_to_json,
    verify_external_source,
)

PAYLOAD = b'{"advisory":{"id":"CVE-2026-52869","affected":true},"version":"2.4.1"}'
URI = "https://advisories.example.test/v1/CVE-2026-52869.json"


def policy(**changes: Any) -> SourceRetrievalPolicy:
    """Return one strict source retrieval policy."""
    values: dict[str, object] = {
        "allowed_hosts": ("advisories.example.test",),
        "allow_cross_origin_redirects": False,
        "maximum_redirects": 2,
        "timeout_seconds": 5,
        "maximum_bytes": 4096,
        "allowed_media_types": ("application/json",),
        "freshness_seconds": 3600,
    }
    values.update(changes)
    return SourceRetrievalPolicy.build(**values)


def claim(**changes: Any) -> ExternalSourceClaim:
    """Return one JSON-pointer advisory assertion."""
    values: dict[str, object] = {
        "claim_id": "cve-2026-52869-affected",
        "kind": "advisory",
        "subject": "CVE-2026-52869",
        "predicate": "affected",
        "expected_value": True,
        "source_uri": URI,
        "extraction_method": "json-pointer",
        "selector": "/advisory/affected",
    }
    values.update(changes)
    return ExternalSourceClaim.build(**values)


def capture(payload: bytes = PAYLOAD, **changes: Any) -> SourceCapture:
    """Return one exact retained-payload capture."""
    values: dict[str, object] = {
        "requested_uri": URI,
        "final_uri": URI,
        "redirect_count": 0,
        "http_status": 200,
        "media_type": "application/json",
        "retrieved_at": "2026-07-17T08:00:00Z",
        "retrieval_policy": policy(),
        "retriever_name": "curl",
        "retriever_version": "8.10.1",
        "retriever_executable_digest": "a" * 64,
    }
    values.update(changes)
    return SourceCapture.record(payload, **values)


def verification() -> SourceVerification:
    """Return one successful exact source verification."""
    return verify_external_source(
        claim(),
        capture(),
        PAYLOAD,
        verified_at="2026-07-17T08:30:00Z",
        verifier="auditor/one",
    )


def test_advisory_version_standard_and_digest_claims_verify_exact_values() -> None:
    """All four public claim kinds use exact captured bytes and finite extraction."""
    advisory = verification()
    assert advisory.verified_value is True
    assert advisory.authority_scope == "retrieval-policy-only"
    assert SourceVerification.from_dict(advisory.to_dict()) == advisory

    version = claim(
        claim_id="package-version",
        kind="version",
        subject="example-package",
        predicate="release",
        expected_value="2.4.1",
        selector="/version",
    )
    standard_payload = b'{"standards":[{"edition":2022}]}'
    standard_uri = "https://advisories.example.test/standards/iso-27001.json"
    standard = claim(
        claim_id="iso-27001-edition",
        kind="standard",
        subject="ISO/IEC 27001",
        predicate="edition",
        expected_value=2022,
        source_uri=standard_uri,
        selector="/standards/0/edition",
    )
    digest = claim(
        claim_id="standard-document-digest",
        kind="content-digest",
        subject="ISO/IEC 27001:2022",
        predicate="sha256",
        expected_value=hashlib.sha256(standard_payload).hexdigest(),
        source_uri=standard_uri,
        extraction_method="whole-payload-sha256",
        selector="",
    )
    assert (
        verify_external_source(
            version,
            capture(),
            PAYLOAD,
            verified_at="2026-07-17T08:30:00Z",
            verifier="auditor/one",
        ).verified_value
        == "2.4.1"
    )
    standard_capture = capture(
        standard_payload,
        requested_uri=standard_uri,
        final_uri=standard_uri,
    )
    assert (
        verify_external_source(
            standard,
            standard_capture,
            standard_payload,
            verified_at="2026-07-17T08:30:00Z",
            verifier="auditor/one",
        ).verified_value
        == 2022
    )
    assert (
        verify_external_source(
            digest,
            standard_capture,
            standard_payload,
            verified_at="2026-07-17T08:30:00Z",
            verifier="auditor/one",
        ).verified_value
        == hashlib.sha256(standard_payload).hexdigest()
    )


def test_claim_policy_capture_and_verification_round_trip_and_tamper() -> None:
    """Strict parsers reject extra fields, schema drift, and every derived digest drift."""
    objects = (
        (claim(), ExternalSourceClaim, "claim_digest"),
        (policy(), SourceRetrievalPolicy, "policy_digest"),
        (capture(), SourceCapture, "capture_digest"),
        (verification(), SourceVerification, "verification_digest"),
    )
    for instance, record_type, digest_field in objects:
        document = instance.to_dict()
        assert record_type.from_dict(document) == instance
        changed = dict(document)
        changed[digest_field] = "0" * 64
        with pytest.raises(ValueError, match="digest"):
            record_type.from_dict(changed)
        with pytest.raises(ValueError, match="fields"):
            record_type.from_dict({**document, "unexpected": True})
        with pytest.raises(ValueError, match="schema"):
            record_type.from_dict({**document, "schema_version": "2.0"})
    assert json.loads(source_provenance_to_json(verification())) == verification().to_dict()
    with pytest.raises(ValueError, match="to_dict"):
        source_provenance_to_json(object())
    assert pickle.loads(pickle.dumps(verification())) == verification()  # nosec B301


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"kind": "unknown"}, "unsupported"),
        ({"extraction_method": "regex"}, "unsupported"),
        ({"source_uri": "http://example.test/a"}, "canonical HTTPS"),
        ({"source_uri": "https://USER@example.test/a"}, "credentials"),
        ({"source_uri": "https://example.test:443/a"}, "invalid port"),
        ({"source_uri": "https://example.test/a#fragment"}, "fragment"),
        ({"source_uri": "https://EXAMPLE.test/a"}, "canonical HTTPS"),
        ({"source_uri": "https://example.test/a/../b"}, "dot path"),
        ({"source_uri": "https://example.test/a/%2E%2E/b"}, "dot path"),
        ({"source_uri": "https://example.test/a/%zz"}, "percent encoding"),
        ({"source_uri": "https://example.test:invalid/a"}, "invalid port"),
        ({"source_uri": "https://example.test/a b"}, "printable-ASCII"),
        ({"source_uri": "https://example.test/" + "a" * 2049}, "bounded"),
        ({"selector": "affected"}, "JSON Pointer"),
        ({"selector": ""}, "JSON Pointer"),
        ({"subject": "x" * 513}, "bounded single-line"),
        ({"expected_value": "x" * 4097}, "bounded single-line"),
    ],
)
def test_claim_rejects_ambiguous_kind_uri_and_selector(
    changes: dict[str, object], message: str
) -> None:
    """Claims cannot broaden source identity or use non-deterministic extraction."""
    with pytest.raises(ValueError, match=message):
        claim(**changes)


def test_digest_claim_relations_are_exact() -> None:
    """A whole-payload claim is reserved for an exact lowercase SHA-256 assertion."""
    base = {
        "claim_id": "payload-digest",
        "kind": "content-digest",
        "predicate": "sha256",
        "expected_value": "1" * 64,
        "extraction_method": "whole-payload-sha256",
        "selector": "",
    }
    for changes in (
        {"predicate": "sha512"},
        {"extraction_method": "json-pointer"},
        {"expected_value": "not-a-digest"},
        {"selector": "/digest"},
    ):
        with pytest.raises(ValueError):
            claim(**{**base, **changes})
    with pytest.raises(ValueError, match="non-digest"):
        claim(extraction_method="whole-payload-sha256", selector="")


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"allowed_hosts": ()}, "at least 1"),
        ({"allowed_hosts": ("b.test", "a.test")}, "sorted unique"),
        ({"allowed_hosts": ("a.test", "a.test")}, "sorted unique"),
        ({"allowed_hosts": ("https://a.test",)}, "DNS names"),
        ({"allowed_hosts": ("A.test",)}, "DNS names"),
        ({"allowed_hosts": ("127.0.0.1",)}, "DNS names"),
        ({"allowed_hosts": ("localhost",)}, "DNS names"),
        ({"allowed_hosts": ("bad_name.test",)}, "DNS names"),
        ({"maximum_redirects": 11}, "<= 10"),
        ({"timeout_seconds": 0}, ">= 1"),
        ({"maximum_bytes": 0}, ">= 1"),
        ({"maximum_bytes": MAX_SOURCE_BYTES + 1}, f"<= {MAX_SOURCE_BYTES}"),
        ({"allowed_media_types": ()}, "at least 1"),
        ({"allowed_media_types": ("text/plain", "application/json")}, "sorted"),
        ({"allowed_media_types": ("Application/JSON",)}, "lowercase"),
        ({"allowed_media_types": ("application json",)}, "media type"),
        ({"allowed_media_types": ("applicationjson",)}, "media type"),
        ({"allowed_media_types": ("application/json; charset=utf-8",)}, "parameters"),
        ({"freshness_seconds": 0}, ">= 1"),
    ],
)
def test_retrieval_policy_rejects_ambiguous_or_unbounded_values(
    changes: dict[str, object], message: str
) -> None:
    """Authority, redirects, time, bytes, media, and freshness are finite."""
    with pytest.raises(ValueError, match=message):
        policy(**changes)

    with pytest.raises(ValueError, match="non-empty string"):
        require_media_type(7, "media")


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"requested_uri": "https://other.test/a"}, "absent"),
        ({"final_uri": "https://other.test/a", "redirect_count": 1}, "absent"),
        ({"final_uri": URI + "?redirected=1"}, "without a redirect"),
        (
            {
                "final_uri": "https://mirror.example.test/a",
                "redirect_count": 1,
                "retrieval_policy": policy(
                    allowed_hosts=("advisories.example.test", "mirror.example.test")
                ),
            },
            "cross-origin",
        ),
        ({"redirect_count": 3}, "exceeds"),
        ({"http_status": 304}, "status 200"),
        ({"media_type": "text/html"}, "absent"),
        ({"media_type": "application/json; charset=utf-8"}, "parameters"),
        ({"retriever_version": "latest"}, "semantic version"),
        ({"retriever_executable_digest": "bad"}, "SHA-256"),
    ],
)
def test_capture_rejects_policy_and_observation_divergence(
    changes: dict[str, object], message: str
) -> None:
    """Capture construction cannot launder transport-policy divergence."""
    with pytest.raises(ValueError, match=message):
        capture(**changes)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="exceeds"):
        capture(b"12345", retrieval_policy=policy(maximum_bytes=4))


def test_capture_accepts_bounded_same_and_cross_origin_redirects() -> None:
    """Redirect metadata must be explicit and cross-origin movement requires policy."""
    same = capture(final_uri=URI + "?resolved=1", redirect_count=1)
    assert same.redirect_count == 1
    cross_policy = policy(
        allowed_hosts=("advisories.example.test", "mirror.example.test"),
        allow_cross_origin_redirects=True,
    )
    cross = capture(
        final_uri="https://mirror.example.test/cve.json",
        redirect_count=1,
        retrieval_policy=cross_policy,
    )
    assert cross.final_uri.startswith("https://mirror.example.test/")


@pytest.mark.parametrize(
    ("payload", "selector", "expected", "message"),
    [
        (b'{"value":1,"value":1}', "/value", 1, "duplicate key"),
        (b"\xff", "/value", 1, "UTF-8 JSON"),
        (b"NaN", "/value", 1, "non-finite"),
        (b'{"array":[1]}', "/array/01", 1, "array index"),
        (b'{"array":[1]}', "/array/2", 1, "out of range"),
        (b'{"value":1}', "/value/nested", 1, "crosses a scalar"),
        (b'{"value":1}', "/absent", 1, "absent"),
        (b'{"value":1}', "/value~2bad", 1, "escape"),
        (b'{"value":1}', "/value", True, "expected value"),
    ],
)
def test_verification_rejects_malformed_or_nonmatching_source_values(
    payload: bytes,
    selector: str,
    expected: object,
    message: str,
) -> None:
    """Only one exact finite JSON scalar can become successful evidence."""
    source = claim(selector=selector, expected_value=expected)
    with pytest.raises(ValueError, match=message):
        verify_external_source(
            source,
            capture(payload),
            payload,
            verified_at="2026-07-17T08:30:00Z",
            verifier="auditor/one",
        )


def test_verification_rejects_uri_payload_time_and_parser_tampering() -> None:
    """Wrong source, bytes, clock ordering, expiry, and success-shaped documents fail."""
    other_uri = "https://advisories.example.test/other.json"
    with pytest.raises(ValueError, match="URI"):
        verify_external_source(
            claim(source_uri=other_uri),
            capture(),
            PAYLOAD,
            verified_at="2026-07-17T08:30:00Z",
            verifier="auditor/one",
        )
    for payload in (PAYLOAD + b" ", PAYLOAD[:-1]):
        with pytest.raises(ValueError, match="capture identity"):
            verify_external_source(
                claim(),
                capture(),
                payload,
                verified_at="2026-07-17T08:30:00Z",
                verifier="auditor/one",
            )
    for instant in ("2026-07-17T07:59:59Z", "2026-07-17T09:00:01Z"):
        with pytest.raises(ValueError, match="freshness"):
            verify_external_source(
                claim(),
                capture(),
                PAYLOAD,
                verified_at=instant,
                verifier="auditor/one",
            )
    changed = verification().to_dict()
    changed["authority_scope"] = "publisher-signature"
    with pytest.raises(ValueError, match="authority"):
        SourceVerification.from_dict(changed)


def test_json_pointer_escapes_are_supported_exactly() -> None:
    """Valid slash and tilde escapes select their literal object keys."""
    payload = b'{"a/b":{"m~n":"exact"}}'
    source = claim(selector="/a~1b/m~0n", expected_value="exact")
    result = verify_external_source(
        source,
        capture(payload),
        payload,
        verified_at="2026-07-17T08:30:00Z",
        verifier="auditor/one",
    )
    assert result.verified_value == "exact"


def test_real_file_read_is_no_follow_single_link_stable_and_bounded(tmp_path: Path) -> None:
    """The public reader accepts one real file and fails closed on unsafe aliases."""
    payload = tmp_path / "source.json"
    payload.write_bytes(PAYLOAD)
    assert read_source_payload(payload, maximum_bytes=len(PAYLOAD)) == PAYLOAD
    with pytest.raises(ValueError, match="exceeds"):
        read_source_payload(payload, maximum_bytes=len(PAYLOAD) - 1)
    with pytest.raises(ValueError, match=">= 1"):
        read_source_payload(payload, maximum_bytes=0)
    with pytest.raises(ValueError, match=f"<= {MAX_SOURCE_BYTES}"):
        read_source_payload(payload, maximum_bytes=MAX_SOURCE_BYTES + 1)

    alias = tmp_path / "alias.json"
    os.link(payload, alias)
    with pytest.raises(RuntimeError, match="multiple hard links"):
        read_source_payload(payload, maximum_bytes=len(PAYLOAD))
    alias.unlink()

    target = tmp_path / "target.json"
    payload.rename(target)
    payload.symlink_to(target.name)
    with pytest.raises(RuntimeError, match="cannot access"):
        read_source_payload(payload, maximum_bytes=len(PAYLOAD))

    with pytest.raises(ValueError, match="JSON scalar"):
        claim(expected_value={})


def test_parser_rejects_nested_policy_and_capture_identity_drift() -> None:
    """Nested policy and capture identities cannot disagree with their containers."""
    document = capture().to_dict()
    document["retrieval_policy_digest"] = "0" * 64
    with pytest.raises(ValueError, match="retrieval-policy digest"):
        SourceCapture.from_dict(document)

    changed = capture().to_dict()
    nested = dict(cast(dict[str, object], changed["retrieval_policy"]))
    nested["policy_digest"] = "0" * 64
    changed["retrieval_policy"] = nested
    with pytest.raises(ValueError, match="policy digest"):
        SourceCapture.from_dict(changed)


def test_record_identity_changes_only_with_semantic_inputs() -> None:
    """Exact record identities are deterministic and react to semantic mutations."""
    baseline = verification()
    assert verification() == baseline
    changed_claim = claim(expected_value=False)
    assert changed_claim.claim_digest != baseline.claim.claim_digest
    changed_policy = policy(freshness_seconds=7200)
    assert changed_policy.policy_digest != baseline.capture.retrieval_policy_digest
    changed_capture = capture(retrieved_at="2026-07-17T08:00:01Z")
    assert changed_capture.capture_digest != baseline.capture.capture_digest
    with pytest.raises(TypeError):
        replace(baseline, verifier="auditor/two")
