# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — external-source digest propagation tests
"""Prove exact claim and retrieval-policy propagation through source evidence."""

from __future__ import annotations

from typing import cast

from rigor_foundry.digest_dependencies import DigestNode, transitive_dependents
from rigor_foundry.source_capture import SourceCapture, SourceRetrievalPolicy
from rigor_foundry.source_provenance import (
    ExternalSourceClaim,
    verify_external_source,
)

DigestSnapshot = dict[DigestNode, str]
URI = "https://versions.example.test/package.json"
PAYLOAD = b'{"version":"2.4.1"}'


def _claim(*, subject: str = "example-package") -> ExternalSourceClaim:
    """Return one exact package-version assertion."""
    return ExternalSourceClaim.build(
        claim_id="package-version",
        kind="version",
        subject=subject,
        predicate="release",
        expected_value="2.4.1",
        source_uri=URI,
        extraction_method="json-pointer",
        selector="/version",
    )


def _policy(*, freshness_seconds: int = 3600) -> SourceRetrievalPolicy:
    """Return one exact versions-source retrieval policy."""
    return SourceRetrievalPolicy.build(
        allowed_hosts=("versions.example.test",),
        allow_cross_origin_redirects=False,
        maximum_redirects=0,
        timeout_seconds=5,
        maximum_bytes=1024,
        allowed_media_types=("application/json",),
        freshness_seconds=freshness_seconds,
    )


def _snapshot(
    *,
    subject: str = "example-package",
    freshness_seconds: int = 3600,
) -> DigestSnapshot:
    """Return complete claim, policy, capture, and verification identities."""
    claim = _claim(subject=subject)
    policy = _policy(freshness_seconds=freshness_seconds)
    capture = SourceCapture.record(
        PAYLOAD,
        requested_uri=URI,
        final_uri=URI,
        redirect_count=0,
        http_status=200,
        media_type="application/json",
        retrieved_at="2026-07-17T08:00:00Z",
        retrieval_policy=policy,
        retriever_name="curl",
        retriever_version="8.10.1",
        retriever_executable_digest="a" * 64,
    )
    verification = verify_external_source(
        claim,
        capture,
        PAYLOAD,
        verified_at="2026-07-17T08:30:00Z",
        verifier="auditor/one",
    )
    return {
        "source-claim": claim.claim_digest,
        "source-retrieval-policy": policy.policy_digest,
        "source-capture": capture.capture_digest,
        "source-verification": verification.verification_digest,
    }


def _assert_transition(
    mutated: DigestNode,
    before: DigestSnapshot,
    after: DigestSnapshot,
) -> None:
    """Require exactly the declared source subgraph identities to change."""
    assert before.keys() == after.keys()
    changed = {node for node in before if before[node] != after[node]}
    expected = {mutated, *transitive_dependents(mutated)}.intersection(before)
    assert changed == expected


def test_source_claim_mutation_changes_only_verification() -> None:
    """Claim semantics bind verification without changing acquisition evidence."""
    _assert_transition(
        cast(DigestNode, "source-claim"),
        _snapshot(),
        _snapshot(subject="example-package-renamed"),
    )


def test_retrieval_policy_mutation_changes_capture_and_verification() -> None:
    """Acquisition-policy semantics propagate through capture to verification."""
    _assert_transition(
        cast(DigestNode, "source-retrieval-policy"),
        _snapshot(),
        _snapshot(freshness_seconds=7200),
    )
