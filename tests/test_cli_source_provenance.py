# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — external-source provenance CLI tests
"""Exercise retained capture and offline verification through the real CLI parser."""

from __future__ import annotations

import json
from pathlib import Path

from rigor_foundry.cli import main
from rigor_foundry.source_capture import SourceCapture, SourceRetrievalPolicy
from rigor_foundry.source_provenance import (
    ExternalSourceClaim,
    SourceVerification,
    source_provenance_to_json,
)

PAYLOAD = b'{"advisory":{"affected":true}}'
URI = "https://advisories.example.test/CVE-2026-52869.json"


def _documents(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Write exact payload, policy, and claim inputs for CLI tests."""
    payload = tmp_path / "source.json"
    payload.write_bytes(PAYLOAD)
    policy = SourceRetrievalPolicy.build(
        allowed_hosts=("advisories.example.test",),
        allow_cross_origin_redirects=False,
        maximum_redirects=0,
        timeout_seconds=5,
        maximum_bytes=1024,
        allowed_media_types=("application/json",),
        freshness_seconds=3600,
    )
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(source_provenance_to_json(policy), encoding="utf-8")
    claim = ExternalSourceClaim.build(
        claim_id="cve-2026-52869-affected",
        kind="advisory",
        subject="CVE-2026-52869",
        predicate="affected",
        expected_value=True,
        source_uri=URI,
        extraction_method="json-pointer",
        selector="/advisory/affected",
    )
    claim_path = tmp_path / "claim.json"
    claim_path.write_text(source_provenance_to_json(claim), encoding="utf-8")
    return payload, policy_path, claim_path


def _capture_args(payload: Path, policy: Path, output: Path) -> list[str]:
    """Return the complete explicit source-capture invocation."""
    return [
        "source-capture",
        "--policy",
        str(policy),
        "--payload",
        str(payload),
        "--requested-uri",
        URI,
        "--final-uri",
        URI,
        "--redirect-count",
        "0",
        "--http-status",
        "200",
        "--media-type",
        "application/json",
        "--retrieved-at",
        "2026-07-17T08:00:00Z",
        "--retriever-name",
        "curl",
        "--retriever-version",
        "8.10.1",
        "--retriever-executable-digest",
        "a" * 64,
        "--output",
        str(output),
    ]


def _verify_args(
    payload: Path,
    claim: Path,
    capture: Path,
    output: Path,
) -> list[str]:
    """Return the complete explicit source-verify invocation."""
    return [
        "source-verify",
        "--claim",
        str(claim),
        "--capture",
        str(capture),
        "--payload",
        str(payload),
        "--verified-at",
        "2026-07-17T08:30:00Z",
        "--verifier",
        "auditor/one",
        "--output",
        str(output),
    ]


def test_cli_records_capture_then_verifies_exact_source_offline(tmp_path: Path) -> None:
    """The public parser completes the retained-payload workflow end to end."""
    payload, policy, claim = _documents(tmp_path)
    capture_path = tmp_path / "capture.json"
    verification_path = tmp_path / "verification.json"
    assert main(_capture_args(payload, policy, capture_path)) == 0
    capture = SourceCapture.from_dict(json.loads(capture_path.read_text(encoding="utf-8")))
    assert capture.payload_size == len(PAYLOAD)
    assert main(_verify_args(payload, claim, capture_path, verification_path)) == 0
    verification = SourceVerification.from_dict(
        json.loads(verification_path.read_text(encoding="utf-8"))
    )
    assert verification.verified_value is True
    assert verification.capture.capture_digest == capture.capture_digest


def test_cli_fails_closed_for_changed_payload_and_missing_output_parent(
    tmp_path: Path,
    capsys: object,
) -> None:
    """Changed bytes and guessed output directories never produce success evidence."""
    payload, policy, claim = _documents(tmp_path)
    capture_path = tmp_path / "capture.json"
    assert main(_capture_args(payload, policy, capture_path)) == 0
    payload.write_bytes(PAYLOAD + b" ")
    output = tmp_path / "verification.json"
    assert main(_verify_args(payload, claim, capture_path, output)) == 2
    assert not output.exists()

    missing = tmp_path / "missing" / "capture.json"
    assert main(_capture_args(payload, policy, missing)) == 2
    assert not missing.exists()


def test_cli_rejects_malformed_protocol_documents(tmp_path: Path) -> None:
    """Invalid JSON and strict-schema drift return the root CLI invalid-input code."""
    payload, policy, _claim = _documents(tmp_path)
    policy.write_text("{", encoding="utf-8")
    assert main(_capture_args(payload, policy, tmp_path / "capture.json")) == 2

    policy.write_text('{"schema_version":"1.0"}', encoding="utf-8")
    assert main(_capture_args(payload, policy, tmp_path / "capture.json")) == 2
