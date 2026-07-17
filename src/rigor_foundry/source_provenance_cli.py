# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — external-source provenance CLI adapter
"""Wire retained source capture and deterministic offline verification into the CLI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .source_capture import SourceCapture, SourceRetrievalPolicy, read_source_payload
from .source_provenance import (
    ExternalSourceClaim,
    source_provenance_to_json,
    verify_external_source,
)


def _document(path: Path) -> object:
    """Read one explicit UTF-8 JSON protocol document."""
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, text: str) -> None:
    """Write an explicit output without creating or guessing its parent."""
    if not path.parent.is_dir():
        raise ValueError(f"output parent does not exist: {path.parent}")
    path.write_text(text, encoding="utf-8")


def _capture_command(args: argparse.Namespace) -> int:
    """Record retained response bytes under an explicit retrieval policy."""
    policy = SourceRetrievalPolicy.from_dict(_document(args.policy))
    payload = read_source_payload(args.payload, maximum_bytes=policy.maximum_bytes)
    capture = SourceCapture.record(
        payload,
        requested_uri=args.requested_uri,
        final_uri=args.final_uri,
        redirect_count=args.redirect_count,
        http_status=args.http_status,
        media_type=args.media_type,
        retrieved_at=args.retrieved_at,
        retrieval_policy=policy,
        retriever_name=args.retriever_name,
        retriever_version=args.retriever_version,
        retriever_executable_digest=args.retriever_executable_digest,
    )
    _write(args.output, source_provenance_to_json(capture))
    return 0


def _verify_command(args: argparse.Namespace) -> int:
    """Verify one source claim against exact retained capture bytes offline."""
    claim = ExternalSourceClaim.from_dict(_document(args.claim))
    capture = SourceCapture.from_dict(_document(args.capture))
    payload = read_source_payload(
        args.payload,
        maximum_bytes=capture.retrieval_policy.maximum_bytes,
    )
    verification = verify_external_source(
        claim,
        capture,
        payload,
        verified_at=args.verified_at,
        verifier=args.verifier,
    )
    _write(args.output, source_provenance_to_json(verification))
    return 0


def add_source_provenance_commands(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Add source-capture and source-verify commands to the root parser."""
    capture = subparsers.add_parser(
        "source-capture",
        help="Record retained HTTPS response bytes and acquisition metadata.",
    )
    capture.add_argument("--policy", type=Path, required=True)
    capture.add_argument("--payload", type=Path, required=True)
    capture.add_argument("--requested-uri", required=True)
    capture.add_argument("--final-uri", required=True)
    capture.add_argument("--redirect-count", type=int, required=True)
    capture.add_argument("--http-status", type=int, required=True)
    capture.add_argument("--media-type", required=True)
    capture.add_argument("--retrieved-at", required=True)
    capture.add_argument("--retriever-name", required=True)
    capture.add_argument("--retriever-version", required=True)
    capture.add_argument("--retriever-executable-digest", required=True)
    capture.add_argument("--output", type=Path, required=True)
    capture.set_defaults(handler=_capture_command)

    verify = subparsers.add_parser(
        "source-verify",
        help="Verify one external claim against retained captured bytes offline.",
    )
    verify.add_argument("--claim", type=Path, required=True)
    verify.add_argument("--capture", type=Path, required=True)
    verify.add_argument("--payload", type=Path, required=True)
    verify.add_argument("--verified-at", required=True)
    verify.add_argument("--verifier", required=True)
    verify.add_argument("--output", type=Path, required=True)
    verify.set_defaults(handler=_verify_command)
