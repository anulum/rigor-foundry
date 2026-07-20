# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — offline verification CLI adapter
"""Wire ubiquitous evidence verification into the public command line."""

from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path

from .offline_verification import verify_evidence_bundle
from .offline_verification_models import VerificationBundle
from .safe_output import write_new_output
from .verification_policy import OfflineTrustPolicy

MAX_VERIFICATION_DOCUMENT_BYTES = 16 * 1024 * 1024


def _read_document(path: Path, *, label: str) -> object:
    """Read one bounded, single-link, non-symlink UTF-8 JSON document."""
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise RuntimeError("offline verification requires O_NOFOLLOW support")
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | no_follow)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError(f"{label} must be a single-link regular file")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            payload = handle.read(MAX_VERIFICATION_DOCUMENT_BYTES + 1)
            after = os.fstat(handle.fileno())
        if len(payload) > MAX_VERIFICATION_DOCUMENT_BYTES:
            raise ValueError(f"{label} exceeds {MAX_VERIFICATION_DOCUMENT_BYTES} bytes")
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValueError(f"{label} changed while it was read")
        return json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {label} {path}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _verify_command(args: argparse.Namespace) -> int:
    """Verify one caller-supplied evidence bundle and trust policy offline."""
    bundle = VerificationBundle.from_dict(_read_document(args.bundle, label="verification bundle"))
    policy = OfflineTrustPolicy.from_dict(
        _read_document(args.trust_policy, label="offline trust policy")
    )
    report = verify_evidence_bundle(bundle, policy, evaluated_at=args.at)
    output = report.to_json()
    if args.output is None:
        print(output, end="")
    else:
        write_new_output(args.output, output)
    return 0 if report.status == "verified" else 1


def add_offline_verify_command(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Add the free, network-independent verification command."""
    parser = subparsers.add_parser(
        "verify",
        help="Verify signed evidence, key lifecycle, freshness, and alias collapse offline.",
    )
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--trust-policy", type=Path, required=True)
    parser.add_argument(
        "--at",
        required=True,
        help="Explicit UTC evaluation time for deterministic replay.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional exclusive output path; parent must already exist.",
    )
    parser.set_defaults(handler=_verify_command)
