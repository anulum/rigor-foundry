# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — verified CodeQL bundle installer
"""Download one immutable CodeQL bundle after manifest and archive checks."""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import urllib.error
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol, cast
from urllib.parse import urlparse

CODEQL_VERSION = "2.26.0"
CODEQL_BUNDLE_NAME = "codeql-bundle-linux64.tar.zst"
CODEQL_CHECKSUM_NAME = f"{CODEQL_BUNDLE_NAME}.checksum.txt"
CODEQL_CHECKSUM_DIGEST = "b609931c8e7e5a91d53cb4870d795da9dcc7a8b9bb4601cbf4968b1a1169b23f"
CODEQL_BUNDLE_DIGEST = "eeaaffa28291513a11565654d9828bac39d9234375a6fc0cd698f61c6d007bae"
CODEQL_BUNDLE_BYTES = 578_485_312
_BASE_URL = (
    f"https://github.com/github/codeql-action/releases/download/codeql-bundle-v{CODEQL_VERSION}"
)
_MAX_CHECKSUM_BYTES = 1024
_ALLOWED_DOWNLOAD_HOSTS = frozenset({"github.com", "release-assets.githubusercontent.com"})


class _DownloadResponse(Protocol):
    """Typed subset of the urllib response used by the installer."""

    headers: Mapping[str, str]

    def geturl(self) -> str:
        """Return the final response URL."""

    def read(self, amount: int = -1) -> bytes:
        """Read at most ``amount`` bytes."""

    def close(self) -> None:
        """Close the response stream."""

    def __enter__(self) -> _DownloadResponse:
        """Enter the managed response."""

    def __exit__(self, *_: object) -> None:
        """Close the managed response."""


def _open(url: str) -> _DownloadResponse:
    """Open one HTTPS release asset after validating its final host."""
    request = urllib.request.Request(  # nosec B310
        url,
        headers={"User-Agent": "rigor-foundry-codeql-installer/1"},
    )
    try:
        response = urllib.request.urlopen(request, timeout=60)  # nosec B310
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise RuntimeError("cannot retrieve pinned CodeQL release asset") from exc
    final = urlparse(response.geturl())
    if final.scheme != "https" or final.hostname not in _ALLOWED_DOWNLOAD_HOSTS:
        response.close()
        raise RuntimeError("CodeQL release download redirected outside trusted hosts")
    return cast(_DownloadResponse, response)


def verify_checksum_document(payload: bytes) -> None:
    """Verify the exact checksum document and its bundle relation."""
    if hashlib.sha256(payload).hexdigest() != CODEQL_CHECKSUM_DIGEST:
        raise ValueError("CodeQL checksum document digest does not match the release pin")
    expected = f"{CODEQL_BUNDLE_DIGEST}  {CODEQL_BUNDLE_NAME}\n".encode()
    if payload != expected:
        raise ValueError("CodeQL checksum document does not bind the pinned bundle")


def _download_checksum() -> bytes:
    """Retrieve the bounded checksum document."""
    with _open(f"{_BASE_URL}/{CODEQL_CHECKSUM_NAME}") as response:
        declared = response.headers.get("Content-Length")
        if declared is not None and int(declared) > _MAX_CHECKSUM_BYTES:
            raise RuntimeError("CodeQL checksum document exceeds its byte bound")
        payload = response.read(_MAX_CHECKSUM_BYTES + 1)
    if len(payload) > _MAX_CHECKSUM_BYTES:
        raise RuntimeError("CodeQL checksum document exceeds its byte bound")
    verify_checksum_document(payload)
    return payload


def install_codeql_bundle(destination: Path) -> Path:
    """Stream, verify, and atomically install the pinned CodeQL bundle."""
    _download_checksum()
    destination = destination.absolute()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.verified-new")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        digest = hashlib.sha256()
        observed = 0
        with _open(f"{_BASE_URL}/{CODEQL_BUNDLE_NAME}") as response:
            declared = response.headers.get("Content-Length")
            if declared is not None and int(declared) != CODEQL_BUNDLE_BYTES:
                raise RuntimeError("CodeQL bundle declared size does not match the release pin")
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                while chunk := response.read(1024 * 1024):
                    observed += len(chunk)
                    if observed > CODEQL_BUNDLE_BYTES:
                        raise RuntimeError("CodeQL bundle exceeds its exact byte bound")
                    digest.update(chunk)
                    handle.write(chunk)
                handle.flush()
                os.fsync(handle.fileno())
        if observed != CODEQL_BUNDLE_BYTES:
            raise RuntimeError("CodeQL bundle size does not match the release pin")
        if digest.hexdigest() != CODEQL_BUNDLE_DIGEST:
            raise ValueError("CodeQL bundle digest does not match the release pin")
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, destination)
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    return destination


def main(argv: list[str] | None = None) -> int:
    """Install the pinned Linux x86-64 CodeQL bundle archive."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--destination",
        type=Path,
        default=Path(sys.prefix) / CODEQL_BUNDLE_NAME,
    )
    arguments = parser.parse_args(argv)
    installed = install_codeql_bundle(arguments.destination)
    print(f"installed CodeQL bundle {CODEQL_VERSION} at {installed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
