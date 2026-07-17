# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — verified Docker Buildx installer
"""Install one immutable Buildx executable after two release digest checks."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import urllib.error
import urllib.request
from pathlib import Path
from typing import cast
from urllib.parse import urlparse

BUILDX_VERSION = "0.35.0"
BUILDX_ASSET_NAME = f"buildx-v{BUILDX_VERSION}.linux-amd64"
BUILDX_CHECKSUM_NAME = "checksums.txt"
BUILDX_CHECKSUM_DIGEST = "2bbd7a876e76e9c1757e79c60c59dc1a65daba031e214b582573ce1b7486d0f5"
BUILDX_BINARY_DIGEST = "d41ece72044243b4f58b343441ae37446d9c29a7d6b5e11c61847bbcf8f7dfda"
BUILDKIT_IMAGE = (
    "moby/buildkit@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec"
)
_BASE_URL = f"https://github.com/docker/buildx/releases/download/v{BUILDX_VERSION}"
_MAX_CHECKSUM_BYTES = 16 * 1024
_MAX_BINARY_BYTES = 80 * 1024 * 1024
_ALLOWED_DOWNLOAD_HOSTS = frozenset({"github.com", "release-assets.githubusercontent.com"})


def _sha256(payload: bytes) -> str:
    """Return the lowercase SHA-256 digest for exact bytes."""
    return hashlib.sha256(payload).hexdigest()


def _download(url: str, maximum_bytes: int) -> bytes:
    """Retrieve one bounded HTTPS release asset from fixed GitHub hosts."""
    request = urllib.request.Request(  # nosec B310
        url,
        headers={"User-Agent": "rigor-foundry-buildx-installer/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310
            final = urlparse(response.geturl())
            if final.scheme != "https" or final.hostname not in _ALLOWED_DOWNLOAD_HOSTS:
                raise RuntimeError("Buildx release download redirected outside trusted hosts")
            declared = response.headers.get("Content-Length")
            if declared is not None and int(declared) > maximum_bytes:
                raise RuntimeError("Buildx release asset exceeds its byte bound")
            payload = cast(bytes, response.read(maximum_bytes + 1))
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise RuntimeError("cannot retrieve pinned Buildx release asset") from exc
    if len(payload) > maximum_bytes:
        raise RuntimeError("Buildx release asset exceeds its byte bound")
    return payload


def verify_buildx_payloads(checksums: bytes, binary: bytes) -> None:
    """Verify checksum-document, executable, and document-to-asset identities."""
    if _sha256(checksums) != BUILDX_CHECKSUM_DIGEST:
        raise ValueError("Buildx checksum document digest does not match the release pin")
    if _sha256(binary) != BUILDX_BINARY_DIGEST:
        raise ValueError("Buildx executable digest does not match the release pin")
    try:
        lines = checksums.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("Buildx checksum document is not UTF-8") from exc
    matches = [line for line in lines if line.endswith(f" *{BUILDX_ASSET_NAME}")]
    if matches != [f"{BUILDX_BINARY_DIGEST} *{BUILDX_ASSET_NAME}"]:
        raise ValueError("Buildx checksum document does not bind the pinned executable")


def install_buildx(destination: Path) -> Path:
    """Download, verify, and atomically install the pinned Buildx executable."""
    checksums = _download(f"{_BASE_URL}/{BUILDX_CHECKSUM_NAME}", _MAX_CHECKSUM_BYTES)
    binary = _download(f"{_BASE_URL}/{BUILDX_ASSET_NAME}", _MAX_BINARY_BYTES)
    verify_buildx_payloads(checksums, binary)
    destination = destination.absolute()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.verified-new")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o700,
        )
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(binary)
            handle.flush()
            os.fsync(handle.fileno())
        os.close(descriptor)
        descriptor = None
        temporary.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        os.replace(temporary, destination)
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    return destination


def main(argv: list[str] | None = None) -> int:
    """Install the pinned Linux x86-64 Docker CLI plugin."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--destination",
        type=Path,
        default=Path.home() / ".docker/cli-plugins/docker-buildx",
    )
    arguments = parser.parse_args(argv)
    installed = install_buildx(arguments.destination)
    print(f"installed Buildx {BUILDX_VERSION} at {installed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
