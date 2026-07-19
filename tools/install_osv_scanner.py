# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — verified OSV-Scanner installer
"""Install one immutable OSV-Scanner release after two pinned digest checks."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import cast
from urllib.parse import urlparse

OSV_SCANNER_VERSION = "2.4.0"
OSV_SCANNER_BINARY_NAME = "osv-scanner_linux_amd64"
OSV_SCANNER_CHECKSUM_NAME = "osv-scanner_SHA256SUMS"
OSV_SCANNER_CHECKSUM_DIGEST = "9d6fff9bac4d77269c8b04a1b74b72cd087842106abd11d8e0426ab07b2dd441"
OSV_SCANNER_BINARY_DIGEST = "15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0"
_BASE_URL = f"https://github.com/google/osv-scanner/releases/download/v{OSV_SCANNER_VERSION}"
_MAX_CHECKSUM_BYTES = 16 * 1024
_MAX_BINARY_BYTES = 96 * 1024 * 1024
_ALLOWED_DOWNLOAD_HOSTS = frozenset({"github.com", "release-assets.githubusercontent.com"})


def _sha256(payload: bytes) -> str:
    """Return the lowercase SHA-256 digest for exact bytes."""
    return hashlib.sha256(payload).hexdigest()


def _download(url: str, maximum_bytes: int) -> bytes:
    """Retrieve one bounded HTTPS release asset from fixed GitHub hosts."""
    request = urllib.request.Request(  # nosec B310
        url,
        headers={"User-Agent": "rigor-foundry-osv-scanner-installer/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310
            final = urlparse(response.geturl())
            if final.scheme != "https" or final.hostname not in _ALLOWED_DOWNLOAD_HOSTS:
                raise RuntimeError("OSV-Scanner download redirected outside trusted hosts")
            declared = response.headers.get("Content-Length")
            if declared is not None and int(declared) > maximum_bytes:
                raise RuntimeError("OSV-Scanner release asset exceeds its byte bound")
            payload = cast(bytes, response.read(maximum_bytes + 1))
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise RuntimeError("cannot retrieve pinned OSV-Scanner release asset") from exc
    if len(payload) > maximum_bytes:
        raise RuntimeError("OSV-Scanner release asset exceeds its byte bound")
    return payload


def verify_release_payloads(checksums: bytes, binary: bytes) -> None:
    """Verify the pinned checksum document and Linux binary identities."""
    if _sha256(checksums) != OSV_SCANNER_CHECKSUM_DIGEST:
        raise ValueError("OSV-Scanner checksum document digest does not match the release pin")
    if _sha256(binary) != OSV_SCANNER_BINARY_DIGEST:
        raise ValueError("OSV-Scanner binary digest does not match the release pin")
    try:
        lines = checksums.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("OSV-Scanner checksum document is not UTF-8") from exc
    matches = [line.split() for line in lines if line.endswith(f"  {OSV_SCANNER_BINARY_NAME}")]
    if matches != [[OSV_SCANNER_BINARY_DIGEST, OSV_SCANNER_BINARY_NAME]]:
        raise ValueError("OSV-Scanner checksum document does not bind the pinned binary")


def install_osv_scanner(destination: Path) -> Path:
    """Download, verify, and atomically install the pinned Linux executable."""
    checksums = _download(f"{_BASE_URL}/{OSV_SCANNER_CHECKSUM_NAME}", _MAX_CHECKSUM_BYTES)
    binary = _download(f"{_BASE_URL}/{OSV_SCANNER_BINARY_NAME}", _MAX_BINARY_BYTES)
    verify_release_payloads(checksums, binary)
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
    """Install the pinned Linux x86-64 binary into the active environment."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--destination",
        type=Path,
        default=Path(sys.prefix) / "bin" / "osv-scanner",
    )
    args = parser.parse_args(argv)
    installed = install_osv_scanner(args.destination)
    print(f"installed OSV-Scanner {OSV_SCANNER_VERSION} at {installed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
