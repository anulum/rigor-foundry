# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — verified Trivy installer
"""Install one immutable Trivy release after document, archive and binary checks."""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import stat
import sys
import tarfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import cast
from urllib.parse import urlparse

TRIVY_VERSION = "0.76.1"
TRIVY_ARCHIVE_NAME = f"trivy_{TRIVY_VERSION}_Linux-64bit.tar.gz"
TRIVY_CHECKSUM_NAME = f"trivy_{TRIVY_VERSION}_checksums.txt"
TRIVY_CHECKSUM_DIGEST = "885debc41b570179e81af560e5f393a66be29b9ff8c52915674f3eb2304c535d"
TRIVY_ARCHIVE_DIGEST = "c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0"
TRIVY_BINARY_DIGEST = "d1dfca6ae10a1ad4540bb94e64f0510077c47008920a9b554986b39dca573d83"
_BASE_URL = f"https://github.com/aquasecurity/trivy/releases/download/v{TRIVY_VERSION}"
_MAX_CHECKSUM_BYTES = 16 * 1024
_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
_ALLOWED_DOWNLOAD_HOSTS = frozenset({"github.com", "release-assets.githubusercontent.com"})


def _sha256(payload: bytes) -> str:
    """Return the lowercase SHA-256 digest for exact bytes."""
    return hashlib.sha256(payload).hexdigest()


def _download(url: str, maximum_bytes: int) -> bytes:
    """Retrieve one bounded HTTPS release asset from fixed GitHub hosts."""
    request = urllib.request.Request(  # nosec B310
        url,
        headers={"User-Agent": "rigor-foundry-trivy-installer/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310
            final = urlparse(response.geturl())
            if final.scheme != "https" or final.hostname not in _ALLOWED_DOWNLOAD_HOSTS:
                raise RuntimeError("Trivy release download redirected outside trusted hosts")
            declared = response.headers.get("Content-Length")
            if declared is not None and int(declared) > maximum_bytes:
                raise RuntimeError("Trivy release asset exceeds its byte bound")
            payload = cast(bytes, response.read(maximum_bytes + 1))
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise RuntimeError("cannot retrieve pinned Trivy release asset") from exc
    if len(payload) > maximum_bytes:
        raise RuntimeError("Trivy release asset exceeds its byte bound")
    return payload


def verify_release_payloads(checksums: bytes, archive: bytes) -> None:
    """Verify the pinned checksum document and Linux archive identities."""
    if _sha256(checksums) != TRIVY_CHECKSUM_DIGEST:
        raise ValueError("Trivy checksum document digest does not match the release pin")
    if _sha256(archive) != TRIVY_ARCHIVE_DIGEST:
        raise ValueError("Trivy archive digest does not match the release pin")
    try:
        lines = checksums.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("Trivy checksum document is not UTF-8") from exc
    matches = [line.split() for line in lines if line.endswith(f"  {TRIVY_ARCHIVE_NAME}")]
    if matches != [[TRIVY_ARCHIVE_DIGEST, TRIVY_ARCHIVE_NAME]]:
        raise ValueError("Trivy checksum document does not bind the pinned archive")


def _binary_from_archive(archive: bytes) -> bytes:
    """Return the sole regular ``trivy`` binary from a verified tar archive."""
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
            members = [member for member in bundle.getmembers() if member.name == "trivy"]
            if len(members) != 1:
                raise ValueError("Trivy archive does not contain exactly one binary")
            member = members[0]
            if not member.isfile() or member.size <= 0 or member.size > 256 * 1024 * 1024:
                raise ValueError("Trivy archive binary metadata is invalid")
            # Regular members return BufferedReader; truncated data raises ReadError.
            # https://docs.python.org/3/library/tarfile.html#tarfile.TarFile.extractfile
            handle = cast("io.BufferedReader", bundle.extractfile(member))
            with handle:
                binary = handle.read(member.size)
    except (OSError, tarfile.TarError) as exc:
        raise ValueError("Trivy release archive is invalid") from exc
    if _sha256(binary) != TRIVY_BINARY_DIGEST:
        raise ValueError("Trivy archive binary digest does not match the release pin")
    return binary


def install_trivy(destination: Path) -> Path:
    """Download, verify, and atomically install the pinned Trivy executable.

    Parameters
    ----------
    destination : Path
        Managed executable path; an existing temporary file is preserved.

    Returns
    -------
    Path
        Absolute path to the verified, owner-executable binary.

    Raises
    ------
    OSError
        The temporary file cannot be created, written or atomically installed.
    RuntimeError
        The bounded HTTPS download cannot complete at a trusted host.
    ValueError
        The release payload, archive member or executable fails verification.
    """
    checksum_url = f"{_BASE_URL}/{TRIVY_CHECKSUM_NAME}"
    archive_url = f"{_BASE_URL}/{TRIVY_ARCHIVE_NAME}"
    checksums = _download(checksum_url, _MAX_CHECKSUM_BYTES)
    archive = _download(archive_url, _MAX_ARCHIVE_BYTES)
    verify_release_payloads(checksums, archive)
    binary = _binary_from_archive(archive)
    destination = destination.absolute()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.verified-new")
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o700,
        )
        created = True
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
        if created:
            temporary.unlink(missing_ok=True)
        raise
    return destination


def main(argv: list[str] | None = None) -> int:
    """Install the pinned Linux x86-64 binary into the active environment."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--destination",
        type=Path,
        default=Path(sys.prefix) / "bin" / "trivy",
    )
    args = parser.parse_args(argv)
    installed = install_trivy(args.destination)
    print(f"installed Trivy {TRIVY_VERSION} at {installed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
