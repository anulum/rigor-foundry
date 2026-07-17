# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — verified Ubuntu Bubblewrap package installer
"""Download the exact Ubuntu Bubblewrap package after a byte-level identity check."""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import cast
from urllib.parse import urlparse

BUBBLEWRAP_VERSION = "0.9.0-1ubuntu0.1"
BUBBLEWRAP_PACKAGE_NAME = f"bubblewrap_{BUBBLEWRAP_VERSION}_amd64.deb"
BUBBLEWRAP_PACKAGE_BYTES = 50_178
BUBBLEWRAP_PACKAGE_DIGEST = "1b506492bd9c7fd0cdb4f02ac822f1d3e336b0aead5113c1239baf8db5db562a"
BUBBLEWRAP_EXECUTABLE_DIGEST = "52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712"
_PACKAGE_URL = (
    f"https://security.ubuntu.com/ubuntu/pool/main/b/bubblewrap/{BUBBLEWRAP_PACKAGE_NAME}"
)


def verify_bubblewrap_package(payload: bytes) -> None:
    """Verify the exact package size and SHA-256 identity."""
    if len(payload) != BUBBLEWRAP_PACKAGE_BYTES:
        raise ValueError("Bubblewrap package size does not match the release pin")
    if hashlib.sha256(payload).hexdigest() != BUBBLEWRAP_PACKAGE_DIGEST:
        raise ValueError("Bubblewrap package digest does not match the release pin")


def _download() -> bytes:
    """Retrieve the exact package from the Ubuntu Security origin."""
    request = urllib.request.Request(  # nosec B310
        _PACKAGE_URL,
        headers={"User-Agent": "rigor-foundry-bubblewrap-installer/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310
            final = urlparse(response.geturl())
            if final.scheme != "https" or final.hostname != "security.ubuntu.com":
                raise RuntimeError("Bubblewrap package redirected outside Ubuntu Security")
            declared = response.headers.get("Content-Length")
            if declared is not None and int(declared) != BUBBLEWRAP_PACKAGE_BYTES:
                raise RuntimeError("Bubblewrap package declared size does not match the pin")
            payload = cast(bytes, response.read(BUBBLEWRAP_PACKAGE_BYTES + 1))
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise RuntimeError("cannot retrieve pinned Bubblewrap package") from exc
    verify_bubblewrap_package(payload)
    return payload


def install_bubblewrap_package(destination: Path) -> Path:
    """Download, verify, and atomically retain the package for ``dpkg -i``."""
    payload = _download()
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
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
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
    """Retain the verified package at an explicit destination."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--destination",
        type=Path,
        default=Path(sys.prefix) / BUBBLEWRAP_PACKAGE_NAME,
    )
    arguments = parser.parse_args(argv)
    installed = install_bubblewrap_package(arguments.destination)
    print(f"verified Bubblewrap {BUBBLEWRAP_VERSION} package at {installed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
