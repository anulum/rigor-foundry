# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — verified Typos installer
"""Install one immutable Typos release after archive and binary digest checks."""

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
from pathlib import Path, PurePosixPath
from typing import cast
from urllib.parse import urlparse

TYPOS_VERSION = "1.48.0"
TYPOS_ARCHIVE_NAME = f"typos-v{TYPOS_VERSION}-x86_64-unknown-linux-musl.tar.gz"
TYPOS_ARCHIVE_DIGEST = "72a930c9a94fc3914aa56835c5b859c892a797d40c1c42638b98d93f16ff519c"
TYPOS_BINARY_DIGEST = "ef8c70a3d168b9f040646ec012ba69e1883ace35cd2a85d54f85ec8ce7234517"
_ARCHIVE_URL = (
    f"https://github.com/crate-ci/typos/releases/download/v{TYPOS_VERSION}/{TYPOS_ARCHIVE_NAME}"
)
_MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
_MAX_BINARY_BYTES = 32 * 1024 * 1024
_ALLOWED_DOWNLOAD_HOSTS = frozenset({"github.com", "release-assets.githubusercontent.com"})


def _sha256(payload: bytes) -> str:
    """Return the lowercase SHA-256 digest for exact bytes."""
    return hashlib.sha256(payload).hexdigest()


def _download() -> bytes:
    """Retrieve the bounded release archive from fixed GitHub hosts."""
    request = urllib.request.Request(  # nosec B310
        _ARCHIVE_URL,
        headers={"User-Agent": "rigor-foundry-typos-installer/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310
            final = urlparse(response.geturl())
            if final.scheme != "https" or final.hostname not in _ALLOWED_DOWNLOAD_HOSTS:
                raise RuntimeError("Typos release download redirected outside trusted hosts")
            declared = response.headers.get("Content-Length")
            if declared is not None and int(declared) > _MAX_ARCHIVE_BYTES:
                raise RuntimeError("Typos release archive exceeds its byte bound")
            payload = cast(bytes, response.read(_MAX_ARCHIVE_BYTES + 1))
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise RuntimeError("cannot retrieve pinned Typos release archive") from exc
    if len(payload) > _MAX_ARCHIVE_BYTES:
        raise RuntimeError("Typos release archive exceeds its byte bound")
    return payload


def verified_typos_binary(archive: bytes) -> bytes:
    """Return the exact digest-bound executable from a verified archive."""
    if _sha256(archive) != TYPOS_ARCHIVE_DIGEST:
        raise ValueError("Typos archive digest does not match the release pin")
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
            members = [
                member
                for member in bundle.getmembers()
                if PurePosixPath(member.name).name == "typos"
            ]
            if len(members) != 1:
                raise ValueError("Typos archive does not contain exactly one executable")
            member = members[0]
            if not member.isfile() or member.size <= 0 or member.size > _MAX_BINARY_BYTES:
                raise ValueError("Typos archive executable metadata is invalid")
            handle = bundle.extractfile(member)
            if handle is None:
                raise ValueError("Typos archive executable cannot be read")
            binary = handle.read(member.size + 1)
    except (OSError, tarfile.TarError) as exc:
        raise ValueError("Typos release archive is invalid") from exc
    if len(binary) != member.size:
        raise ValueError("Typos executable size does not match archive metadata")
    if _sha256(binary) != TYPOS_BINARY_DIGEST:
        raise ValueError("Typos executable digest does not match the release pin")
    return binary


def install_typos(destination: Path) -> Path:
    """Download, verify, and atomically install the pinned Typos executable."""
    binary = verified_typos_binary(_download())
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
    """Install the pinned Linux x86-64 executable."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--destination",
        type=Path,
        default=Path(sys.prefix) / "bin" / "typos",
    )
    arguments = parser.parse_args(argv)
    installed = install_typos(arguments.destination)
    print(f"installed Typos {TYPOS_VERSION} at {installed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
