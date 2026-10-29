# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — Trivy installer HTTPS protocol fixtures
"""Exercise real TLS, archive parsing and filesystem operations with pinned test data."""

from __future__ import annotations

import hashlib
import io
import ssl
import subprocess
import tarfile
import threading
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from tools import install_trivy


@dataclass(frozen=True)
class ReleasePayloads:
    """Controlled release bytes for transport and atomic-installation contracts."""

    checksums: bytes
    archive: bytes
    binary: bytes


@dataclass(frozen=True)
class Response:
    """An actual HTTP response served through the local TLS tunnel."""

    body: bytes
    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)


def archive_payload(entries: list[tuple[tarfile.TarInfo, bytes]]) -> bytes:
    """Serialize real tar members without replacing the production archive reader."""
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as bundle:
        for member, data in entries:
            bundle.addfile(member, io.BytesIO(data))
    return stream.getvalue()


def pin_release(
    monkeypatch: pytest.MonkeyPatch,
    archive: bytes,
    binary: bytes,
    *,
    checksums: bytes | None = None,
) -> ReleasePayloads:
    """Configure public digest constants for explicitly non-vendor protocol data."""
    archive_digest = hashlib.sha256(archive).hexdigest()
    if checksums is None:
        checksums = f"{archive_digest}  {install_trivy.TRIVY_ARCHIVE_NAME}\n".encode()
    monkeypatch.setattr(install_trivy, "TRIVY_ARCHIVE_DIGEST", archive_digest)
    monkeypatch.setattr(install_trivy, "TRIVY_BINARY_DIGEST", hashlib.sha256(binary).hexdigest())
    monkeypatch.setattr(
        install_trivy, "TRIVY_CHECKSUM_DIGEST", hashlib.sha256(checksums).hexdigest()
    )
    return ReleasePayloads(checksums, archive, binary)


def tls_contexts(directory: Path) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    """Create a process-local test CA without modifying the host trust store."""
    certificate = directory / "certificate.pem"
    key = directory / "key.pem"
    subprocess.run(  # nosec B603
        [
            "/usr/bin/openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
            "-days",
            "1",
            "-subj",
            "/CN=github.com",
            "-addext",
            "subjectAltName=DNS:github.com,DNS:release-assets.githubusercontent.com,DNS:example.invalid",
        ],
        check=True,
        capture_output=True,
        timeout=20,
    )
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(certificate, key)
    client = ssl.create_default_context(cafile=str(certificate))
    return server, client


@contextmanager
def release_transport(
    contexts: tuple[ssl.SSLContext, ssl.SSLContext],
    responses: dict[str, Response],
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[list[str]]:
    """Serve real HTTPS for the unchanged release URLs through a CONNECT proxy.

    Only public urllib proxy and TLS configuration changes. Production host,
    scheme, size, digest, archive and filesystem checks all remain active.
    Workers are joined and urllib's environment-default opener is restored.
    """
    requests: list[str] = []
    server_context, client_context = contexts

    class AssetHandler(BaseHTTPRequestHandler):
        """Return the configured HTTP asset through the encrypted tunnel."""

        def do_GET(self) -> None:
            """Send the exact response, including deliberately invalid headers."""
            requests.append(self.path)
            response = responses[self.path]
            self.send_response(response.status)
            for name, value in response.headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(response.body)

        def log_message(self, format: str, *args: object) -> None:
            """Keep expected negative protocol traffic out of pytest output."""

    class ProxyHandler(BaseHTTPRequestHandler):
        """Tunnel one HTTPS request to a trusted fixture certificate."""

        def do_CONNECT(self) -> None:
            """Negotiate TLS and run the actual HTTP response handler."""
            self.send_response(200, "Connection established")
            self.end_headers()
            self.wfile.flush()
            with server_context.wrap_socket(self.connection, server_side=True) as connection:
                AssetHandler(connection, self.client_address, self.server)

        def log_message(self, format: str, *args: object) -> None:
            """Keep proxy negotiation out of pytest output."""

    server = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
    server.daemon_threads = False
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    worker.start()
    monkeypatch.setenv("no_proxy", "")
    monkeypatch.setenv("NO_PROXY", "")
    proxy = f"http://127.0.0.1:{server.server_port}"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"https": proxy}),
        urllib.request.HTTPSHandler(context=client_context),
    )
    urllib.request.install_opener(opener)
    try:
        yield requests
    finally:
        urllib.request.install_opener(urllib.request.build_opener())
        server.shutdown()
        worker.join(timeout=5)
        server.server_close()
        assert not worker.is_alive()


def release_responses(payloads: ReleasePayloads) -> dict[str, Response]:
    """Map the unchanged vendor URL paths to controlled release payloads."""
    prefix = f"/aquasecurity/trivy/releases/download/v{install_trivy.TRIVY_VERSION}"
    return {
        f"{prefix}/{install_trivy.TRIVY_CHECKSUM_NAME}": Response(payloads.checksums),
        f"{prefix}/{install_trivy.TRIVY_ARCHIVE_NAME}": Response(payloads.archive),
    }
