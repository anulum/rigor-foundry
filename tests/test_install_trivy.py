# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — verified Trivy installer tests
"""Verify the installed result and immutable release pins used by CI."""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import resource
import signal
import ssl
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
from trivy_installer_support import (
    ReleasePayloads,
    Response,
    archive_payload,
    pin_release,
    release_responses,
    release_transport,
    tls_contexts,
)

from tools import install_trivy
from tools.install_trivy import (
    TRIVY_ARCHIVE_DIGEST,
    TRIVY_ARCHIVE_NAME,
    TRIVY_BINARY_DIGEST,
    TRIVY_CHECKSUM_DIGEST,
    TRIVY_VERSION,
    main,
    verify_release_payloads,
)


def test_active_environment_contains_the_verified_trivy_release() -> None:
    """The workflow-installed executable is exact-versioned and not group-writable."""
    executable = Path(sys.prefix) / "bin" / "trivy"
    completed = subprocess.run(  # nosec B603
        [str(executable), "--version"],
        check=True,
        capture_output=True,
        shell=False,
        text=True,
        timeout=10,
    )
    metadata = executable.stat(follow_symlinks=False)
    assert completed.stdout.strip() == f"Version: {TRIVY_VERSION}"
    assert stat.S_ISREG(metadata.st_mode)
    assert metadata.st_uid in {0, os.getuid()}
    assert stat.S_IMODE(metadata.st_mode) & (stat.S_IWGRP | stat.S_IWOTH) == 0
    assert len(TRIVY_CHECKSUM_DIGEST) == 64
    assert len(TRIVY_ARCHIVE_DIGEST) == 64
    assert len(TRIVY_BINARY_DIGEST) == 64
    assert _sha256_file(executable) == TRIVY_BINARY_DIGEST
    assert f"trivy_{TRIVY_VERSION}_Linux-64bit.tar.gz" == TRIVY_ARCHIVE_NAME


def test_installer_cli_help_and_digest_failures_are_fail_closed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The public installer command documents its destination and rejects unpinned bytes."""
    with pytest.raises(SystemExit) as exit_info:
        main(["--help"])
    assert exit_info.value.code == 0
    assert "--destination" in capsys.readouterr().out

    with pytest.raises(ValueError, match="checksum document digest"):
        verify_release_payloads(b"untrusted checksums", b"untrusted archive")


def _sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of one test executable."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_installer_script_help_works_outside_checkout(tmp_path: Path) -> None:
    """The documented standalone command starts without checkout-relative imports."""
    completed = subprocess.run(  # nosec B603
        [sys.executable, str(Path(install_trivy.__file__).resolve()), "--help"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert "--destination" in completed.stdout
    assert not completed.stderr
    assert not list(tmp_path.iterdir())


@pytest.fixture(scope="module")
def https_contexts(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    """Use a real certificate and TLS stack for all installer protocol tests."""
    return tls_contexts(tmp_path_factory.mktemp("trivy-tls"))


@pytest.fixture
def release(monkeypatch: pytest.MonkeyPatch) -> ReleasePayloads:
    """Pin a real system executable as non-vendor transport and installation data."""
    binary = Path("/usr/bin/true").read_bytes()
    member = tarfile.TarInfo("trivy")
    member.size = len(binary)
    return pin_release(monkeypatch, archive_payload([(member, binary)]), binary)


def test_public_cli_installs_and_atomically_refreshes_verified_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    https_contexts: tuple[ssl.SSLContext, ssl.SSLContext],
    release: ReleasePayloads,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Both first installation and replacement preserve byte identity and owner-only mode."""
    destination = tmp_path / "bin" / "trivy"
    with release_transport(https_contexts, release_responses(release), monkeypatch) as requests:
        assert main(["--destination", str(destination)]) == 0
        assert destination.read_bytes() == release.binary
        destination.write_bytes(b"superseded executable")
        assert install_trivy.install_trivy(destination) == destination.absolute()
    assert len(requests) == 4
    assert destination.read_bytes() == release.binary
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert not destination.with_name(".trivy.verified-new").exists()
    assert f"installed Trivy {TRIVY_VERSION}" in capsys.readouterr().out


@pytest.mark.parametrize("kind", ["file", "symlink", "directory"])
def test_existing_temporary_objects_survive_exclusive_create_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    https_contexts: tuple[ssl.SSLContext, ssl.SSLContext],
    release: ReleasePayloads,
    kind: str,
) -> None:
    """A collision cannot delete a pre-existing file, link or directory."""
    destination = tmp_path / "trivy"
    destination.write_bytes(b"previous verified executable")
    temporary = tmp_path / ".trivy.verified-new"
    sentinel = tmp_path / "sentinel"
    sentinel.write_bytes(b"unrelated work")
    if kind == "symlink":
        temporary.symlink_to(sentinel)
    elif kind == "directory":
        temporary.mkdir()
        (temporary / "retained").write_bytes(b"owned elsewhere")
    else:
        temporary.write_bytes(b"owned elsewhere")
    before = temporary.lstat()
    with (
        release_transport(https_contexts, release_responses(release), monkeypatch),
        pytest.raises(FileExistsError),
    ):
        install_trivy.install_trivy(destination)
    assert temporary.lstat() == before
    assert destination.read_bytes() == b"previous verified executable"
    assert sentinel.read_bytes() == b"unrelated work"
    if kind == "directory":
        assert (temporary / "retained").read_bytes() == b"owned elsewhere"
    else:
        assert temporary.read_bytes() == (
            b"unrelated work" if kind == "symlink" else b"owned elsewhere"
        )


def test_failed_atomic_replace_removes_only_new_temporary_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    https_contexts: tuple[ssl.SSLContext, ssl.SSLContext],
    release: ReleasePayloads,
) -> None:
    """A real rename failure preserves the destination and removes this attempt's staging file."""
    destination = tmp_path / "trivy"
    destination.mkdir()
    sentinel = destination / "retained"
    sentinel.write_bytes(b"existing directory contents")
    with (
        release_transport(https_contexts, release_responses(release), monkeypatch),
        pytest.raises(IsADirectoryError),
    ):
        install_trivy.install_trivy(destination)
    assert sentinel.read_bytes() == b"existing directory contents"
    assert not (tmp_path / ".trivy.verified-new").exists()


def test_real_write_limit_failure_preserves_previous_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    https_contexts: tuple[ssl.SSLContext, ssl.SSLContext],
    release: ReleasePayloads,
) -> None:
    """A kernel-enforced file limit exercises descriptor and owned-file cleanup."""
    destination = tmp_path / "trivy"
    destination.write_bytes(b"previous executable")
    limits = resource.getrlimit(resource.RLIMIT_FSIZE)
    previous_signal = signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    with release_transport(https_contexts, release_responses(release), monkeypatch):
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (0, limits[1]))
            with pytest.raises(OSError, match="File too large"):
                install_trivy.install_trivy(destination)
        finally:
            resource.setrlimit(resource.RLIMIT_FSIZE, limits)
            signal.signal(signal.SIGXFSZ, previous_signal)
    assert destination.read_bytes() == b"previous executable"
    assert not (tmp_path / ".trivy.verified-new").exists()


@pytest.mark.parametrize(
    ("response", "error"),
    [
        (Response(b"", status=503), "cannot retrieve"),
        (Response(b"", headers={"Content-Length": "16385"}), "byte bound"),
        (Response(b"", headers={"Content-Length": "invalid"}), "cannot retrieve"),
        (Response(b"x" * 16385), "byte bound"),
        (
            Response(b"", status=302, headers={"Location": "https://example.invalid/rejected"}),
            "trusted hosts",
        ),
    ],
)
def test_public_install_rejects_invalid_http_responses_before_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    https_contexts: tuple[ssl.SSLContext, ssl.SSLContext],
    release: ReleasePayloads,
    response: Response,
    error: str,
) -> None:
    """The real HTTPS stack enforces HTTP errors, byte bounds and final-host restrictions."""
    responses = release_responses(release)
    checksum_path = next(iter(responses))
    responses[checksum_path] = response
    responses["/rejected"] = Response(b"untrusted host bytes")
    destination = tmp_path / "trivy"
    with (
        release_transport(https_contexts, responses, monkeypatch),
        pytest.raises(RuntimeError, match=error),
    ):
        install_trivy.install_trivy(destination)
    assert not destination.exists()
    assert not (tmp_path / ".trivy.verified-new").exists()


@pytest.mark.parametrize("mutation", ["document", "archive", "binding", "encoding"])
def test_public_release_verification_rejects_corruption_or_unbound_archive(
    monkeypatch: pytest.MonkeyPatch, release: ReleasePayloads, mutation: str
) -> None:
    """Digest identities, document encoding and unique archive binding are separate checks."""
    checksums, archive = release.checksums, release.archive
    if mutation == "document":
        checksums += b"corrupted"
        error = "document digest"
    elif mutation == "archive":
        archive += b"corrupted"
        error = "archive digest"
    else:
        checksums = b"\xff" if mutation == "encoding" else b"unbound archive\n"
        pin_release(monkeypatch, archive, release.binary, checksums=checksums)
        error = "not UTF-8" if mutation == "encoding" else "does not bind"
    with pytest.raises(ValueError, match=error):
        verify_release_payloads(checksums, archive)


@pytest.mark.parametrize(
    "kind",
    ["missing", "duplicate", "symlink", "empty", "oversized", "truncated", "invalid", "binary"],
)
def test_public_install_rejects_invalid_archive_before_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    https_contexts: tuple[ssl.SSLContext, ssl.SSLContext],
    kind: str,
) -> None:
    """Real tar parsing rejects ambiguous members, unsafe metadata and incorrect binary identity."""
    binary = b"protocol fixture executable"
    member = tarfile.TarInfo("other" if kind == "missing" else "trivy")
    member.size = len(binary)
    error = "exactly one binary"
    if kind == "symlink":
        member.type = tarfile.SYMTYPE
        member.linkname = "other"
        error = "metadata is invalid"
    elif kind == "empty":
        member.size = 0
        error = "metadata is invalid"
    archive = archive_payload([(member, binary)] * (2 if kind == "duplicate" else 1))
    if kind == "oversized":
        member.size = 256 * 1024 * 1024 + 1
        stream = io.BytesIO()
        with gzip.GzipFile(fileobj=stream, mode="wb") as compressed:
            compressed.write(member.tobuf())
            block = b"\0" * (1024 * 1024)
            blocks, remainder = divmod(member.size, len(block))
            for _ in range(blocks):
                compressed.write(block)
            compressed.write(block[:remainder])
            padding = -member.size % tarfile.BLOCKSIZE
            compressed.write(b"\0" * (padding + 2 * tarfile.BLOCKSIZE))
        archive = stream.getvalue()
        error = "metadata is invalid"
    elif kind == "truncated":
        archive = gzip.compress(member.tobuf() + binary[:-1])
        error = "archive is invalid"
    elif kind == "invalid":
        archive = b"not a gzip archive"
        error = "archive is invalid"
    elif kind == "binary":
        error = "binary digest"
    release = pin_release(monkeypatch, archive, binary + b"expected different binary")
    destination = tmp_path / "trivy"
    with (
        release_transport(https_contexts, release_responses(release), monkeypatch),
        pytest.raises(ValueError, match=error),
    ):
        install_trivy.install_trivy(destination)
    assert not destination.exists()
    assert not (tmp_path / ".trivy.verified-new").exists()
