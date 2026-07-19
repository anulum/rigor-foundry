# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — offline OSV database snapshot tests
"""Exercise strict manifest parsing and no-follow database projection."""

from __future__ import annotations

import hashlib
import io
import json
import os
import zipfile
from pathlib import Path

import pytest

import rigor_foundry.osv_database as osv_database
from rigor_foundry.git_inventory import StableRegularRead
from rigor_foundry.osv_database import (
    MAX_OSV_ARCHIVE_BYTES,
    OSVDatabaseArchive,
    OSVDatabaseInvalid,
    OSVDatabaseManifest,
    OSVDatabaseUnavailable,
    materialise_osv_database,
)


def _archive(*, name: str = "OSV-TEST.json", payload: bytes | None = None) -> bytes:
    """Return one deterministic ZIP archive containing an OSV-shaped record."""
    body = (
        payload
        or json.dumps(
            {
                "id": "OSV-TEST-1",
                "modified": "2026-07-19T00:00:00Z",
                "published": "2026-07-19T00:00:00Z",
                "affected": [],
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo(name, date_time=(2026, 7, 19, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, body)
    return output.getvalue()


def _manifest(payload: bytes, ecosystem: str = "PyPI") -> OSVDatabaseManifest:
    """Build one exact single-archive manifest."""
    return OSVDatabaseManifest.build(
        (
            OSVDatabaseArchive(
                ecosystem=ecosystem,
                archive_sha256=hashlib.sha256(payload).hexdigest(),
                archive_bytes=len(payload),
            ),
        )
    )


def _write_source(root: Path, ecosystem: str, payload: bytes) -> Path:
    """Write the official OSV cache layout under one private test root."""
    source = root / "source"
    archive = source / "osv-scanner" / ecosystem / "all.zip"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(payload)
    return source


def test_manifest_round_trip_and_verified_projection(tmp_path: Path) -> None:
    """Exact archive bytes produce a read-only projected database and stable digest."""
    payload = _archive()
    manifest = _manifest(payload)
    encoded = json.dumps(manifest.to_dict(), sort_keys=True).encode()

    parsed = OSVDatabaseManifest.from_bytes(encoded)
    source = _write_source(tmp_path, "PyPI", payload)
    destination = tmp_path / "destination"

    assert materialise_osv_database(parsed, source, destination) == manifest.database_digest
    projected = destination / "osv-scanner" / "PyPI" / "all.zip"
    assert projected.read_bytes() == payload
    assert projected.stat().st_mode & 0o222 == 0


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"implicit": True}, "fields do not match"),
        ({"schema_version": "9.0"}, "schema version"),
        ({"database_digest": "0" * 64}, "digest does not match"),
    ],
)
def test_manifest_parser_rejects_changed_fields(change: dict[str, object], message: str) -> None:
    """Imported manifests cannot add fields, change schemas, or rewrite identity."""
    document = {**_manifest(_archive()).to_dict(), **change}
    with pytest.raises(ValueError, match=message):
        OSVDatabaseManifest.from_bytes(json.dumps(document).encode())


def test_manifest_bounds_order_and_strict_json_are_fail_closed() -> None:
    """Unsafe ecosystems, duplicate order, empty sets, and ambiguous JSON fail."""
    payload = _archive()
    valid = OSVDatabaseArchive("PyPI", hashlib.sha256(payload).hexdigest(), len(payload))
    with pytest.raises(OSVDatabaseInvalid, match="archive count"):
        OSVDatabaseManifest.build(())
    with pytest.raises(OSVDatabaseInvalid, match="sorted and unique"):
        OSVDatabaseManifest.build((valid, valid))
    for document, message in (
        (b'{"schema_version":"1.0","schema_version":"1.0"}', "duplicate"),
        (b'{"schema_version":NaN}', "non-finite"),
        (b"\xff", "strict UTF-8"),
        (b"[]", "must be an object"),
    ):
        with pytest.raises(ValueError, match=message):
            OSVDatabaseManifest.from_bytes(document)

    manifest_document = _manifest(payload).to_dict()
    archives = manifest_document["archives"]
    assert isinstance(archives, list) and isinstance(archives[0], dict)
    archives[0]["ecosystem"] = "../PyPI"
    manifest_document["database_digest"] = "0" * 64
    with pytest.raises(OSVDatabaseInvalid, match="unsafe"):
        OSVDatabaseManifest.from_bytes(json.dumps(manifest_document).encode())


def test_manifest_archive_and_aggregate_bounds_are_fail_closed() -> None:
    """Archive fields, digests, per-file sizes, and aggregate sizes are bounded."""
    payload = _archive()
    archive = OSVDatabaseArchive("PyPI", hashlib.sha256(payload).hexdigest(), len(payload))
    for changed, message in (
        ({**archive.to_dict(), "extra": True}, "fields do not match"),
        ({**archive.to_dict(), "archive_sha256": "A" * 64}, "lowercase SHA-256"),
        ({**archive.to_dict(), "archive_bytes": MAX_OSV_ARCHIVE_BYTES + 1}, "profile bound"),
    ):
        with pytest.raises(OSVDatabaseInvalid, match=message):
            OSVDatabaseArchive.from_dict(changed, 0)

    oversized = tuple(
        OSVDatabaseArchive(
            ecosystem=f"Ecosystem{index}",
            archive_sha256="0" * 64,
            archive_bytes=MAX_OSV_ARCHIVE_BYTES,
        )
        for index in range(5)
    )
    with pytest.raises(OSVDatabaseInvalid, match="aggregate byte bound"):
        OSVDatabaseManifest.build(oversized)
    with pytest.raises(OSVDatabaseInvalid, match="unsafe"):
        OSVDatabaseManifest.build(
            (
                OSVDatabaseArchive(
                    ecosystem="../unsafe",
                    archive_sha256="0" * 64,
                    archive_bytes=1,
                ),
            )
        )

    document = _manifest(payload).to_dict()
    document["archives"] = "not-an-array"
    with pytest.raises(OSVDatabaseInvalid, match="must be an array"):
        OSVDatabaseManifest.from_bytes(json.dumps(document).encode())


def test_projection_rejects_missing_changed_and_linked_archives(tmp_path: Path) -> None:
    """Missing bytes, content mutation, and hard-link aliases cannot enter evidence."""
    payload = _archive()
    manifest = _manifest(payload)
    absent = tmp_path / "absent"
    absent.mkdir()
    with pytest.raises(OSVDatabaseUnavailable, match="archive is unavailable"):
        materialise_osv_database(manifest, absent, tmp_path / "missing-output")

    source = _write_source(tmp_path, "PyPI", payload + b"changed")
    with pytest.raises(OSVDatabaseInvalid, match="does not match manifest"):
        materialise_osv_database(manifest, source, tmp_path / "changed-output")

    archive = source / "osv-scanner" / "PyPI" / "all.zip"
    archive.write_bytes(payload)
    alias = archive.with_name("alias.zip")
    os.link(archive, alias)
    with pytest.raises(OSVDatabaseUnavailable, match="archive is unavailable"):
        materialise_osv_database(manifest, source, tmp_path / "linked-output")


@pytest.mark.parametrize(
    "name",
    ["../escape.json", "/absolute.json", "folder\\escape.json", "plain.txt", "folder/"],
)
def test_projection_rejects_unsafe_or_non_advisory_zip_members(tmp_path: Path, name: str) -> None:
    """Archive traversal, non-JSON members, and directories are never projected."""
    payload = _archive(name=name)
    source = _write_source(tmp_path, "PyPI", payload)
    with pytest.raises(OSVDatabaseInvalid, match="member is unsafe"):
        materialise_osv_database(_manifest(payload), source, tmp_path / "output")


def test_projection_rejects_malformed_empty_and_oversized_zip_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Malformed, empty, over-count, tiny, and over-expanded archives fail closed."""
    empty = io.BytesIO()
    with zipfile.ZipFile(empty, "w"):
        pass
    for payload, message in (
        (b"not-a-zip", "archive is invalid"),
        (empty.getvalue(), "entry count"),
    ):
        source = _write_source(tmp_path / hashlib.sha256(payload).hexdigest(), "PyPI", payload)
        with pytest.raises(OSVDatabaseInvalid, match=message):
            materialise_osv_database(_manifest(payload), source, tmp_path / "invalid-output")

    tiny = _archive(payload=b"x")
    source = _write_source(tmp_path / "tiny", "PyPI", tiny)
    with pytest.raises(OSVDatabaseInvalid, match="member is unsafe"):
        materialise_osv_database(_manifest(tiny), source, tmp_path / "tiny-output")

    valid = _archive()
    source = _write_source(tmp_path / "count", "PyPI", valid)
    monkeypatch.setattr(osv_database, "MAX_OSV_ZIP_ENTRIES", 0)
    with pytest.raises(OSVDatabaseInvalid, match="entry count"):
        materialise_osv_database(_manifest(valid), source, tmp_path / "count-output")
    monkeypatch.setattr(osv_database, "MAX_OSV_ZIP_ENTRIES", 200_000)
    monkeypatch.setattr(osv_database, "MAX_OSV_UNCOMPRESSED_BYTES", 1)
    with pytest.raises(OSVDatabaseInvalid, match="expands beyond"):
        materialise_osv_database(_manifest(valid), source, tmp_path / "expanded-output")


def test_projection_handles_read_and_write_boundary_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Read truncation and projection write errors fail without retaining output."""
    payload = _archive()
    manifest = _manifest(payload)
    source = _write_source(tmp_path, "PyPI", payload)
    observed = StableRegularRead(
        content_digest=hashlib.sha256(payload).hexdigest(),
        byte_size=len(payload),
        payload=None,
        git_blob_id=None,
    )
    monkeypatch.setattr(
        osv_database, "read_stable_regular_file_at", lambda *args, **kwargs: observed
    )
    with pytest.raises(OSVDatabaseInvalid, match="exceeds its byte bound"):
        materialise_osv_database(manifest, source, tmp_path / "truncated-output")

    monkeypatch.undo()
    output = tmp_path / "write-output"

    def fail_write(_self: Path, _payload: bytes) -> int:
        raise OSError("simulated write failure")

    monkeypatch.setattr(Path, "write_bytes", fail_write)
    with pytest.raises(OSError, match="simulated write failure"):
        materialise_osv_database(manifest, source, output)
    assert not output.exists()


def test_projection_requires_an_absolute_cache_root(tmp_path: Path) -> None:
    """Relative cache roots cannot make execution depend on the caller's cwd."""
    with pytest.raises(OSVDatabaseInvalid, match="must be absolute"):
        materialise_osv_database(_manifest(_archive()), Path("relative"), tmp_path / "out")
    with pytest.raises(OSVDatabaseUnavailable, match="cache root is unavailable"):
        materialise_osv_database(
            _manifest(_archive()),
            tmp_path / "does-not-exist",
            tmp_path / "out",
        )
    payload = _archive()
    source = _write_source(tmp_path, "PyPI", payload)
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    with pytest.raises(OSVDatabaseInvalid, match="destination already exists"):
        materialise_osv_database(_manifest(payload), source, occupied)
