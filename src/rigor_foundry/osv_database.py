# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — verified offline OSV database snapshots
"""Validate and materialise exact local OSV-Scanner database archives."""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from .audit_primitives import canonical_digest, require_integer, require_mapping, require_string
from .git_inventory import open_directory_no_follow, read_stable_regular_file_at

OSV_DATABASE_MANIFEST_SCHEMA_VERSION = "1.0"
OSV_DATABASE_ENVIRONMENT = "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"
OSV_DATABASE_SANDBOX_ROOT = "/workspace/.rigor-osv-db"
MAX_OSV_ARCHIVES = 32
MAX_OSV_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_OSV_DATABASE_BYTES = 512 * 1024 * 1024
MAX_OSV_ZIP_ENTRIES = 200_000
MAX_OSV_UNCOMPRESSED_BYTES = 4 * 1024 * 1024 * 1024
_ECOSYSTEM = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")


class OSVDatabaseUnavailable(RuntimeError):
    """The declared local OSV database snapshot is not present."""


class OSVDatabaseInvalid(ValueError):
    """The local OSV database snapshot does not match its manifest."""


def _digest(value: object, field: str) -> str:
    """Return one validated lowercase SHA-256 digest."""
    digest = require_string(value, field)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise OSVDatabaseInvalid(f"{field} must be a lowercase SHA-256 digest")
    return digest


def _strict_json(payload: bytes) -> object:
    """Decode strict UTF-8 JSON without duplicate keys or non-finite values."""

    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise OSVDatabaseInvalid("OSV database manifest contains duplicate keys")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise OSVDatabaseInvalid(f"OSV database manifest contains non-finite number: {value}")

    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=unique_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OSVDatabaseInvalid("OSV database manifest is not strict UTF-8 JSON") from exc


@dataclass(frozen=True)
class OSVDatabaseArchive:
    """One exact ecosystem database archive in the official cache layout."""

    ecosystem: str
    archive_sha256: str
    archive_bytes: int

    @classmethod
    def from_dict(cls, value: object, index: int) -> OSVDatabaseArchive:
        """Parse one strict archive record."""
        field = f"archives[{index}]"
        data = require_mapping(value, field)
        if set(data) != {"ecosystem", "archive_sha256", "archive_bytes"}:
            raise OSVDatabaseInvalid(f"{field} fields do not match schema")
        ecosystem = require_string(data.get("ecosystem"), f"{field}.ecosystem")
        if _ECOSYSTEM.fullmatch(ecosystem) is None:
            raise OSVDatabaseInvalid(f"{field}.ecosystem is unsafe")
        archive_bytes = require_integer(
            data.get("archive_bytes"), f"{field}.archive_bytes", minimum=1
        )
        if archive_bytes > MAX_OSV_ARCHIVE_BYTES:
            raise OSVDatabaseInvalid(f"{field}.archive_bytes exceeds the profile bound")
        return cls(
            ecosystem=ecosystem,
            archive_sha256=_digest(data.get("archive_sha256"), f"{field}.archive_sha256"),
            archive_bytes=archive_bytes,
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise one archive record."""
        return {
            "ecosystem": self.ecosystem,
            "archive_sha256": self.archive_sha256,
            "archive_bytes": self.archive_bytes,
        }


@dataclass(frozen=True)
class OSVDatabaseManifest:
    """Content-addressed list of every allowed offline database archive."""

    archives: tuple[OSVDatabaseArchive, ...]
    database_digest: str

    @classmethod
    def build(cls, archives: tuple[OSVDatabaseArchive, ...]) -> OSVDatabaseManifest:
        """Build a canonical manifest from an ordered ecosystem set."""
        if not archives or len(archives) > MAX_OSV_ARCHIVES:
            raise OSVDatabaseInvalid("OSV database manifest archive count is out of bounds")
        archives = tuple(
            OSVDatabaseArchive.from_dict(item.to_dict(), index)
            for index, item in enumerate(archives)
        )
        ecosystems = tuple(item.ecosystem for item in archives)
        if ecosystems != tuple(sorted(ecosystems)) or len(ecosystems) != len(set(ecosystems)):
            raise OSVDatabaseInvalid("OSV database manifest ecosystems must be sorted and unique")
        if sum(item.archive_bytes for item in archives) > MAX_OSV_DATABASE_BYTES:
            raise OSVDatabaseInvalid("OSV database manifest exceeds the aggregate byte bound")
        fields = {
            "schema_version": OSV_DATABASE_MANIFEST_SCHEMA_VERSION,
            "archives": [item.to_dict() for item in archives],
        }
        return cls(archives=archives, database_digest=canonical_digest(fields))

    @classmethod
    def from_bytes(cls, payload: bytes) -> OSVDatabaseManifest:
        """Parse and integrity-check one tracked manifest payload."""
        data = require_mapping(_strict_json(payload), "OSV database manifest")
        if set(data) != {"schema_version", "archives", "database_digest"}:
            raise OSVDatabaseInvalid("OSV database manifest fields do not match schema")
        if data.get("schema_version") != OSV_DATABASE_MANIFEST_SCHEMA_VERSION:
            raise OSVDatabaseInvalid("OSV database manifest schema version is unsupported")
        raw_archives = data.get("archives")
        if not isinstance(raw_archives, list):
            raise OSVDatabaseInvalid("OSV database manifest archives must be an array")
        archives = tuple(
            OSVDatabaseArchive.from_dict(item, index)
            for index, item in enumerate(cast(list[object], raw_archives))
        )
        manifest = cls.build(archives)
        if _digest(data.get("database_digest"), "database_digest") != manifest.database_digest:
            raise OSVDatabaseInvalid("OSV database digest does not match its manifest")
        return manifest

    def to_dict(self) -> dict[str, object]:
        """Serialise the complete database manifest."""
        return {
            "schema_version": OSV_DATABASE_MANIFEST_SCHEMA_VERSION,
            "archives": [item.to_dict() for item in self.archives],
            "database_digest": self.database_digest,
        }


def _validate_zip(payload: bytes, ecosystem: str) -> None:
    """Reject malformed, unsafe, empty, encrypted, or unbounded OSV archives."""
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            members = archive.infolist()
    except (OSError, zipfile.BadZipFile) as exc:
        raise OSVDatabaseInvalid(f"OSV database archive is invalid: {ecosystem}") from exc
    if not members or len(members) > MAX_OSV_ZIP_ENTRIES:
        raise OSVDatabaseInvalid(f"OSV database archive entry count is invalid: {ecosystem}")
    uncompressed = 0
    for member in members:
        member_path = PurePosixPath(member.filename)
        if (
            member.is_dir()
            or not member.filename.endswith(".json")
            or member_path.is_absolute()
            or ".." in member_path.parts
            or "\\" in member.filename
            or member.flag_bits & 0x1
            or member.file_size < 2
        ):
            raise OSVDatabaseInvalid(f"OSV database archive member is unsafe: {ecosystem}")
        uncompressed += member.file_size
        if uncompressed > MAX_OSV_UNCOMPRESSED_BYTES:
            raise OSVDatabaseInvalid(f"OSV database archive expands beyond its bound: {ecosystem}")


def _read_archive(root_descriptor: int, archive: OSVDatabaseArchive) -> bytes:
    """Read one official-layout archive through no-follow directory descriptors."""
    descriptor = root_descriptor
    opened: list[int] = []
    relative = f"osv-scanner/{archive.ecosystem}/all.zip"
    try:
        for component in ("osv-scanner", archive.ecosystem):
            descriptor = os.open(
                component,
                os.O_RDONLY
                | os.O_DIRECTORY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            opened.append(descriptor)
        observed = read_stable_regular_file_at(
            descriptor,
            "all.zip",
            relative,
            buffer_limit=MAX_OSV_ARCHIVE_BYTES,
            require_single_link=True,
        )
    except (OSError, RuntimeError) as exc:
        raise OSVDatabaseUnavailable(f"OSV database archive is unavailable: {relative}") from exc
    finally:
        for item in reversed(opened):
            os.close(item)
    if observed.payload is None:
        raise OSVDatabaseInvalid(f"OSV database archive exceeds its byte bound: {relative}")
    if (
        observed.byte_size != archive.archive_bytes
        or observed.content_digest != archive.archive_sha256
    ):
        raise OSVDatabaseInvalid(f"OSV database archive does not match manifest: {relative}")
    _validate_zip(observed.payload, archive.ecosystem)
    return observed.payload


def materialise_osv_database(
    manifest: OSVDatabaseManifest,
    source_root: Path,
    destination_root: Path,
) -> str:
    """Copy a verified snapshot into the private adapter workspace read-only."""
    if not source_root.is_absolute():
        raise OSVDatabaseInvalid("OSV database cache root must be absolute")
    if destination_root.exists():
        raise OSVDatabaseInvalid("OSV database projection destination already exists")
    try:
        root_descriptor = open_directory_no_follow(source_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise OSVDatabaseUnavailable("OSV database cache root is unavailable") from exc
    try:
        payloads = tuple(
            (archive, _read_archive(root_descriptor, archive)) for archive in manifest.archives
        )
    finally:
        os.close(root_descriptor)
    try:
        scanner_root = destination_root / "osv-scanner"
        scanner_root.mkdir(parents=True, mode=0o755)
        for archive, payload in payloads:
            ecosystem_root = scanner_root / archive.ecosystem
            ecosystem_root.mkdir(mode=0o755)
            destination = ecosystem_root / "all.zip"
            destination.write_bytes(payload)
            destination.chmod(0o444)
    except Exception:
        shutil.rmtree(destination_root, ignore_errors=True)
        raise
    return manifest.database_digest
