# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project-memory protocol primitives
"""Define canonical values and compact provenance types for project memory."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import cast

PROJECT_MEMORY_SCHEMA_VERSION = "project-memory.v1"
PROJECT_MEMORY_SERIALIZER = "RFC8785-JCS"
PROJECT_MEMORY_SENSITIVITY = "PROJECT_PRIVATE_ADMISSIBLE"
PROJECT_MEMORY_SOFT_CONTENT_BYTES = 24 * 1024
PROJECT_MEMORY_MAX_CONTENT_BYTES = 32 * 1024
PROJECT_MEMORY_MAX_RECORDS = 50
PROJECT_MEMORY_MAX_MANIFEST_BYTES = 64 * 1024
PROJECT_MEMORY_MAX_INDEX_BYTES = 16 * 1024
PROJECT_MEMORY_MAX_SOURCES = 32
PROJECT_MEMORY_MAX_SUPERSEDES = 16

PROJECT_MEMORY_CATEGORIES = (
    "architecture-contracts",
    "continuity",
    "decisions",
    "evidence",
    "identity",
    "operations",
)
PROJECT_MEMORY_ASSERTION_CLASSES = (
    "contract",
    "decision",
    "evidence",
    "handover",
    "observation",
)
PROJECT_MEMORY_FRESHNESS_POLICIES = (
    "expires",
    "immutable",
    "review-on-source-change",
)
PROJECT_MEMORY_PARENT_KINDS = (
    "ecosystem-boot",
    "ecosystem-rules",
    "ecosystem-memory",
    "group-memory",
    "project-sessions",
    "project-handovers",
    "vendor-memory",
)

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_ACTOR_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_PARENT_LOCATOR = re.compile(r"(?:\.\./)*[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*/?")
_SAFE_INTEGER = 2**53 - 1


class ProjectMemoryInvalid(ValueError):
    """The project-memory document violates the exact v1 contract."""


def require_mapping(value: object, field: str) -> dict[str, object]:
    """Return one string-keyed mapping or fail closed."""
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ProjectMemoryInvalid(f"{field} must be an object")
    return cast(dict[str, object], value)


def require_exact_fields(value: dict[str, object], expected: frozenset[str], field: str) -> None:
    """Require exactly the versioned field set."""
    if set(value) != expected:
        raise ProjectMemoryInvalid(f"{field} fields do not match project-memory.v1")


def require_string(value: object, field: str, *, maximum: int) -> str:
    """Return one bounded printable-ASCII metadata string."""
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or not value.isascii()
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
    ):
        raise ProjectMemoryInvalid(f"{field} must be bounded printable ASCII")
    return value


def require_identifier(value: object, field: str) -> str:
    """Return one portable bounded identifier."""
    text = require_string(value, field, maximum=128)
    if _IDENTIFIER.fullmatch(text) is None:
        raise ProjectMemoryInvalid(f"{field} must be a portable identifier")
    return text


def require_digest(value: object, field: str) -> str:
    """Return one lowercase SHA-256 digest."""
    text = require_string(value, field, maximum=64)
    if _SHA256.fullmatch(text) is None:
        raise ProjectMemoryInvalid(f"{field} must be a lowercase SHA-256 digest")
    return text


def require_timestamp(value: object, field: str) -> tuple[str, datetime]:
    """Return one exact microsecond UTC timestamp and parsed value."""
    text = require_string(value, field, maximum=27)
    if _TIMESTAMP.fullmatch(text) is None:
        raise ProjectMemoryInvalid(f"{field} must be microsecond UTC RFC 3339")
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise ProjectMemoryInvalid(f"{field} is not a calendar timestamp") from exc
    return text, parsed


def generation_id_for(generated_at: str) -> str:
    """Return the sortable generation identifier for one exact timestamp."""
    _, parsed = require_timestamp(generated_at, "generated_at")
    return parsed.strftime("%Y%m%dT%H%M%S%fZ")


def strict_json(payload: bytes) -> object:
    """Decode UTF-8 JSON while rejecting duplicates, floats and non-finite numbers."""

    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ProjectMemoryInvalid("project-memory manifest contains duplicate keys")
            result[key] = value
        return result

    def reject_number(value: str) -> object:
        raise ProjectMemoryInvalid(f"project-memory manifest contains forbidden number: {value}")

    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=unique_pairs,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProjectMemoryInvalid("project-memory manifest is not strict UTF-8 JSON") from exc


def _validate_canonical_value(value: object, field: str = "manifest") -> None:
    """Restrict values to the interoperable no-float JCS subset."""
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -_SAFE_INTEGER <= value <= _SAFE_INTEGER:
            raise ProjectMemoryInvalid(f"{field} integer exceeds the JCS interoperability bound")
        return
    if isinstance(value, str):
        require_string(value, field, maximum=max(1, len(value)))
        return
    if isinstance(value, list):
        for index, item in enumerate(cast(list[object], value)):
            _validate_canonical_value(item, f"{field}[{index}]")
        return
    if isinstance(value, dict):
        data = require_mapping(value, field)
        for key, item in data.items():
            require_string(key, f"{field} key", maximum=max(1, len(key)))
            _validate_canonical_value(item, f"{field}.{key}")
        return
    raise ProjectMemoryInvalid(f"{field} contains a value outside the no-float JCS profile")


def canonical_json_bytes(value: object) -> bytes:
    """Return RFC 8785-compatible bytes for the restricted v1 value domain."""
    _validate_canonical_value(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass(frozen=True)
class ProjectMemorySource:
    """One content-addressed source supporting a memory assertion."""

    source_id: str
    locator: str
    sha256: str

    @classmethod
    def from_dict(cls, value: object, field: str) -> ProjectMemorySource:
        """Parse one exact source object."""
        data = require_mapping(value, field)
        require_exact_fields(data, frozenset({"source_id", "locator", "sha256"}), field)
        return cls(
            source_id=require_identifier(data.get("source_id"), f"{field}.source_id"),
            locator=require_string(data.get("locator"), f"{field}.locator", maximum=1024),
            sha256=require_digest(data.get("sha256"), f"{field}.sha256"),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the source object."""
        return {"source_id": self.source_id, "locator": self.locator, "sha256": self.sha256}


@dataclass(frozen=True)
class ProjectMemoryFreshness:
    """The explicit review or expiry policy of one record."""

    policy: str
    valid_until: str | None

    @classmethod
    def from_dict(cls, value: object, field: str) -> ProjectMemoryFreshness:
        """Parse and cross-check one freshness contract."""
        data = require_mapping(value, field)
        require_exact_fields(data, frozenset({"policy", "valid_until"}), field)
        policy = require_string(data.get("policy"), f"{field}.policy", maximum=32)
        if policy not in PROJECT_MEMORY_FRESHNESS_POLICIES:
            raise ProjectMemoryInvalid(f"{field}.policy is unsupported")
        raw_valid_until = data.get("valid_until")
        if policy == "expires":
            valid_until, _ = require_timestamp(raw_valid_until, f"{field}.valid_until")
        elif raw_valid_until is not None:
            raise ProjectMemoryInvalid(f"{field}.valid_until must be null for {policy}")
        else:
            valid_until = None
        return cls(policy=policy, valid_until=valid_until)

    def to_dict(self) -> dict[str, object]:
        """Serialise the freshness contract."""
        return {"policy": self.policy, "valid_until": self.valid_until}


@dataclass(frozen=True)
class ProjectMemoryActor:
    """The exact writing seat and Synapse claim provenance."""

    identity: str
    claim_id: str

    @classmethod
    def from_dict(cls, value: object, field: str) -> ProjectMemoryActor:
        """Parse one exact actor object."""
        data = require_mapping(value, field)
        require_exact_fields(data, frozenset({"identity", "claim_id"}), field)
        identity = require_string(data.get("identity"), f"{field}.identity", maximum=256)
        if _ACTOR_IDENTITY.fullmatch(identity) is None:
            raise ProjectMemoryInvalid(f"{field}.identity is not portable")
        return cls(
            identity=identity,
            claim_id=require_identifier(data.get("claim_id"), f"{field}.claim_id"),
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the actor provenance."""
        return {"identity": self.identity, "claim_id": self.claim_id}


@dataclass(frozen=True)
class ProjectMemoryParent:
    """One selective upward link rendered into the project index."""

    kind: str
    locator: str

    @classmethod
    def from_dict(cls, value: object, field: str) -> ProjectMemoryParent:
        """Parse one relative parent-layer reference."""
        data = require_mapping(value, field)
        require_exact_fields(data, frozenset({"kind", "locator"}), field)
        kind = require_string(data.get("kind"), f"{field}.kind", maximum=32)
        if kind not in PROJECT_MEMORY_PARENT_KINDS:
            raise ProjectMemoryInvalid(f"{field}.kind is unsupported")
        locator = require_string(data.get("locator"), f"{field}.locator", maximum=1024)
        if _PARENT_LOCATOR.fullmatch(locator) is None:
            raise ProjectMemoryInvalid(f"{field}.locator must be a normalised relative path")
        return cls(kind=kind, locator=locator)

    def to_dict(self) -> dict[str, object]:
        """Serialise the parent-layer reference."""
        return {"kind": self.kind, "locator": self.locator}
