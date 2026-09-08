# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — strict discovery snapshot input
"""Parse bounded discovery data without evaluating or promoting its prose."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass

from .audit_primitives import require_exact_fields, require_mapping
from .model_primitives import require_digest, require_identifier

SCHEMA = "discovery-source-closure.v1"
MAX_LIMIT = 2**31 - 1
MAX_JSON_DEPTH = 16


class DiscoveryValidationError(ValueError):
    """Reject invalid discovery data using a fixed, content-free error code."""


class DiscoveryReadError(OSError):
    """Reject inaccessible or unsupported capture reads without leaking paths."""


@dataclass(frozen=True)
class DiscoveryLimits:
    """Require explicit positive limits, each at most 2**31 - 1.

    Total bytes include the manifest and every declared capture exactly once.
    Count limits bound sources, shards, all candidates and all supporting edges.
    These parser budgets confer no execution or audit authority.
    """

    total_bytes: int
    file_bytes: int
    sources: int
    shards: int
    candidates: int
    spans: int

    def __post_init__(self) -> None:
        """Reject booleans, nonintegers and unbounded caller budgets."""
        if any(
            type(value) is not int or not 0 < value <= MAX_LIMIT for value in asdict(self).values()
        ):
            raise DiscoveryValidationError("invalid-limit")


def exact_object(value: object, fields: str) -> dict[str, object]:
    """Require exactly the whitespace-separated field names in an object."""
    try:
        result = require_mapping(value, "object")
        require_exact_fields(result, frozenset(fields.split()), "object")
    except ValueError as exc:
        raise DiscoveryValidationError("invalid-fields") from exc
    return result


def integer(value: object, *, minimum: int = 0) -> int:
    """Validate one bounded exact integer, never accepting a JSON boolean."""
    if type(value) is not int or not minimum <= value <= MAX_LIMIT:
        raise DiscoveryValidationError("invalid-integer")
    return value


def identifier(value: object) -> str:
    """Apply the shared bounded identifier grammar with content-free errors."""
    try:
        return require_identifier(value, "identifier")
    except ValueError as exc:
        raise DiscoveryValidationError("invalid-identifier") from exc


def digest(value: object) -> str:
    """Apply the shared lowercase SHA-256 grammar with content-free errors."""
    try:
        return require_digest(value, "digest")
    except ValueError as exc:
        raise DiscoveryValidationError("invalid-digest") from exc


def capture_name(value: object) -> str:
    """Require a flat portable filename without URI, traversal or device names."""
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value) is None
    ):
        raise DiscoveryValidationError("invalid-capture")
    stem = value.split(".", 1)[0].upper()
    if (
        value.endswith(".")
        or stem in {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
        or re.fullmatch(r"(COM|LPT)[1-9]", stem)
    ):
        raise DiscoveryValidationError("invalid-capture")
    return value


def nonempty_list(value: object, limit: int) -> list[object]:
    """Require a nonempty bounded JSON array before processing its records."""
    if not isinstance(value, list) or not 0 < len(value) <= limit:
        raise DiscoveryValidationError("invalid-count")
    return value


def text_bytes(payload: bytes) -> str:
    """Decode strictly as UTF-8 without normalizing any source bytes."""
    try:
        return payload.decode("utf-8")
    except UnicodeError as exc:
        raise DiscoveryValidationError("invalid-utf8") from exc


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON keys, including nested and escaped equivalents."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DiscoveryValidationError("duplicate-key")
        result[key] = value
    return result


def _constant(value: str) -> object:
    """Refuse non-finite JSON constants regardless of their spelling."""
    raise DiscoveryValidationError("invalid-json-number")


def parse_json(payload: bytes) -> object:
    """Parse one strict JSON value with a lexical nesting ceiling of sixteen.

    Scan nesting outside quoted strings before json.loads allocates containers.
    JSON syntax, including mismatched closers, remains the standard parser's job.
    """
    text = text_bytes(payload)
    depth = 0
    quoted = False
    escaped = False
    for character in text:
        if escaped:
            escaped = False
        elif quoted and character == "\\":
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif not quoted:
            if character in "[{":
                depth += 1
                if depth > MAX_JSON_DEPTH:
                    raise DiscoveryValidationError("json-depth-exceeded")
            elif character in "]}":
                depth -= 1
    try:
        return json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, RecursionError) as exc:
        raise DiscoveryValidationError("invalid-json") from exc


def discovery_object(value: object, fields: str) -> dict[str, object]:
    """Require exact discovery schema and non-authoritative lifecycle status."""
    result = exact_object(value, fields)
    if result["schema_version"] != SCHEMA or result["status"] != "discovery-only":
        raise DiscoveryValidationError("invalid-discovery-state")
    return result
