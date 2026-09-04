# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — project registry canonical value primitives
"""Validate the bounded no-float canonical value profile used by the registry."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import PurePosixPath
from typing import cast

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")
_GENERATION_ID = re.compile(r"[0-9]{8}T[0-9]{12}Z")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SAFE_INTEGER = 2**53 - 1


class ProjectRegistryInvalid(ValueError):
    """The project registry violates its exact versioned contract."""


def _mapping(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ProjectRegistryInvalid(f"{field} must be an object")
    return cast(dict[str, object], value)


def _exact_fields(value: dict[str, object], expected: frozenset[str], field: str) -> None:
    if set(value) != expected:
        raise ProjectRegistryInvalid(f"{field} fields do not match the registry schema")


def _string(value: object, field: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or not value.isascii()
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
    ):
        raise ProjectRegistryInvalid(f"{field} must be bounded printable ASCII")
    return value


def _identifier(value: object, field: str) -> str:
    text = _string(value, field, 128)
    if _IDENTIFIER.fullmatch(text) is None:
        raise ProjectRegistryInvalid(f"{field} must be a portable identifier")
    return text


def _identity(value: object, field: str) -> str:
    text = _string(value, field, 256)
    if _IDENTITY.fullmatch(text) is None:
        raise ProjectRegistryInvalid(f"{field} must be a portable identity")
    return text


def _digest(value: object, field: str) -> str:
    text = _string(value, field, 64)
    if _SHA256.fullmatch(text) is None:
        raise ProjectRegistryInvalid(f"{field} must be a lowercase SHA-256 digest")
    return text


def _timestamp(value: object, field: str) -> tuple[str, datetime]:
    text = _string(value, field, 27)
    if _TIMESTAMP.fullmatch(text) is None:
        raise ProjectRegistryInvalid(f"{field} must be microsecond UTC RFC 3339")
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise ProjectRegistryInvalid(f"{field} is not a calendar timestamp") from exc
    return text, parsed


def project_registry_generation_id(generated_at: str) -> str:
    """Return the sortable identifier for an exact registry timestamp."""
    _, parsed = _timestamp(generated_at, "generated_at")
    return parsed.strftime("%Y%m%dT%H%M%S%fZ")


def _relative_path(value: object, field: str) -> str:
    text = _string(value, field, 512)
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or path.as_posix() != text
        or any(part in {"", ".", "..", ".git"} for part in path.parts)
    ):
        raise ProjectRegistryInvalid(f"{field} must be a normalised relative path")
    return text


def _validate_canonical_value(value: object, field: str = "document") -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -_SAFE_INTEGER <= value <= _SAFE_INTEGER:
            raise ProjectRegistryInvalid(f"{field} integer exceeds the JCS bound")
        return
    if isinstance(value, str):
        _string(value, field, max(1, len(value)))
        return
    if isinstance(value, list):
        for index, item in enumerate(cast(list[object], value)):
            _validate_canonical_value(item, f"{field}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in _mapping(value, field).items():
            _string(key, f"{field} key", max(1, len(key)))
            _validate_canonical_value(item, f"{field}.{key}")
        return
    raise ProjectRegistryInvalid(f"{field} contains a value outside the no-float JCS profile")


def project_registry_canonical_json(value: object) -> bytes:
    """Return canonical JSON bytes for the restricted registry value domain."""
    _validate_canonical_value(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def project_registry_strict_json(payload: bytes) -> object:
    """Decode strict UTF-8 JSON while rejecting duplicate and non-integer numbers."""

    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ProjectRegistryInvalid("registry JSON contains duplicate keys")
            result[key] = item
        return result

    def reject_number(value: str) -> object:
        raise ProjectRegistryInvalid(f"registry JSON contains a forbidden number: {value}")

    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=unique_pairs,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProjectRegistryInvalid("registry document is not strict UTF-8 JSON") from exc
