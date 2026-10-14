# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — recovery evidence field validation
"""Validate exact PCS-CANON-1 recovery evidence fields without file authority."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping
from typing import cast

from .effect_journal_records_v2 import canonical_journal_json_v2
from .model_primitives import require_digest, require_identifier, require_utc_timestamp
from .models import canonical_digest
from .project_registry_primitives import ProjectRegistryInvalid, project_registry_strict_json

_SAFE_INTEGER = 2**53 - 1
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")


def closed_object(value: object, fields: frozenset[str], label: str) -> dict[str, object]:
    """Require an exact closed PCS-CANON-1 object field set.

    Parameters
    ----------
    value : object
        Untrusted decoded field or object; validation does not grant execution authority.
    fields : frozenset[str]
        Exact allowed keys; missing and additional keys both refuse.
    label : str
        Field label used in a validation error.

    Returns
    -------
    dict[str, object]
        The original object after exact key-set validation.

    Raises
    ------
    ValueError
        The input violates the exact canonical field or closed schema contract.
    """
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} fields differ")
    return cast(dict[str, object], value)


def bounded_int(value: object, *, minimum: int, maximum: int = _SAFE_INTEGER) -> int:
    """Require a JSON integer in one explicit safe range.

    Parameters
    ----------
    value : object
        Untrusted decoded field or object; validation does not grant execution authority.
    minimum : int
        Inclusive minimum accepted JSON integer; booleans are rejected.
    maximum : int
        Inclusive integer or decoded-byte limit for the selected schema field.

    Returns
    -------
    int
        The unchanged safe-range integer.

    Raises
    ------
    ValueError
        The input violates the exact canonical field or closed schema contract.
    """
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("recovery evidence integer is outside its range")
    return value


def digest(value: object, label: str) -> str:
    """Require one lowercase full SHA-256 digest.

    Parameters
    ----------
    value : object
        Untrusted decoded field or object; validation does not grant execution authority.
    label : str
        Field label used in a validation error.

    Returns
    -------
    str
        The unchanged exact lowercase SHA-256 string.

    Raises
    ------
    ValueError
        The input violates the exact canonical field or closed schema contract.
    """
    return require_digest(value, label)


def identity(value: object) -> dict[str, object]:
    """Check exact selected path/identity encoding before descriptor comparison.

    Parameters
    ----------
    value : object
        Untrusted decoded field or object; validation does not grant execution authority.

    Returns
    -------
    dict[str, object]
        The unchanged canonical path, digest and decimal device/inode identity.

    Raises
    ------
    ValueError
        The input violates the exact canonical field or closed schema contract.
    """
    fields = frozenset({"path", "path_digest", "device", "inode"})
    item = closed_object(value, fields, "recovery file identity")
    path = item["path"]
    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or "\x00" in path
        or (path != "/" and path.endswith("/"))
        or any(part in ("", ".", "..") for part in path[1:].split("/") if path != "/")
    ):
        raise ValueError("recovery file path is not an exact absolute path")
    if digest(item["path_digest"], "recovery.path_digest") != canonical_digest(path):
        raise ValueError("recovery file path digest differs")
    for label in ("device", "inode"):
        number = item[label]
        if not isinstance(number, str) or _DECIMAL.fullmatch(number) is None:
            raise ValueError(f"recovery file {label} is not canonical decimal")
        if label == "inode" and number == "0":
            raise ValueError("recovery file inode is zero")
    return item


def canonical_time(value: object) -> str:
    """Require byte-canonical UTC rather than accepting a normalisable alias.

    Parameters
    ----------
    value : object
        Untrusted decoded field or object; validation does not grant execution authority.

    Returns
    -------
    str
        The unchanged canonical UTC spelling, including exact microseconds if present.

    Raises
    ------
    ValueError
        The input violates the exact canonical field or closed schema contract.
    """
    text = require_utc_timestamp(value, "recovery.host_time")
    if value != text:
        raise ValueError("recovery host time is not canonical UTC")
    return text


def principal(value: object) -> str:
    """Require the existing portable authenticated principal grammar.

    Parameters
    ----------
    value : object
        Untrusted decoded field or object; validation does not grant execution authority.

    Returns
    -------
    str
        The portable principal identifier; this grammar check does not authenticate it.

    Raises
    ------
    ValueError
        The input violates the exact canonical field or closed schema contract.
    """
    return require_identifier(value, "recovery.operator_identity")


def removed_bytes(value: object, *, maximum: int) -> bytes:
    """Decode exact standard padded RFC-4648 base64 with no line breaks.

    Parameters
    ----------
    value : object
        Untrusted decoded field or object; validation does not grant execution authority.
    maximum : int
        Inclusive integer or decoded-byte limit for the selected schema field.

    Returns
    -------
    bytes
        Strict padded base64-decoded bytes within the selected limit.

    Raises
    ------
    ValueError
        The input violates the exact canonical field or closed schema contract.
    """
    if not isinstance(value, str) or not value.isascii():
        raise ValueError("recovery removed bytes must be ASCII base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("recovery removed bytes are invalid base64") from exc
    if not 1 <= len(decoded) <= maximum or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("recovery removed bytes are not canonical base64")
    return decoded


def canonical_object_bytes(value: Mapping[str, object]) -> bytes:
    """Encode a schema-checked object to exact PCS-CANON-1 UTF-8 bytes.

    Parameters
    ----------
    value : Mapping[str, object]
        Untrusted decoded field or object; validation does not grant execution authority.

    Returns
    -------
    bytes
        Deterministic PCS-CANON-1 UTF-8; schema validation is the caller's duty.

    Raises
    ------
    ValueError
        The input violates the exact canonical field or closed schema contract.
    """
    return canonical_journal_json_v2(dict(value))


def parse_canonical_object_bytes(data: bytes) -> dict[str, object]:
    """Reject duplicate keys, noncanonical JSON and non-object evidence.

    Parameters
    ----------
    data : bytes
        Exact canonical UTF-8 evidence bytes; whitespace and duplicate-key aliases refuse.

    Returns
    -------
    dict[str, object]
        Decoded canonical object with unique keys.

    Raises
    ------
    ValueError
        The input violates the exact canonical field or closed schema contract.
    """
    try:
        decoded = project_registry_strict_json(data)
        encoded = canonical_journal_json_v2(decoded)
    except (ProjectRegistryInvalid, ValueError, UnicodeEncodeError) as exc:
        raise ValueError("recovery evidence JSON is invalid") from exc
    if encoded != data or not isinstance(decoded, dict):
        raise ValueError("recovery evidence bytes are not a canonical object")
    return cast(dict[str, object], decoded)
