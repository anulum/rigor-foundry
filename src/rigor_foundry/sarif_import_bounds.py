# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — bounded and typed reading of imported SARIF values
"""Read what a SARIF producer wrote within fixed bounds and its SARIF types, or skip it.

One rule governs every result field: an absent field takes its SARIF default, and a present
field must have its SARIF type, or the result is skipped with a reason. An explicit JSON
``null`` is present, so it is skipped wherever SARIF names a type. Values that exceed a
bound are kept by the SHA-256 of their canonical JSON instead of their content.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


class ResultSkipped(ValueError):
    """One result that cannot be recorded, with a stable reason code."""

    def __init__(self, reason: str) -> None:
        """Record the reason code.

        Parameters
        ----------
        reason : str
            Stable machine-readable skip code.
        """
        super().__init__(reason)
        self.reason = reason


def json_bytes(value: object) -> bytes:
    """Return the canonical JSON bytes that bounds and digests are measured on.

    Parameters
    ----------
    value : object
        A decoded JSON value.

    Returns
    -------
    bytes
        Sorted-key compact UTF-8 JSON.
    """
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def bounded_text(text: str, limit: int) -> tuple[str, bool]:
    """Return ``text`` cut to at most ``limit`` UTF-8 bytes and whether it was cut.

    Parameters
    ----------
    text : str
        The producer's text.
    limit : int
        The byte bound.

    Returns
    -------
    tuple[str, bool]
        The kept text, never ending in a split character, and whether it was cut.
    """
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text, False
    return encoded[:limit].decode("utf-8", errors="ignore"), True


def bounded_value(value: object, limit: int) -> tuple[object | None, str, bool]:
    """Return a JSON value kept verbatim within ``limit`` bytes, its digest and truncation.

    Parameters
    ----------
    value : object
        A decoded JSON value.
    limit : int
        The byte bound of its canonical JSON.

    Returns
    -------
    tuple[object | None, str, bool]
        The value or None past the bound, the digest of its canonical JSON, and whether it
        was dropped.
    """
    digest = hashlib.sha256(json_bytes(value)).hexdigest()
    if len(json_bytes(value)) <= limit:
        return value, digest, False
    return None, digest, True


def present_field(
    record: dict[str, Any], key: str, expected: type, reason: str, default: Any
) -> Any:
    """Return one field, its SARIF default when absent, or skip the result when mistyped.

    Parameters
    ----------
    record : dict[str, Any]
        The SARIF object holding the field.
    key : str
        The field name.
    expected : type
        The field's SARIF JSON type.
    reason : str
        The skip reason when the field is present with another type, ``null`` included.
    default : Any
        The SARIF default of an absent field.

    Returns
    -------
    Any
        The present value or the default.

    Raises
    ------
    ResultSkipped
        With ``reason`` when the present value is not of ``expected`` type.
    """
    if key not in record:
        return default
    value = record[key]
    if not isinstance(value, expected):
        raise ResultSkipped(reason)
    return value
