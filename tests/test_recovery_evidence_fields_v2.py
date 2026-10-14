# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — canonical recovery evidence field boundary
"""Challenge exact integer, identity and canonical-byte public field contracts."""

from __future__ import annotations

import pytest

from rigor_foundry.models import canonical_digest
from rigor_foundry.recovery_evidence_fields_v2 import (
    bounded_int,
    canonical_object_bytes,
    closed_object,
    identity,
    parse_canonical_object_bytes,
    removed_bytes,
)


@pytest.mark.parametrize("value", [True, False, 1.0, "1", -1, 2**53])
def test_integer_field_refuses_noninteger_and_unsafe_range(value: object) -> None:
    """Boolean aliases and values beyond exact JSON integer range refuse."""
    with pytest.raises(ValueError, match="range"):
        bounded_int(value, minimum=0)


def test_integer_and_closed_object_preserve_exact_input() -> None:
    """Endpoints remain exact and a closed object does not normalise its keys."""
    assert bounded_int(0, minimum=0) == 0
    assert bounded_int(2**53 - 1, minimum=0) == 2**53 - 1
    value: dict[str, object] = {"tail": 1}
    assert closed_object(value, frozenset({"tail"}), "intent") is value
    for invalid in ({}, {"tail": 1, "extra": 2}, [1]):
        with pytest.raises(ValueError, match="fields differ"):
            closed_object(invalid, frozenset({"tail"}), "intent")


def test_root_path_identity_retains_decimal_strings() -> None:
    """The root path has one canonical digest; device zero is not an alias."""
    value: dict[str, object] = {
        "path": "/",
        "path_digest": canonical_digest("/"),
        "device": "0",
        "inode": "1",
    }
    assert identity(value) is value


@pytest.mark.parametrize("data", [b'{"x":1,"x":2}', b'{"x":NaN}', b"\xff", b"[]", b'{"x": 1}'])
def test_object_parser_refuses_ambiguous_or_noncanonical_bytes(data: bytes) -> None:
    """Duplicate keys, nonfinite values, invalid UTF-8 and spacing refuse."""
    with pytest.raises(ValueError):
        parse_canonical_object_bytes(data)


def test_canonical_bytes_roundtrip_without_schema_authority() -> None:
    """Generic object encoding is exact but cannot establish a recovery domain."""
    value: dict[str, object] = {"removed": "eA==", "count": 1}
    assert canonical_object_bytes(value) == b'{"count":1,"removed":"eA=="}'
    assert parse_canonical_object_bytes(canonical_object_bytes(value)) == value


@pytest.mark.parametrize("value", ["eB==", "eA===", "eA==\n", "eA==eA==", ""])
def test_base64_refuses_unused_bits_and_encoding_aliases(value: str) -> None:
    """Valid-looking padding and nonzero unused bits cannot rename captured bytes."""
    with pytest.raises(ValueError):
        removed_bytes(value, maximum=1)
