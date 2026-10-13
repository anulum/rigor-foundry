# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — atomic invocation owner tests
"""Exercise the public parser's wire boundary and independent declarations."""

from __future__ import annotations

import base64
import json
from typing import cast

import pytest

from rigor_foundry.tier0_builtin.atomic_file_replace_invocation import (
    AtomicFileReplaceInvocationV2,
)


def _payload() -> bytes:
    """Encode actual binary content and deliberately different declarations."""
    return json.dumps(
        {
            "operation_id": "local-file-write.atomic-replace",
            "path": "/srv/actual.bin",
            "content_b64": base64.b64encode(bytes(range(256))).decode("ascii"),
            "declared": {
                "target_ref": {"form": "path", "value": "/srv/declared.bin"},
                "byte_count": 0,
                "operation_variant": "append",
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def test_parser_preserves_actual_bytes_and_unchecked_declarations() -> None:
    """Parsing preserves discrepancies for the later extraction comparison."""
    payload = _payload()
    parsed = AtomicFileReplaceInvocationV2.from_bytes(payload)
    assert parsed.payload == payload
    assert parsed.path == "/srv/actual.bin"
    assert parsed.content == bytes(range(256))
    assert parsed.declared_target_ref == {"form": "path", "value": "/srv/declared.bin"}
    assert parsed.declared_byte_count == 0
    assert parsed.declared_operation_variant == "append"


@pytest.mark.parametrize("payload", [b"", b"{}", b"[]", b'{"path":"/a","path":"/b"}'])
def test_closed_wire_refuses_missing_fields_and_duplicate_keys(payload: bytes) -> None:
    """Strict decoding rejects an incomplete or ambiguous request."""
    with pytest.raises(ValueError):
        AtomicFileReplaceInvocationV2.from_bytes(payload)


def test_text_alias_and_noncanonical_wire_refuse() -> None:
    """The parser accepts bytes with a single canonical JSON spelling."""
    with pytest.raises(ValueError, match="must be bytes"):
        AtomicFileReplaceInvocationV2.from_bytes(cast(bytes, _payload().decode()))
    with pytest.raises(ValueError, match="canonical JSON"):
        AtomicFileReplaceInvocationV2.from_bytes(b" " + _payload())
