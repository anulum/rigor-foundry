# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — actual content count extractor tests
"""Count decoded bytes through the public fixed extractor."""

from __future__ import annotations

import base64
import json

import pytest

from rigor_foundry.tier0_builtin.extract_content_byte_count import extract


@pytest.mark.parametrize("content", [b"", b"\x00\xff", "žluťoučký".encode()])
def test_count_is_decoded_byte_length_not_declaration(content: bytes) -> None:
    """An untrusted declared zero cannot replace the actual binary length."""
    payload = json.dumps(
        {
            "operation_id": "local-file-write.atomic-replace",
            "path": "/srv/result.bin",
            "content_b64": base64.b64encode(content).decode("ascii"),
            "declared": {
                "target_ref": {"form": "path", "value": "/srv/result.bin"},
                "byte_count": 0,
                "operation_variant": "replace-or-create",
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    assert extract(payload) == len(content)


def test_invalid_request_cannot_supply_a_count() -> None:
    """The extractor validates the complete wire before returning a value."""
    with pytest.raises(ValueError):
        extract(b'{"declared":{"byte_count":42}}')
