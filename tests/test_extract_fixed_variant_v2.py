# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — fixed operation variant tests
"""The fixed extractor derives its variant from the operation contract."""

from __future__ import annotations

import json

import pytest

from rigor_foundry.tier0_builtin.extract_fixed_variant import extract


@pytest.mark.parametrize("declared", ["append", "truncate", "replace-or-create"])
def test_variant_is_fixed_independently_of_declaration(declared: str) -> None:
    """A valid invocation cannot change the operation by declaring a variant."""
    payload = json.dumps(
        {
            "operation_id": "local-file-write.atomic-replace",
            "path": "/srv/result.bin",
            "content_b64": "",
            "declared": {
                "target_ref": {"form": "path", "value": "/srv/result.bin"},
                "byte_count": 0,
                "operation_variant": declared,
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    assert extract(payload) == "replace-or-create"


def test_wrong_operation_cannot_obtain_the_fixed_variant() -> None:
    """The public extractor refuses a request outside its fixed operation."""
    with pytest.raises(ValueError):
        extract(b'{"operation_id":"append"}')
