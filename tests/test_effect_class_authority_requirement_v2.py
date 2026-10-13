# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — v2 effect-class authority requirement tests
"""Check canonical requirement lists and scope-independent membership."""

import json
from typing import cast

import pytest

from rigor_foundry.effect_class_authority_requirement_v2 import (
    AUTHORITY_REQUIREMENT_SCHEMA_V2,
    DEFAULT_ENFORCED_REQUIRED_V2,
    EffectClassAuthorityRequirementV2,
)
from rigor_foundry.effect_journal_records_v2 import canonical_journal_json_v2
from rigor_foundry.models import canonical_digest


def _wire(classes: list[object], **extra: object) -> bytes:
    """Encode an explicit class list with optional malformed fixture fields."""
    return canonical_journal_json_v2(
        {"schema": AUTHORITY_REQUIREMENT_SCHEMA_V2, "enforced_required": classes, **extra}
    )


def test_default_is_a_canonical_proposal_only() -> None:
    """Preserve the canonical default class list without treating parsed requirement data as selection."""
    value = EffectClassAuthorityRequirementV2.build_default()
    assert value.enforced_required == DEFAULT_ENFORCED_REQUIRED_V2
    assert value.body_bytes == _wire(list(DEFAULT_ENFORCED_REQUIRED_V2))
    assert value.requirement_digest == canonical_digest(json.loads(value.body_bytes))
    assert value.requires_enforced("external-send")
    assert not value.requires_enforced("compute-job")
    with pytest.raises(ValueError, match="unknown effect class"):
        value.requires_enforced("arbitrary")


@pytest.mark.parametrize(
    "payload",
    [
        b"not json",
        b"{}",
        b'{"enforced_required":[],"schema":"rigor.effect-class-authority-requirement.v2","x":1}',
        _wire([], schema="wrong"),
        canonical_journal_json_v2(
            {"schema": AUTHORITY_REQUIREMENT_SCHEMA_V2, "enforced_required": "read"}
        ),
        _wire(["unknown"]),
        _wire([True]),
        _wire(["read", "read"]),
        _wire(["read", "cloud-resource"]),
        b'{ "enforced_required":[],"schema":"rigor.effect-class-authority-requirement.v2"}',
    ],
)
def test_invalid_wires_refuse(payload: bytes) -> None:
    """Reject malformed or noncanonical authority-requirement payloads through the public parser."""
    with pytest.raises(ValueError):
        EffectClassAuthorityRequirementV2.from_bytes(payload)


def test_any_sorted_subset_is_valid_without_implying_selection() -> None:
    """Accept canonical subsets as data without granting authority or selecting an operative policy."""
    value = EffectClassAuthorityRequirementV2.from_bytes(_wire([]))
    assert value.enforced_required == ()
    assert not value.requires_enforced("external-send")
    assert EffectClassAuthorityRequirementV2.from_bytes(_wire(["read"])).enforced_required == (
        "read",
    )


def test_non_bytes_refuse() -> None:
    """Reject non-byte authority-requirement input instead of coercing its type."""
    with pytest.raises(ValueError, match="must be bytes"):
        EffectClassAuthorityRequirementV2.from_bytes(cast(bytes, "{}"))
