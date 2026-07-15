# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — audit protocol primitive tests
"""Verify canonical digests, strict fields, and the compatibility facade."""

import hashlib

import pytest

from rigor_foundry import models
from rigor_foundry.audit_primitives import (
    AUDIT_DOMAINS,
    POLICY_SCHEMA_VERSION,
    REVIEW_SCHEMA_VERSION,
    SCANNER_VERSION,
    SCHEMA_VERSION,
    canonical_digest,
    require_integer,
    require_mapping,
    require_string,
    require_string_tuple,
)


def test_canonical_digest_is_order_independent_and_protocol_stable() -> None:
    """Canonical JSON ordering produces one independently derived digest."""
    expected = hashlib.sha256(b'{"a":1,"b":2}').hexdigest()
    assert canonical_digest({"b": 2, "a": 1}) == expected
    assert canonical_digest({"a": 1, "b": 2}) == expected


def test_strict_field_validators_reject_ambiguous_values() -> None:
    """Protocol fields reject Python values that JSON could blur."""
    with pytest.raises(ValueError, match="string keys"):
        require_mapping({1: "value"}, "record")
    with pytest.raises(ValueError, match="non-empty string"):
        require_string(" ", "record.name")
    with pytest.raises(ValueError, match="integer"):
        require_integer(True, "record.count")
    with pytest.raises(ValueError, match="string array"):
        require_string_tuple(("value",), "record.names")


def test_models_facade_preserves_protocol_primitive_exports() -> None:
    """The module split keeps the original public import surface intact."""
    assert AUDIT_DOMAINS
    assert len(AUDIT_DOMAINS) == len(set(AUDIT_DOMAINS))
    assert SCHEMA_VERSION == "1.1"
    assert POLICY_SCHEMA_VERSION == "1.0"
    assert REVIEW_SCHEMA_VERSION == "1.0"
    assert SCANNER_VERSION == "0.1.0"
    assert models.AUDIT_DOMAINS is AUDIT_DOMAINS
    assert models.canonical_digest is canonical_digest
