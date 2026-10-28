# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — closed source reference tests
"""Exercise exact reference identities without appointing a source resolver."""

from __future__ import annotations

from dataclasses import replace

import pytest

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.typed_object_reference import TypedObjectRef1


def reference(
    kind: str = "task-definition",
    version: str = "1.0",
    identity: str = "task",
    digest: str = "a" * 64,
) -> TypedObjectRef1:
    """Build a complete supported metadata reference for public-boundary cases."""
    return TypedObjectRef1.build(
        kind=kind, format_version=version, object_id=identity, object_digest=digest
    )


@pytest.mark.parametrize(
    ("kind", "version"),
    [
        ("rule-corpus-ratification", "1.0"),
        ("rule-corpus-acceptance", "1.0"),
        ("evidence-reference", "2.0"),
        ("evidence-reference", "1.0"),
        ("review-attestation", "2.0"),
        ("standard-pack", "2.0"),
        ("evidence-contract", "2.0"),
        ("evidence-contract", "1.0"),
        ("semantic-decision", "1.0"),
        ("review-policy", "1.0"),
        ("adapter-lock", "1.0"),
        ("reviewer-identity-policy", "semantic-reviewer-identity-policy.v1"),
        ("control-definition", "2.0"),
        ("control-definition", "1.0"),
        ("authority-clause", "2.0"),
        ("freshness-policy", "2.0"),
        ("task-definition", "1.0"),
        ("context-producer-contract", "1.0"),
        ("repository-state", "1.0"),
        ("inventory-domain", "1.0"),
        ("inventory-baseline", "1.0"),
        ("work-task", "1.0"),
        ("work-record", "1.0"),
        ("work-closure", "1.0"),
        ("source-capture", "1.0"),
        ("native-source-pin", "native-source-pin.v1"),
        ("discovery-source-receipt", "discovery-source-closure.v1"),
        ("project-registry", "gotm-project-registry.v1"),
        ("project-registry", "project-registry.v2"),
    ],
)
def test_supported_pairs_round_trip_with_complete_digest(kind: str, version: str) -> None:
    """Each actually implemented source format retains exact kind/version identity."""
    actual = reference(kind, version)
    assert TypedObjectRef1.from_dict(actual.to_dict()) == actual
    body = actual.to_dict()
    assert body.pop("ref_digest") == canonical_digest(body)
    assert not {"path", "url", "resolver", "installed", "guard_admissible"}.intersection(body)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("kind", "unknown"),
        ("kind", "work-record-v2"),
        ("format_version", "2.0"),
        ("format_version", 1),
        ("object_id", "bad identity"),
        ("object_digest", "a" * 40),
        ("schema_version", "2.0"),
        ("object_kind", "other"),
    ],
)
def test_rehashed_unknown_or_invalid_fields_refuse(field: str, value: object) -> None:
    """Rehashing cannot enroll an unsupported format or normalize an identity."""
    body = reference().to_dict()
    body.pop("ref_digest")
    body[field] = value
    with pytest.raises(ValueError):
        TypedObjectRef1.from_dict({**body, "ref_digest": canonical_digest(body)})


def test_direct_forgery_and_closed_fields_refuse() -> None:
    """Public serialization rechecks direct objects, missing fields and digest changes."""
    actual = reference()
    data = actual.to_dict()
    for bad in [None, {**data, "path": "/caller"}, {k: v for k, v in data.items() if k != "kind"}]:
        with pytest.raises(ValueError):
            TypedObjectRef1.from_dict(bad)
    with pytest.raises(ValueError, match="differs"):
        replace(actual, object_digest="b" * 64)
    object.__setattr__(actual, "ref_digest", "0" * 64)
    with pytest.raises(ValueError, match="differs"):
        actual.to_dict()
