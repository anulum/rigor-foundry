# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — policy parser budget tests
"""Exercise explicit policy budget records through their public constructors."""

from __future__ import annotations

from dataclasses import replace

import pytest

from rigor_foundry.audit_primitives import canonical_digest
from rigor_foundry.policy_read_budget import PolicyReadBudget1


def budget() -> PolicyReadBudget1:
    """Return explicit test ceilings without a production default."""
    return PolicyReadBudget1.build(
        max_document_bytes=1024,
        max_source_bytes=1024,
        max_total_source_bytes=2048,
        max_sources=4,
        max_rules=8,
        max_references=16,
        max_depth=8,
    )


def test_round_trip_and_header_bound_identity() -> None:
    """Exact fields and headers participate in deterministic budget identity."""
    value = budget()
    data = value.to_dict()
    assert PolicyReadBudget1.from_dict(data) == value
    assert data["schema_version"] == "1.0"
    assert data["object_kind"] == "policy-read-budget"
    assert len(data) == 10
    assert data.pop("budget_digest") == canonical_digest(data)
    assert replace(value, max_depth=7, budget_digest=canonical_digest({**data, "max_depth": 7}))


@pytest.mark.parametrize(
    ("name", "ceiling"),
    [
        ("max_document_bytes", 8 * 1024 * 1024),
        ("max_source_bytes", 8 * 1024 * 1024),
        ("max_total_source_bytes", 64 * 1024 * 1024),
        ("max_sources", 4096),
        ("max_rules", 16384),
        ("max_references", 65536),
        ("max_depth", 32),
    ],
)
def test_every_limit_accepts_its_ceiling_and_refuses_overflow(name: str, ceiling: int) -> None:
    """Allocation ceilings cannot be raised by recomputing a valid digest."""
    data = budget().to_dict()
    data.pop("budget_digest")
    data[name] = ceiling
    assert (
        getattr(
            PolicyReadBudget1.from_dict({**data, "budget_digest": canonical_digest(data)}), name
        )
        == ceiling
    )
    data[name] = ceiling + 1
    with pytest.raises(ValueError, match="ceiling"):
        PolicyReadBudget1.from_dict({**data, "budget_digest": canonical_digest(data)})


@pytest.mark.parametrize(
    "name",
    [
        "max_document_bytes",
        "max_source_bytes",
        "max_total_source_bytes",
        "max_sources",
        "max_rules",
        "max_references",
        "max_depth",
    ],
)
@pytest.mark.parametrize("invalid", [0, -1, True, 1.5, "1", None])
def test_limits_reject_nonpositive_or_coerced_values(name: str, invalid: object) -> None:
    """Every input limit is a positive non-Boolean integer."""
    data = budget().to_dict()
    data[name] = invalid
    with pytest.raises(ValueError):
        PolicyReadBudget1.from_dict(data)


@pytest.mark.parametrize("field", ["schema_version", "object_kind"])
def test_record_identity_is_closed(field: str) -> None:
    """Rehashed unsupported headers remain unsupported."""
    data = budget().to_dict()
    data.pop("budget_digest")
    data[field] = "other"
    with pytest.raises(ValueError, match="unsupported"):
        PolicyReadBudget1.from_dict({**data, "budget_digest": canonical_digest(data)})


def test_missing_extra_nonmapping_and_tampered_records_refuse() -> None:
    """No fallback, extension bag or direct forged digest is accepted."""
    data = budget().to_dict()
    for invalid in [
        None,
        {**data, "extra": 1},
        {k: v for k, v in data.items() if k != "max_depth"},
    ]:
        with pytest.raises(ValueError):
            PolicyReadBudget1.from_dict(invalid)
    with pytest.raises(ValueError, match="digest"):
        replace(budget(), budget_digest="0" * 64)
    with pytest.raises(ValueError):
        replace(budget(), max_depth=0)


def test_public_serialization_rechecks_a_bypassed_frozen_instance() -> None:
    """A direct mutation cannot cross a subsequent consumer boundary."""
    value = budget()
    object.__setattr__(value, "max_depth", 0)
    with pytest.raises(ValueError):
        value.to_dict()
    value = budget()
    object.__setattr__(value, "budget_digest", "0" * 64)
    with pytest.raises(ValueError, match="digest"):
        value.to_dict()
