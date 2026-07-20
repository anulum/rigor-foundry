# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — optional CRA policy extension tests
"""Verify schema-1.3 inertness and strict schema-1.4 CRA activation."""

from __future__ import annotations

import pytest

from rigor_foundry.cra_policy import CraPolicy
from rigor_foundry.ignored_inventory import IgnoredInventoryDeclaration
from rigor_foundry.models import AuditPolicy


def required_policy() -> CraPolicy:
    """Return one explicit required CRA policy."""
    return CraPolicy.build(
        applicability="required",
        rationale="Manufacturer declares this product in CRA audit scope.",
        product_key="widget",
        disclosure_policy_path="SECURITY.md",
        state_evidence_id="cra-state",
    )


def test_policy_absence_is_byte_compatible_and_required_scope_is_digest_bound() -> None:
    """Legacy policy stays 1.3 while activated CRA policy uses strict 1.4."""
    legacy = AuditPolicy()
    assert legacy.to_dict()["schema_version"] == "1.3"
    assert "cra" not in legacy.to_dict()
    assert AuditPolicy.from_dict(legacy.to_dict()) == legacy

    cra = required_policy()
    policy = AuditPolicy(
        ignored_inventory=(
            IgnoredInventoryDeclaration("cra-state", ".rigor/cra", "directory-sha256"),
        ),
        cra=cra,
    )
    assert policy.to_dict()["schema_version"] == "1.4"
    assert AuditPolicy.from_dict(policy.to_dict()) == policy
    changed = cra.to_dict()
    changed["product_key"] = "other"
    with pytest.raises(ValueError, match="digest"):
        CraPolicy.from_dict(changed)


def test_not_applicable_is_inert_and_required_scope_rejects_ambiguous_evidence() -> None:
    """Not-applicable carries no product state; required scope binds exact ignored root."""
    inactive = CraPolicy.build(
        applicability="not-applicable",
        rationale="No product with digital elements is placed on the market.",
        product_key=None,
        disclosure_policy_path=None,
        state_evidence_id=None,
    )
    policy = AuditPolicy(cra=inactive)
    assert AuditPolicy.from_dict(policy.to_dict()) == policy
    with pytest.raises(ValueError, match="must not declare"):
        CraPolicy.build(
            applicability="not-applicable",
            rationale="out",
            product_key="widget",
            disclosure_policy_path=None,
            state_evidence_id=None,
        )
    with pytest.raises(ValueError, match="bind state_evidence_id"):
        AuditPolicy.from_dict(AuditPolicy(cra=required_policy()).to_dict())
    presence_only = AuditPolicy(
        ignored_inventory=(IgnoredInventoryDeclaration("cra-state", ".rigor/cra", "presence"),),
        cra=required_policy(),
    )
    with pytest.raises(ValueError, match="directory-sha256"):
        AuditPolicy.from_dict(presence_only.to_dict())


@pytest.mark.parametrize(
    "changes",
    [
        {"applicability": "unknown"},
        {"product_key": None},
        {"disclosure_policy_path": "/tmp/policy"},
        {"disclosure_policy_path": "docs/../SECURITY.md"},
        {"state_evidence_id": "bad id"},
    ],
)
def test_required_policy_rejects_invalid_fields(changes: dict[str, object]) -> None:
    """Activation fields are exact and portable."""
    values: dict[str, object] = {
        "applicability": "required",
        "rationale": "scope",
        "product_key": "widget",
        "disclosure_policy_path": "SECURITY.md",
        "state_evidence_id": "cra-state",
    }
    values.update(changes)
    with pytest.raises(ValueError):
        CraPolicy.build(**values)  # type: ignore[arg-type]


def test_policy_schema_versions_reject_unknown_or_mixed_shapes() -> None:
    """Unknown versions and cross-version fields fail migration closed."""
    legacy = AuditPolicy().to_dict()
    legacy["schema_version"] = "9.0"
    with pytest.raises(ValueError):
        AuditPolicy.from_dict(legacy)
    mixed = AuditPolicy().to_dict()
    mixed["cra"] = required_policy().to_dict()
    with pytest.raises(ValueError, match="fields"):
        AuditPolicy.from_dict(mixed)
    malformed = required_policy().to_dict()
    malformed["schema_version"] = "9.0"
    with pytest.raises(ValueError, match="schema_version"):
        CraPolicy.from_dict(malformed)
