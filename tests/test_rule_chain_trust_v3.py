# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — selected v3 role-policy tests
"""Exercise complete original policy ownership and v3 role separation."""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest
from signing_fixtures import public_key_hex

from rigor_foundry.models import canonical_digest
from rigor_foundry.rule_chain_trust_v3 import (
    RuleObjectKindV3,
    TrustRolesV3,
    rule_chain_v3_signature_boundary,
)
from rigor_foundry.trust import TrustedPublicKey
from rigor_foundry.verification_policy import OfflineTrustPolicy, VerificationKeyPolicy

KINDS: tuple[RuleObjectKindV3, ...] = (
    "standard-pack",
    "project-profile",
    "effective-profile-lock",
    "rule-corpus-author",
    "rule-corpus-acceptance",
)
ATTRIBUTES = (
    "pack_issuers",
    "project_selectors",
    "lock_resolvers",
    "semantic_authors",
    "semantic_reviewers",
)


def role_policy(
    key_id: str, *, identity: str | None = None, revoked_at: str = "", material: str | None = None
) -> OfflineTrustPolicy:
    """Construct a real deterministic TEST public-key policy with original owners."""
    return OfflineTrustPolicy.build(
        (
            VerificationKeyPolicy.build(
                key=TrustedPublicKey.build(
                    key_id=key_id, public_key_hex=public_key_hex(material or key_id)
                ),
                valid_from="2026-10-01T00:00:00Z",
                valid_until="2026-12-01T00:00:00Z",
                revoked_at=revoked_at,
                enrolled_identity=identity,
            ),
        )
    )


def role_inputs() -> dict[str, OfflineTrustPolicy]:
    """Select all five separate TEST roles and actual semantic enrollment records."""
    return {
        "pack_issuers": role_policy("v3-pack"),
        "project_selectors": role_policy("v3-selector"),
        "lock_resolvers": role_policy("v3-resolver"),
        "semantic_authors": role_policy("v3-author", identity="example/author"),
        "semantic_reviewers": role_policy("v3-reviewer", identity="example/reviewer"),
    }


def selected_roles() -> TrustRolesV3:
    """Return an actual fully validated five-role selection for TEST signatures."""
    return TrustRolesV3.build(**role_inputs())


@pytest.mark.parametrize("index", range(5))
def test_closed_role_table_and_complete_selected_digest(index: int) -> None:
    """Each supported signature kind resolves its own original policy and new domain."""
    roles = selected_roles()
    kind, version, role, domain = rule_chain_v3_signature_boundary(KINDS[index])
    assert kind == KINDS[index]
    assert version == ("3.0", "3.0", "3.0", "1.0", "1.0")[index]
    assert (
        role
        == (
            "pack-issuer",
            "project-selector",
            "lock-resolver",
            "semantic-author",
            "semantic-reviewer",
        )[index]
    )
    assert (
        domain
        == (
            "rigor-foundry.standard-pack.v3",
            "rigor-foundry.project-profile-selection.v3",
            "rigor-foundry.effective-profile-lock.v3",
            "rigor-foundry.rule-corpus-author.v3",
            "rigor-foundry.rule-corpus-acceptance.v3",
        )[index]
    )
    assert roles.policy_for(kind) == role_inputs()[ATTRIBUTES[index]]
    assert roles.trust_roles_digest == canonical_digest(
        {
            "schema_version": "3.0",
            **{name: policy.policy_digest for name, policy in role_inputs().items()},
        }
    )
    inputs = role_inputs()
    current = inputs[ATTRIBUTES[index]].keys[0]
    inputs[ATTRIBUTES[index]] = role_policy(
        current.key.key_id, identity=current.enrolled_identity, revoked_at="2026-11-01T00:00:00Z"
    )
    assert TrustRolesV3.build(**inputs).trust_roles_digest != roles.trust_roles_digest


def test_rotation_binds_all_original_keys_and_canonical_order() -> None:
    """A second actual key is retained, and original sorted ownership determines identity."""
    inputs = role_inputs()
    first = inputs["pack_issuers"].keys[0]
    second = role_policy("v3-pack-rotation").keys[0]
    inputs["pack_issuers"] = OfflineTrustPolicy.build((second, first))
    roles = TrustRolesV3.build(**inputs)
    assert roles.pack_issuers.keys == tuple(
        sorted((first, second), key=lambda key: key.key.key_id)
    )
    assert roles.trust_roles_digest != selected_roles().trust_roles_digest
    inputs["pack_issuers"] = OfflineTrustPolicy.build((first, second))
    assert TrustRolesV3.build(**inputs) == roles


@pytest.mark.parametrize(
    "fault",
    [
        "duplicate-id",
        "duplicate-material",
        "wrong-semantic-version",
        "wrong-parent-version",
        "shared-seat",
        "corrupt-policy",
        "foreign-type",
    ],
)
def test_original_policy_violations_cannot_enter_v3_roles(fault: str) -> None:
    """Role titles and new enclosing versions cannot bypass original key ownership."""
    inputs = role_inputs()
    if fault == "duplicate-id":
        inputs["project_selectors"] = inputs["pack_issuers"]
    elif fault == "duplicate-material":
        inputs["project_selectors"] = role_policy("alias", material="v3-pack")
    elif fault == "wrong-semantic-version":
        inputs["semantic_authors"] = role_policy("missing-identity")
    elif fault == "wrong-parent-version":
        inputs["pack_issuers"] = role_policy("identified-parent", identity="example/parent")
    elif fault == "shared-seat":
        inputs["semantic_reviewers"] = role_policy("same-seat", identity="EXAMPLE/AUTHOR")
    elif fault == "corrupt-policy":
        inputs["lock_resolvers"] = replace(inputs["lock_resolvers"], policy_digest="a" * 64)
    else:
        inputs["lock_resolvers"] = cast(OfflineTrustPolicy, "caller-policy")
    with pytest.raises(ValueError):
        TrustRolesV3.build(**inputs)


@pytest.mark.parametrize(
    "kind", ["clause-semantics-set", "audit-receipt", "STANDARD-PACK", "", None]
)
def test_old_alias_and_unknown_kind_have_no_selected_policy(kind: object) -> None:
    """Neither old semantic-kind names nor malformed identities borrow a new role."""
    with pytest.raises(ValueError):
        rule_chain_v3_signature_boundary(kind)
    with pytest.raises(ValueError):
        selected_roles().policy_for(cast(RuleObjectKindV3, kind))
