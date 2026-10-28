# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — real v3 signature and lifecycle tests
"""Exercise actual five-role Ed25519 verification, selected policies and replay refusal."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from typing import cast

import pytest
from signing_fixtures import sign_message
from test_rule_chain_trust_v3 import ATTRIBUTES, KINDS, role_inputs, role_policy, selected_roles

from rigor_foundry.models import canonical_digest
from rigor_foundry.policy_read_budget import PolicyReadBudget1
from rigor_foundry.rule_chain_trust_v3 import (
    RuleObjectKindV3,
    TrustRolesV3,
    rule_chain_v3_signature_boundary,
)
from rigor_foundry.signed_rule_chain_v2 import RuleChainV2Signature, rule_chain_v2_payload_digest
from rigor_foundry.signed_rule_chain_v3 import RuleChainV3Signature, rule_chain_v3_payload_digest
from rigor_foundry.verification_policy import OfflineTrustPolicy

BODY = canonical_digest({"fixture": "signature-primitive-authenticity-only"})
SIGNED = "2026-10-20T00:00:00Z"
NOW = datetime(2026, 10, 28, tzinfo=UTC)
BUDGET = PolicyReadBudget1.build(
    max_document_bytes=10000,
    max_source_bytes=10000,
    max_total_source_bytes=10000,
    max_sources=10,
    max_rules=10,
    max_references=100,
    max_depth=10,
)


def signed_fixture(
    kind: RuleObjectKindV3,
    *,
    key_id: str | None = None,
    signed_at: str = SIGNED,
    signing_domain: str | None = None,
) -> RuleChainV3Signature:
    """Sign an actual typed digest with a deterministic TEST key and actual crypto."""
    _, version, _, domain = rule_chain_v3_signature_boundary(kind)
    key = key_id or selected_roles().policy_for(kind).keys[0].key.key_id
    payload = rule_chain_v3_payload_digest(
        object_kind=kind, body_schema_version=version, body_digest=BODY, signed_at=signed_at
    )
    return RuleChainV3Signature.build(
        object_kind=kind,
        body_schema_version=version,
        key_id=key,
        body_digest=BODY,
        signed_at=signed_at,
        signature_hex=sign_message(key, signing_domain or domain, payload),
        budget=BUDGET,
    )


def verify_fixture(
    signature: RuleChainV3Signature,
    *,
    kind: RuleObjectKindV3 = "standard-pack",
    body: str = BODY,
    roles: TrustRolesV3 | None = None,
    selected_digest: str | None = None,
    now: datetime = NOW,
    budget: PolicyReadBudget1 = BUDGET,
) -> bool:
    """Invoke the public verifier with independently expected type and whole-policy identity."""
    actual = roles or selected_roles()
    return signature.verify(
        object_kind=kind,
        body_schema_version=rule_chain_v3_signature_boundary(kind)[1],
        body_digest=body,
        roles=actual,
        trust_roles_digest=selected_digest or actual.trust_roles_digest,
        now=now,
        budget=budget,
    )


@pytest.mark.parametrize("kind", KINDS)
def test_each_supported_kind_roundtrips_and_verifies_actual_bytes(kind: RuleObjectKindV3) -> None:
    """Each distinct domain verifies its own kind, owning body version and real key."""
    signature = signed_fixture(kind)
    wire = signature.to_dict(budget=BUDGET)
    assert len(wire) == 12
    assert wire["schema_version"] == "3.0"
    parsed = RuleChainV3Signature.from_dict(wire, budget=BUDGET)
    assert parsed == signature and verify_fixture(parsed, kind=kind)
    assert not verify_fixture(parsed, kind=kind, body="b" * 64)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("signing_kind", KINDS)
def test_full_actual_five_role_matrix(
    kind: RuleObjectKindV3, signing_kind: RuleObjectKindV3
) -> None:
    """A valid real signature from another selected role still fails the owning role."""
    key = selected_roles().policy_for(signing_kind).keys[0].key.key_id
    assert verify_fixture(signed_fixture(kind, key_id=key), kind=kind) is (kind == signing_kind)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("instant", ["2026-10-20T00:00:00+00:00", "2026-10-20T00:00:00.000000Z"])
def test_public_utc_aliases_build_canonical_verifiable_roundtrips(
    kind: RuleObjectKindV3, instant: str
) -> None:
    """Accepted UTC aliases retain the actual signed payload in a canonical complete record."""
    canonical = signed_fixture(kind)
    normalized = RuleChainV3Signature.build(
        object_kind=kind,
        body_schema_version=canonical.body_schema_version,
        key_id=canonical.key_id,
        body_digest=BODY,
        signed_at=instant,
        signature_hex=canonical.signature_hex,
        budget=BUDGET,
    )
    assert normalized == canonical and normalized.signed_at == SIGNED
    assert normalized.payload_digest == canonical.payload_digest
    assert normalized.signature_hex == canonical.signature_hex
    wire = normalized.to_dict(budget=BUDGET)
    assert wire["signed_at"] == SIGNED
    assert RuleChainV3Signature.from_dict(wire, budget=BUDGET) == canonical
    assert verify_fixture(normalized, kind=kind)
    direct = replace(canonical, signed_at=instant)
    with pytest.raises(ValueError, match="canonical UTC"):
        direct.to_dict(budget=BUDGET)
    assert not verify_fixture(direct, kind=kind)
    wire["signed_at"] = instant
    with pytest.raises(ValueError):
        RuleChainV3Signature.from_dict(wire, budget=BUDGET)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "2.0"),
        ("body_schema_version", "2.0"),
        ("object_kind", "clause-semantics-set"),
        ("algorithm", "ed448"),
        ("signer_role", "semantic-author"),
        ("signature_domain", "rigor-foundry.standard-pack.v2"),
        ("key_id", ""),
        ("body_digest", "c" * 64),
        ("signed_at", "2026-10-21T00:00:00Z"),
        ("payload_digest", "d" * 64),
        ("signature_hex", "A" * 128),
        ("signature_digest", "e" * 64),
    ],
)
def test_complete_wire_mutations_are_refused(field: str, value: str) -> None:
    """Every integrity-bearing wire field is checked with its exact original scalar owner."""
    wire = signed_fixture("standard-pack").to_dict(budget=BUDGET)
    wire[field] = value
    with pytest.raises(ValueError):
        RuleChainV3Signature.from_dict(wire, budget=BUDGET)


def test_closed_wire_and_real_budgets_refuse_partial_or_extra_data() -> None:
    """Whole-record byte/depth limits apply before accepting decoded input or direct data."""
    signature = signed_fixture("standard-pack")
    wire = signature.to_dict(budget=BUDGET)
    with pytest.raises(ValueError):
        RuleChainV3Signature.from_dict({**wire, "extra": "field"}, budget=BUDGET)
    del wire["algorithm"]
    with pytest.raises(ValueError):
        RuleChainV3Signature.from_dict(wire, budget=BUDGET)
    small = PolicyReadBudget1.build(
        max_document_bytes=10,
        max_source_bytes=10000,
        max_total_source_bytes=10000,
        max_sources=10,
        max_rules=10,
        max_references=100,
        max_depth=10,
    )
    with pytest.raises(ValueError):
        signature.to_dict(budget=small)
    assert not verify_fixture(signature, budget=small)
    with pytest.raises(ValueError):
        RuleChainV3Signature.from_dict(
            {"extra": [[]]},
            budget=PolicyReadBudget1.build(
                max_document_bytes=10000,
                max_source_bytes=10000,
                max_total_source_bytes=10000,
                max_sources=10,
                max_rules=10,
                max_references=100,
                max_depth=1,
            ),
        )


@pytest.mark.parametrize(
    "fault",
    [
        "future",
        "expired",
        "before-validity",
        "revoked-at-signing",
        "revoked-now",
        "unknown-key",
        "naive",
        "non-utc",
        "wrong-time-type",
        "bad-crypto",
        "changed-body-kind",
        "forged-metadata",
        "forged-policy-digest",
        "wrong-roles-type",
        "malformed-selected-digest",
    ],
)
def test_lifecycle_type_domain_and_direct_forgery_controls(fault: str) -> None:
    """Current policy and signature checks refuse real lifecycle and forgery failures."""
    signature = signed_fixture("standard-pack")
    roles = selected_roles()
    selected_digest = roles.trust_roles_digest
    now = NOW
    kind: RuleObjectKindV3 = "standard-pack"
    if fault == "future":
        now = datetime(2026, 10, 19, tzinfo=UTC)
    elif fault == "expired":
        now = datetime(2026, 12, 1, tzinfo=UTC)
    elif fault == "before-validity":
        signature = signed_fixture("standard-pack", signed_at="2026-09-30T00:00:00Z")
    elif fault in {"revoked-at-signing", "revoked-now"}:
        inputs = role_inputs()
        inputs["pack_issuers"] = role_policy(
            "v3-pack",
            revoked_at="2026-10-19T00:00:00Z"
            if fault == "revoked-at-signing"
            else "2026-10-27T00:00:00Z",
        )
        roles = TrustRolesV3.build(**inputs)
        selected_digest = roles.trust_roles_digest
    elif fault == "unknown-key":
        signature = signed_fixture("standard-pack", key_id="unknown-real-test-key")
    elif fault == "naive":
        now = datetime(2026, 10, 28)
    elif fault == "non-utc":
        now = datetime(2026, 10, 28, tzinfo=timezone(timedelta(hours=1)))
    elif fault == "wrong-time-type":
        now = cast(datetime, "2026-10-28T00:00:00Z")
    elif fault == "bad-crypto":
        signature = signed_fixture(
            "standard-pack", signing_domain="rigor-foundry.standard-pack.v2"
        )
    elif fault == "changed-body-kind":
        kind = "project-profile"
    elif fault == "forged-metadata":
        signature = replace(signature, signature_digest="f" * 64)
    elif fault == "forged-policy-digest":
        roles = replace(roles, trust_roles_digest="f" * 64)
    elif fault == "wrong-roles-type":
        roles = cast(TrustRolesV3, "caller-dict")
    else:
        selected_digest = "not-a-digest"
    assert not signature.verify(
        object_kind=kind,
        body_schema_version="3.0",
        body_digest=BODY,
        roles=roles,
        trust_roles_digest=selected_digest,
        now=now,
        budget=BUDGET,
    )


@pytest.mark.parametrize("attribute", ATTRIBUTES)
def test_changed_unrelated_role_policy_refuses_old_selected_identity(attribute: str) -> None:
    """Even a non-signing role mutation changes the exact selected policy generation."""
    roles = selected_roles()
    inputs = role_inputs()
    key = inputs[attribute].keys[0]
    inputs[attribute] = role_policy(
        key.key.key_id, identity=key.enrolled_identity, revoked_at="2026-11-01T00:00:00Z"
    )
    changed = TrustRolesV3.build(**inputs)
    assert not verify_fixture(
        signed_fixture("standard-pack"), roles=changed, selected_digest=roles.trust_roles_digest
    )


def test_replayed_v2_signature_never_verifies_as_v3() -> None:
    """Old bytes stay parseable only by their original owner and cannot authenticate a new payload."""
    old_payload = rule_chain_v2_payload_digest(
        object_kind="standard-pack", body_digest=BODY, signed_at=SIGNED
    )
    old = RuleChainV2Signature.build(
        object_kind="standard-pack",
        key_id="v3-pack",
        body_digest=BODY,
        signed_at=SIGNED,
        signature_hex=sign_message("v3-pack", "rigor-foundry.standard-pack.v2", old_payload),
    )
    assert RuleChainV2Signature.from_dict(old.to_dict()) == old
    with pytest.raises(ValueError):
        RuleChainV3Signature.from_dict(old.to_dict(), budget=BUDGET)
    current = signed_fixture("standard-pack")
    with pytest.raises(ValueError):
        RuleChainV2Signature.from_dict(current.to_dict(budget=BUDGET))
    replay = RuleChainV3Signature.build(
        object_kind="standard-pack",
        body_schema_version="3.0",
        key_id=old.key_id,
        body_digest=BODY,
        signed_at=SIGNED,
        signature_hex=old.signature_hex,
        budget=BUDGET,
    )
    assert not verify_fixture(replay)
    with pytest.raises(ValueError):
        rule_chain_v3_payload_digest(
            object_kind="standard-pack",
            body_schema_version="2.0",
            body_digest=BODY,
            signed_at=SIGNED,
        )


def test_rotated_real_key_verifies_only_under_complete_new_selection() -> None:
    """An actual second key needs the exact new whole-policy identity at verification."""
    inputs = role_inputs()
    original = inputs["pack_issuers"].keys[0]
    rotated = role_policy("v3-pack-rotation").keys[0]
    inputs["pack_issuers"] = OfflineTrustPolicy.build((original, rotated))
    roles = TrustRolesV3.build(**inputs)
    signature = signed_fixture("standard-pack", key_id="v3-pack-rotation")
    assert verify_fixture(signature, roles=roles)
    assert not verify_fixture(signature)
    assert not verify_fixture(
        signature, roles=roles, selected_digest=selected_roles().trust_roles_digest
    )


def test_signature_subclass_and_corrupt_original_policy_are_not_authority() -> None:
    """Exact metadata and all original policies are reparsed at the public verification call."""

    class DerivedSignature(RuleChainV3Signature):
        """Represent an unrecognized signature implementation at the public boundary."""

    signature = signed_fixture("standard-pack")
    derived = DerivedSignature(**signature.__dict__)
    assert not verify_fixture(derived)
    roles = selected_roles()
    assert not verify_fixture(
        signature,
        roles=replace(roles, pack_issuers=replace(roles.pack_issuers, policy_digest="b" * 64)),
    )
    with pytest.raises(ValueError):
        RuleChainV3Signature.build(
            object_kind=cast(RuleObjectKindV3, "unknown"),
            body_schema_version="3.0",
            key_id="v3-pack",
            body_digest=BODY,
            signed_at=SIGNED,
            signature_hex=signature.signature_hex,
            budget=BUDGET,
        )
