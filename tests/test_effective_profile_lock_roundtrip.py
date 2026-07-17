# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — effective profile lock offline round-trip tests
"""Verify sealed lock and nested records rebind digests through from_dict."""

from __future__ import annotations

import json
from typing import cast

import pytest

from rigor_foundry.effective_profile import (
    AdapterLock,
    EffectiveProfileLock,
    PolicyContradiction,
)
from tests.test_oscal_export import _lock as two_control_lock


def test_lock_round_trip_preserves_digest() -> None:
    """Serialise then parse a sealed lock without changing its digest."""
    lock, _controls = two_control_lock()
    rebound = EffectiveProfileLock.from_dict(lock.to_dict())
    assert rebound == lock
    assert rebound.lock_digest == lock.lock_digest


def test_lock_from_dict_rejects_tampered_digest() -> None:
    """A forged lock_digest fails closed."""
    lock, _controls = two_control_lock()
    payload = lock.to_dict()
    payload["lock_digest"] = "0" * 64
    with pytest.raises(ValueError, match="lock digest does not match"):
        EffectiveProfileLock.from_dict(payload)


def test_lock_from_dict_rejects_tampered_control() -> None:
    """Mutating a nested control without updating digests fails closed."""
    lock, _controls = two_control_lock()
    payload = lock.to_dict()
    controls = cast(list[dict[str, object]], payload["controls"])
    control = cast(dict[str, object], controls[0]["control"])
    control["title"] = "tampered title"
    with pytest.raises(ValueError, match="digest does not match"):
        EffectiveProfileLock.from_dict(payload)


def test_adapter_and_contradiction_round_trips() -> None:
    """Nested adapter and contradiction records rebind their digests."""
    adapter = AdapterLock.build(
        adapter_id="scan-adapter",
        version="1.0.0",
        executable_digest="5" * 64,
        config_digest="6" * 64,
        command_digest="7" * 64,
        environment_digest="8" * 64,
        domains=("application-security",),
    )
    assert AdapterLock.from_dict(adapter.to_dict()) == adapter
    contradiction = PolicyContradiction.build(
        code="fixture-warning",
        subject="fixture",
        sources=("source-a",),
        detail="non-blocking fixture",
        blocking=False,
    )
    assert PolicyContradiction.from_dict(contradiction.to_dict()) == contradiction


def test_json_round_trip_bytes() -> None:
    """JSON encode/decode of a lock yields the same sealed object."""
    lock, _controls = two_control_lock()
    encoded = json.dumps(lock.to_dict(), sort_keys=True)
    rebound = EffectiveProfileLock.from_dict(json.loads(encoded))
    assert rebound.lock_digest == lock.lock_digest


def test_pack_verification_round_trip() -> None:
    """Offline pack-verification evidence rebinds its digest."""
    lock, _controls = two_control_lock()
    # Rebuild verification evidence through the lock's sealed digests is not stored;
    # construct one via Adapter-like path using PackVerification.from_dict of a live build.
    from signing_fixtures import pack_signature, trust_store

    from rigor_foundry.effective_profile import PackVerification
    from rigor_foundry.standard_pack import (
        ControlDefinition,
        EvidenceContract,
        RemediationContract,
        StandardPack,
    )

    control = ControlDefinition.build(
        control_id="core/app-security",
        version="1.0.0",
        title="x",
        domain="application-security",
        severity="P1",
        target_level="production",
        mode="require",
        default_applicable=True,
        condition=None,
        evidence=EvidenceContract.build(
            contract_id="core/app-security/evidence",
            required_adapters=("scan-adapter",),
            evidence_types=("scan-report",),
            freshness_seconds=3600,
            minimum_independent_reviewers=1,
        ),
        remediation=RemediationContract.build(
            dependencies=(),
            procedure_ids=("fix",),
            acceptance_gates=("gate",),
            reopen_triggers=("source-change",),
            independent_verifier_required=True,
        ),
    )
    source_digest = "1" * 64
    payload = StandardPack.payload_digest(
        pack_id="core",
        version="1.0.0",
        source_uri="https://standards.example/core",
        source_digest=source_digest,
        licence="MIT",
        controls=(control,),
    )
    pack = StandardPack.build(
        pack_id="core",
        version="1.0.0",
        source_uri="https://standards.example/core",
        source_digest=source_digest,
        licence="MIT",
        signature=pack_signature(payload),
        controls=(control,),
    )
    verification = PackVerification.build(
        pack=pack,
        trust_store=trust_store("trusted-key"),
        verified_at="2026-07-15T11:50:00Z",
    )
    assert PackVerification.from_dict(verification.to_dict()) == verification
    bad = verification.to_dict()
    bad["verification_digest"] = "0" * 64
    with pytest.raises(ValueError, match="verification digest"):
        PackVerification.from_dict(bad)


def test_resolved_variable_round_trip() -> None:
    """Resolved variables with scalar and string-list values rebind digests."""
    from rigor_foundry.effective_profile import ResolvedVariable
    from rigor_foundry.model_primitives import (
        VariableAssignment,
        VariableConstraints,
        VariableDefinition,
    )

    definition = VariableDefinition.build(
        variable_id="fixture-var",
        value_type="string",
        scope="project",
        sensitivity="public",
        required=False,
        constraints=VariableConstraints.build(),
        default_value="alpha",
        default_secret_ref=None,
        source="profile",
    )
    assignment = VariableAssignment.build(
        definition,
        value="beta",
        secret_ref=None,
        source="test",
    )
    resolved = ResolvedVariable.build(definition, assignment)
    assert ResolvedVariable.from_dict(resolved.to_dict()) == resolved
    bad = resolved.to_dict()
    bad["value_digest"] = "0" * 64
    with pytest.raises(ValueError, match="value digest"):
        ResolvedVariable.from_dict(bad)

    list_def = VariableDefinition.build(
        variable_id="fixture-list",
        value_type="string-list",
        scope="project",
        sensitivity="public",
        required=False,
        constraints=VariableConstraints.build(),
        default_value=("a", "b"),
        default_secret_ref=None,
        source="profile",
    )
    list_assignment = VariableAssignment.build(
        list_def,
        value=("a", "b"),
        secret_ref=None,
        source="test",
    )
    list_resolved = ResolvedVariable.build(list_def, list_assignment)
    assert ResolvedVariable.from_dict(list_resolved.to_dict()) == list_resolved


def test_from_dict_rejects_blocking_warnings_in_lock() -> None:
    """A lock document carrying blocking warnings fails closed."""
    lock, _controls = two_control_lock()
    payload = lock.to_dict()
    payload["warnings"] = [
        PolicyContradiction.build(
            code="block",
            subject="x",
            sources=("s",),
            detail="blocked",
            blocking=True,
        ).to_dict()
    ]
    # tamper digest so we hit validation before digest compare ideally
    with pytest.raises(ValueError):
        EffectiveProfileLock.from_dict(payload)


def test_adapter_from_dict_negative_paths() -> None:
    """Adapter parse rejects non-array domains and digest forgery."""
    adapter = AdapterLock.build(
        adapter_id="scan-adapter",
        version="1.0.0",
        executable_digest="5" * 64,
        config_digest="6" * 64,
        command_digest="7" * 64,
        environment_digest="8" * 64,
        domains=("application-security",),
    )
    payload = adapter.to_dict()
    payload["domains"] = "not-a-list"
    with pytest.raises(ValueError, match="domains must be an array"):
        AdapterLock.from_dict(payload)
    forged = adapter.to_dict()
    forged["adapter_digest"] = "0" * 64
    with pytest.raises(ValueError, match="adapter digest"):
        AdapterLock.from_dict(forged)


def test_lock_from_dict_rejects_non_array_fields() -> None:
    """Lock parse rejects non-array pack digests and controls."""
    lock, _controls = two_control_lock()
    payload = lock.to_dict()
    payload["pack_digests"] = "nope"
    with pytest.raises(ValueError, match="must be an array"):
        EffectiveProfileLock.from_dict(payload)
    payload = lock.to_dict()
    payload["controls"] = {}
    with pytest.raises(ValueError, match="must be an array"):
        EffectiveProfileLock.from_dict(payload)


def test_contradiction_from_dict_rejects_non_array_sources() -> None:
    """Contradiction parse rejects non-array sources."""
    payload = PolicyContradiction.build(
        code="fixture-warning",
        subject="fixture",
        sources=("source-a",),
        detail="non-blocking fixture",
        blocking=False,
    ).to_dict()
    payload["sources"] = "x"
    with pytest.raises(ValueError, match="sources must be an array"):
        PolicyContradiction.from_dict(payload)


def test_resolved_variable_rejects_bad_value_type() -> None:
    """Variable parse rejects unsupported value containers."""
    from rigor_foundry.effective_profile import ResolvedVariable
    from rigor_foundry.model_primitives import (
        VariableAssignment,
        VariableConstraints,
        VariableDefinition,
    )

    definition = VariableDefinition.build(
        variable_id="fixture-var",
        value_type="string",
        scope="project",
        sensitivity="public",
        required=False,
        constraints=VariableConstraints.build(),
        default_value="alpha",
        default_secret_ref=None,
        source="profile",
    )
    assignment = VariableAssignment.build(
        definition,
        value="beta",
        secret_ref=None,
        source="test",
    )
    payload = ResolvedVariable.build(definition, assignment).to_dict()
    payload["value"] = {"nested": True}
    with pytest.raises(ValueError, match="unsupported type"):
        ResolvedVariable.from_dict(payload)


def test_schema_version_rejects() -> None:
    """Wrong schema versions fail closed on lock and verification parse."""
    from rigor_foundry.effective_profile import PackVerification

    lock, _ = two_control_lock()
    payload = lock.to_dict()
    payload["schema_version"] = "9.9"
    with pytest.raises(ValueError, match="unsupported effective-profile lock schema"):
        EffectiveProfileLock.from_dict(payload)
    payload = lock.to_dict()
    payload["resolver_version"] = "9.9.9"
    with pytest.raises(ValueError, match="unsupported effective-profile resolver"):
        EffectiveProfileLock.from_dict(payload)

    # verification schema
    from signing_fixtures import pack_signature, trust_store

    from rigor_foundry.standard_pack import (
        ControlDefinition,
        EvidenceContract,
        RemediationContract,
        StandardPack,
    )

    control = ControlDefinition.build(
        control_id="core/app-security",
        version="1.0.0",
        title="x",
        domain="application-security",
        severity="P1",
        target_level="production",
        mode="require",
        default_applicable=True,
        condition=None,
        evidence=EvidenceContract.build(
            contract_id="core/app-security/evidence",
            required_adapters=("scan-adapter",),
            evidence_types=("scan-report",),
            freshness_seconds=3600,
            minimum_independent_reviewers=1,
        ),
        remediation=RemediationContract.build(
            dependencies=(),
            procedure_ids=("fix",),
            acceptance_gates=("gate",),
            reopen_triggers=("source-change",),
            independent_verifier_required=True,
        ),
    )
    source_digest = "1" * 64
    payload_digest = StandardPack.payload_digest(
        pack_id="core",
        version="1.0.0",
        source_uri="https://standards.example/core",
        source_digest=source_digest,
        licence="MIT",
        controls=(control,),
    )
    pack = StandardPack.build(
        pack_id="core",
        version="1.0.0",
        source_uri="https://standards.example/core",
        source_digest=source_digest,
        licence="MIT",
        signature=pack_signature(payload_digest),
        controls=(control,),
    )
    verification = PackVerification.build(
        pack=pack,
        trust_store=trust_store("trusted-key"),
        verified_at="2026-07-15T11:50:00Z",
    )
    vpayload = verification.to_dict()
    vpayload["schema_version"] = "9.9"
    with pytest.raises(ValueError, match="unsupported pack-verification schema"):
        PackVerification.from_dict(vpayload)


def test_effective_control_rejects_bad_mode_and_level() -> None:
    """Effective control parse rejects unsupported mode and target level."""
    from rigor_foundry.effective_profile import EffectiveControl

    lock, controls = two_control_lock()
    payload = controls[0].to_dict()
    payload["mode"] = "maybe"
    with pytest.raises(ValueError, match="mode is unsupported"):
        EffectiveControl.from_dict(payload)
    payload = controls[0].to_dict()
    payload["target_level"] = "mythic"
    with pytest.raises(ValueError, match="target_level is unsupported"):
        EffectiveControl.from_dict(payload)


def test_contradiction_digest_forgery() -> None:
    """Forged contradiction digests fail closed."""
    payload = PolicyContradiction.build(
        code="fixture-warning",
        subject="fixture",
        sources=("source-a",),
        detail="non-blocking fixture",
        blocking=False,
    ).to_dict()
    payload["contradiction_digest"] = "0" * 64
    with pytest.raises(ValueError, match="contradiction digest"):
        PolicyContradiction.from_dict(payload)


def test_string_list_members_must_be_strings() -> None:
    """String-list resolved values reject non-string members."""
    from rigor_foundry.effective_profile import ResolvedVariable
    from rigor_foundry.model_primitives import (
        VariableAssignment,
        VariableConstraints,
        VariableDefinition,
    )

    list_def = VariableDefinition.build(
        variable_id="fixture-list",
        value_type="string-list",
        scope="project",
        sensitivity="public",
        required=False,
        constraints=VariableConstraints.build(),
        default_value=("a", "b"),
        default_secret_ref=None,
        source="profile",
    )
    list_assignment = VariableAssignment.build(
        list_def,
        value=("a", "b"),
        secret_ref=None,
        source="test",
    )
    payload = ResolvedVariable.build(list_def, list_assignment).to_dict()
    payload["value"] = ["a", 1]
    with pytest.raises(ValueError, match="string-list members must be strings"):
        ResolvedVariable.from_dict(payload)
