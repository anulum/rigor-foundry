# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — effective-profile resolver tests
"""Verify fail-closed composition of packs, profiles, overlays, and waivers."""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest
from signing_fixtures import pack_signature, trust_store

from rigor_foundry.condition_language import ConditionExpression
from rigor_foundry.effective_profile import AdapterLock, PackVerification
from rigor_foundry.model_primitives import VariableConstraints, VariableDefinition
from rigor_foundry.profile_resolution import resolve_effective_profile
from rigor_foundry.project_profile import (
    REQUIRED_INTENT_CATEGORIES,
    ApplicabilityDecision,
    ControlOverlay,
    ExceptionWaiver,
    PackSelection,
    ProjectIntent,
    ProjectProfile,
    RequirementBinding,
    RequirementCategory,
)
from rigor_foundry.standard_pack import (
    ControlDefinition,
    EvidenceContract,
    RemediationContract,
    StandardPack,
)


def control(
    *,
    pack_id: str = "core",
    control_name: str = "no-godfiles",
    target_level: str = "production",
    mode: str = "require",
    condition: ConditionExpression | None = None,
    dependencies: tuple[str, ...] = (),
) -> ControlDefinition:
    """Return one complete versioned control."""
    return ControlDefinition.build(
        control_id=f"{pack_id}/{control_name}",
        version="1.0.0",
        title="Verified architecture responsibility boundary",
        domain="godfile-responsibility",
        severity="P1",
        target_level=cast(object, target_level),
        mode=cast(object, mode),
        default_applicable=True,
        condition=condition,
        evidence=EvidenceContract.build(
            contract_id=f"{pack_id}/{control_name}/evidence",
            required_adapters=("loc-adapter",),
            evidence_types=("loc-report",),
            freshness_seconds=3600,
            minimum_independent_reviewers=1,
        ),
        remediation=RemediationContract.build(
            dependencies=dependencies,
            procedure_ids=("split-module",),
            acceptance_gates=("loc-gate",),
            reopen_triggers=("source-change",),
            independent_verifier_required=True,
        ),
    )


def pack(
    *,
    pack_id: str = "core",
    controls: tuple[ControlDefinition, ...] | None = None,
    licence: str = "MIT",
) -> StandardPack:
    """Return one payload-bound signed standard pack."""
    selected_controls = controls or (control(pack_id=pack_id),)
    source_digest = "1" * 64
    payload = StandardPack.payload_digest(
        pack_id=pack_id,
        version="1.0.0",
        source_uri=f"https://standards.example/{pack_id}",
        source_digest=source_digest,
        licence=licence,
        controls=selected_controls,
    )
    return StandardPack.build(
        pack_id=pack_id,
        version="1.0.0",
        source_uri=f"https://standards.example/{pack_id}",
        source_digest=source_digest,
        licence=licence,
        signature=pack_signature(payload),
        controls=selected_controls,
    )


def profile(
    standard: StandardPack,
    *,
    overlays: tuple[ControlOverlay, ...] = (),
    waivers: tuple[ExceptionWaiver, ...] = (),
    applicability: tuple[ApplicabilityDecision, ...] = (),
) -> ProjectProfile:
    """Return one complete profile selecting the exact supplied pack."""
    requirements = tuple(
        RequirementBinding.build(cast(RequirementCategory, category), ("explicit",))
        for category in sorted(REQUIRED_INTENT_CATEGORIES)
    )
    intent = ProjectIntent.build(
        risk_class="production",
        regulatory_classes=(),
        target_maturity="enterprise",
        requirements=requirements,
    )
    definition = VariableDefinition.build(
        variable_id="deployment.os",
        value_type="string",
        scope="project",
        sensitivity="public",
        required=True,
        constraints=VariableConstraints.build(),
        default_value="linux",
        default_secret_ref=None,
        source="profile",
    )
    return ProjectProfile.build(
        profile_id="rigor-foundry",
        intent=intent,
        packs=(
            PackSelection.build(
                pack_id=standard.pack_id,
                version=standard.version,
                source_digest=standard.source_digest,
                pack_digest=standard.pack_digest,
                trusted_key_ids=(standard.signature.key_id,),
            ),
        ),
        variables=(definition,),
        assignments=(),
        applicability=applicability,
        overlays=overlays,
        waivers=waivers,
        created_by="profile-owner",
        created_at="2026-07-15T12:00:00Z",
    )


def verification(standard: StandardPack) -> PackVerification:
    """Return external cryptographic-verification evidence for the exact pack."""
    return PackVerification.build(
        pack=standard,
        trust_store=trust_store("trusted-key"),
        verified_at="2026-07-15T11:55:00Z",
    )


def adapter() -> AdapterLock:
    """Return a complete exact adapter lock."""
    return AdapterLock.build(
        adapter_id="loc-adapter",
        version="1.0.0",
        executable_digest="5" * 64,
        config_digest="6" * 64,
        command_digest="7" * 64,
        environment_digest="8" * 64,
        domains=("godfile-responsibility",),
    )


def resolve(
    project: ProjectProfile,
    standard: StandardPack,
    *,
    verifications: tuple[PackVerification, ...] | None = None,
    adapters: tuple[AdapterLock, ...] | None = None,
    allowed_licences: tuple[str, ...] = ("MIT",),
):
    """Resolve one profile with deterministic evidence coordinates."""
    return resolve_effective_profile(
        project,
        packs=(standard,),
        verifications=(verification(standard),) if verifications is None else verifications,
        adapters=(adapter(),) if adapters is None else adapters,
        trust_store=trust_store("trusted-key"),
        allowed_licences=allowed_licences,
        toolchain_digest="9" * 64,
        resolved_at="2026-07-15T12:00:00Z",
    )


def test_exact_verified_licensed_inputs_produce_a_ready_lock() -> None:
    """A valid exact composition resolves to one immutable, auditable lock."""
    standard = pack()
    result = resolve(profile(standard), standard)
    assert result.ready
    assert result.lock is not None
    assert result.lock.pack_digests == (standard.pack_digest,)
    assert result.lock.controls[0].target_level == "production"
    assert result.lock.controls[0].missing_adapter_ids == ()
    assert result.contradictions == ()


@pytest.mark.parametrize(
    ("verifications", "allowed", "code"),
    [
        ((), ("MIT",), "unverified-pack"),
        (None, ("Apache-2.0",), "unlicensed-pack"),
    ],
)
def test_missing_trust_or_licence_blocks_lock(
    verifications: tuple[PackVerification, ...] | None,
    allowed: tuple[str, ...],
    code: str,
) -> None:
    """A selected pack never enters a lock without exact trust and licence approval."""
    standard = pack()
    supplied = (verification(standard),) if verifications is None else verifications
    result = resolve(
        profile(standard),
        standard,
        verifications=supplied,
        allowed_licences=allowed,
    )
    assert not result.ready and result.lock is None
    assert code in {item.code for item in result.contradictions}


def test_stricter_overlay_wins_and_missing_adapter_remains_explicit() -> None:
    """Strengthening is applied while absent evidence adapters remain fail-closed metadata."""
    standard = pack()
    overlay = ControlOverlay.build(
        control_id="core/no-godfiles",
        target_level="industrial-safety",
        mode="deny",
        source="project safety overlay",
    )
    result = resolve(profile(standard, overlays=(overlay,)), standard, adapters=())
    assert result.ready and result.lock is not None
    effective = result.lock.controls[0]
    assert effective.target_level == "industrial-safety"
    assert effective.mode == "deny"
    assert effective.missing_adapter_ids == ("loc-adapter",)


def test_signature_proof_and_adapter_domain_are_exactly_bound() -> None:
    """A verification binds detached proof bytes and adapters cover the control domain."""
    standard = pack()
    wrong_proof = replace(verification(standard), signature_digest="0" * 64)
    rejected = resolve(profile(standard), standard, verifications=(wrong_proof,))
    assert not rejected.ready
    assert "unverified-pack" in {item.code for item in rejected.contradictions}

    wrong_domain = AdapterLock.build(
        adapter_id="loc-adapter",
        version="1.0.0",
        executable_digest="5" * 64,
        config_digest="6" * 64,
        command_digest="7" * 64,
        environment_digest="8" * 64,
        domains=("application-security",),
    )
    resolved = resolve(profile(standard), standard, adapters=(wrong_domain,))
    assert resolved.ready and resolved.lock is not None
    assert resolved.lock.controls[0].missing_adapter_ids == ("loc-adapter",)


def test_fabricated_pack_signature_cannot_create_verification_evidence() -> None:
    """Digest-shaped signature bytes and an approved key label establish no trust."""
    standard = pack()
    forged_signature = standard.signature.build(
        key_id=standard.signature.key_id,
        payload_digest=standard.signature.payload_digest,
        signature_hex="0" * 128,
    )
    forged_pack = StandardPack.build(
        pack_id=standard.pack_id,
        version=standard.version,
        source_uri=standard.source_uri,
        source_digest=standard.source_digest,
        licence=standard.licence,
        signature=forged_signature,
        controls=standard.controls,
    )
    with pytest.raises(ValueError, match="not valid"):
        PackVerification.build(
            pack=forged_pack,
            trust_store=trust_store("trusted-key"),
            verified_at="2026-07-15T11:55:00Z",
        )
    with pytest.raises(ValueError, match="signature"):
        PackVerification.build(
            pack=replace(standard, licence="Apache-2.0"),
            trust_store=trust_store("trusted-key"),
            verified_at="2026-07-15T11:55:00Z",
        )


def test_weakening_requires_one_active_exact_waiver() -> None:
    """Lowering a pack target blocks unless independently authorized for exact values."""
    standard = pack()
    overlay = ControlOverlay.build(
        control_id="core/no-godfiles",
        target_level="baseline",
        mode="require",
        source="temporary migration overlay",
    )
    denied = resolve(profile(standard, overlays=(overlay,)), standard)
    assert not denied.ready
    assert "unauthorized-weakening" in {item.code for item in denied.contradictions}

    waiver = ExceptionWaiver.build(
        waiver_id="level-migration",
        control_id="core/no-godfiles",
        field="target_level",
        from_value="production",
        to_value="baseline",
        owner="migration-owner",
        authorized_by="independent-risk-owner",
        rationale="bounded compatibility migration",
        evidence_digest="a" * 64,
        created_at="2026-07-01T00:00:00Z",
        expires_at="2026-08-01T00:00:00Z",
    )
    allowed = resolve(profile(standard, overlays=(overlay,), waivers=(waiver,)), standard)
    assert allowed.ready and allowed.lock is not None
    assert allowed.lock.controls[0].target_level == "baseline"
    assert allowed.lock.controls[0].active_waiver_ids == (waiver.waiver_id,)
    assert allowed.lock.controls[0].risk_acceptance_waiver_ids == ()


def test_only_exact_active_risk_acceptance_waiver_is_carried() -> None:
    """Unrelated active exceptions never enter the dedicated risk-acceptance set."""
    standard = pack()
    unrelated = ExceptionWaiver.build(
        waiver_id="unused-level-waiver",
        control_id="core/no-godfiles",
        field="target_level",
        from_value="production",
        to_value="baseline",
        owner="migration-owner",
        authorized_by="independent-risk-owner",
        rationale="unrelated migration permission",
        evidence_digest="a" * 64,
        created_at="2026-07-01T00:00:00Z",
        expires_at="2026-08-01T00:00:00Z",
    )
    risk = ExceptionWaiver.build(
        waiver_id="bounded-risk-acceptance",
        control_id="core/no-godfiles",
        field="assessment-status",
        from_value="fail",
        to_value="accepted-risk",
        owner="risk-owner",
        authorized_by="independent-risk-owner",
        rationale="bounded evidence-backed risk acceptance",
        evidence_digest="b" * 64,
        created_at="2026-07-01T00:00:00Z",
        expires_at="2026-08-01T00:00:00Z",
    )
    result = resolve(profile(standard, waivers=(unrelated, risk)), standard)
    assert result.ready and result.lock is not None
    effective = result.lock.controls[0]
    assert effective.active_waiver_ids == ()
    assert effective.risk_acceptance_waiver_ids == (risk.waiver_id,)


def test_inactive_waiver_is_preserved_as_nonblocking_warning() -> None:
    """Expired exceptions remain visible but do not block unrelated exact policy."""
    standard = pack()
    waiver = ExceptionWaiver.build(
        waiver_id="expired-waiver",
        control_id="core/no-godfiles",
        field="target_level",
        from_value="production",
        to_value="baseline",
        owner="migration-owner",
        authorized_by="independent-risk-owner",
        rationale="past migration window",
        evidence_digest="a" * 64,
        created_at="2026-06-01T00:00:00Z",
        expires_at="2026-07-01T00:00:00Z",
    )
    result = resolve(profile(standard, waivers=(waiver,)), standard)
    assert result.ready and result.lock is not None
    assert [item.code for item in result.lock.warnings] == ["inactive-waiver"]


def test_unknown_control_and_missing_dependency_are_blocking() -> None:
    """Crosswired overlays and unresolved control dependencies cannot create a lock."""
    dependent = control(dependencies=("core/missing-control",))
    standard = pack(controls=(dependent,))
    overlay = ControlOverlay.build(
        control_id="core/not-in-pack",
        target_level="enterprise",
        mode="require",
        source="bad crosswire",
    )
    result = resolve(profile(standard, overlays=(overlay,)), standard)
    codes = {item.code for item in result.contradictions}
    assert result.lock is None
    assert {"unknown-control-reference", "missing-control-dependency"}.issubset(codes)


def test_pack_and_adapter_inventory_crosswiring_is_reported() -> None:
    """Missing, duplicate, unexpected, and pin-mismatched inputs produce explicit blockers."""
    standard = pack()
    project = profile(standard)
    common = {
        "profile": project,
        "verifications": (verification(standard),),
        "adapters": (adapter(),),
        "trust_store": trust_store("trusted-key"),
        "allowed_licences": ("MIT",),
        "toolchain_digest": "9" * 64,
        "resolved_at": "2026-07-15T12:00:00Z",
    }
    missing = resolve_effective_profile(packs=(), **common)
    assert "missing-pack" in {item.code for item in missing.contradictions}
    duplicate = resolve_effective_profile(
        packs=(standard, standard),
        **common,
    )
    assert "duplicate-pack" in {item.code for item in duplicate.contradictions}
    mismatched = pack(licence="Apache-2.0")
    pin = resolve_effective_profile(
        packs=(mismatched,),
        **common,
    )
    assert "pack-pin-mismatch" in {item.code for item in pin.contradictions}
    foreign = pack(pack_id="foreign")
    unexpected = resolve_effective_profile(
        project,
        packs=(standard, foreign),
        verifications=(verification(standard), verification(foreign)),
        adapters=(adapter(),),
        trust_store=trust_store("trusted-key"),
        allowed_licences=("MIT",),
        toolchain_digest="9" * 64,
        resolved_at="2026-07-15T12:00:00Z",
    )
    assert "unexpected-pack" in {item.code for item in unexpected.contradictions}
    duplicate_adapter = resolve_effective_profile(
        project,
        packs=(standard,),
        verifications=(verification(standard),),
        adapters=(adapter(), adapter()),
        trust_store=trust_store("trusted-key"),
        allowed_licences=("MIT",),
        toolchain_digest="9" * 64,
        resolved_at="2026-07-15T12:00:00Z",
    )
    assert "duplicate-adapter" in {item.code for item in duplicate_adapter.contradictions}


def test_condition_error_and_applicability_weakening_are_not_silently_coerced() -> None:
    """Condition errors block and excluding an applicable control requires an exact waiver."""
    invalid_condition = ConditionExpression.build(
        "gt",
        reference="profile.risk_class",
        value=2,
    )
    standard = pack(controls=(control(condition=invalid_condition),))
    failed = resolve(profile(standard), standard)
    assert "condition-type-error" in {item.code for item in failed.contradictions}

    standard = pack()
    decision = ApplicabilityDecision.build(
        control_id="core/no-godfiles",
        applicable=False,
        rationale="no production Python source exists in this target",
    )
    denied = resolve(profile(standard, applicability=(decision,)), standard)
    assert not denied.ready
    assert "unauthorized-weakening" in {item.code for item in denied.contradictions}
    waiver = ExceptionWaiver.build(
        waiver_id="scope-exclusion",
        control_id="core/no-godfiles",
        field="applicable",
        from_value=True,
        to_value=False,
        owner="scope-owner",
        authorized_by="independent-risk-owner",
        rationale="verified target contains no applicable Python surface",
        evidence_digest="a" * 64,
        created_at="2026-07-01T00:00:00Z",
        expires_at="2026-08-01T00:00:00Z",
    )
    result = resolve(
        profile(standard, applicability=(decision,), waivers=(waiver,)),
        standard,
    )
    assert result.ready and result.lock is not None
    effective = result.lock.controls[0]
    assert not effective.applicable
    assert effective.applicability_rationale == decision.rationale
    assert effective.active_waiver_ids == (waiver.waiver_id,)


def test_deny_mode_can_only_be_weakened_by_an_active_exact_waiver() -> None:
    """Pack deny mode wins unless one independently authorized exact exception is active."""
    standard = pack(controls=(control(mode="deny"),))
    overlay = ControlOverlay.build(
        control_id="core/no-godfiles",
        target_level="production",
        mode="require",
        source="temporary mode overlay",
    )
    denied = resolve(profile(standard, overlays=(overlay,)), standard)
    assert "deny-wins" in {item.code for item in denied.contradictions}
    waiver = ExceptionWaiver.build(
        waiver_id="mode-migration",
        control_id="core/no-godfiles",
        field="mode",
        from_value="deny",
        to_value="require",
        owner="migration-owner",
        authorized_by="independent-risk-owner",
        rationale="bounded mode migration",
        evidence_digest="a" * 64,
        created_at="2026-07-01T00:00:00Z",
        expires_at="2026-08-01T00:00:00Z",
    )
    allowed = resolve(profile(standard, overlays=(overlay,), waivers=(waiver,)), standard)
    assert allowed.ready and allowed.lock is not None
    assert allowed.lock.controls[0].mode == "require"
    assert allowed.lock.controls[0].active_waiver_ids == (waiver.waiver_id,)
