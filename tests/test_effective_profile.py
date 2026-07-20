# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — effective profile-lock tests
"""Verify exact adapter, variable, control, and resolution lock records."""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest
from signing_fixtures import pack_signature, trust_store

from rigor_foundry.cra_policy import CraPolicy
from rigor_foundry.effective_profile import (
    AdapterLock,
    EffectiveControl,
    EffectiveProfileLock,
    PackVerification,
    PolicyContradiction,
    ProfileResolution,
    ResolvedVariable,
)
from rigor_foundry.model_primitives import (
    VariableAssignment,
    VariableConstraints,
    VariableDefinition,
)
from rigor_foundry.project_profile import (
    REQUIRED_INTENT_CATEGORIES,
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


def standard_pack(*, pack_id: str = "core") -> StandardPack:
    """Return one canonical signed pack."""
    evidence = EvidenceContract.build(
        contract_id=f"{pack_id}/evidence",
        required_adapters=("loc-adapter",),
        evidence_types=("loc-report",),
        freshness_seconds=3600,
        minimum_independent_reviewers=1,
    )
    remediation = RemediationContract.build(
        dependencies=(),
        procedure_ids=("split-module",),
        acceptance_gates=("loc-gate",),
        reopen_triggers=("source-change",),
        independent_verifier_required=True,
    )
    controls = (
        ControlDefinition.build(
            control_id=f"{pack_id}/no-godfiles",
            version="1.0.0",
            title="No unjustified GodFiles",
            domain="godfile-responsibility",
            severity="P1",
            target_level="production",
            mode="require",
            default_applicable=True,
            condition=None,
            evidence=evidence,
            remediation=remediation,
        ),
    )
    source_digest = "1" * 64
    payload = StandardPack.payload_digest(
        pack_id=pack_id,
        version="1.0.0",
        source_uri=f"https://standards.example/{pack_id}",
        source_digest=source_digest,
        licence="MIT",
        controls=controls,
    )
    return StandardPack.build(
        pack_id=pack_id,
        version="1.0.0",
        source_uri=f"https://standards.example/{pack_id}",
        source_digest=source_digest,
        licence="MIT",
        signature=pack_signature(payload),
        controls=controls,
    )


def profile(pack: StandardPack) -> ProjectProfile:
    """Return one complete profile selecting the supplied pack."""
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
                pack_id=pack.pack_id,
                version=pack.version,
                source_digest=pack.source_digest,
                pack_digest=pack.pack_digest,
                trusted_key_ids=(pack.signature.key_id,),
            ),
        ),
        variables=(definition,),
        assignments=(),
        applicability=(),
        overlays=(),
        waivers=(),
        created_by="profile-owner",
        created_at="2026-07-15T12:00:00Z",
    )


def components() -> tuple[
    ProjectProfile,
    StandardPack,
    PackVerification,
    AdapterLock,
    ResolvedVariable,
    EffectiveControl,
]:
    """Return mutually bound records for one effective lock."""
    pack = standard_pack()
    project = profile(pack)
    verification = PackVerification.build(
        pack=pack,
        trust_store=trust_store("trusted-key"),
        verified_at="2026-07-15T11:55:00Z",
    )
    adapter = AdapterLock.build(
        adapter_id="loc-adapter",
        version="1.0.0",
        executable_digest="5" * 64,
        config_digest="6" * 64,
        command_digest="7" * 64,
        environment_digest="8" * 64,
        domains=("godfile-responsibility",),
    )
    variable = ResolvedVariable.build(project.variables[0], None)
    control = EffectiveControl.build(
        source_pack=pack,
        control=pack.controls[0],
        applicable=True,
        applicability_rationale="pack default and project maturity",
        target_level="enterprise",
        mode="require",
        active_waiver_ids=(),
        missing_adapter_ids=(),
    )
    return project, pack, verification, adapter, variable, control


def lock(cra_policy: CraPolicy | None = None) -> EffectiveProfileLock:
    """Return one contradiction-free immutable effective profile lock."""
    project, pack, verification, adapter, variable, control = components()
    warning = PolicyContradiction.build(
        code="expired-nonselected-waiver",
        subject="waiver-1",
        sources=(project.profile_digest,),
        detail="recorded for operator visibility",
        blocking=False,
    )
    return EffectiveProfileLock.build(
        profile=project,
        packs=(pack,),
        verifications=(verification,),
        adapters=(adapter,),
        variables=(variable,),
        controls=(control,),
        warnings=(warning,),
        trust_store=trust_store("trusted-key"),
        toolchain_digest="9" * 64,
        resolved_at="2026-07-15T12:00:00Z",
        cra_policy=cra_policy,
    )


def test_effective_lock_preserves_legacy_bytes_and_optionally_binds_cra_policy() -> None:
    """Absent CRA stays schema 1.0; activated CRA changes and rebinds schema 1.1."""
    legacy = lock()
    assert legacy.to_dict()["schema_version"] == "1.0"
    assert "cra_policy_digest" not in legacy.to_dict()
    cra_policy = CraPolicy.build(
        applicability="required",
        rationale="explicit CRA scope",
        product_key="widget",
        disclosure_policy_path="SECURITY.md",
        state_evidence_id="cra-state",
    )
    activated = lock(cra_policy)
    assert activated.to_dict()["schema_version"] == "1.1"
    assert activated.to_dict()["cra_policy_digest"] == cra_policy.cra_policy_digest
    assert activated.lock_digest != legacy.lock_digest
    assert EffectiveProfileLock.from_dict(activated.to_dict()) == activated
    malformed = activated.to_dict()
    malformed.pop("cra_policy_digest")
    with pytest.raises(ValueError, match="requires CRA"):
        EffectiveProfileLock.from_dict(malformed)


def test_effective_lock_binds_every_exact_input() -> None:
    """The lock contains full adapter identity, verification, values, and controls."""
    expected = lock()
    encoded = expected.to_dict()
    assert encoded["profile_digest"] == expected.profile_digest
    assert encoded["pack_digests"] == list(expected.pack_digests)
    assert expected.adapters[0].to_dict()["executable_digest"] == "5" * 64
    assert expected.variables[0].to_dict()["value"] == "linux"
    assert expected.controls[0].to_dict()["risk_acceptance_waiver_ids"] == []
    _, pack, verification, _, _, _ = components()
    assert verification.valid_for(pack, trust_store("trusted-key"))
    resolution = ProfileResolution.build(
        profile_digest=expected.profile_digest,
        lock=expected,
        contradictions=expected.warnings,
    )
    assert resolution.ready


def test_effective_records_reject_partial_or_crosswired_inputs() -> None:
    """Unsupported domains, foreign controls, invalid proofs, and blocking warnings fail."""
    project, pack, verification, adapter, variable, control = components()
    with pytest.raises(ValueError, match="unsupported"):
        AdapterLock.build(
            adapter_id="bad",
            version="1.0.0",
            executable_digest="1" * 64,
            config_digest="2" * 64,
            command_digest="3" * 64,
            environment_digest="4" * 64,
            domains=("architecture",),
        )
    foreign = standard_pack(pack_id="foreign")
    with pytest.raises(ValueError, match="not a member"):
        EffectiveControl.build(
            source_pack=pack,
            control=foreign.controls[0],
            applicable=True,
            applicability_rationale="crosswired",
            target_level="production",
            mode="require",
            active_waiver_ids=(),
            missing_adapter_ids=(),
        )
    with pytest.raises(ValueError, match="must be disjoint"):
        EffectiveControl.build(
            source_pack=pack,
            control=pack.controls[0],
            applicable=True,
            applicability_rationale="crosswired waiver classes",
            target_level="production",
            mode="require",
            active_waiver_ids=("shared-waiver",),
            missing_adapter_ids=(),
            risk_acceptance_waiver_ids=("shared-waiver",),
        )
    blocking = PolicyContradiction.build(
        code="blocking",
        subject="profile",
        sources=(project.profile_digest,),
        detail="cannot lock",
    )
    with pytest.raises(ValueError, match="blocking"):
        EffectiveProfileLock.build(
            profile=project,
            packs=(pack,),
            verifications=(verification,),
            adapters=(adapter,),
            variables=(variable,),
            controls=(control,),
            warnings=(blocking,),
            trust_store=trust_store("trusted-key"),
            toolchain_digest="9" * 64,
            resolved_at="2026-07-15T12:00:00Z",
        )
    invalid = replace(verification, trust_store_digest="0" * 64)
    with pytest.raises(ValueError, match="unique and valid"):
        EffectiveProfileLock.build(
            profile=project,
            packs=(pack,),
            verifications=(invalid,),
            adapters=(adapter,),
            variables=(variable,),
            controls=(control,),
            warnings=(),
            trust_store=trust_store("trusted-key"),
            toolchain_digest="9" * 64,
            resolved_at="2026-07-15T12:00:00Z",
        )


def test_resolution_requires_consistent_lock_or_blocker() -> None:
    """A resolution cannot silently omit a lock or attach it to another profile."""
    expected = lock()
    with pytest.raises(ValueError, match="blocking contradiction"):
        ProfileResolution.build(
            profile_digest=expected.profile_digest,
            lock=None,
            contradictions=(),
        )
    blocker = PolicyContradiction.build(
        code="missing-pack",
        subject="core",
        sources=(expected.profile_digest,),
        detail="selected pack missing",
    )
    rejected = ProfileResolution.build(
        profile_digest=expected.profile_digest,
        lock=None,
        contradictions=(blocker,),
    )
    assert not rejected.ready
    with pytest.raises(ValueError, match="different project profile"):
        ProfileResolution.build(
            profile_digest="f" * 64,
            lock=expected,
            contradictions=(),
        )
    with pytest.raises(ValueError, match="blocking contradictions"):
        ProfileResolution.build(
            profile_digest=expected.profile_digest,
            lock=expected,
            contradictions=(blocker,),
        )


def test_resolved_variable_explicit_assignment_and_unresolved_default_edges() -> None:
    """Explicit assignments are rederived and required missing defaults fail closed."""
    project, _, _, _, _, _ = components()
    definition = project.variables[0]
    assignment = VariableAssignment.build(
        definition,
        value="freebsd",
        secret_ref=None,
        source="environment",
    )
    resolved = ResolvedVariable.build(definition, assignment)
    assert resolved.value == "freebsd"
    with pytest.raises(ValueError, match="inconsistent"):
        ResolvedVariable.build(
            definition,
            replace(assignment, assignment_digest="0" * 64),
        )
    unresolved = VariableDefinition.build(
        variable_id="deployment.required",
        value_type="string",
        scope="project",
        sensitivity="public",
        required=True,
        constraints=VariableConstraints.build(),
        default_value=None,
        default_secret_ref=None,
        source="profile",
    )
    with pytest.raises(ValueError, match="required variable"):
        ResolvedVariable.build(unresolved, None)


def test_effective_control_and_lock_uniqueness_edges_fail_closed() -> None:
    """Unsupported effective values, duplicate identities, and unlocked sources are rejected."""
    project, pack, verification, adapter, variable, control = components()
    for target, mode, message in (
        ("ultimate", "require", "target_level"),
        ("production", "allow", "mode"),
    ):
        with pytest.raises(ValueError, match=message):
            EffectiveControl.build(
                source_pack=pack,
                control=pack.controls[0],
                applicable=True,
                applicability_rationale="invalid",
                target_level=cast(object, target),
                mode=cast(object, mode),
                active_waiver_ids=(),
                missing_adapter_ids=(),
            )

    def build_lock(**changes: object) -> EffectiveProfileLock:
        values = {
            "profile": project,
            "packs": (pack,),
            "verifications": (verification,),
            "adapters": (adapter,),
            "variables": (variable,),
            "controls": (control,),
            "warnings": (),
            "trust_store": trust_store("trusted-key"),
            "toolchain_digest": "9" * 64,
            "resolved_at": "2026-07-15T12:00:00Z",
        }
        return EffectiveProfileLock.build(**{**values, **changes})

    with pytest.raises(ValueError, match="unique ids"):
        build_lock(packs=(pack, pack), verifications=(verification,))
    with pytest.raises(ValueError, match="one verification"):
        build_lock(verifications=())
    with pytest.raises(ValueError, match="adapter ids"):
        build_lock(adapters=(adapter, adapter))
    with pytest.raises(ValueError, match="variable ids"):
        build_lock(variables=(variable, variable))
    with pytest.raises(ValueError, match="control ids"):
        build_lock(controls=(control, control))
    with pytest.raises(ValueError, match="unlocked source pack"):
        build_lock(controls=(replace(control, source_pack_digest="0" * 64),))
