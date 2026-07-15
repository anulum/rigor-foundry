# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — effective profile resolution
"""Compose exact packs and project overlays into an effective profile lock."""

from __future__ import annotations

from datetime import datetime

from .effective_profile import (
    AdapterLock,
    EffectiveControl,
    EffectiveProfileLock,
    PackVerification,
    PolicyContradiction,
    ProfileResolution,
    ResolvedVariable,
)
from .model_primitives import (
    require_utc_timestamp,
    serialise_variable_value,
    validate_unique_strings,
)
from .project_profile import (
    ApplicabilityDecision,
    ControlOverlay,
    ExceptionWaiver,
    ProjectProfile,
)
from .standard_pack import TARGET_LEVEL_ORDER, ControlDefinition, StandardPack
from .trust import VerificationTrustStore


def _active_waiver(
    waivers: tuple[ExceptionWaiver, ...],
    *,
    control_id: str,
    field: str,
    from_value: object,
    to_value: object,
    now: datetime,
) -> ExceptionWaiver | None:
    """Return the one exact active waiver for a requested weakening."""
    matches = tuple(
        item
        for item in waivers
        if item.control_id == control_id
        and item.field == field
        and item.from_value == from_value
        and item.to_value == to_value
        and item.active_at(now)
    )
    if len(matches) > 1:
        raise ValueError(f"multiple active waivers match {control_id}.{field}")
    return matches[0] if matches else None


def _profile_context(
    profile: ProjectProfile,
    variables: tuple[ResolvedVariable, ...],
) -> dict[str, object]:
    """Build inert condition data while excluding every secret variable."""
    requirements = {item.category: list(item.requirements) for item in profile.intent.requirements}
    public_variables = {
        item.variable_id: serialise_variable_value(item.value)
        for item in variables
        if item.sensitivity != "secret"
    }
    return {
        "profile": {
            "risk_class": profile.intent.risk_class,
            "regulatory_classes": list(profile.intent.regulatory_classes),
            "target_maturity": profile.intent.target_maturity,
            "requirements": requirements,
        },
        "variables": public_variables,
    }


def resolve_effective_profile(
    profile: ProjectProfile,
    *,
    packs: tuple[StandardPack, ...],
    verifications: tuple[PackVerification, ...],
    adapters: tuple[AdapterLock, ...],
    trust_store: VerificationTrustStore,
    allowed_licences: tuple[str, ...],
    toolchain_digest: str,
    resolved_at: str,
) -> ProfileResolution:
    """Resolve a project profile or return explicit blocking contradictions."""
    now_text = require_utc_timestamp(resolved_at, "resolved_at")
    now = datetime.fromisoformat(now_text.replace("Z", "+00:00"))
    allowed = set(validate_unique_strings(allowed_licences, "allowed_licences", minimum=1))
    contradictions: list[PolicyContradiction] = []
    selected = {item.pack_id: item for item in profile.packs}
    supplied = {item.pack_id: item for item in packs}
    if len(supplied) != len(packs):
        contradictions.append(
            PolicyContradiction.build(
                code="duplicate-pack",
                subject=profile.profile_id,
                sources=(profile.profile_digest,),
                detail="multiple supplied packs share one pack id",
            )
        )
    valid_packs: list[StandardPack] = []
    valid_verifications: list[PackVerification] = []
    for pack_id, selection in selected.items():
        pack = supplied.get(pack_id)
        if pack is None:
            contradictions.append(
                PolicyContradiction.build(
                    code="missing-pack",
                    subject=pack_id,
                    sources=(selection.selection_digest,),
                    detail="selected standard pack was not supplied",
                )
            )
            continue
        if (
            pack.version != selection.version
            or pack.source_digest != selection.source_digest
            or pack.pack_digest != selection.pack_digest
        ):
            contradictions.append(
                PolicyContradiction.build(
                    code="pack-pin-mismatch",
                    subject=pack_id,
                    sources=(selection.selection_digest, pack.pack_digest),
                    detail="supplied pack does not match the exact profile selection",
                )
            )
            continue
        if pack.licence not in allowed:
            contradictions.append(
                PolicyContradiction.build(
                    code="unlicensed-pack",
                    subject=pack_id,
                    sources=(pack.pack_digest,),
                    detail=f"pack licence is not allowed: {pack.licence}",
                )
            )
            continue
        verification_matches = tuple(
            item
            for item in verifications
            if item.pack_digest == pack.pack_digest
            and item.key_id == pack.signature.key_id
            and item.key_id in selection.trusted_key_ids
            and item.valid_for(pack, trust_store)
        )
        if len(verification_matches) != 1:
            contradictions.append(
                PolicyContradiction.build(
                    code="unverified-pack",
                    subject=pack_id,
                    sources=(pack.pack_digest,),
                    detail="pack requires exactly one valid trusted signature verification",
                )
            )
            continue
        valid_packs.append(pack)
        valid_verifications.append(verification_matches[0])
    for pack_id in sorted(set(supplied).difference(selected)):
        contradictions.append(
            PolicyContradiction.build(
                code="unexpected-pack",
                subject=pack_id,
                sources=(supplied[pack_id].pack_digest,),
                detail="supplied pack was not selected by the project profile",
            )
        )
    adapter_by_id = {item.adapter_id: item for item in adapters}
    if len(adapter_by_id) != len(adapters):
        contradictions.append(
            PolicyContradiction.build(
                code="duplicate-adapter",
                subject=profile.profile_id,
                sources=(profile.profile_digest,),
                detail="multiple adapter locks share one adapter id",
            )
        )
    assignments = {item.variable_id: item for item in profile.assignments}
    resolved_variables = tuple(
        ResolvedVariable.build(definition, assignments.get(definition.variable_id))
        for definition in profile.variables
    )
    context = _profile_context(profile, resolved_variables)
    control_sources: dict[str, tuple[StandardPack, ControlDefinition]] = {}
    for pack in valid_packs:
        for control in pack.controls:
            if control.control_id in control_sources:
                contradictions.append(
                    PolicyContradiction.build(
                        code="control-collision",
                        subject=control.control_id,
                        sources=(
                            control_sources[control.control_id][0].pack_digest,
                            pack.pack_digest,
                        ),
                        detail="multiple packs define the same control id",
                    )
                )
            else:
                control_sources[control.control_id] = (pack, control)
    applicability = {item.control_id: item for item in profile.applicability}
    overlays = {item.control_id: item for item in profile.overlays}
    unknown_refs = set(applicability).union(overlays).difference(control_sources)
    for control_id in sorted(unknown_refs):
        contradictions.append(
            PolicyContradiction.build(
                code="unknown-control-reference",
                subject=control_id,
                sources=(profile.profile_digest,),
                detail="profile applicability or overlay references an unknown control",
            )
        )
    effective_controls: list[EffectiveControl] = []
    for control_id, (pack, control) in control_sources.items():
        maturity_applies = (
            TARGET_LEVEL_ORDER[control.target_level]
            <= TARGET_LEVEL_ORDER[profile.intent.target_maturity]
        )
        try:
            condition_applies = (
                control.condition.evaluate(context)
                if control.condition is not None
                else control.default_applicable
            )
        except ValueError as exc:
            contradictions.append(
                PolicyContradiction.build(
                    code="condition-type-error",
                    subject=control_id,
                    sources=(control.control_digest, profile.profile_digest),
                    detail=str(exc),
                )
            )
            condition_applies = False
        decision: ApplicabilityDecision | None = applicability.get(control_id)
        applicable = maturity_applies and condition_applies
        rationale = "pack condition and project maturity"
        active_waivers: list[str] = []
        risk_waiver = _active_waiver(
            profile.waivers,
            control_id=control_id,
            field="assessment-status",
            from_value="fail",
            to_value="accepted-risk",
            now=now,
        )
        risk_acceptance_waiver_ids = (risk_waiver.waiver_id,) if risk_waiver else ()
        if decision is not None:
            rationale = decision.rationale
            if applicable and not decision.applicable:
                waiver = _active_waiver(
                    profile.waivers,
                    control_id=control_id,
                    field="applicable",
                    from_value=True,
                    to_value=False,
                    now=now,
                )
                if waiver is None:
                    contradictions.append(
                        PolicyContradiction.build(
                            code="unauthorized-weakening",
                            subject=control_id,
                            sources=(control.control_digest, decision.decision_digest),
                            detail="applicability weakening lacks an active exact waiver",
                        )
                    )
                else:
                    applicable = False
                    active_waivers.append(waiver.waiver_id)
            else:
                applicable = decision.applicable
        target_level = control.target_level
        mode = control.mode
        overlay: ControlOverlay | None = overlays.get(control_id)
        if overlay is not None:
            if TARGET_LEVEL_ORDER[overlay.target_level] < TARGET_LEVEL_ORDER[target_level]:
                waiver = _active_waiver(
                    profile.waivers,
                    control_id=control_id,
                    field="target_level",
                    from_value=target_level,
                    to_value=overlay.target_level,
                    now=now,
                )
                if waiver is None:
                    contradictions.append(
                        PolicyContradiction.build(
                            code="unauthorized-weakening",
                            subject=control_id,
                            sources=(control.control_digest, overlay.overlay_digest),
                            detail="target level weakening lacks an active exact waiver",
                        )
                    )
                else:
                    target_level = overlay.target_level
                    active_waivers.append(waiver.waiver_id)
            else:
                target_level = overlay.target_level
            if mode == "deny" and overlay.mode == "require":
                waiver = _active_waiver(
                    profile.waivers,
                    control_id=control_id,
                    field="mode",
                    from_value="deny",
                    to_value="require",
                    now=now,
                )
                if waiver is None:
                    contradictions.append(
                        PolicyContradiction.build(
                            code="deny-wins",
                            subject=control_id,
                            sources=(control.control_digest, overlay.overlay_digest),
                            detail="deny cannot be weakened without an active exact waiver",
                        )
                    )
                else:
                    mode = "require"
                    active_waivers.append(waiver.waiver_id)
            elif overlay.mode == "deny":
                mode = "deny"
        missing_adapters = tuple(
            sorted(
                adapter_id
                for adapter_id in control.evidence.required_adapters
                if adapter_id not in adapter_by_id
                or control.domain not in adapter_by_id[adapter_id].domains
            )
        )
        effective_controls.append(
            EffectiveControl.build(
                source_pack=pack,
                control=control,
                applicable=applicable,
                applicability_rationale=rationale,
                target_level=target_level,
                mode=mode,
                active_waiver_ids=tuple(active_waivers),
                missing_adapter_ids=missing_adapters,
                risk_acceptance_waiver_ids=risk_acceptance_waiver_ids,
            )
        )
    all_control_ids = set(control_sources)
    for effective_control in effective_controls:
        missing_dependencies = set(effective_control.control.remediation.dependencies).difference(
            all_control_ids
        )
        if missing_dependencies:
            contradictions.append(
                PolicyContradiction.build(
                    code="missing-control-dependency",
                    subject=effective_control.control.control_id,
                    sources=(effective_control.control.control_digest,),
                    detail="missing dependencies: " + ", ".join(sorted(missing_dependencies)),
                )
            )
    for waiver in profile.waivers:
        if not waiver.active_at(now):
            contradictions.append(
                PolicyContradiction.build(
                    code="inactive-waiver",
                    subject=waiver.waiver_id,
                    sources=(waiver.waiver_digest,),
                    detail="waiver is not active at profile resolution time",
                    blocking=False,
                )
            )
    ordered_contradictions = tuple(
        sorted(contradictions, key=lambda item: (not item.blocking, item.code, item.subject))
    )
    if any(item.blocking for item in ordered_contradictions):
        return ProfileResolution.build(
            profile_digest=profile.profile_digest,
            lock=None,
            contradictions=ordered_contradictions,
        )
    warnings = tuple(item for item in ordered_contradictions if not item.blocking)
    lock = EffectiveProfileLock.build(
        profile=profile,
        packs=tuple(valid_packs),
        verifications=tuple(valid_verifications),
        adapters=adapters,
        variables=resolved_variables,
        controls=tuple(effective_controls),
        warnings=warnings,
        trust_store=trust_store,
        toolchain_digest=toolchain_digest,
        resolved_at=now_text,
    )
    return ProfileResolution.build(
        profile_digest=profile.profile_digest,
        lock=lock,
        contradictions=ordered_contradictions,
    )
