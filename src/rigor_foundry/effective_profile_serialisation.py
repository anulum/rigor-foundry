# SPDX-License-Identifier: Apache-2.0
# Apache License 2.0; see LICENSE.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# RigorFoundry — offline effective-profile lock serialisation
"""Parse sealed effective-profile lock records without re-running resolution."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from .model_primitives import (
    SecretReference,
    VariableValue,
    require_boolean,
    require_digest,
    require_identifier,
    require_utc_timestamp,
    serialise_variable_value,
    validate_unique_strings,
)
from .models import canonical_digest, require_mapping, require_string
from .standard_pack import (
    TARGET_LEVEL_ORDER,
    ControlDefinition,
    ControlMode,
    TargetLevel,
)

if TYPE_CHECKING:
    from .effective_profile import (
        AdapterLock,
        EffectiveControl,
        EffectiveProfileLock,
        PackVerification,
        PolicyContradiction,
        ResolvedVariable,
    )


def _object_array(value: object, field: str) -> list[object]:
    """Return one JSON array for protocol parsing."""
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array")
    return cast(list[object], value)


def adapter_lock_from_dict(value: object) -> AdapterLock:
    """Parse one adapter lock and rederive its content digest."""
    from .effective_profile import AdapterLock

    data = require_mapping(value, "adapter")
    raw_domains = data.get("domains")
    if not isinstance(raw_domains, list):
        raise ValueError("adapter.domains must be an array")
    adapter = AdapterLock.build(
        adapter_id=require_string(data.get("adapter_id"), "adapter.adapter_id"),
        version=require_string(data.get("version"), "adapter.version"),
        executable_digest=require_string(
            data.get("executable_digest"),
            "adapter.executable_digest",
        ),
        config_digest=require_string(data.get("config_digest"), "adapter.config_digest"),
        command_digest=require_string(data.get("command_digest"), "adapter.command_digest"),
        environment_digest=require_string(
            data.get("environment_digest"),
            "adapter.environment_digest",
        ),
        domains=tuple(require_string(item, "adapter.domains[]") for item in raw_domains),
    )
    if data.get("adapter_digest") != adapter.adapter_digest:
        raise ValueError("adapter digest does not match its content")
    return adapter


def pack_verification_from_dict(value: object) -> PackVerification:
    """Parse offline verification evidence and rederive its digest."""
    from .effective_profile import PACK_VERIFICATION_SCHEMA_VERSION, PackVerification

    data = require_mapping(value, "verification")
    if data.get("schema_version") != PACK_VERIFICATION_SCHEMA_VERSION:
        raise ValueError("unsupported pack-verification schema version")
    fields: dict[str, object] = {
        "schema_version": PACK_VERIFICATION_SCHEMA_VERSION,
        "pack_digest": require_digest(data.get("pack_digest"), "verification.pack_digest"),
        "key_id": require_identifier(data.get("key_id"), "verification.key_id"),
        "signature_domain": require_string(
            data.get("signature_domain"),
            "verification.signature_domain",
        ),
        "signature_digest": require_digest(
            data.get("signature_digest"),
            "verification.signature_digest",
        ),
        "trust_store_digest": require_digest(
            data.get("trust_store_digest"),
            "verification.trust_store_digest",
        ),
        "verified_at": require_utc_timestamp(
            data.get("verified_at"),
            "verification.verified_at",
        ),
    }
    verification = PackVerification(
        schema_version=PACK_VERIFICATION_SCHEMA_VERSION,
        pack_digest=cast(str, fields["pack_digest"]),
        key_id=cast(str, fields["key_id"]),
        signature_domain=cast(str, fields["signature_domain"]),
        signature_digest=cast(str, fields["signature_digest"]),
        trust_store_digest=cast(str, fields["trust_store_digest"]),
        verified_at=cast(str, fields["verified_at"]),
        verification_digest=canonical_digest(fields),
    )
    if data.get("verification_digest") != verification.verification_digest:
        raise ValueError("verification digest does not match its content")
    return verification


def resolved_variable_from_dict(value: object) -> ResolvedVariable:
    """Parse one resolved variable binding and rederive its value digest."""
    from .effective_profile import ResolvedVariable

    data = require_mapping(value, "variable")
    raw_value = data.get("value")
    if isinstance(raw_value, list):
        raw_value = tuple(cast(list[object], raw_value))
    if raw_value is not None and not isinstance(raw_value, (str, int, float, bool, tuple)):
        raise ValueError("variable.value has an unsupported type")
    if isinstance(raw_value, tuple) and any(not isinstance(item, str) for item in raw_value):
        raise ValueError("variable.value string-list members must be strings")
    raw_secret = data.get("secret_ref")
    secret_ref = None if raw_secret is None else SecretReference.from_dict(raw_secret)
    typed_value = cast(VariableValue | None, raw_value)
    fields: dict[str, object] = {
        "variable_id": require_identifier(data.get("variable_id"), "variable.variable_id"),
        "definition_digest": require_digest(
            data.get("definition_digest"),
            "variable.definition_digest",
        ),
        "assignment_digest": require_digest(
            data.get("assignment_digest"),
            "variable.assignment_digest",
        ),
        "sensitivity": require_string(data.get("sensitivity"), "variable.sensitivity"),
        "value": serialise_variable_value(typed_value),
        "secret_ref": secret_ref.to_dict() if secret_ref is not None else None,
    }
    resolved = ResolvedVariable(
        variable_id=cast(str, fields["variable_id"]),
        definition_digest=cast(str, fields["definition_digest"]),
        assignment_digest=cast(str, fields["assignment_digest"]),
        sensitivity=cast(str, fields["sensitivity"]),
        value=typed_value,
        secret_ref=secret_ref,
        value_digest=canonical_digest(fields),
    )
    if data.get("value_digest") != resolved.value_digest:
        raise ValueError("variable value digest does not match its content")
    return resolved


def policy_contradiction_from_dict(value: object) -> PolicyContradiction:
    """Parse one contradiction and rederive its digest."""
    from .effective_profile import PolicyContradiction

    data = require_mapping(value, "contradiction")
    raw_sources = data.get("sources")
    if not isinstance(raw_sources, list):
        raise ValueError("contradiction.sources must be an array")
    contradiction = PolicyContradiction.build(
        code=require_string(data.get("code"), "contradiction.code"),
        subject=require_string(data.get("subject"), "contradiction.subject"),
        sources=tuple(require_string(item, "contradiction.sources[]") for item in raw_sources),
        detail=require_string(data.get("detail"), "contradiction.detail"),
        blocking=require_boolean(data.get("blocking"), "contradiction.blocking"),
    )
    if data.get("contradiction_digest") != contradiction.contradiction_digest:
        raise ValueError("contradiction digest does not match its content")
    return contradiction


def effective_control_from_dict(value: object) -> EffectiveControl:
    """Parse one effective control and rederive its content digest."""
    from .effective_profile import EffectiveControl

    data = require_mapping(value, "effective_control")
    control = ControlDefinition.from_dict(data.get("control"))
    target_level = cast(
        TargetLevel,
        require_string(data.get("target_level"), "effective_control.target_level"),
    )
    mode = cast(ControlMode, require_string(data.get("mode"), "effective_control.mode"))
    if target_level not in TARGET_LEVEL_ORDER:
        raise ValueError("effective_control.target_level is unsupported")
    if mode not in {"require", "deny"}:
        raise ValueError("effective_control.mode is unsupported")
    policy_waivers = validate_unique_strings(
        tuple(
            require_string(item, "effective_control.active_waiver_ids[]")
            for item in _object_array(
                data.get("active_waiver_ids"),
                "effective_control.active_waiver_ids",
            )
        ),
        "effective_control.active_waiver_ids",
    )
    risk_waivers = validate_unique_strings(
        tuple(
            require_string(item, "effective_control.risk_acceptance_waiver_ids[]")
            for item in _object_array(
                data.get("risk_acceptance_waiver_ids"),
                "effective_control.risk_acceptance_waiver_ids",
            )
        ),
        "effective_control.risk_acceptance_waiver_ids",
    )
    if set(policy_waivers).intersection(risk_waivers):
        raise ValueError("policy and risk-acceptance waiver ids must be disjoint")
    missing = validate_unique_strings(
        tuple(
            require_string(item, "effective_control.missing_adapter_ids[]")
            for item in _object_array(
                data.get("missing_adapter_ids"),
                "effective_control.missing_adapter_ids",
            )
        ),
        "effective_control.missing_adapter_ids",
    )
    fields: dict[str, object] = {
        "source_pack_id": require_identifier(
            data.get("source_pack_id"),
            "effective_control.source_pack_id",
        ),
        "source_pack_digest": require_digest(
            data.get("source_pack_digest"),
            "effective_control.source_pack_digest",
        ),
        "control": control.to_dict(),
        "applicable": require_boolean(data.get("applicable"), "effective_control.applicable"),
        "applicability_rationale": require_string(
            data.get("applicability_rationale"),
            "effective_control.applicability_rationale",
        ),
        "target_level": target_level,
        "mode": mode,
        "active_waiver_ids": list(policy_waivers),
        "risk_acceptance_waiver_ids": list(risk_waivers),
        "missing_adapter_ids": list(missing),
    }
    effective = EffectiveControl(
        source_pack_id=cast(str, fields["source_pack_id"]),
        source_pack_digest=cast(str, fields["source_pack_digest"]),
        control=control,
        applicable=cast(bool, fields["applicable"]),
        applicability_rationale=cast(str, fields["applicability_rationale"]),
        target_level=target_level,
        mode=mode,
        active_waiver_ids=tuple(policy_waivers),
        risk_acceptance_waiver_ids=tuple(risk_waivers),
        missing_adapter_ids=tuple(missing),
        effective_digest=canonical_digest(fields),
    )
    if data.get("effective_digest") != effective.effective_digest:
        raise ValueError("effective-control digest does not match its content")
    return effective


def effective_profile_lock_from_dict(value: object) -> EffectiveProfileLock:
    """Parse one serialised lock and rederive its content digest."""
    from .effective_profile import (
        LEGACY_LOCK_SCHEMA_VERSION,
        LOCK_SCHEMA_VERSION,
        RESOLVER_VERSION,
        EffectiveProfileLock,
    )

    data = require_mapping(value, "lock")
    schema_version = data.get("schema_version")
    if schema_version not in {LEGACY_LOCK_SCHEMA_VERSION, LOCK_SCHEMA_VERSION}:
        raise ValueError("unsupported effective-profile lock schema version")
    if schema_version == LEGACY_LOCK_SCHEMA_VERSION and "cra_policy_digest" in data:
        raise ValueError("legacy effective-profile lock must not carry CRA policy")
    if schema_version == LOCK_SCHEMA_VERSION and "cra_policy_digest" not in data:
        raise ValueError("effective-profile lock schema 1.1 requires CRA policy digest")
    if data.get("resolver_version") != RESOLVER_VERSION:
        raise ValueError("unsupported effective-profile resolver version")
    pack_digests = tuple(
        require_digest(item, "lock.pack_digests[]")
        for item in _object_array(data.get("pack_digests"), "lock.pack_digests")
    )
    verification_digests = tuple(
        require_digest(item, "lock.verification_digests[]")
        for item in _object_array(
            data.get("verification_digests"),
            "lock.verification_digests",
        )
    )
    adapters = tuple(
        adapter_lock_from_dict(item)
        for item in _object_array(data.get("adapters"), "lock.adapters")
    )
    variables = tuple(
        resolved_variable_from_dict(item)
        for item in _object_array(data.get("variables"), "lock.variables")
    )
    controls = tuple(
        effective_control_from_dict(item)
        for item in _object_array(data.get("controls"), "lock.controls")
    )
    warnings = tuple(
        policy_contradiction_from_dict(item)
        for item in _object_array(data.get("warnings"), "lock.warnings")
    )
    if any(item.blocking for item in warnings):
        raise ValueError("effective profile lock cannot contain blocking contradictions")
    for values, label in (
        ((item.adapter_id for item in adapters), "adapter ids"),
        ((item.variable_id for item in variables), "variable ids"),
        ((item.control.control_id for item in controls), "control ids"),
    ):
        identifiers = tuple(values)
        if len(identifiers) != len(set(identifiers)):
            raise ValueError(f"effective profile {label} must be unique")
    pack_digest_set = set(pack_digests)
    if any(item.source_pack_digest not in pack_digest_set for item in controls):
        raise ValueError("effective control references an unlocked source pack")
    ordered_adapters = tuple(sorted(adapters, key=lambda item: item.adapter_id))
    ordered_variables = tuple(sorted(variables, key=lambda item: item.variable_id))
    ordered_controls = tuple(sorted(controls, key=lambda item: item.control.versioned_id))
    fields: dict[str, object] = {
        "schema_version": schema_version,
        "resolver_version": RESOLVER_VERSION,
        "profile_digest": require_digest(data.get("profile_digest"), "lock.profile_digest"),
        "intent_digest": require_digest(data.get("intent_digest"), "lock.intent_digest"),
        "pack_digests": sorted(pack_digests),
        "verification_digests": sorted(verification_digests),
        "adapters": [item.to_dict() for item in ordered_adapters],
        "variables": [item.to_dict() for item in ordered_variables],
        "controls": [item.to_dict() for item in ordered_controls],
        "warnings": [item.to_dict() for item in warnings],
        "toolchain_digest": require_digest(
            data.get("toolchain_digest"),
            "lock.toolchain_digest",
        ),
        "resolved_at": require_utc_timestamp(data.get("resolved_at"), "lock.resolved_at"),
    }
    if schema_version == LOCK_SCHEMA_VERSION:
        fields["cra_policy_digest"] = require_digest(
            data.get("cra_policy_digest"),
            "lock.cra_policy_digest",
        )
    lock = EffectiveProfileLock(
        profile_digest=cast(str, fields["profile_digest"]),
        intent_digest=cast(str, fields["intent_digest"]),
        pack_digests=tuple(cast(list[str], fields["pack_digests"])),
        verification_digests=tuple(cast(list[str], fields["verification_digests"])),
        adapters=ordered_adapters,
        variables=ordered_variables,
        controls=ordered_controls,
        warnings=warnings,
        toolchain_digest=cast(str, fields["toolchain_digest"]),
        resolved_at=cast(str, fields["resolved_at"]),
        cra_policy_digest=cast(str | None, fields.get("cra_policy_digest")),
        lock_digest=canonical_digest(fields),
    )
    if data.get("lock_digest") != lock.lock_digest:
        raise ValueError("lock digest does not match its content")
    return lock
